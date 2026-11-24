package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fabricio948/system_login/internal/config"
	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/repository"
)

// AuthService implements the public authentication flows.
type AuthService interface {
	Register(ctx context.Context, input RegisterInput) (*Profile, error)
	Login(ctx context.Context, input LoginInput) (*LoginResult, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	Logout(ctx context.Context, accessToken string) error
	Authenticate(ctx context.Context, accessToken string) (*Profile, error)
	ForgotPassword(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error)
	ResetPassword(ctx context.Context, input ResetPasswordInput) error
}

type authService struct {
	cfg        *config.Config
	users      repository.UserRepository
	sessions   repository.SessionRepository
	recoveries repository.PasswordRecoveryRepository
	hasher     PasswordHasher
	notifier   NotificationService
	publisher  EventPublisher
	clock      Clock
	dummyHash  string
}

// NewAuthService wires the authentication service dependencies.
func NewAuthService(
	cfg *config.Config,
	users repository.UserRepository,
	sessions repository.SessionRepository,
	recoveries repository.PasswordRecoveryRepository,
	hasher PasswordHasher,
	notifier NotificationService,
	publisher EventPublisher,
	clock Clock,
) AuthService {
	if clock == nil {
		clock = NewSystemClock()
	}

	// Used to equalize timing when the email does not exist.
	dummyHash, _ := hasher.Hash("dummy-password-for-timing")

	return &authService{
		cfg:        cfg,
		users:      users,
		sessions:   sessions,
		recoveries: recoveries,
		hasher:     hasher,
		notifier:   notifier,
		publisher:  publisher,
		clock:      clock,
		dummyHash:  dummyHash,
	}
}

func (s *authService) Register(ctx context.Context, input RegisterInput) (*Profile, error) {
	name := strings.TrimSpace(input.Name)
	if err := validateName(name); err != nil {
		return nil, err
	}

	email := normalizeEmail(input.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if err := validatePassword("password", input.Password); err != nil {
		return nil, err
	}

	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Name:         name,
		Email:        email,
		PasswordHash: passwordHash,
	}
	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	created, err := s.users.FindByID(ctx, user.ID)
	if err != nil {
		return nil, err
	}

	publishEvent(ctx, s.publisher, s.clock, EventUserRegistered, created.ID, nil)
	return profileFromUser(created), nil
}

func (s *authService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	now := s.clock.Now()
	email := normalizeEmail(input.Email)

	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) {
		_ = s.hasher.Verify(s.dummyHash, input.Password)
		return nil, model.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		_ = s.hasher.Verify(s.dummyHash, input.Password)
		return nil, model.ErrInvalidCredentials
	}

	if err := clearStaleBlock(ctx, s.users, user, now); err != nil {
		return nil, err
	}
	if user.IsBlocked(now) {
		return nil, blockedError(user, now)
	}

	if err := s.hasher.Verify(user.PasswordHash, input.Password); err != nil {
		attempts, incrementErr := s.users.IncrementFailedLoginAttempts(ctx, user.ID)
		if incrementErr != nil {
			return nil, incrementErr
		}
		publishEvent(ctx, s.publisher, s.clock, EventLoginFailed, user.ID, nil)

		if attempts >= s.cfg.MaxFailedLoginAttempts {
			until := now.Add(s.cfg.TempBlockDuration)
			reason := "too many failed login attempts"
			if blockErr := s.users.SetTemporaryBlock(ctx, user.ID, until, reason, now); blockErr != nil {
				return nil, blockErr
			}
			publishEvent(ctx, s.publisher, s.clock, EventUserBlocked, user.ID, map[string]string{"type": "temporary"})
			return nil, &BlockedError{
				Reason:    reason,
				Until:     &until,
				Remaining: s.cfg.TempBlockDuration,
			}
		}
		return nil, model.ErrInvalidCredentials
	}

	if user.FailedLoginAttempts > 0 {
		if err := s.users.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
			return nil, err
		}
	}

	session, pair, err := s.newSession(user.ID, now)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, err
	}

	publishEvent(ctx, s.publisher, s.clock, EventLoginSucceeded, user.ID, nil)
	return &LoginResult{
		TokenPair: *pair,
		User:      *profileFromUser(user),
	}, nil
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	now := s.clock.Now()

	current, err := s.sessions.FindByRefreshTokenHash(ctx, hashToken(refreshToken))
	if errors.Is(err, model.ErrSessionNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	if current.IsRevoked() {
		return nil, ErrInvalidRefreshToken
	}
	if !current.IsRefreshTokenValid(now) {
		return nil, model.ErrRefreshTokenExpired
	}

	user, err := s.users.FindByID(ctx, current.UserID)
	if errors.Is(err, model.ErrUserNotFound) {
		return nil, ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	if err := clearStaleBlock(ctx, s.users, user, now); err != nil {
		return nil, err
	}
	if !user.IsActive {
		return nil, model.ErrUserInactive
	}
	if user.IsBlocked(now) {
		return nil, blockedError(user, now)
	}

	next, pair, err := s.newSession(user.ID, now)
	if err != nil {
		return nil, err
	}
	if err := s.sessions.Rotate(ctx, current.ID, now, next); err != nil {
		if errors.Is(err, model.ErrSessionRevoked) || errors.Is(err, model.ErrSessionNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	publishEvent(ctx, s.publisher, s.clock, EventSessionRefreshed, user.ID, nil)
	return pair, nil
}

func (s *authService) Logout(ctx context.Context, accessToken string) error {
	now := s.clock.Now()

	session, err := s.sessions.FindByAccessTokenHash(ctx, hashToken(accessToken))
	if errors.Is(err, model.ErrSessionNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if session.IsRevoked() {
		return nil
	}

	if err := s.sessions.Revoke(ctx, session.ID, now); err != nil {
		if errors.Is(err, model.ErrSessionNotFound) {
			return nil
		}
		return err
	}

	publishEvent(ctx, s.publisher, s.clock, EventSessionRevoked, session.UserID, nil)
	return nil
}

func (s *authService) Authenticate(ctx context.Context, accessToken string) (*Profile, error) {
	now := s.clock.Now()

	session, err := s.sessions.FindByAccessTokenHash(ctx, hashToken(accessToken))
	if errors.Is(err, model.ErrSessionNotFound) {
		return nil, ErrInvalidAccessToken
	}
	if err != nil {
		return nil, err
	}
	if session.IsRevoked() {
		return nil, ErrInvalidAccessToken
	}
	if !session.IsAccessTokenValid(now) {
		return nil, model.ErrAccessTokenExpired
	}

	user, err := s.users.FindByID(ctx, session.UserID)
	if errors.Is(err, model.ErrUserNotFound) {
		return nil, ErrInvalidAccessToken
	}
	if err != nil {
		return nil, err
	}
	if err := clearStaleBlock(ctx, s.users, user, now); err != nil {
		return nil, err
	}
	if !user.IsActive {
		return nil, model.ErrUserInactive
	}
	if user.IsBlocked(now) {
		return nil, blockedError(user, now)
	}

	return profileFromUser(user), nil
}

func (s *authService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error) {
	now := s.clock.Now()
	email := normalizeEmail(input.Email)
	if err := validateEmail(email); err != nil {
		return nil, err
	}

	code, err := generateRecoveryCode()
	if err != nil {
		return nil, err
	}

	result := &ForgotPasswordResult{
		Message:      ForgotPasswordMessage,
		CodeReturned: !s.notifier.DeliveryEnabled(),
		ExpiresAt:    now.Add(s.cfg.RecoveryCodeTTL),
	}

	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) || (err == nil && !user.IsActive) {
		// The fake code is never persisted, so it cannot be used.
		if result.CodeReturned {
			result.Code = code
		}
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	if err := clearStaleBlock(ctx, s.users, user, now); err != nil {
		return nil, err
	}

	recovery := &model.PasswordRecovery{
		UserID:    user.ID,
		CodeHash:  hashRecoveryCode(s.cfg.RecoveryCodePepper, code),
		ExpiresAt: result.ExpiresAt,
	}
	if err := s.recoveries.Create(ctx, recovery, now); err != nil {
		return nil, err
	}

	if err := s.notifier.SendPasswordRecoveryCode(ctx, email, code); err != nil {
		_ = s.recoveries.Invalidate(ctx, recovery.ID, now)
		return nil, fmt.Errorf("send recovery code: %w", err)
	}

	if result.CodeReturned {
		result.Code = code
	}
	publishEvent(ctx, s.publisher, s.clock, EventRecoveryRequested, user.ID, nil)
	return result, nil
}

func (s *authService) ResetPassword(ctx context.Context, input ResetPasswordInput) error {
	now := s.clock.Now()
	email := normalizeEmail(input.Email)
	if err := validateEmail(email); err != nil {
		return err
	}
	if err := validateRecoveryCode(input.Code); err != nil {
		return err
	}
	if err := validatePassword("new_password", input.NewPassword); err != nil {
		return err
	}

	user, err := s.users.FindByEmail(ctx, email)
	if errors.Is(err, model.ErrUserNotFound) {
		return ErrInvalidRecoveryCode
	}
	if err != nil {
		return err
	}
	if !user.IsActive {
		return ErrInvalidRecoveryCode
	}
	if err := clearStaleBlock(ctx, s.users, user, now); err != nil {
		return err
	}

	recovery, err := s.recoveries.FindLatestByUserID(ctx, user.ID)
	if errors.Is(err, model.ErrRecoveryCodeNotFound) {
		return ErrInvalidRecoveryCode
	}
	if err != nil {
		return err
	}
	if recovery.IsUsed() || recovery.IsInvalidated() {
		return ErrInvalidRecoveryCode
	}
	if recovery.IsExpired(now) {
		return model.ErrRecoveryCodeExpired
	}
	if recovery.FailedAttempts >= s.cfg.MaxRecoveryAttempts {
		if invalidateErr := s.recoveries.Invalidate(ctx, recovery.ID, now); invalidateErr != nil &&
			!errors.Is(invalidateErr, model.ErrRecoveryCodeInvalidated) {
			return invalidateErr
		}
		return model.ErrRecoveryAttemptsExceeded
	}

	expected := hashRecoveryCode(s.cfg.RecoveryCodePepper, input.Code)
	if subtle.ConstantTimeCompare([]byte(recovery.CodeHash), []byte(expected)) != 1 {
		attempts, incrementErr := s.recoveries.IncrementFailedAttempts(ctx, recovery.ID)
		if incrementErr != nil {
			return incrementErr
		}
		if attempts >= s.cfg.MaxRecoveryAttempts {
			if invalidateErr := s.recoveries.Invalidate(ctx, recovery.ID, now); invalidateErr != nil &&
				!errors.Is(invalidateErr, model.ErrRecoveryCodeInvalidated) {
				return invalidateErr
			}
			return model.ErrRecoveryAttemptsExceeded
		}
		return ErrInvalidRecoveryCode
	}

	passwordHash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return err
	}

	if err := s.recoveries.MarkUsed(ctx, recovery.ID, now); err != nil {
		if errors.Is(err, model.ErrRecoveryCodeUsed) || errors.Is(err, model.ErrRecoveryCodeInvalidated) {
			return ErrInvalidRecoveryCode
		}
		return err
	}
	if err := s.users.UpdatePassword(ctx, user.ID, passwordHash); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeByUserID(ctx, user.ID, now); err != nil {
		return err
	}

	publishEvent(ctx, s.publisher, s.clock, EventPasswordReset, user.ID, nil)
	return nil
}

func (s *authService) newSession(userID uint64, now time.Time) (*model.Session, *TokenPair, error) {
	accessToken, err := generateToken()
	if err != nil {
		return nil, nil, err
	}
	refreshToken, err := generateToken()
	if err != nil {
		return nil, nil, err
	}

	accessExpiresAt := now.Add(s.cfg.AccessTokenTTL)
	refreshExpiresAt := now.Add(s.cfg.RefreshTokenTTL)

	session := &model.Session{
		UserID:           userID,
		AccessTokenHash:  hashToken(accessToken),
		RefreshTokenHash: hashToken(refreshToken),
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}
	pair := &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}
	return session, pair, nil
}
