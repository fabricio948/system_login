package service

import (
	"context"
	"strings"

	"github.com/fabricio948/system_login/internal/repository"
)

// AccountService implements the authenticated account flows. Every method
// receives the user ID resolved from the access token; there is no target ID,
// which structurally prevents cross-user access.
type AccountService interface {
	GetProfile(ctx context.Context, userID uint64) (*Profile, error)
	UpdateName(ctx context.Context, userID uint64, input UpdateNameInput) (*Profile, error)
	ChangePassword(ctx context.Context, userID uint64, input ChangePasswordInput) error
	DeleteAccount(ctx context.Context, userID uint64) error
}

type accountService struct {
	users     repository.UserRepository
	sessions  repository.SessionRepository
	hasher    PasswordHasher
	publisher EventPublisher
	clock     Clock
}

// NewAccountService wires the account service dependencies.
func NewAccountService(
	users repository.UserRepository,
	sessions repository.SessionRepository,
	hasher PasswordHasher,
	publisher EventPublisher,
	clock Clock,
) AccountService {
	if clock == nil {
		clock = NewSystemClock()
	}
	return &accountService{
		users:     users,
		sessions:  sessions,
		hasher:    hasher,
		publisher: publisher,
		clock:     clock,
	}
}

func (s *accountService) GetProfile(ctx context.Context, userID uint64) (*Profile, error) {
	user, err := loadAccessibleUser(ctx, s.users, userID, s.clock.Now())
	if err != nil {
		return nil, err
	}
	return profileFromUser(user), nil
}

func (s *accountService) UpdateName(ctx context.Context, userID uint64, input UpdateNameInput) (*Profile, error) {
	name := strings.TrimSpace(input.Name)
	if err := validateName(name); err != nil {
		return nil, err
	}

	user, err := loadAccessibleUser(ctx, s.users, userID, s.clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.users.UpdateName(ctx, user.ID, name); err != nil {
		return nil, err
	}

	user.Name = name
	return profileFromUser(user), nil
}

func (s *accountService) ChangePassword(ctx context.Context, userID uint64, input ChangePasswordInput) error {
	if err := validatePassword("new_password", input.NewPassword); err != nil {
		return err
	}

	now := s.clock.Now()
	user, err := loadAccessibleUser(ctx, s.users, userID, now)
	if err != nil {
		return err
	}

	if err := s.hasher.Verify(user.PasswordHash, input.CurrentPassword); err != nil {
		return ErrInvalidCurrentPassword
	}
	if err := s.hasher.Verify(user.PasswordHash, input.NewPassword); err == nil {
		return ErrPasswordUnchanged
	}

	passwordHash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return err
	}
	if err := s.users.UpdatePassword(ctx, user.ID, passwordHash); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeByUserID(ctx, user.ID, now); err != nil {
		return err
	}

	publishEvent(ctx, s.publisher, s.clock, EventPasswordChanged, user.ID, nil)
	return nil
}

func (s *accountService) DeleteAccount(ctx context.Context, userID uint64) error {
	now := s.clock.Now()
	user, err := loadAccessibleUser(ctx, s.users, userID, now)
	if err != nil {
		return err
	}

	if err := s.users.SoftDelete(ctx, user.ID); err != nil {
		return err
	}
	if _, err := s.sessions.RevokeByUserID(ctx, user.ID, now); err != nil {
		return err
	}

	publishEvent(ctx, s.publisher, s.clock, EventAccountDeleted, user.ID, nil)
	return nil
}
