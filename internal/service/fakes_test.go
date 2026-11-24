package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/fabricio948/system_login/internal/config"
	"github.com/fabricio948/system_login/internal/model"
)

type fakeUserRepo struct {
	users  map[uint64]*model.User
	nextID uint64
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{users: make(map[uint64]*model.User)}
}

func cloneUser(user *model.User) *model.User {
	clone := *user
	return &clone
}

func (r *fakeUserRepo) Create(ctx context.Context, user *model.User) error {
	for _, existing := range r.users {
		if strings.EqualFold(existing.Email, user.Email) {
			return model.ErrEmailAlreadyExists
		}
	}
	r.nextID++
	user.ID = r.nextID
	if user.CreatedAt.IsZero() {
		user.CreatedAt = time.Now().UTC()
	}
	user.UpdatedAt = user.CreatedAt
	r.users[user.ID] = cloneUser(user)
	return nil
}

func (r *fakeUserRepo) FindByEmail(ctx context.Context, email string) (*model.User, error) {
	for _, user := range r.users {
		if strings.EqualFold(user.Email, email) {
			return cloneUser(user), nil
		}
	}
	return nil, model.ErrUserNotFound
}

func (r *fakeUserRepo) FindByID(ctx context.Context, id uint64) (*model.User, error) {
	user, ok := r.users[id]
	if !ok {
		return nil, model.ErrUserNotFound
	}
	return cloneUser(user), nil
}

func (r *fakeUserRepo) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	for _, user := range r.users {
		if strings.EqualFold(user.Email, email) {
			return true, nil
		}
	}
	return false, nil
}

func (r *fakeUserRepo) GetAuthStatus(ctx context.Context, id uint64) (model.AuthStatus, error) {
	user, ok := r.users[id]
	if !ok {
		return model.AuthStatus{}, model.ErrUserNotFound
	}
	status := model.AuthStatus{
		UserID:         user.ID,
		IsActive:       user.IsActive,
		IsAdminBlocked: user.IsAdminBlocked,
		BlockType:      user.BlockType,
	}
	if user.BlockedUntil != nil {
		until := *user.BlockedUntil
		status.BlockedUntil = &until
	}
	return status, nil
}

func (r *fakeUserRepo) UpdateName(ctx context.Context, id uint64, name string) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.Name = name
	return nil
}

func (r *fakeUserRepo) UpdatePassword(ctx context.Context, id uint64, passwordHash string) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.PasswordHash = passwordHash
	return nil
}

func (r *fakeUserRepo) IncrementFailedLoginAttempts(ctx context.Context, id uint64) (int, error) {
	user, ok := r.users[id]
	if !ok {
		return 0, model.ErrUserNotFound
	}
	user.FailedLoginAttempts++
	return user.FailedLoginAttempts, nil
}

func (r *fakeUserRepo) ResetFailedLoginAttempts(ctx context.Context, id uint64) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.FailedLoginAttempts = 0
	return nil
}

func (r *fakeUserRepo) SetTemporaryBlock(ctx context.Context, id uint64, until time.Time, reason string, blockedAt time.Time) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.BlockedUntil = &until
	user.BlockedAt = &blockedAt
	user.BlockType = model.BlockTypeTemporary
	user.BlockReason = reason
	return nil
}

func (r *fakeUserRepo) ClearBlock(ctx context.Context, id uint64) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.BlockedUntil = nil
	user.BlockedAt = nil
	user.BlockType = ""
	user.BlockReason = ""
	user.FailedLoginAttempts = 0
	return nil
}

func (r *fakeUserRepo) SoftDelete(ctx context.Context, id uint64) error {
	user, ok := r.users[id]
	if !ok {
		return model.ErrUserNotFound
	}
	user.IsActive = false
	return nil
}

type fakeSessionRepo struct {
	sessions map[uint64]*model.Session
	nextID   uint64
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{sessions: make(map[uint64]*model.Session)}
}

func cloneSession(session *model.Session) *model.Session {
	clone := *session
	return &clone
}

func (r *fakeSessionRepo) Create(ctx context.Context, session *model.Session) error {
	r.nextID++
	session.ID = r.nextID
	r.sessions[session.ID] = cloneSession(session)
	return nil
}

func (r *fakeSessionRepo) FindByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	for _, session := range r.sessions {
		if session.AccessTokenHash == hash {
			return cloneSession(session), nil
		}
	}
	return nil, model.ErrSessionNotFound
}

func (r *fakeSessionRepo) FindByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	for _, session := range r.sessions {
		if session.RefreshTokenHash == hash {
			return cloneSession(session), nil
		}
	}
	return nil, model.ErrSessionNotFound
}

func (r *fakeSessionRepo) Rotate(ctx context.Context, currentID uint64, revokedAt time.Time, next *model.Session) error {
	current, ok := r.sessions[currentID]
	if !ok {
		return model.ErrSessionNotFound
	}
	if current.RevokedAt != nil {
		return model.ErrSessionRevoked
	}
	current.RevokedAt = &revokedAt
	return r.Create(ctx, next)
}

func (r *fakeSessionRepo) Revoke(ctx context.Context, id uint64, revokedAt time.Time) error {
	session, ok := r.sessions[id]
	if !ok {
		return model.ErrSessionNotFound
	}
	session.RevokedAt = &revokedAt
	return nil
}

func (r *fakeSessionRepo) RevokeByUserID(ctx context.Context, userID uint64, revokedAt time.Time) (int64, error) {
	var revoked int64
	for _, session := range r.sessions {
		if session.UserID == userID && session.RevokedAt == nil {
			session.RevokedAt = &revokedAt
			revoked++
		}
	}
	return revoked, nil
}

func (r *fakeSessionRepo) DeleteExpired(ctx context.Context, now time.Time) (int64, error) {
	var deleted int64
	for id, session := range r.sessions {
		if session.RefreshExpiresAt.Before(now) {
			delete(r.sessions, id)
			deleted++
		}
	}
	return deleted, nil
}

type fakeRecoveryRepo struct {
	recoveries map[uint64]*model.PasswordRecovery
	nextID     uint64
}

func newFakeRecoveryRepo() *fakeRecoveryRepo {
	return &fakeRecoveryRepo{recoveries: make(map[uint64]*model.PasswordRecovery)}
}

func cloneRecovery(recovery *model.PasswordRecovery) *model.PasswordRecovery {
	clone := *recovery
	return &clone
}

func (r *fakeRecoveryRepo) Create(ctx context.Context, recovery *model.PasswordRecovery, now time.Time) error {
	for _, existing := range r.recoveries {
		if existing.UserID == recovery.UserID && existing.UsedAt == nil && existing.InvalidatedAt == nil {
			invalidatedAt := now
			existing.InvalidatedAt = &invalidatedAt
		}
	}
	r.nextID++
	recovery.ID = r.nextID
	recovery.CreatedAt = now
	r.recoveries[recovery.ID] = cloneRecovery(recovery)
	return nil
}

func (r *fakeRecoveryRepo) FindLatestByUserID(ctx context.Context, userID uint64) (*model.PasswordRecovery, error) {
	var latest *model.PasswordRecovery
	for _, recovery := range r.recoveries {
		if recovery.UserID != userID {
			continue
		}
		if latest == nil ||
			recovery.CreatedAt.After(latest.CreatedAt) ||
			(recovery.CreatedAt.Equal(latest.CreatedAt) && recovery.ID > latest.ID) {
			latest = recovery
		}
	}
	if latest == nil {
		return nil, model.ErrRecoveryCodeNotFound
	}
	return cloneRecovery(latest), nil
}

func (r *fakeRecoveryRepo) IncrementFailedAttempts(ctx context.Context, id uint64) (int, error) {
	recovery, ok := r.recoveries[id]
	if !ok {
		return 0, model.ErrRecoveryCodeNotFound
	}
	recovery.FailedAttempts++
	return recovery.FailedAttempts, nil
}

func (r *fakeRecoveryRepo) MarkUsed(ctx context.Context, id uint64, usedAt time.Time) error {
	recovery, ok := r.recoveries[id]
	if !ok {
		return model.ErrRecoveryCodeNotFound
	}
	if recovery.UsedAt != nil {
		return model.ErrRecoveryCodeUsed
	}
	if recovery.InvalidatedAt != nil {
		return model.ErrRecoveryCodeInvalidated
	}
	recovery.UsedAt = &usedAt
	return nil
}

func (r *fakeRecoveryRepo) Invalidate(ctx context.Context, id uint64, invalidatedAt time.Time) error {
	recovery, ok := r.recoveries[id]
	if !ok {
		return model.ErrRecoveryCodeNotFound
	}
	if recovery.UsedAt != nil {
		return model.ErrRecoveryCodeUsed
	}
	if recovery.InvalidatedAt != nil {
		return model.ErrRecoveryCodeInvalidated
	}
	recovery.InvalidatedAt = &invalidatedAt
	return nil
}

type sentCode struct {
	Email string
	Code  string
}

type fakeNotifier struct {
	enabled bool
	sent    []sentCode
	err     error
}

func (n *fakeNotifier) DeliveryEnabled() bool {
	return n.enabled
}

func (n *fakeNotifier) SendPasswordRecoveryCode(ctx context.Context, email, code string) error {
	if n.err != nil {
		return n.err
	}
	n.sent = append(n.sent, sentCode{Email: email, Code: code})
	return nil
}

type fakePublisher struct {
	events []Event
}

func (p *fakePublisher) Publish(ctx context.Context, event Event) error {
	p.events = append(p.events, event)
	return nil
}

func (p *fakePublisher) has(eventType string) bool {
	for _, event := range p.events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	return c.now
}

func (c *fakeClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

type testHasher struct{}

func (testHasher) Hash(password string) (string, error) {
	return "hash:" + password, nil
}

func (testHasher) Verify(hash, password string) error {
	if hash == "hash:"+password {
		return nil
	}
	return errors.New("password mismatch")
}

type fixture struct {
	cfg        *config.Config
	users      *fakeUserRepo
	sessions   *fakeSessionRepo
	recoveries *fakeRecoveryRepo
	notifier   *fakeNotifier
	publisher  *fakePublisher
	clock      *fakeClock
	auth       AuthService
	account    AccountService
}

func newFixture() *fixture {
	f := &fixture{
		cfg: &config.Config{
			AccessTokenTTL:         15 * time.Minute,
			RefreshTokenTTL:        7 * 24 * time.Hour,
			RecoveryCodeTTL:        15 * time.Minute,
			MaxFailedLoginAttempts: 4,
			TempBlockDuration:      10 * time.Minute,
			MaxRecoveryAttempts:    5,
			RecoveryCodePepper:     strings.Repeat("p", 64),
		},
		users:      newFakeUserRepo(),
		sessions:   newFakeSessionRepo(),
		recoveries: newFakeRecoveryRepo(),
		notifier:   &fakeNotifier{},
		publisher:  &fakePublisher{},
		clock:      &fakeClock{now: time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)},
	}

	f.auth = NewAuthService(
		f.cfg,
		f.users,
		f.sessions,
		f.recoveries,
		testHasher{},
		f.notifier,
		f.publisher,
		f.clock,
	)
	f.account = NewAccountService(
		f.users,
		f.sessions,
		testHasher{},
		f.publisher,
		f.clock,
	)
	return f
}

func (f *fixture) seedUser(name, email, password string) *model.User {
	user := &model.User{
		Name:         name,
		Email:        strings.ToLower(email),
		PasswordHash: "hash:" + password,
		IsActive:     true,
		CreatedAt:    f.clock.Now(),
	}
	if err := f.users.Create(context.Background(), user); err != nil {
		panic(err)
	}
	return f.users.users[user.ID]
}
