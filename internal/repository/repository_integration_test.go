//go:build integration

package repository_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/repository"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()

	dsn := os.Getenv("TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("ping database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

const missingID uint64 = 1 << 62

func tokenHash(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func TestRepositoriesIntegration(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	userRepo := repository.NewUserRepository(db)
	sessionRepo := repository.NewSessionRepository(db)
	recoveryRepo := repository.NewPasswordRecoveryRepository(db)

	now := time.Now().UTC().Truncate(time.Microsecond)
	email := fmt.Sprintf("repo-test-%d@example.com", now.UnixNano())

	user := &model.User{
		Name:         "Repository Test",
		Email:        email,
		PasswordHash: "initial-hash",
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, user.ID); err != nil {
			t.Errorf("cleanup user: %v", err)
		}
	})

	t.Run("user repository", func(t *testing.T) {
		duplicate := &model.User{
			Name:         "Duplicate",
			Email:        strings.ToUpper(email),
			PasswordHash: "hash",
		}
		if err := userRepo.Create(ctx, duplicate); !errors.Is(err, model.ErrEmailAlreadyExists) {
			t.Fatalf("duplicate create error = %v, want %v", err, model.ErrEmailAlreadyExists)
		}

		found, err := userRepo.FindByEmail(ctx, strings.ToUpper(email))
		if err != nil {
			t.Fatalf("find user by email: %v", err)
		}
		if found.ID != user.ID {
			t.Fatalf("found ID = %d, want %d", found.ID, user.ID)
		}
		if !found.CanAuthenticate(now) {
			t.Fatal("new user cannot authenticate")
		}

		exists, err := userRepo.ExistsByEmail(ctx, email)
		if err != nil || !exists {
			t.Fatalf("exists by email = %v, %v; want true, nil", exists, err)
		}
		exists, err = userRepo.ExistsByEmail(ctx, "missing-"+email)
		if err != nil || exists {
			t.Fatalf("exists by email = %v, %v; want false, nil", exists, err)
		}

		if err := userRepo.UpdateName(ctx, user.ID, "Renamed User"); err != nil {
			t.Fatalf("update name: %v", err)
		}
		if err := userRepo.UpdatePassword(ctx, user.ID, "new-hash"); err != nil {
			t.Fatalf("update password: %v", err)
		}

		updated, err := userRepo.FindByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("find user by id: %v", err)
		}
		if updated.Name != "Renamed User" || updated.PasswordHash != "new-hash" {
			t.Fatalf("user not updated: %+v", updated)
		}

		for want := 1; want <= 4; want++ {
			attempts, err := userRepo.IncrementFailedLoginAttempts(ctx, user.ID)
			if err != nil {
				t.Fatalf("increment attempts: %v", err)
			}
			if attempts != want {
				t.Fatalf("attempts = %d, want %d", attempts, want)
			}
		}
		if err := userRepo.ResetFailedLoginAttempts(ctx, user.ID); err != nil {
			t.Fatalf("reset attempts: %v", err)
		}

		until := now.Add(10 * time.Minute)
		if err := userRepo.SetTemporaryBlock(ctx, user.ID, until, "too many failures", now); err != nil {
			t.Fatalf("set temporary block: %v", err)
		}

		blocked, err := userRepo.FindByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("find blocked user: %v", err)
		}
		if blocked.BlockType != model.BlockTypeTemporary || !blocked.IsBlocked(now) {
			t.Fatalf("user not blocked: %+v", blocked)
		}
		if blocked.BlockReason != "too many failures" || blocked.BlockedUntil == nil {
			t.Fatalf("block metadata missing: %+v", blocked)
		}

		status, err := userRepo.GetAuthStatus(ctx, user.ID)
		if err != nil {
			t.Fatalf("get auth status: %v", err)
		}
		if status.CanAuthenticate(now) {
			t.Fatal("blocked user can authenticate")
		}

		if err := userRepo.ClearBlock(ctx, user.ID); err != nil {
			t.Fatalf("clear block: %v", err)
		}
		cleared, err := userRepo.FindByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("find cleared user: %v", err)
		}
		if cleared.IsBlocked(now) || cleared.FailedLoginAttempts != 0 {
			t.Fatalf("block not cleared: %+v", cleared)
		}
	})

	t.Run("session repository", func(t *testing.T) {
		access1 := tokenHash("access-1-" + email)
		refresh1 := tokenHash("refresh-1-" + email)
		first := &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  access1,
			RefreshTokenHash: refresh1,
			AccessExpiresAt:  now.Add(15 * time.Minute),
			RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
		}
		if err := sessionRepo.Create(ctx, first); err != nil {
			t.Fatalf("create session: %v", err)
		}

		found, err := sessionRepo.FindByRefreshTokenHash(ctx, refresh1)
		if err != nil {
			t.Fatalf("find session: %v", err)
		}
		if found.ID != first.ID || found.IsRevoked() {
			t.Fatalf("unexpected session: %+v", found)
		}

		next := &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  tokenHash("access-2-" + email),
			RefreshTokenHash: tokenHash("refresh-2-" + email),
			AccessExpiresAt:  now.Add(15 * time.Minute),
			RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
		}
		if err := sessionRepo.Rotate(ctx, first.ID, now.Add(time.Second), next); err != nil {
			t.Fatalf("rotate session: %v", err)
		}
		if next.ID == 0 {
			t.Fatal("rotated session ID was not set")
		}

		old, err := sessionRepo.FindByAccessTokenHash(ctx, access1)
		if err != nil {
			t.Fatalf("find old session: %v", err)
		}
		if !old.IsRevoked() {
			t.Fatal("old session was not revoked")
		}

		if err := sessionRepo.Rotate(ctx, first.ID, now.Add(2*time.Second), &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  tokenHash("access-3-" + email),
			RefreshTokenHash: tokenHash("refresh-3-" + email),
			AccessExpiresAt:  now.Add(15 * time.Minute),
			RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
		}); !errors.Is(err, model.ErrSessionRevoked) {
			t.Fatalf("rotate revoked error = %v, want %v", err, model.ErrSessionRevoked)
		}

		if err := sessionRepo.Rotate(ctx, missingID, now, &model.Session{}); !errors.Is(err, model.ErrSessionNotFound) {
			t.Fatalf("rotate missing error = %v, want %v", err, model.ErrSessionNotFound)
		}

		if err := sessionRepo.Revoke(ctx, next.ID, now.Add(3*time.Second)); err != nil {
			t.Fatalf("revoke session: %v", err)
		}
		if err := sessionRepo.Revoke(ctx, missingID, now); !errors.Is(err, model.ErrSessionNotFound) {
			t.Fatalf("revoke missing error = %v, want %v", err, model.ErrSessionNotFound)
		}

		for i := 4; i <= 5; i++ {
			session := &model.Session{
				UserID:           user.ID,
				AccessTokenHash:  tokenHash(fmt.Sprintf("access-%d-%s", i, email)),
				RefreshTokenHash: tokenHash(fmt.Sprintf("refresh-%d-%s", i, email)),
				AccessExpiresAt:  now.Add(15 * time.Minute),
				RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
			}
			if err := sessionRepo.Create(ctx, session); err != nil {
				t.Fatalf("create session %d: %v", i, err)
			}
		}
		revoked, err := sessionRepo.RevokeByUserID(ctx, user.ID, now.Add(4*time.Second))
		if err != nil {
			t.Fatalf("revoke user sessions: %v", err)
		}
		if revoked != 2 {
			t.Fatalf("revoked sessions = %d, want 2", revoked)
		}

		expired := &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  tokenHash("access-expired-" + email),
			RefreshTokenHash: tokenHash("refresh-expired-" + email),
			AccessExpiresAt:  now.Add(-2 * time.Hour),
			RefreshExpiresAt: now.Add(-time.Hour),
		}
		if err := sessionRepo.Create(ctx, expired); err != nil {
			t.Fatalf("create expired session: %v", err)
		}
		deleted, err := sessionRepo.DeleteExpired(ctx, now)
		if err != nil {
			t.Fatalf("delete expired sessions: %v", err)
		}
		if deleted < 1 {
			t.Fatalf("deleted sessions = %d, want at least 1", deleted)
		}
	})

	t.Run("password recovery repository", func(t *testing.T) {
		first := &model.PasswordRecovery{
			UserID:    user.ID,
			CodeHash:  "code-hash-1",
			ExpiresAt: now.Add(15 * time.Minute),
		}
		if err := recoveryRepo.Create(ctx, first, now); err != nil {
			t.Fatalf("create recovery code: %v", err)
		}

		latest, err := recoveryRepo.FindLatestByUserID(ctx, user.ID)
		if err != nil {
			t.Fatalf("find latest recovery code: %v", err)
		}
		if latest.ID != first.ID || !latest.IsActive(now) {
			t.Fatalf("unexpected recovery code: %+v", latest)
		}

		second := &model.PasswordRecovery{
			UserID:    user.ID,
			CodeHash:  "code-hash-2",
			ExpiresAt: now.Add(15 * time.Minute),
		}
		if err := recoveryRepo.Create(ctx, second, now.Add(time.Minute)); err != nil {
			t.Fatalf("create second recovery code: %v", err)
		}
		if err := recoveryRepo.MarkUsed(ctx, first.ID, now.Add(2*time.Minute)); !errors.Is(err, model.ErrRecoveryCodeInvalidated) {
			t.Fatalf("old code error = %v, want %v", err, model.ErrRecoveryCodeInvalidated)
		}

		if err := recoveryRepo.MarkUsed(ctx, second.ID, now.Add(2*time.Minute)); err != nil {
			t.Fatalf("mark code used: %v", err)
		}
		if err := recoveryRepo.MarkUsed(ctx, second.ID, now.Add(3*time.Minute)); !errors.Is(err, model.ErrRecoveryCodeUsed) {
			t.Fatalf("used code error = %v, want %v", err, model.ErrRecoveryCodeUsed)
		}

		third := &model.PasswordRecovery{
			UserID:    user.ID,
			CodeHash:  "code-hash-3",
			ExpiresAt: now.Add(15 * time.Minute),
		}
		if err := recoveryRepo.Create(ctx, third, now.Add(2*time.Minute)); err != nil {
			t.Fatalf("create third recovery code: %v", err)
		}
		if err := recoveryRepo.Invalidate(ctx, third.ID, now.Add(3*time.Minute)); err != nil {
			t.Fatalf("invalidate code: %v", err)
		}
		if err := recoveryRepo.Invalidate(ctx, third.ID, now.Add(4*time.Minute)); !errors.Is(err, model.ErrRecoveryCodeInvalidated) {
			t.Fatalf("invalidated code error = %v, want %v", err, model.ErrRecoveryCodeInvalidated)
		}

		fourth := &model.PasswordRecovery{
			UserID:    user.ID,
			CodeHash:  "code-hash-4",
			ExpiresAt: now.Add(15 * time.Minute),
		}
		if err := recoveryRepo.Create(ctx, fourth, now.Add(3*time.Minute)); err != nil {
			t.Fatalf("create fourth recovery code: %v", err)
		}
		for want := 1; want <= 5; want++ {
			attempts, err := recoveryRepo.IncrementFailedAttempts(ctx, fourth.ID)
			if err != nil {
				t.Fatalf("increment recovery attempts: %v", err)
			}
			if attempts != want {
				t.Fatalf("attempts = %d, want %d", attempts, want)
			}
		}
		if err := recoveryRepo.MarkUsed(ctx, fourth.ID, now.Add(4*time.Minute)); err != nil {
			t.Fatalf("mark fourth code used: %v", err)
		}

		if _, err := recoveryRepo.FindLatestByUserID(ctx, missingID); !errors.Is(err, model.ErrRecoveryCodeNotFound) {
			t.Fatalf("missing code error = %v, want %v", err, model.ErrRecoveryCodeNotFound)
		}
		if _, err := recoveryRepo.IncrementFailedAttempts(ctx, missingID); !errors.Is(err, model.ErrRecoveryCodeNotFound) {
			t.Fatalf("missing increment error = %v, want %v", err, model.ErrRecoveryCodeNotFound)
		}
		if err := recoveryRepo.MarkUsed(ctx, missingID, now); !errors.Is(err, model.ErrRecoveryCodeNotFound) {
			t.Fatalf("missing mark used error = %v, want %v", err, model.ErrRecoveryCodeNotFound)
		}
	})

	t.Run("soft delete", func(t *testing.T) {
		if err := userRepo.SoftDelete(ctx, user.ID); err != nil {
			t.Fatalf("soft delete user: %v", err)
		}

		deleted, err := userRepo.FindByEmail(ctx, email)
		if err != nil {
			t.Fatalf("find soft deleted user: %v", err)
		}
		if deleted.IsActive || deleted.CanAuthenticate(now) {
			t.Fatalf("user still active: %+v", deleted)
		}

		exists, err := userRepo.ExistsByEmail(ctx, email)
		if err != nil || !exists {
			t.Fatalf("reserved email exists = %v, %v; want true, nil", exists, err)
		}
	})
}
