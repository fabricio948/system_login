package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/fabricio948/system_login/internal/model"
)

func TestGetProfile(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		profile, err := f.account.GetProfile(ctx, user.ID)
		if err != nil {
			t.Fatalf("get profile: %v", err)
		}
		if profile.ID != user.ID || profile.Name != "Alice" || profile.Email != "alice@example.com" {
			t.Errorf("unexpected profile: %+v", profile)
		}
	})

	t.Run("not found", func(t *testing.T) {
		f := newFixture()
		if _, err := f.account.GetProfile(ctx, 999); !errors.Is(err, model.ErrUserNotFound) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserNotFound)
		}
	})

	t.Run("inactive", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsActive = false
		if _, err := f.account.GetProfile(ctx, user.ID); !errors.Is(err, model.ErrUserInactive) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserInactive)
		}
	})

	t.Run("administratively blocked", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsAdminBlocked = true
		user.BlockReason = "compliance review"

		_, err := f.account.GetProfile(ctx, user.ID)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %v, want BlockedError", err)
		}
		if !blocked.Admin || blocked.Reason != "compliance review" {
			t.Errorf("unexpected block: %+v", blocked)
		}
	})

	t.Run("temporarily blocked", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		until := f.clock.Now().Add(5 * time.Minute)
		user.BlockType = model.BlockTypeTemporary
		user.BlockedUntil = &until

		_, err := f.account.GetProfile(ctx, user.ID)
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %v, want BlockedError", err)
		}
		if blocked.Remaining != 5*time.Minute {
			t.Errorf("remaining = %v, want 5m", blocked.Remaining)
		}
	})

	t.Run("expired temporary block is cleared", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		until := f.clock.Now().Add(-time.Minute)
		user.BlockType = model.BlockTypeTemporary
		user.BlockedUntil = &until
		user.FailedLoginAttempts = 4

		if _, err := f.account.GetProfile(ctx, user.ID); err != nil {
			t.Fatalf("get profile: %v", err)
		}
		if user.BlockType != "" || user.BlockedUntil != nil || user.FailedLoginAttempts != 0 {
			t.Errorf("expired block was not cleared: %+v", user)
		}
	})
}

func TestUpdateName(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		profile, err := f.account.UpdateName(ctx, user.ID, UpdateNameInput{Name: "  Alice Silva  "})
		if err != nil {
			t.Fatalf("update name: %v", err)
		}
		if profile.Name != "Alice Silva" {
			t.Errorf("name = %q, want Alice Silva", profile.Name)
		}
		if user.Name != "Alice Silva" {
			t.Errorf("stored name = %q, want Alice Silva", user.Name)
		}
	})

	t.Run("invalid name", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		_, err := f.account.UpdateName(ctx, user.ID, UpdateNameInput{Name: "Ana"})
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) || validationErr.Field != "name" {
			t.Fatalf("error = %v, want name ValidationError", err)
		}
		if user.Name != "Alice" {
			t.Error("stored name changed after validation error")
		}
	})

	t.Run("not found", func(t *testing.T) {
		f := newFixture()
		_, err := f.account.UpdateName(ctx, 999, UpdateNameInput{Name: "Alice Silva"})
		if !errors.Is(err, model.ErrUserNotFound) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserNotFound)
		}
	})
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()

	t.Run("success revokes all sessions", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		if _, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
			t.Fatalf("first login: %v", err)
		}
		if _, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
			t.Fatalf("second login: %v", err)
		}

		if err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Secret123!",
			NewPassword:     "NewSecret456!",
		}); err != nil {
			t.Fatalf("change password: %v", err)
		}

		if user.PasswordHash != "hash:NewSecret456!" {
			t.Errorf("password hash = %q, want hash:NewSecret456!", user.PasswordHash)
		}
		activeSessions := 0
		for _, session := range f.sessions.sessions {
			if session.RevokedAt == nil {
				activeSessions++
			}
		}
		if activeSessions != 0 {
			t.Errorf("active sessions = %d, want 0", activeSessions)
		}
		if !f.publisher.has(EventPasswordChanged) {
			t.Error("password changed event was not published")
		}
	})

	t.Run("wrong current password", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Wrong123!",
			NewPassword:     "NewSecret456!",
		})
		if !errors.Is(err, ErrInvalidCurrentPassword) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidCurrentPassword)
		}
		if user.PasswordHash != "hash:Secret123!" {
			t.Error("password changed with wrong current password")
		}
	})

	t.Run("same password", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Secret123!",
			NewPassword:     "Secret123!",
		})
		if !errors.Is(err, ErrPasswordUnchanged) {
			t.Fatalf("error = %v, want %v", err, ErrPasswordUnchanged)
		}
	})

	t.Run("weak new password", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Secret123!",
			NewPassword:     "weak",
		})
		var validationErr *ValidationError
		if !errors.As(err, &validationErr) || validationErr.Field != "new_password" {
			t.Fatalf("error = %v, want new_password ValidationError", err)
		}
	})

	t.Run("inactive user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsActive = false

		err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Secret123!",
			NewPassword:     "NewSecret456!",
		})
		if !errors.Is(err, model.ErrUserInactive) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserInactive)
		}
	})

	t.Run("blocked user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsAdminBlocked = true

		err := f.account.ChangePassword(ctx, user.ID, ChangePasswordInput{
			CurrentPassword: "Secret123!",
			NewPassword:     "NewSecret456!",
		})
		var blocked *BlockedError
		if !errors.As(err, &blocked) {
			t.Fatalf("error = %v, want BlockedError", err)
		}
	})
}

func TestDeleteAccount(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	if _, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
		t.Fatalf("login: %v", err)
	}

	if err := f.account.DeleteAccount(ctx, user.ID); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if user.IsActive {
		t.Error("user is still active")
	}
	activeSessions := 0
	for _, session := range f.sessions.sessions {
		if session.RevokedAt == nil {
			activeSessions++
		}
	}
	if activeSessions != 0 {
		t.Errorf("active sessions = %d, want 0", activeSessions)
	}

	exists, err := f.users.ExistsByEmail(ctx, "alice@example.com")
	if err != nil || !exists {
		t.Errorf("reserved email exists = %v, %v; want true, nil", exists, err)
	}
	if !f.publisher.has(EventAccountDeleted) {
		t.Error("account deleted event was not published")
	}

	if err := f.account.DeleteAccount(ctx, user.ID); !errors.Is(err, model.ErrUserInactive) {
		t.Fatalf("second delete error = %v, want %v", err, model.ErrUserInactive)
	}
}
