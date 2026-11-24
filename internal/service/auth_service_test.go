package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fabricio948/system_login/internal/model"
)

func TestRegister(t *testing.T) {
	f := newFixture()

	profile, err := f.auth.Register(context.Background(), RegisterInput{
		Name:     " Alice ",
		Email:    "Alice@Example.COM",
		Password: "Secret123!",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if profile.Name != "Alice" {
		t.Errorf("name = %q, want Alice", profile.Name)
	}
	if profile.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", profile.Email)
	}

	stored, err := f.users.FindByEmail(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("find user: %v", err)
	}
	if stored.PasswordHash == "Secret123!" || stored.PasswordHash != "hash:Secret123!" {
		t.Errorf("password was not hashed: %q", stored.PasswordHash)
	}
	if !f.publisher.has(EventUserRegistered) {
		t.Error("user.registered event was not published")
	}
}

func TestRegisterValidation(t *testing.T) {
	base := RegisterInput{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "Secret123!",
	}

	tests := []struct {
		name   string
		mutate func(*RegisterInput)
		field  string
	}{
		{"empty name", func(in *RegisterInput) { in.Name = "" }, "name"},
		{"three character name", func(in *RegisterInput) { in.Name = "Ana" }, "name"},
		{"org domain", func(in *RegisterInput) { in.Email = "alice@example.org" }, "email"},
		{"edu.br domain", func(in *RegisterInput) { in.Email = "alice@school.edu.br" }, "email"},
		{"bare edu.br domain", func(in *RegisterInput) { in.Email = "alice@edu.br" }, "email"},
		{"invalid email", func(in *RegisterInput) { in.Email = "not-an-email" }, "email"},
		{"short password", func(in *RegisterInput) { in.Password = "Ab1!" }, "password"},
		{"password without letter", func(in *RegisterInput) { in.Password = "12345678!" }, "password"},
		{"password without number", func(in *RegisterInput) { in.Password = "Abcdefgh!" }, "password"},
		{"password without special", func(in *RegisterInput) { in.Password = "Abcdefg1" }, "password"},
		{"password longer than bcrypt limit", func(in *RegisterInput) {
			in.Password = strings.Repeat("Aa1!", 20)
		}, "password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture()
			input := base
			tt.mutate(&input)

			_, err := f.auth.Register(context.Background(), input)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %v, want ValidationError", err)
			}
			if validationErr.Field != tt.field {
				t.Errorf("field = %q, want %q", validationErr.Field, tt.field)
			}
		})
	}
}

func TestRegisterKeepsEmailReserved(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	_, err := f.auth.Register(context.Background(), RegisterInput{
		Name:     "Another Alice",
		Email:    "ALICE@example.com",
		Password: "Secret123!",
	})
	if !errors.Is(err, model.ErrEmailAlreadyExists) {
		t.Fatalf("duplicate error = %v, want %v", err, model.ErrEmailAlreadyExists)
	}

	if err := f.users.SoftDelete(context.Background(), user.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}

	_, err = f.auth.Register(context.Background(), RegisterInput{
		Name:     "Another Alice",
		Email:    "alice@example.com",
		Password: "Secret123!",
	})
	if !errors.Is(err, model.ErrEmailAlreadyExists) {
		t.Fatalf("reserved email error = %v, want %v", err, model.ErrEmailAlreadyExists)
	}
}

func TestLoginSuccess(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	user.FailedLoginAttempts = 2

	result, err := f.auth.Login(context.Background(), LoginInput{
		Email:    "ALICE@example.com",
		Password: "Secret123!",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if result.AccessToken == "" || result.RefreshToken == "" {
		t.Fatal("tokens were not issued")
	}
	if result.AccessToken == result.RefreshToken {
		t.Fatal("access and refresh tokens are identical")
	}
	if result.User.ID != user.ID || result.User.Email != "alice@example.com" {
		t.Errorf("unexpected profile: %+v", result.User)
	}
	if len(f.sessions.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(f.sessions.sessions))
	}

	var session *model.Session
	for _, stored := range f.sessions.sessions {
		session = stored
	}
	if session.AccessTokenHash != hashToken(result.AccessToken) {
		t.Error("access token hash does not match")
	}
	if session.RefreshTokenHash != hashToken(result.RefreshToken) {
		t.Error("refresh token hash does not match")
	}
	if !session.AccessExpiresAt.Equal(f.clock.Now().Add(15 * time.Minute)) {
		t.Errorf("access expiry = %v, want now+15m", session.AccessExpiresAt)
	}
	if !session.RefreshExpiresAt.Equal(f.clock.Now().Add(7 * 24 * time.Hour)) {
		t.Errorf("refresh expiry = %v, want now+7d", session.RefreshExpiresAt)
	}
	if user.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", user.FailedLoginAttempts)
	}
	if !f.publisher.has(EventLoginSucceeded) {
		t.Error("login event was not published")
	}
}

func TestLoginMultipleDevices(t *testing.T) {
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	first, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	second, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if first.RefreshToken == second.RefreshToken {
		t.Fatal("logins share the same refresh token")
	}
	if len(f.sessions.sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(f.sessions.sessions))
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	_, err := f.auth.Login(context.Background(), LoginInput{Email: "nobody@example.com", Password: "Secret123!"})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("unknown email error = %v, want %v", err, model.ErrInvalidCredentials)
	}

	_, err = f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Wrong123!"})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want %v", err, model.ErrInvalidCredentials)
	}
	if len(f.sessions.sessions) != 0 {
		t.Fatal("session created for invalid credentials")
	}
}

func TestLoginInactiveAccount(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	user.IsActive = false

	_, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if !errors.Is(err, model.ErrInvalidCredentials) {
		t.Fatalf("inactive error = %v, want %v", err, model.ErrInvalidCredentials)
	}
	if user.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", user.FailedLoginAttempts)
	}
}

func TestLoginAdminBlocked(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	user.IsAdminBlocked = true
	user.BlockReason = "compliance review"

	_, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want BlockedError", err)
	}
	if !blocked.Admin || blocked.Reason != "compliance review" {
		t.Errorf("unexpected block: %+v", blocked)
	}
}

func TestLoginTemporaryBlocked(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	until := f.clock.Now().Add(5 * time.Minute)
	user.BlockType = model.BlockTypeTemporary
	user.BlockReason = "too many failures"
	user.BlockedUntil = &until

	_, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("error = %v, want BlockedError", err)
	}
	if blocked.Admin || blocked.Remaining != 5*time.Minute {
		t.Errorf("unexpected block: %+v", blocked)
	}
}

func TestLoginClearsExpiredTemporaryBlock(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	until := f.clock.Now().Add(-time.Minute)
	user.BlockType = model.BlockTypeTemporary
	user.BlockReason = "too many failures"
	user.BlockedUntil = &until
	user.FailedLoginAttempts = 4

	if _, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if user.BlockType != "" || user.BlockedUntil != nil {
		t.Errorf("block was not cleared: %+v", user)
	}
	if user.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", user.FailedLoginAttempts)
	}
}

func TestLoginClearsStaleAdminBlockMetadata(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")
	blockedAt := f.clock.Now().Add(-time.Hour)
	user.IsAdminBlocked = false
	user.BlockType = model.BlockTypeAdmin
	user.BlockReason = "compliance review"
	user.BlockedAt = &blockedAt
	user.FailedLoginAttempts = 4

	if _, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
		t.Fatalf("login: %v", err)
	}
	if user.BlockType != "" || user.BlockReason != "" || user.BlockedAt != nil || user.FailedLoginAttempts != 0 {
		t.Errorf("stale admin block was not cleared: %+v", user)
	}
}

func TestLoginBlocksAfterFourFailures(t *testing.T) {
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	for attempt := 1; attempt <= 3; attempt++ {
		_, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Wrong123!"})
		if !errors.Is(err, model.ErrInvalidCredentials) {
			t.Fatalf("attempt %d error = %v, want %v", attempt, err, model.ErrInvalidCredentials)
		}
		if user.FailedLoginAttempts != attempt {
			t.Fatalf("attempts = %d, want %d", user.FailedLoginAttempts, attempt)
		}
	}

	_, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Wrong123!"})
	var blocked *BlockedError
	if !errors.As(err, &blocked) {
		t.Fatalf("fourth failure error = %v, want BlockedError", err)
	}
	if blocked.Admin {
		t.Error("temporary block was reported as administrative")
	}
	if blocked.Remaining != 10*time.Minute {
		t.Errorf("remaining = %v, want 10m", blocked.Remaining)
	}
	if blocked.Until == nil || !blocked.Until.Equal(f.clock.Now().Add(10*time.Minute)) {
		t.Errorf("until = %v, want now+10m", blocked.Until)
	}
	if user.BlockType != model.BlockTypeTemporary || user.BlockedUntil == nil {
		t.Fatalf("user was not blocked: %+v", user)
	}

	_, err = f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if !errors.As(err, &blocked) {
		t.Fatalf("blocked login error = %v, want BlockedError", err)
	}
}

func TestRefreshRotatesSession(t *testing.T) {
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	login, err := f.auth.Login(context.Background(), LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	f.clock.Advance(5 * time.Minute)

	pair, err := f.auth.Refresh(context.Background(), login.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if pair.RefreshToken == login.RefreshToken || pair.AccessToken == login.AccessToken {
		t.Fatal("tokens were not rotated")
	}
	if !pair.AccessExpiresAt.Equal(f.clock.Now().Add(15 * time.Minute)) {
		t.Errorf("access expiry = %v, want now+15m", pair.AccessExpiresAt)
	}

	oldSession, err := f.sessions.FindByRefreshTokenHash(context.Background(), hashToken(login.RefreshToken))
	if err != nil {
		t.Fatalf("find old session: %v", err)
	}
	if !oldSession.IsRevoked() {
		t.Error("old session was not revoked")
	}

	newSession, err := f.sessions.FindByRefreshTokenHash(context.Background(), hashToken(pair.RefreshToken))
	if err != nil {
		t.Fatalf("find new session: %v", err)
	}
	if newSession.IsRevoked() {
		t.Error("new session is revoked")
	}
	if len(f.sessions.sessions) != 2 {
		t.Errorf("sessions = %d, want 2", len(f.sessions.sessions))
	}
	if !f.publisher.has(EventSessionRefreshed) {
		t.Error("refresh event was not published")
	}

	if _, err := f.auth.Refresh(context.Background(), login.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("reused refresh error = %v, want %v", err, ErrInvalidRefreshToken)
	}
}

func TestRefreshErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown token", func(t *testing.T) {
		f := newFixture()
		if _, err := f.auth.Refresh(ctx, "unknown"); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRefreshToken)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		if err := f.sessions.Create(ctx, &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  hashToken("access"),
			RefreshTokenHash: hashToken("expired"),
			AccessExpiresAt:  f.clock.Now().Add(-time.Minute),
			RefreshExpiresAt: f.clock.Now().Add(-time.Minute),
		}); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		if _, err := f.auth.Refresh(ctx, "expired"); !errors.Is(err, model.ErrRefreshTokenExpired) {
			t.Fatalf("error = %v, want %v", err, model.ErrRefreshTokenExpired)
		}
	})

	t.Run("inactive user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		if err := f.sessions.Create(ctx, &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  hashToken("access"),
			RefreshTokenHash: hashToken("refresh"),
			AccessExpiresAt:  f.clock.Now().Add(15 * time.Minute),
			RefreshExpiresAt: f.clock.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		user.IsActive = false
		if _, err := f.auth.Refresh(ctx, "refresh"); !errors.Is(err, model.ErrUserInactive) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserInactive)
		}
	})

	t.Run("blocked user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		if err := f.sessions.Create(ctx, &model.Session{
			UserID:           user.ID,
			AccessTokenHash:  hashToken("access"),
			RefreshTokenHash: hashToken("refresh"),
			AccessExpiresAt:  f.clock.Now().Add(15 * time.Minute),
			RefreshExpiresAt: f.clock.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		user.IsAdminBlocked = true
		if _, err := f.auth.Refresh(ctx, "refresh"); err == nil {
			t.Fatal("refresh succeeded for blocked user")
		} else {
			var blocked *BlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("error = %v, want BlockedError", err)
			}
		}
	})

	t.Run("revoked session", func(t *testing.T) {
		f := newFixture()
		f.seedUser("Alice", "alice@example.com", "Secret123!")
		login, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if err := f.auth.Logout(ctx, login.AccessToken); err != nil {
			t.Fatalf("logout: %v", err)
		}
		if _, err := f.auth.Refresh(ctx, login.RefreshToken); !errors.Is(err, ErrInvalidRefreshToken) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRefreshToken)
		}
	})
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	login, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	profile, err := f.auth.Authenticate(ctx, login.AccessToken)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if profile.ID != user.ID {
		t.Errorf("profile ID = %d, want %d", profile.ID, user.ID)
	}

	if _, err := f.auth.Authenticate(ctx, "unknown"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("unknown token error = %v, want %v", err, ErrInvalidAccessToken)
	}

	f.clock.Advance(16 * time.Minute)
	if _, err := f.auth.Authenticate(ctx, login.AccessToken); !errors.Is(err, model.ErrAccessTokenExpired) {
		t.Fatalf("expired token error = %v, want %v", err, model.ErrAccessTokenExpired)
	}
}

func TestAuthenticateChecksAccountStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("inactive", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		login, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		user.IsActive = false
		if _, err := f.auth.Authenticate(ctx, login.AccessToken); !errors.Is(err, model.ErrUserInactive) {
			t.Fatalf("error = %v, want %v", err, model.ErrUserInactive)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		login, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		user.IsAdminBlocked = true
		if _, err := f.auth.Authenticate(ctx, login.AccessToken); err == nil {
			t.Fatal("authenticate succeeded for blocked user")
		} else {
			var blocked *BlockedError
			if !errors.As(err, &blocked) {
				t.Fatalf("error = %v, want BlockedError", err)
			}
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	login, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := f.auth.Logout(ctx, login.AccessToken); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := f.auth.Authenticate(ctx, login.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Fatalf("authenticate after logout error = %v, want %v", err, ErrInvalidAccessToken)
	}
	if err := f.auth.Logout(ctx, login.AccessToken); err != nil {
		t.Fatalf("idempotent logout: %v", err)
	}
	if err := f.auth.Logout(ctx, "unknown"); err != nil {
		t.Fatalf("unknown logout: %v", err)
	}
	if !f.publisher.has(EventSessionRevoked) {
		t.Error("session revoked event was not published")
	}
}

func TestForgotPassword(t *testing.T) {
	ctx := context.Background()

	t.Run("existing user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")

		result, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "ALICE@example.com"})
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if result.Message != ForgotPasswordMessage || !result.CodeReturned {
			t.Errorf("unexpected result: %+v", result)
		}
		if !sixDigits(result.Code) {
			t.Errorf("code = %q, want six digits", result.Code)
		}
		if len(f.notifier.sent) != 1 || f.notifier.sent[0].Code != result.Code {
			t.Errorf("notification = %+v, want code %q", f.notifier.sent, result.Code)
		}
		if len(f.recoveries.recoveries) != 1 {
			t.Fatalf("recoveries = %d, want 1", len(f.recoveries.recoveries))
		}

		var recovery *model.PasswordRecovery
		for _, stored := range f.recoveries.recoveries {
			recovery = stored
		}
		if recovery.UserID != user.ID {
			t.Errorf("user ID = %d, want %d", recovery.UserID, user.ID)
		}
		if recovery.CodeHash == result.Code || len(recovery.CodeHash) != 64 {
			t.Error("code was not stored as an HMAC")
		}
		if !recovery.ExpiresAt.Equal(f.clock.Now().Add(15 * time.Minute)) {
			t.Errorf("expiry = %v, want now+15m", recovery.ExpiresAt)
		}
		if !f.publisher.has(EventRecoveryRequested) {
			t.Error("recovery event was not published")
		}
	})

	t.Run("unknown user returns fake code", func(t *testing.T) {
		f := newFixture()
		result, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "nobody@example.com"})
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if !sixDigits(result.Code) || !result.CodeReturned {
			t.Errorf("unexpected result: %+v", result)
		}
		if len(f.recoveries.recoveries) != 0 {
			t.Error("fake code was persisted")
		}
		if len(f.notifier.sent) != 0 {
			t.Error("notification sent for unknown user")
		}
	})

	t.Run("expired block is cleared", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		until := f.clock.Now().Add(-time.Minute)
		user.BlockType = model.BlockTypeTemporary
		user.BlockedUntil = &until
		user.FailedLoginAttempts = 4

		if _, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"}); err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if user.BlockType != "" || user.BlockedUntil != nil || user.FailedLoginAttempts != 0 {
			t.Errorf("expired block was not cleared: %+v", user)
		}
	})

	t.Run("inactive user returns fake code", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsActive = false

		result, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if !sixDigits(result.Code) || !result.CodeReturned {
			t.Errorf("unexpected result: %+v", result)
		}
		if len(f.recoveries.recoveries) != 0 {
			t.Error("code was persisted for inactive user")
		}
		if len(f.notifier.sent) != 0 {
			t.Error("notification sent for inactive user")
		}
	})

	t.Run("delivery enabled hides code", func(t *testing.T) {
		f := newFixture()
		f.notifier.enabled = true
		f.seedUser("Alice", "alice@example.com", "Secret123!")

		result, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if result.CodeReturned || result.Code != "" {
			t.Errorf("code was returned with delivery enabled: %+v", result)
		}
		if len(f.notifier.sent) != 1 {
			t.Errorf("notifications = %d, want 1", len(f.notifier.sent))
		}

		unknown, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "nobody@example.com"})
		if err != nil {
			t.Fatalf("forgot unknown: %v", err)
		}
		if unknown.CodeReturned || unknown.Code != "" {
			t.Errorf("fake code was returned: %+v", unknown)
		}
	})

	t.Run("new code invalidates previous", func(t *testing.T) {
		f := newFixture()
		f.seedUser("Alice", "alice@example.com", "Secret123!")

		if _, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"}); err != nil {
			t.Fatalf("first forgot: %v", err)
		}
		if _, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"}); err != nil {
			t.Fatalf("second forgot: %v", err)
		}
		if len(f.recoveries.recoveries) != 2 {
			t.Fatalf("recoveries = %d, want 2", len(f.recoveries.recoveries))
		}
		for id, recovery := range f.recoveries.recoveries {
			if id == 1 && recovery.InvalidatedAt == nil {
				t.Error("first code was not invalidated")
			}
			if id == 2 && recovery.InvalidatedAt != nil {
				t.Error("second code was invalidated")
			}
		}
	})

	t.Run("notification failure invalidates code", func(t *testing.T) {
		f := newFixture()
		f.seedUser("Alice", "alice@example.com", "Secret123!")
		f.notifier.err = errors.New("provider unavailable")

		if _, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"}); err == nil {
			t.Fatal("forgot returned nil error")
		}
		for _, recovery := range f.recoveries.recoveries {
			if recovery.InvalidatedAt == nil {
				t.Error("code was not invalidated after notification failure")
			}
		}
	})
}

func TestResetPasswordSuccess(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	if _, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
		t.Fatalf("first login: %v", err)
	}
	if _, err := f.auth.Login(ctx, LoginInput{Email: "alice@example.com", Password: "Secret123!"}); err != nil {
		t.Fatalf("second login: %v", err)
	}

	user.IsAdminBlocked = true
	user.BlockReason = "compliance review"

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}

	if err := f.auth.ResetPassword(ctx, ResetPasswordInput{
		Email:       "ALICE@example.com",
		Code:        forgot.Code,
		NewPassword: "NewSecret456!",
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	if user.PasswordHash != "hash:NewSecret456!" {
		t.Errorf("password hash = %q, want hash:NewSecret456!", user.PasswordHash)
	}
	if !user.IsAdminBlocked || user.BlockReason != "compliance review" {
		t.Errorf("reset changed the block: %+v", user)
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
	for _, recovery := range f.recoveries.recoveries {
		if recovery.UsedAt == nil {
			t.Error("recovery code was not marked as used")
		}
	}
	if !f.publisher.has(EventPasswordReset) {
		t.Error("password reset event was not published")
	}
}

func TestResetPasswordWrongCode(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	user := f.seedUser("Alice", "alice@example.com", "Secret123!")

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}
	wrong := "000000"
	if forgot.Code == wrong {
		wrong = "111111"
	}

	for attempt := 1; attempt <= 4; attempt++ {
		err := f.auth.ResetPassword(ctx, ResetPasswordInput{
			Email:       "alice@example.com",
			Code:        wrong,
			NewPassword: "NewSecret456!",
		})
		if !errors.Is(err, ErrInvalidRecoveryCode) {
			t.Fatalf("attempt %d error = %v, want %v", attempt, err, ErrInvalidRecoveryCode)
		}
	}

	err = f.auth.ResetPassword(ctx, ResetPasswordInput{
		Email:       "alice@example.com",
		Code:        wrong,
		NewPassword: "NewSecret456!",
	})
	if !errors.Is(err, model.ErrRecoveryAttemptsExceeded) {
		t.Fatalf("fifth attempt error = %v, want %v", err, model.ErrRecoveryAttemptsExceeded)
	}
	for _, recovery := range f.recoveries.recoveries {
		if recovery.InvalidatedAt == nil {
			t.Error("code was not invalidated after five failures")
		}
	}
	if user.PasswordHash != "hash:Secret123!" {
		t.Error("password changed after failed attempts")
	}

	err = f.auth.ResetPassword(ctx, ResetPasswordInput{
		Email:       "alice@example.com",
		Code:        forgot.Code,
		NewPassword: "NewSecret456!",
	})
	if !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatalf("invalidated code error = %v, want %v", err, ErrInvalidRecoveryCode)
	}
}

func TestResetPasswordAttemptsAlreadyExceeded(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}
	for _, recovery := range f.recoveries.recoveries {
		recovery.FailedAttempts = 5
	}

	err = f.auth.ResetPassword(ctx, ResetPasswordInput{
		Email:       "alice@example.com",
		Code:        forgot.Code,
		NewPassword: "NewSecret456!",
	})
	if !errors.Is(err, model.ErrRecoveryAttemptsExceeded) {
		t.Fatalf("error = %v, want %v", err, model.ErrRecoveryAttemptsExceeded)
	}
	for _, recovery := range f.recoveries.recoveries {
		if recovery.InvalidatedAt == nil {
			t.Error("code was not invalidated")
		}
	}
}

func TestResetPasswordExpiredCode(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}
	f.clock.Advance(16 * time.Minute)

	err = f.auth.ResetPassword(ctx, ResetPasswordInput{
		Email:       "alice@example.com",
		Code:        forgot.Code,
		NewPassword: "NewSecret456!",
	})
	if !errors.Is(err, model.ErrRecoveryCodeExpired) {
		t.Fatalf("error = %v, want %v", err, model.ErrRecoveryCodeExpired)
	}
}

func TestResetPasswordInvalidInput(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}

	tests := []struct {
		name  string
		input ResetPasswordInput
		field string
	}{
		{
			name: "malformed code",
			input: ResetPasswordInput{
				Email:       "alice@example.com",
				Code:        "123",
				NewPassword: "NewSecret456!",
			},
			field: "code",
		},
		{
			name: "weak password",
			input: ResetPasswordInput{
				Email:       "alice@example.com",
				Code:        forgot.Code,
				NewPassword: "weak",
			},
			field: "new_password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := f.auth.ResetPassword(ctx, tt.input)
			var validationErr *ValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %v, want ValidationError", err)
			}
			if validationErr.Field != tt.field {
				t.Errorf("field = %q, want %q", validationErr.Field, tt.field)
			}
		})
	}

	for _, recovery := range f.recoveries.recoveries {
		if recovery.UsedAt != nil || recovery.FailedAttempts != 0 {
			t.Error("invalid input consumed the recovery code")
		}
	}
}

func TestResetPasswordUnknownOrInactiveUser(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown email", func(t *testing.T) {
		f := newFixture()
		err := f.auth.ResetPassword(ctx, ResetPasswordInput{
			Email:       "nobody@example.com",
			Code:        "123456",
			NewPassword: "NewSecret456!",
		})
		if !errors.Is(err, ErrInvalidRecoveryCode) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRecoveryCode)
		}
	})

	t.Run("inactive user", func(t *testing.T) {
		f := newFixture()
		user := f.seedUser("Alice", "alice@example.com", "Secret123!")
		user.IsActive = false
		err := f.auth.ResetPassword(ctx, ResetPasswordInput{
			Email:       "alice@example.com",
			Code:        "123456",
			NewPassword: "NewSecret456!",
		})
		if !errors.Is(err, ErrInvalidRecoveryCode) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidRecoveryCode)
		}
	})
}

func TestResetPasswordUsedCode(t *testing.T) {
	ctx := context.Background()
	f := newFixture()
	f.seedUser("Alice", "alice@example.com", "Secret123!")

	forgot, err := f.auth.ForgotPassword(ctx, ForgotPasswordInput{Email: "alice@example.com"})
	if err != nil {
		t.Fatalf("forgot: %v", err)
	}
	input := ResetPasswordInput{
		Email:       "alice@example.com",
		Code:        forgot.Code,
		NewPassword: "NewSecret456!",
	}
	if err := f.auth.ResetPassword(ctx, input); err != nil {
		t.Fatalf("first reset: %v", err)
	}
	if err := f.auth.ResetPassword(ctx, input); !errors.Is(err, ErrInvalidRecoveryCode) {
		t.Fatalf("second reset error = %v, want %v", err, ErrInvalidRecoveryCode)
	}
}

func sixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
