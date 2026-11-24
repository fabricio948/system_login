package model

import (
	"testing"
	"time"
)

func TestUserBlockState(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Minute)
	past := now.Add(-time.Minute)
	temporary := BlockTypeTemporary

	tests := []struct {
		name    string
		user    User
		blocked bool
		canAuth bool
		expired bool
	}{
		{
			name:    "active without block",
			user:    User{IsActive: true},
			blocked: false,
			canAuth: true,
		},
		{
			name:    "inactive user",
			user:    User{IsActive: false},
			blocked: false,
			canAuth: false,
		},
		{
			name:    "temporary block active",
			user:    User{IsActive: true, BlockType: temporary, BlockedUntil: &future},
			blocked: true,
			canAuth: false,
		},
		{
			name:    "temporary block expired",
			user:    User{IsActive: true, BlockType: temporary, BlockedUntil: &past},
			blocked: false,
			canAuth: true,
			expired: true,
		},
		{
			name:    "admin block",
			user:    User{IsActive: true, IsAdminBlocked: true, BlockType: BlockTypeAdmin},
			blocked: true,
			canAuth: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.user.IsBlocked(now); got != tt.blocked {
				t.Errorf("IsBlocked = %v, want %v", got, tt.blocked)
			}
			if got := tt.user.CanAuthenticate(now); got != tt.canAuth {
				t.Errorf("CanAuthenticate = %v, want %v", got, tt.canAuth)
			}
			if got := tt.user.HasExpiredTemporaryBlock(now); got != tt.expired {
				t.Errorf("HasExpiredTemporaryBlock = %v, want %v", got, tt.expired)
			}
		})
	}
}

func TestPasswordRecoveryState(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	used := now.Add(-time.Minute)
	invalidated := now.Add(-time.Minute)
	expiredAt := now.Add(-time.Minute)
	validUntil := now.Add(10 * time.Minute)

	tests := []struct {
		name   string
		code   PasswordRecovery
		active bool
	}{
		{name: "active", code: PasswordRecovery{ExpiresAt: validUntil}, active: true},
		{name: "used", code: PasswordRecovery{ExpiresAt: validUntil, UsedAt: &used}, active: false},
		{name: "invalidated", code: PasswordRecovery{ExpiresAt: validUntil, InvalidatedAt: &invalidated}, active: false},
		{name: "expired", code: PasswordRecovery{ExpiresAt: expiredAt}, active: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.code.IsActive(now); got != tt.active {
				t.Errorf("IsActive = %v, want %v", got, tt.active)
			}
		})
	}
}

func TestSessionValidity(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	revoked := now.Add(-time.Minute)

	valid := Session{
		AccessExpiresAt:  now.Add(time.Minute),
		RefreshExpiresAt: now.Add(time.Hour),
	}
	if !valid.IsAccessTokenValid(now) || !valid.IsRefreshTokenValid(now) {
		t.Fatal("valid session reported as invalid")
	}

	expired := Session{
		AccessExpiresAt:  now.Add(-time.Minute),
		RefreshExpiresAt: now.Add(time.Hour),
	}
	if expired.IsAccessTokenValid(now) {
		t.Fatal("expired access token reported as valid")
	}

	revokedSession := valid
	revokedSession.RevokedAt = &revoked
	if revokedSession.IsRefreshTokenValid(now) {
		t.Fatal("revoked session reported as valid")
	}
}
