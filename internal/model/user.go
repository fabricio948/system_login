package model

import "time"

// BlockType identifies why a user is blocked.
type BlockType string

const (
	BlockTypeTemporary BlockType = "temporary"
	BlockTypeAdmin     BlockType = "admin"
)

// User is the domain representation of an account.
type User struct {
	ID                  uint64
	Name                string
	Email               string
	PasswordHash        string
	IsActive            bool
	IsAdminBlocked      bool
	BlockType           BlockType
	BlockReason         string
	BlockedAt           *time.Time
	BlockedUntil        *time.Time
	FailedLoginAttempts int
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// BlockInfo groups the current block metadata of a user.
type BlockInfo struct {
	Admin        bool
	Type         BlockType
	Reason       string
	BlockedAt    *time.Time
	BlockedUntil *time.Time
}

// BlockInfo returns the block metadata currently stored on the user.
func (u User) BlockInfo() BlockInfo {
	return BlockInfo{
		Admin:        u.IsAdminBlocked,
		Type:         u.BlockType,
		Reason:       u.BlockReason,
		BlockedAt:    u.BlockedAt,
		BlockedUntil: u.BlockedUntil,
	}
}

// IsBlocked reports whether the user is blocked at the given instant.
func (u User) IsBlocked(now time.Time) bool {
	if u.IsAdminBlocked {
		return true
	}
	return u.BlockedUntil != nil && now.Before(*u.BlockedUntil)
}

// HasExpiredTemporaryBlock reports whether a temporary block has elapsed
// but its fields were not cleared yet.
func (u User) HasExpiredTemporaryBlock(now time.Time) bool {
	return u.BlockType == BlockTypeTemporary &&
		u.BlockedUntil != nil &&
		!now.Before(*u.BlockedUntil)
}

// CanAuthenticate reports whether the account may log in or refresh a session.
func (u User) CanAuthenticate(now time.Time) bool {
	return u.IsActive && !u.IsBlocked(now)
}

// AuthStatus is a lightweight projection used by the authentication middleware.
type AuthStatus struct {
	UserID         uint64
	IsActive       bool
	IsAdminBlocked bool
	BlockType      BlockType
	BlockedUntil   *time.Time
}

// IsBlocked reports whether the user is blocked at the given instant.
func (s AuthStatus) IsBlocked(now time.Time) bool {
	if s.IsAdminBlocked {
		return true
	}
	return s.BlockedUntil != nil && now.Before(*s.BlockedUntil)
}

// CanAuthenticate reports whether the account may use the API.
func (s AuthStatus) CanAuthenticate(now time.Time) bool {
	return s.IsActive && !s.IsBlocked(now)
}
