package model

import "time"

// PasswordRecovery stores the lifecycle of a recovery code.
type PasswordRecovery struct {
	ID             uint64
	UserID         uint64
	CodeHash       string
	FailedAttempts int
	ExpiresAt      time.Time
	UsedAt         *time.Time
	InvalidatedAt  *time.Time
	CreatedAt      time.Time
}

// IsUsed reports whether the code was already consumed.
func (r PasswordRecovery) IsUsed() bool {
	return r.UsedAt != nil
}

// IsInvalidated reports whether a newer code replaced this one.
func (r PasswordRecovery) IsInvalidated() bool {
	return r.InvalidatedAt != nil
}

// IsExpired reports whether the code is past its expiration instant.
func (r PasswordRecovery) IsExpired(now time.Time) bool {
	return !now.Before(r.ExpiresAt)
}

// IsActive reports whether the code can still be validated.
func (r PasswordRecovery) IsActive(now time.Time) bool {
	return !r.IsUsed() && !r.IsInvalidated() && !r.IsExpired(now)
}
