package model

import "time"

// Session stores the hashes and expiration of a token pair.
type Session struct {
	ID               uint64
	UserID           uint64
	AccessTokenHash  string
	RefreshTokenHash string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	RevokedAt        *time.Time
	CreatedAt        time.Time
}

// IsRevoked reports whether the session was revoked.
func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsAccessTokenValid reports whether the access token can still be used.
func (s Session) IsAccessTokenValid(now time.Time) bool {
	return !s.IsRevoked() && now.Before(s.AccessExpiresAt)
}

// IsRefreshTokenValid reports whether the refresh token can still be rotated.
func (s Session) IsRefreshTokenValid(now time.Time) bool {
	return !s.IsRevoked() && now.Before(s.RefreshExpiresAt)
}
