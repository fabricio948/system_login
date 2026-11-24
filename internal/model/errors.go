package model

import "errors"

var (
	// User errors.
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrUserInactive       = errors.New("user is inactive")
	ErrUserBlocked        = errors.New("user is blocked")
	ErrInvalidCredentials = errors.New("invalid credentials")

	// Session errors.
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionRevoked      = errors.New("session revoked")
	ErrAccessTokenExpired  = errors.New("access token expired")
	ErrRefreshTokenExpired = errors.New("refresh token expired")

	// Password recovery errors.
	ErrRecoveryCodeNotFound     = errors.New("recovery code not found")
	ErrRecoveryCodeExpired      = errors.New("recovery code expired")
	ErrRecoveryCodeUsed         = errors.New("recovery code already used")
	ErrRecoveryCodeInvalidated  = errors.New("recovery code invalidated")
	ErrRecoveryAttemptsExceeded = errors.New("recovery attempts exceeded")
)
