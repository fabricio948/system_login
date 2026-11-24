package service

import "time"

// ForgotPasswordMessage is the neutral response returned by the forgot flow.
const ForgotPasswordMessage = "If the email exists, a recovery code has been sent."

// Profile is the user data safe to return to clients.
type Profile struct {
	ID        uint64
	Name      string
	Email     string
	CreatedAt time.Time
}

// TokenPair holds the tokens issued to a client.
type TokenPair struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// LoginResult is returned after a successful authentication.
type LoginResult struct {
	TokenPair
	User Profile
}

// ForgotPasswordResult describes the recovery code delivery.
// Code is only populated while no external messaging is configured.
type ForgotPasswordResult struct {
	Message      string
	Code         string
	CodeReturned bool
	ExpiresAt    time.Time
}

// RegisterInput carries the account creation payload.
type RegisterInput struct {
	Name     string
	Email    string
	Password string
}

// LoginInput carries the login payload.
type LoginInput struct {
	Email    string
	Password string
}

// ForgotPasswordInput carries the recovery request payload.
type ForgotPasswordInput struct {
	Email string
}

// ResetPasswordInput carries the password reset payload.
type ResetPasswordInput struct {
	Email       string
	Code        string
	NewPassword string
}

// UpdateNameInput carries the profile name update payload.
type UpdateNameInput struct {
	Name string
}

// ChangePasswordInput carries the authenticated password change payload.
type ChangePasswordInput struct {
	CurrentPassword string
	NewPassword     string
}
