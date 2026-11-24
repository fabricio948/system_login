package service

import (
	"errors"
	"fmt"
	"time"
)

// ValidationError identifies an invalid input field.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// BlockedError describes an administrative or temporary block.
type BlockedError struct {
	Admin     bool
	Reason    string
	Until     *time.Time
	Remaining time.Duration
}

func (e *BlockedError) Error() string {
	if e.Admin {
		return "account administratively blocked"
	}
	return fmt.Sprintf("account temporarily blocked for %s", e.Remaining)
}

var (
	ErrInvalidAccessToken     = errors.New("invalid access token")
	ErrInvalidRefreshToken    = errors.New("invalid refresh token")
	ErrInvalidRecoveryCode    = errors.New("invalid recovery code")
	ErrInvalidCurrentPassword = errors.New("invalid current password")
	ErrPasswordUnchanged      = errors.New("new password must differ from the current password")
)
