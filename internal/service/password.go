package service

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHasher abstracts password hashing for tests and future algorithms.
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(hash, password string) error
}

// BcryptHasher implements PasswordHasher with bcrypt.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher returns a bcrypt hasher. Invalid costs fall back to the default.
func NewBcryptHasher(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

func (h *BcryptHasher) Verify(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
