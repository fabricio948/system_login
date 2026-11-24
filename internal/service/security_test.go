package service

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcryptHasher(t *testing.T) {
	hasher := NewBcryptHasher(bcrypt.MinCost)

	hash, err := hasher.Hash("Secret123!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "Secret123!" || !strings.HasPrefix(hash, "$2") {
		t.Fatalf("unexpected hash: %q", hash)
	}
	if err := hasher.Verify(hash, "Secret123!"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := hasher.Verify(hash, "Wrong123!"); err == nil {
		t.Fatal("verify accepted a wrong password")
	}
}

func TestGenerateRecoveryCode(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			t.Fatalf("generate code: %v", err)
		}
		if !sixDigits(code) {
			t.Fatalf("code = %q, want six digits", code)
		}
		seen[code] = true

		hash := hashRecoveryCode("pepper", code)
		if len(hash) != 64 || hash == code {
			t.Fatalf("unexpected recovery hash: %q", hash)
		}
	}
	if len(seen) < 2 {
		t.Error("recovery codes are not random")
	}

	if hashRecoveryCode("pepper", "123456") == hashRecoveryCode("other-pepper", "123456") {
		t.Error("different peppers produced the same HMAC")
	}
}

func TestGenerateToken(t *testing.T) {
	first, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	second, err := generateToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if first == second {
		t.Error("tokens are not random")
	}
	if len(hashToken(first)) != 64 {
		t.Errorf("token hash length = %d, want 64", len(hashToken(first)))
	}
}

func TestNormalizeEmail(t *testing.T) {
	if got := normalizeEmail("  Alice@Example.COM  "); got != "alice@example.com" {
		t.Errorf("normalizeEmail = %q, want alice@example.com", got)
	}
}
