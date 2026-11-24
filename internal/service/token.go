package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

func generateToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateRecoveryCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("generate recovery code: %w", err)
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

// hashRecoveryCode uses a server-side pepper because six digits have low entropy.
func hashRecoveryCode(pepper, code string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}
