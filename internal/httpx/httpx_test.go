package httpx

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/service"
)

func TestMapError(t *testing.T) {
	until := time.Date(2026, 11, 24, 12, 10, 0, 0, time.UTC)

	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"validation", &service.ValidationError{Field: "email", Message: "invalid"}, http.StatusBadRequest, "validation_error"},
		{"temporary block", &service.BlockedError{Reason: "too many failures", Until: &until, Remaining: 10 * time.Minute}, http.StatusLocked, "user_blocked"},
		{"admin block", &service.BlockedError{Admin: true, Reason: "policy"}, http.StatusLocked, "user_blocked"},
		{"invalid credentials", model.ErrInvalidCredentials, http.StatusUnauthorized, "invalid_credentials"},
		{"email exists", model.ErrEmailAlreadyExists, http.StatusConflict, "email_already_exists"},
		{"not found", model.ErrUserNotFound, http.StatusNotFound, "user_not_found"},
		{"inactive", model.ErrUserInactive, http.StatusLocked, "user_inactive"},
		{"invalid access", service.ErrInvalidAccessToken, http.StatusUnauthorized, "invalid_token"},
		{"access expired", model.ErrAccessTokenExpired, http.StatusUnauthorized, "access_token_expired"},
		{"invalid refresh", service.ErrInvalidRefreshToken, http.StatusUnauthorized, "invalid_refresh_token"},
		{"refresh expired", model.ErrRefreshTokenExpired, http.StatusUnauthorized, "refresh_token_expired"},
		{"current password", service.ErrInvalidCurrentPassword, http.StatusUnauthorized, "invalid_current_password"},
		{"password unchanged", service.ErrPasswordUnchanged, http.StatusBadRequest, "password_unchanged"},
		{"invalid recovery", service.ErrInvalidRecoveryCode, http.StatusBadRequest, "invalid_recovery_code"},
		{"recovery expired", model.ErrRecoveryCodeExpired, http.StatusBadRequest, "recovery_code_expired"},
		{"recovery attempts", model.ErrRecoveryAttemptsExceeded, http.StatusTooManyRequests, "recovery_attempts_exceeded"},
		{"unknown", errors.New("boom"), http.StatusInternalServerError, "internal_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := MapError(tt.err)
			if status != tt.status {
				t.Errorf("status = %d, want %d", status, tt.status)
			}
			if body.Code != tt.code {
				t.Errorf("code = %q, want %q", body.Code, tt.code)
			}
		})
	}
}

func TestMapBlockedErrorDetails(t *testing.T) {
	until := time.Date(2026, 11, 24, 12, 10, 0, 0, time.UTC)
	status, body := MapError(&service.BlockedError{
		Reason:    "too many failures",
		Until:     &until,
		Remaining: 10 * time.Minute,
	})
	if status != http.StatusLocked {
		t.Fatalf("status = %d, want %d", status, http.StatusLocked)
	}
	if body.Reason != "too many failures" {
		t.Errorf("reason = %q", body.Reason)
	}
	if body.RemainingSeconds != 600 {
		t.Errorf("remaining = %d, want 600", body.RemainingSeconds)
	}
	if body.BlockedUntil == nil || !body.BlockedUntil.Equal(until) {
		t.Errorf("blocked until = %v, want %v", body.BlockedUntil, until)
	}
}

func TestDecodeJSON(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		var input struct {
			Name string `json:"name"`
		}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"Alice"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		if err := DecodeJSON(rec, req, &input); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if input.Name != "Alice" {
			t.Errorf("name = %q, want Alice", input.Name)
		}
	})

	tests := []struct {
		name        string
		body        string
		contentType string
	}{
		{"invalid json", `{"name":`, "application/json"},
		{"unknown field", `{"name":"Alice","extra":true}`, "application/json"},
		{"trailing object", `{"name":"Alice"}{"name":"Bob"}`, "application/json"},
		{"wrong content type", `{"name":"Alice"}`, "text/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var input struct {
				Name string `json:"name"`
			}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			rec := httptest.NewRecorder()

			if err := DecodeJSON(rec, req, &input); err == nil {
				t.Fatal("DecodeJSON returned nil error")
			}
		})
	}
}
