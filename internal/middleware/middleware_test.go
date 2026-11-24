package middleware

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/service"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeAuthenticator struct {
	profile *service.Profile
	err     error
}

func (f fakeAuthenticator) Authenticate(ctx context.Context, token string) (*service.Profile, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.profile, nil
}

func TestAuthentication(t *testing.T) {
	profile := &service.Profile{ID: 7, Email: "alice@example.com"}

	t.Run("valid token", func(t *testing.T) {
		var gotProfile *service.Profile
		var gotToken string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotProfile, _ = ProfileFromContext(r.Context())
			gotToken, _ = AccessTokenFromContext(r.Context())
			w.WriteHeader(http.StatusNoContent)
		})

		handler := Authentication(fakeAuthenticator{profile: profile}, discardLogger())(next)
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.Header.Set("Authorization", "Bearer access-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if gotProfile == nil || gotProfile.ID != profile.ID {
			t.Errorf("profile = %+v, want %+v", gotProfile, profile)
		}
		if gotToken != "access-token" {
			t.Errorf("token = %q, want access-token", gotToken)
		}
	})

	tests := []struct {
		name       string
		header     string
		err        error
		wantStatus int
	}{
		{"missing token", "", nil, http.StatusUnauthorized},
		{"malformed token", "Token abc", nil, http.StatusUnauthorized},
		{"invalid token", "Bearer bad", service.ErrInvalidAccessToken, http.StatusUnauthorized},
		{"blocked user", "Bearer token", &service.BlockedError{Admin: true, Reason: "policy"}, http.StatusLocked},
		{"inactive user", "Bearer token", model.ErrUserInactive, http.StatusLocked},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("next handler was called")
			})
			handler := Authentication(fakeAuthenticator{profile: profile, err: tt.err}, discardLogger())(next)
			req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestCORS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("allowed preflight", func(t *testing.T) {
		handler := CORS("http://localhost:3000")(next)
		req := httptest.NewRequest(http.MethodOptions, "/auth/login", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		req.Header.Set("Access-Control-Request-Method", "POST")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
			t.Errorf("allow origin = %q", got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Authorization") {
			t.Errorf("allow headers = %q", got)
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		handler := CORS("http://localhost:3000")(next)
		req := httptest.NewRequest(http.MethodGet, "/users/me", nil)
		req.Header.Set("Origin", "http://evil.example")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("allow origin = %q, want empty", got)
		}
	})
}

func TestRecovery(t *testing.T) {
	handler := Recovery(discardLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"internal_error"`) {
		t.Errorf("body = %q", rec.Body.String())
	}
}
