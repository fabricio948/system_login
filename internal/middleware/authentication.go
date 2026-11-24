package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/fabricio948/system_login/internal/httpx"
	"github.com/fabricio948/system_login/internal/service"
)

// Authenticator resolves an access token into a profile.
type Authenticator interface {
	Authenticate(ctx context.Context, accessToken string) (*service.Profile, error)
}

type contextKey int

const (
	profileKey contextKey = iota
	accessTokenKey
)

// ProfileFromContext returns the authenticated profile.
func ProfileFromContext(ctx context.Context) (*service.Profile, bool) {
	profile, ok := ctx.Value(profileKey).(*service.Profile)
	return profile, ok && profile != nil
}

// AccessTokenFromContext returns the raw access token used by the request.
func AccessTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(accessTokenKey).(string)
	return token, ok && token != ""
}

// Authentication validates the bearer token and stores the profile in context.
// The service also rechecks that the user is active and not blocked.
func Authentication(authenticator Authenticator, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
					"authorization bearer token is required")
				return
			}

			profile, err := authenticator.Authenticate(r.Context(), token)
			if err != nil {
				httpx.WriteError(w, logger, err)
				return
			}

			ctx := context.WithValue(r.Context(), profileKey, profile)
			ctx = context.WithValue(ctx, accessTokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
