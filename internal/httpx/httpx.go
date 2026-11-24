package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/fabricio948/system_login/internal/model"
	"github.com/fabricio948/system_login/internal/service"
)

const maxBodyBytes = 1 << 20

// ErrorBody is the JSON representation of an API error.
type ErrorBody struct {
	Code             string            `json:"code"`
	Message          string            `json:"message"`
	Fields           map[string]string `json:"fields,omitempty"`
	Reason           string            `json:"reason,omitempty"`
	BlockedUntil     *time.Time        `json:"blocked_until,omitempty"`
	RemainingSeconds int64             `json:"remaining_seconds,omitempty"`
}

// ErrorResponse wraps an error body.
type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

// WriteJSON writes a JSON response with the standard headers.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteJSONError writes a plain error payload.
func WriteJSONError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{
		Error: ErrorBody{Code: code, Message: message},
	})
}

// WriteError maps a domain error to an HTTP response.
func WriteError(w http.ResponseWriter, logger *slog.Logger, err error) {
	status, body := MapError(err)
	if status >= http.StatusInternalServerError && logger != nil {
		logger.Error("request failed", "error", err)
	}
	WriteJSON(w, status, ErrorResponse{Error: body})
}

// MapError converts service and model errors into status codes and bodies.
func MapError(err error) (int, ErrorBody) {
	var validationErr *service.ValidationError
	if errors.As(err, &validationErr) {
		return http.StatusBadRequest, ErrorBody{
			Code:    "validation_error",
			Message: "invalid input",
			Fields:  map[string]string{validationErr.Field: validationErr.Message},
		}
	}

	var blockedErr *service.BlockedError
	if errors.As(err, &blockedErr) {
		body := ErrorBody{
			Code:   "user_blocked",
			Reason: blockedErr.Reason,
		}
		if blockedErr.Admin {
			body.Message = "account administratively blocked"
		} else {
			body.Message = "account temporarily blocked"
		}
		if blockedErr.Until != nil {
			until := blockedErr.Until.UTC()
			body.BlockedUntil = &until
		}
		if blockedErr.Remaining > 0 {
			body.RemainingSeconds = int64(math.Ceil(blockedErr.Remaining.Seconds()))
		}
		return http.StatusLocked, body
	}

	switch {
	case errors.Is(err, model.ErrInvalidCredentials):
		return http.StatusUnauthorized, ErrorBody{Code: "invalid_credentials", Message: "invalid credentials"}
	case errors.Is(err, model.ErrEmailAlreadyExists):
		return http.StatusConflict, ErrorBody{Code: "email_already_exists", Message: "email already registered"}
	case errors.Is(err, model.ErrUserNotFound):
		return http.StatusNotFound, ErrorBody{Code: "user_not_found", Message: "user not found"}
	case errors.Is(err, model.ErrUserInactive):
		return http.StatusLocked, ErrorBody{Code: "user_inactive", Message: "account is not active"}
	case errors.Is(err, service.ErrInvalidAccessToken),
		errors.Is(err, model.ErrSessionNotFound),
		errors.Is(err, model.ErrSessionRevoked):
		return http.StatusUnauthorized, ErrorBody{Code: "invalid_token", Message: "invalid access token"}
	case errors.Is(err, model.ErrAccessTokenExpired):
		return http.StatusUnauthorized, ErrorBody{Code: "access_token_expired", Message: "access token expired"}
	case errors.Is(err, service.ErrInvalidRefreshToken):
		return http.StatusUnauthorized, ErrorBody{Code: "invalid_refresh_token", Message: "invalid refresh token"}
	case errors.Is(err, model.ErrRefreshTokenExpired):
		return http.StatusUnauthorized, ErrorBody{Code: "refresh_token_expired", Message: "refresh token expired"}
	case errors.Is(err, service.ErrInvalidCurrentPassword):
		return http.StatusUnauthorized, ErrorBody{Code: "invalid_current_password", Message: "current password is incorrect"}
	case errors.Is(err, service.ErrPasswordUnchanged):
		return http.StatusBadRequest, ErrorBody{Code: "password_unchanged", Message: "new password must differ from the current password"}
	case errors.Is(err, service.ErrInvalidRecoveryCode),
		errors.Is(err, model.ErrRecoveryCodeNotFound),
		errors.Is(err, model.ErrRecoveryCodeUsed),
		errors.Is(err, model.ErrRecoveryCodeInvalidated):
		return http.StatusBadRequest, ErrorBody{Code: "invalid_recovery_code", Message: "invalid recovery code"}
	case errors.Is(err, model.ErrRecoveryCodeExpired):
		return http.StatusBadRequest, ErrorBody{Code: "recovery_code_expired", Message: "recovery code expired"}
	case errors.Is(err, model.ErrRecoveryAttemptsExceeded):
		return http.StatusTooManyRequests, ErrorBody{Code: "recovery_attempts_exceeded", Message: "too many recovery attempts"}
	}

	return http.StatusInternalServerError, ErrorBody{Code: "internal_error", Message: "internal server error"}
}

// DecodeJSON decodes a single JSON object with a size limit and strict fields.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" &&
		!strings.HasPrefix(contentType, "application/json") {
		return errors.New("content type must be application/json")
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON object")
	}
	return nil
}
