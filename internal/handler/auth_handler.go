package handler

import (
	"log/slog"
	"net/http"

	"github.com/fabricio948/system_login/internal/httpx"
	"github.com/fabricio948/system_login/internal/middleware"
	"github.com/fabricio948/system_login/internal/service"
)

// AuthHandler exposes the public authentication flows.
type AuthHandler struct {
	auth   service.AuthService
	logger *slog.Logger
}

// NewAuthHandler creates an authentication handler.
func NewAuthHandler(auth service.AuthService, logger *slog.Logger) *AuthHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthHandler{auth: auth, logger: logger}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	profile, err := h.auth.Register(r.Context(), service.RegisterInput{
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, userEnvelope{User: newProfileResponse(profile)})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	result, err := h.auth.Login(r.Context(), service.LoginInput{
		Email:    input.Email,
		Password: input.Password,
	})
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, loginResponse{
		tokenResponse: newTokenResponse(&result.TokenPair),
		User:          newProfileResponse(&result.User),
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var input struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	pair, err := h.auth.Refresh(r.Context(), input.RefreshToken)
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, newTokenResponse(pair))
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email string `json:"email"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	result, err := h.auth.ForgotPassword(r.Context(), service.ForgotPasswordInput{Email: input.Email})
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	response := forgotPasswordResponse{
		Message:   result.Message,
		ExpiresAt: result.ExpiresAt,
	}
	if result.CodeReturned {
		response.Code = result.Code
	}
	httpx.WriteJSON(w, http.StatusOK, response)
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	if err := h.auth.ResetPassword(r.Context(), service.ResetPasswordInput{
		Email:       input.Email,
		Code:        input.Code,
		NewPassword: input.NewPassword,
	}); err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, messageResponse{Message: "password reset successfully"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token, ok := middleware.AccessTokenFromContext(r.Context())
	if !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
			"authorization bearer token is required")
		return
	}

	if err := h.auth.Logout(r.Context(), token); err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, messageResponse{Message: "logged out"})
}
