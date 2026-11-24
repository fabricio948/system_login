package handler

import (
	"log/slog"
	"net/http"

	"github.com/fabricio948/system_login/internal/httpx"
	"github.com/fabricio948/system_login/internal/middleware"
	"github.com/fabricio948/system_login/internal/service"
)

// AccountHandler exposes the authenticated account flows.
type AccountHandler struct {
	account service.AccountService
	logger  *slog.Logger
}

// NewAccountHandler creates an account handler.
func NewAccountHandler(account service.AccountService, logger *slog.Logger) *AccountHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AccountHandler{account: account, logger: logger}
}

func (h *AccountHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	profile, ok := middleware.ProfileFromContext(r.Context())
	if !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
			"authorization bearer token is required")
		return
	}

	current, err := h.account.GetProfile(r.Context(), profile.ID)
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, userEnvelope{User: newProfileResponse(current)})
}

func (h *AccountHandler) UpdateName(w http.ResponseWriter, r *http.Request) {
	profile, ok := middleware.ProfileFromContext(r.Context())
	if !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
			"authorization bearer token is required")
		return
	}

	var input struct {
		Name string `json:"name"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	updated, err := h.account.UpdateName(r.Context(), profile.ID, service.UpdateNameInput{Name: input.Name})
	if err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, userEnvelope{User: newProfileResponse(updated)})
}

func (h *AccountHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	profile, ok := middleware.ProfileFromContext(r.Context())
	if !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
			"authorization bearer token is required")
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := httpx.DecodeJSON(w, r, &input); err != nil {
		httpx.WriteJSONError(w, http.StatusBadRequest, "invalid_json", "invalid JSON body")
		return
	}

	if err := h.account.ChangePassword(r.Context(), profile.ID, service.ChangePasswordInput{
		CurrentPassword: input.CurrentPassword,
		NewPassword:     input.NewPassword,
	}); err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, messageResponse{Message: "password changed successfully"})
}

func (h *AccountHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	profile, ok := middleware.ProfileFromContext(r.Context())
	if !ok {
		httpx.WriteJSONError(w, http.StatusUnauthorized, "missing_token",
			"authorization bearer token is required")
		return
	}

	if err := h.account.DeleteAccount(r.Context(), profile.ID); err != nil {
		httpx.WriteError(w, h.logger, err)
		return
	}

	httpx.WriteJSON(w, http.StatusOK, messageResponse{Message: "account deleted"})
}
