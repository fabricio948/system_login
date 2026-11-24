package handler

import (
	"math"
	"time"

	"github.com/fabricio948/system_login/internal/service"
)

type profileResponse struct {
	ID        uint64    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

func newProfileResponse(profile *service.Profile) profileResponse {
	return profileResponse{
		ID:        profile.ID,
		Name:      profile.Name,
		Email:     profile.Email,
		CreatedAt: profile.CreatedAt,
	}
}

type userEnvelope struct {
	User profileResponse `json:"user"`
}

type tokenResponse struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"`
	AccessExpiresAt  time.Time `json:"access_expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	ExpiresIn        int64     `json:"expires_in"`
	RefreshExpiresIn int64     `json:"refresh_expires_in"`
}

func newTokenResponse(pair *service.TokenPair) tokenResponse {
	now := time.Now().UTC()
	return tokenResponse{
		AccessToken:      pair.AccessToken,
		RefreshToken:     pair.RefreshToken,
		TokenType:        "Bearer",
		AccessExpiresAt:  pair.AccessExpiresAt,
		RefreshExpiresAt: pair.RefreshExpiresAt,
		ExpiresIn:        secondsUntil(pair.AccessExpiresAt, now),
		RefreshExpiresIn: secondsUntil(pair.RefreshExpiresAt, now),
	}
}

func secondsUntil(at, now time.Time) int64 {
	seconds := int64(math.Ceil(at.Sub(now).Seconds()))
	if seconds < 0 {
		return 0
	}
	return seconds
}

type loginResponse struct {
	tokenResponse
	User profileResponse `json:"user"`
}

type forgotPasswordResponse struct {
	Message   string    `json:"message"`
	Code      string    `json:"code,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

type messageResponse struct {
	Message string `json:"message"`
}
