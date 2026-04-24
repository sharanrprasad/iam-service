package dtos

import (
	"time"
)

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken         string    `json:"access_token"`
	RefreshToken        string    `json:"refresh_token"`
	AccessTokenExpiryIn int       `json:"access_token_expiry"`
	RefreshTokenExpiry  time.Time `json:"refresh_token_expiry"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken         string `json:"access_token"`
	AccessTokenExpiryIn int    `json:"access_token_expiry"`
}
