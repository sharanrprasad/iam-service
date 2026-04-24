package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RefreshToken represents a row in the refresh_tokens table.
type RefreshToken struct {
	ID        string     `db:"id"`
	UserID    string     `db:"user_id"`
	TokenHash string     `db:"token_hash"`
	ExpiresAt time.Time  `db:"expires_at"`
	RevokedAt *time.Time `db:"revoked_at"`
	CreatedAt time.Time  `db:"created_at"`
}

type IamClaims struct {
	UserID string `json:"sub"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type AccessToken struct {
	AccessTokenString    string
	AccessTokenExpiresIn int
}
