package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// RefreshToken represents a row in the refresh_tokens table. ClientID and Scope
// are empty/nil for tokens minted by the legacy POST /refresh flow, which
// predates OAuth clients; tokens from the authorization_code grant set both.
type RefreshToken struct {
	ID        string      `db:"id"`
	UserID    string      `db:"user_id"`
	ClientID  string      `db:"client_id"`
	Scope     StringSlice `db:"scope"`
	TokenHash string      `db:"token_hash"`
	ExpiresAt time.Time   `db:"expires_at"`
	RevokedAt *time.Time  `db:"revoked_at"`
	CreatedAt time.Time   `db:"created_at"`
}

// IamClaims are the custom JWT claims for this service's access tokens. This
// service is both issuer and sole verifier for now, so ClientID/Scope are
// plain custom claims rather than standard OIDC ones (aud, azp) — revisit if a
// separate resource server starts verifying these tokens.
type IamClaims struct {
	UserID   string `json:"sub"`
	Email    string `json:"email"`
	ClientID string `json:"client_id"`
	Scope    string `json:"scope"` // space-delimited, RFC 6749 §3.3
	jwt.RegisteredClaims
}

type AccessToken struct {
	AccessTokenString    string
	AccessTokenExpiresIn int
}
