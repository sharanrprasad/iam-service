package dtos

import (
	"time"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is the JSON body returned by POST /login. It deliberately
// carries no tokens — only where the SPA should navigate next (back into the
// OAuth flow) and when the session cookie expires. The session itself rides in
// an httpOnly cookie, not this body.
type LoginResponse struct {
	Next             string    `json:"next"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
	AccessToken         string `json:"access_token"`
	AccessTokenExpiryIn int    `json:"access_token_expiry"`
}

type RegisterClientRequest struct {
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	GrantTypes   []string `json:"grant_types"`
	IsFirstParty bool     `json:"is_first_party"` // Only true for the application client.
}

type RegisterClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"` // returned ONCE — store it safely
	Name         string `json:"name"`
}

type AuthorizeRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string

	// PKCE - For SPAs and Mobile apps which cannot store the secret on the client side.
	CodeChallenge       string
	CodeChallengeMethod string

	// OIDC
	Nonce string

	// Optional
	Prompt     string
	AccessType string
}
