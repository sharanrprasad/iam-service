package dtos

import (
	"net/url"
	"time"

	"github.com/sharanrprasad/iam-service/internal/validator"
)

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse carries no tokens — only where the SPA navigates next and when
// the session cookie expires. The session rides in an httpOnly cookie.
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

// AuthorizeRequest holds the parsed /oauth/authorize parameters. The `form`
// tags name the OAuth wire parameters (and are the keys used in validation
// error responses); the `validate` tags drive dtos.AuthorizeRequest.Validate.
type AuthorizeRequest struct {
	ResponseType string `form:"response_type" validate:"required,oneof=code"`
	ClientID     string `form:"client_id"     validate:"required,max=255"`
	RedirectURI  string `form:"redirect_uri"  validate:"required,redirect_uri"`
	Scope        string `form:"scope"`
	State        string `form:"state"         validate:"required,min=8,max=512"`

	// PKCE - mandatory here; SPAs and mobile apps cannot hold a client secret.
	// S256 only, never "plain". Charset is enforced at /oauth/token when the
	// verifier is hashed and compared.
	CodeChallenge       string `form:"code_challenge"        validate:"required,min=43,max=128"`
	CodeChallengeMethod string `form:"code_challenge_method" validate:"required,oneof=S256"`

	// OIDC - deferred; accepted but unused for now.
	Nonce string `form:"nonce"`

	// Optional. "" = normal; "none" = don't show a login screen (silent auth).
	// "login" / "consent" not implemented. Unknown values ignored (OIDC).
	Prompt     string `form:"prompt"`
	AccessType string `form:"access_type" validate:"omitempty,oneof=online offline"`
}

func (r AuthorizeRequest) Validate() map[string]string {
	return validator.Struct(r)
}

// ParseAuthorizeRequest maps /oauth/authorize query parameters onto the DTO.
func ParseAuthorizeRequest(q url.Values) AuthorizeRequest {
	return AuthorizeRequest{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
		Prompt:              q.Get("prompt"),
		AccessType:          q.Get("access_type"),
	}
}
