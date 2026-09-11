package dtos

import (
	"net/url"

	"github.com/sharanrprasad/iam-service/internal/validator"
)

// TokenRequest is the form-encoded body of POST /oauth/token. One struct covers every grant_type; which fields matter depends on GrantType.
type TokenRequest struct {
	// Grant to run. Not oneof-validated — that returns invalid_request, but an
	// unknown grant must be unsupported_grant_type (RFC 6749 §5.2).
	GrantType string `form:"grant_type" validate:"required"`

	// grant_type=authorization_code
	Code         string `form:"code" validate:"required_if=GrantType authorization_code"`
	RedirectURI  string `form:"redirect_uri" validate:"required_if=GrantType authorization_code"` // must byte-match the value sent to /oauth/authorize
	CodeVerifier string `form:"code_verifier" validate:"required_if=GrantType authorization_code,omitempty,min=43,max=128"`

	// grant_type=refresh_token
	RefreshToken string `form:"refresh_token" validate:"required_if=GrantType refresh_token"`
	Scope        string `form:"scope"` // optional; may only narrow the token's existing scope

	// Client credentials for client_secret_post. Both are empty when the client uses an
	// Authorization: Basic header instead; ClientSecret is also empty for public clients
	// (SPAs) that authenticate with PKCE.
	ClientID     string `form:"client_id"`     // omitted when Basic auth (Sent in HTTP header) is used
	ClientSecret string `form:"client_secret"` // confidential clients only; public clients like SPA pages use PKCE
}

// ParseTokenRequest maps the POST body form values onto the DTO.
func ParseTokenRequest(f url.Values) TokenRequest {
	return TokenRequest{
		GrantType:    f.Get("grant_type"),
		Code:         f.Get("code"),
		RedirectURI:  f.Get("redirect_uri"),
		CodeVerifier: f.Get("code_verifier"),
		RefreshToken: f.Get("refresh_token"),
		Scope:        f.Get("scope"),
		ClientID:     f.Get("client_id"),
		ClientSecret: f.Get("client_secret"),
	}
}

func (r TokenRequest) Validate() map[string]string {
	return validator.Struct(r)
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // always "Bearer"
	ExpiresIn    int    `json:"expires_in"` // access-token lifetime, seconds
	Scope        string `json:"scope"`      // space-delimited granted scope
	RefreshToken string `json:"refresh_token,omitempty"`
	// IDToken      string `json:"id_token,omitempty"` // OIDC only; Not implemented currently.
}

// TokenErrorResponse is the JSON error body of POST /oauth/token (RFC 6749
// §5.2). HTTP 400, or 401 for invalid_client. Error is a code, not a sentence:
//
//	invalid_request | invalid_client | invalid_grant |
//	unauthorized_client | unsupported_grant_type | invalid_scope
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
