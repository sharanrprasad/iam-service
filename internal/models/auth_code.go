package models

import "time"

// AuthCode is what an OAuth authorization code stands for. It is stored in Redis
// under the opaque code string, is single-use, has a short TTL, and is consumed
// (with the PKCE verifier) at POST /oauth/token in exchange for tokens.
//
// It captures the full request context at consent time so /oauth/token can
// verify the exchange without trusting anything the client re-sends: the code
// was issued to this client, for this user, this redirect_uri, and this scope.
type AuthCode struct {
	ClientID    string   `json:"client_id"`
	UserID      string   `json:"user_id"`
	RedirectURI string   `json:"redirect_uri"`
	Scope       []string `json:"scope"`

	// PKCE — the challenge is fixed here; the matching verifier arrives at
	// /oauth/token and is hashed and compared against CodeChallenge.
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`

	// Nonce is carried through for OIDC (lands in the id_token). Empty for plain OAuth.
	Nonce string `json:"nonce,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}
