// Package oauth holds the wire-level vocabulary of the OAuth 2.0 protocol
package oauth

// Grant types — the "grant_type" form parameter at POST /oauth/token.
const (
	GrantAuthorizationCode = "authorization_code" // RFC 6749 §4.1.3
	GrantRefreshToken      = "refresh_token"      // RFC 6749 §6
	GrantClientCredentials = "client_credentials" // RFC 6749 §4.4
)

// SupportedGrantTypes is the set this server currently implements.
var SupportedGrantTypes = map[string]bool{
	GrantAuthorizationCode: true,
	GrantRefreshToken:      true,
}
