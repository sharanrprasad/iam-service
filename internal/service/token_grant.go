package service

import (
	"context"
	"errors"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/oauth"
)

// Token-endpoint error sentinels (RFC 6749 §5.2); the handler maps each to its
// error code + status. ErrUnsupportedGrantType is defined in client.go.
var (
	ErrInvalidGrant       = errors.New("invalid_grant")
	ErrInvalidClient      = errors.New("invalid_client")
	ErrUnauthorizedClient = errors.New("unauthorized_client")
	ErrInvalidScope       = errors.New("invalid_scope")
)

// TokenGrantService runs the POST /oauth/token grant exchanges.
type TokenGrantService struct {
	clients       clientRepo
	users         userRepo
	authCodes     authCodeRepo
	refreshTokens refreshTokenRepo
	tokens        tokenIssuer
}

// NewTokenGrantService creates a new TokenGrantService.
func NewTokenGrantService(
	clients clientRepo,
	users userRepo,
	authCodes authCodeRepo,
	refreshTokens refreshTokenRepo,
	tokens tokenIssuer,
) *TokenGrantService {
	return &TokenGrantService{
		clients:       clients,
		users:         users,
		authCodes:     authCodes,
		refreshTokens: refreshTokens,
		tokens:        tokens,
	}
}

// Exchange dispatches on req.GrantType. req already has its client credentials
// merged in (Basic header or body) by the caller.
func (s *TokenGrantService) Exchange(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error) {
	switch req.GrantType {
	case oauth.GrantAuthorizationCode:
		return s.authorizationCodeGrant(ctx, req)
	case oauth.GrantRefreshToken:
		return s.refreshTokenGrant(ctx, req)
	default:
		// client_credentials not routed yet — see clientCredentialsGrant / CLAUDE.md decision #5.
		return nil, ErrUnsupportedGrantType
	}
}

// authorizationCodeGrant redeems the single-use code from /oauth/authorize
// (+ PKCE verifier) for an access token and a refresh token.
func (s *TokenGrantService) authorizationCodeGrant(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error) {
	// 1. Authenticate the client: confidential → bcrypt-verify req.ClientSecret
	//    (mismatch → ErrInvalidClient); public → PKCE (step 4) is the proof.
	//    "authorization_code" must be in the client's grant_types → else ErrUnauthorizedClient.
	// 2. Consume the code (single-use); repository.ErrAuthCodeNotFound → ErrInvalidGrant.
	// 3. Bind to this request: authCode.ClientID == req.ClientID and
	//    authCode.RedirectURI == req.RedirectURI → else ErrInvalidGrant.
	// 4. Verify PKCE: base64url(SHA256(req.CodeVerifier)) == authCode.CodeChallenge (S256).
	// 5. Load the user for token claims.
	// 6. Mint the access token (sub, scope, aud, exp).
	// 7. Mint + store the refresh token (user_id, client_id, scope, expiry).
	// 8. Return dtos.TokenResponse.
	return nil, errors.New("authorizationCodeGrant: not implemented")
}

// refreshTokenGrant exchanges a stored refresh token for a fresh access token,
// rotating the refresh token.
func (s *TokenGrantService) refreshTokenGrant(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error) {
	// 1. Authenticate the client (same rules as the code grant).
	// 2. Look up req.RefreshToken by hash; missing / revoked / expired → ErrInvalidGrant.
	// 3. row.ClientID must equal req.ClientID → else ErrInvalidGrant.
	// 4. req.Scope, if set, must be a subset of the stored scope → else ErrInvalidScope.
	// 5. Rotate: issue a new refresh token, revoke the presented one. A revoked
	//    token presented again → revoke the whole chain, return ErrInvalidGrant.
	// 6. Mint a new access token.
	// 7. Return dtos.TokenResponse with the new pair.
	return nil, errors.New("refreshTokenGrant: not implemented")
}

// clientCredentialsGrant: a machine client authenticating as itself — no user,
// no refresh token. Not wired into Exchange; see CLAUDE.md decision #5.
func (s *TokenGrantService) clientCredentialsGrant(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error) {
	// 1. Authenticate the client; MUST be confidential — bad/absent secret → ErrInvalidClient.
	// 2. "client_credentials" must be in the client's grant_types → else ErrUnauthorizedClient.
	// 3. req.Scope must be a subset of the client's registered scopes → else ErrInvalidScope.
	// 4. Mint an access token with sub = client_id, no refresh token.
	// 5. Return dtos.TokenResponse (RefreshToken empty).
	return nil, errors.New("clientCredentialsGrant: not implemented")
}
