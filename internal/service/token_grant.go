package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/oauth"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
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

// Exchange dispatches on req.GrantType.
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
// (+ PKCE verifier) for an access token and a refresh token. Confidential
// clients (e.g. a Next.js backend) also authenticate with a client secret;
// public clients (SPAs) don't have one — PKCE is required either way.
func (s *TokenGrantService) authorizationCodeGrant(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error) {
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("TokenGrantService.authorizationCodeGrant: %w", err)
	}
	if client == nil {
		return nil, ErrInvalidClient
	}

	// Only confidential clients (they were issued a secret) present one, per spec — public clients (ClientSecretHash == "") skip this: PKCE below is
	// their proof of possession instead.
	if client.ClientSecretHash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecretHash), []byte(req.ClientSecret)); err != nil {
			return nil, ErrInvalidClient
		}
	}

	// Consume the code — single-use; missing/expired/already-used → invalid_grant.
	authCode, err := s.authCodes.Consume(ctx, req.Code)
	if errors.Is(err, repository.ErrAuthCodeNotFound) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, fmt.Errorf("TokenGrantService.authorizationCodeGrant: %w", err)
	}

	// The code must have been issued to THIS client for THIS redirect_uri.
	if authCode.ClientID != req.ClientID || authCode.RedirectURI != req.RedirectURI {
		return nil, ErrInvalidGrant
	}

	// PKCE stops a stolen authorization code from being redeemed. The client picks a
	// random secret (code_verifier), sends only its SHA-256 hash (code_challenge) to
	// /authorize, then sends the raw verifier here. We hash the verifier and require
	// it to equal the stored challenge — without the verifier, a stolen code is useless.
	if authCode.CodeChallengeMethod != "S256" {
		return nil, ErrInvalidGrant
	}
	verifierHash := sha256.Sum256([]byte(req.CodeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(authCode.CodeChallenge)) != 1 {
		return nil, ErrInvalidGrant
	}

	// Load the user for the token claims.
	user, err := s.users.GetByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("TokenGrantService.authorizationCodeGrant: %w", err)
	}
	if user == nil {
		return nil, ErrInvalidGrant
	}
	scope := strings.Join(authCode.Scope, " ")

	// Mint the access token.
	accessToken, err := s.tokens.IssueAccessToken(user.ID, user.Email, client.ID, scope)
	if err != nil {
		return nil, fmt.Errorf("TokenGrantService.authorizationCodeGrant: %w", err)
	}

	// Mint + store the refresh token, hashed — the raw value is only ever
	// returned once, to the client.
	refreshTokenRaw, refreshExpiresAt := s.tokens.IssueRefreshToken()
	err = s.refreshTokens.Create(ctx, &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		ClientID:  client.ID,
		Scope:     authCode.Scope,
		TokenHash: hashToken(refreshTokenRaw),
		ExpiresAt: refreshExpiresAt,
	})
	if err != nil {
		return nil, fmt.Errorf("TokenGrantService.authorizationCodeGrant: %w", err)
	}

	return &dtos.TokenResponse{
		AccessToken:  accessToken.AccessTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    accessToken.AccessTokenExpiresIn,
		Scope:        scope,
		RefreshToken: refreshTokenRaw,
	}, nil
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
