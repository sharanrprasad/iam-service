package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

func TestTokenGrantService_authorizationCodeGrant_clientAuth(t *testing.T) {
	const rawSecret = "s3cr3t-value"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	confidential := &models.Client{ID: "client-1", ClientSecretHash: string(hash)}
	public := &models.Client{ID: "client-1"} // no secret hash

	tests := []struct {
		name         string
		lookup       *models.Client
		clientSecret string
		wantInvalid  bool // want ErrInvalidClient specifically
	}{
		{"unknown client", nil, rawSecret, true},
		{"confidential: wrong secret", confidential, "wrong-secret", true},
		{"confidential: correct secret passes auth", confidential, rawSecret, false},
		{"public: no secret needed", public, "", false},
		{"public: secret sent anyway is ignored", public, "whatever", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clients := NewMockClientRepo(t)
			clients.EXPECT().GetByID(mock.Anything, "client-1").Return(tc.lookup, nil)

			var authCodes authCodeRepo
			if !tc.wantInvalid {
				// Client auth is expected to pass here, so the flow continues
				// into code consumption — give it something to call.
				m := NewMockAuthCodeRepo(t)
				m.EXPECT().Consume(mock.Anything, mock.Anything).Return(nil, repository.ErrAuthCodeNotFound)
				authCodes = m
			}

			svc := NewTokenGrantService(clients, nil, authCodes, nil, nil)
			_, err := svc.authorizationCodeGrant(context.Background(), dtos.TokenRequest{
				ClientID:     "client-1",
				ClientSecret: tc.clientSecret,
			})

			if tc.wantInvalid {
				if !errors.Is(err, ErrInvalidClient) {
					t.Fatalf("want ErrInvalidClient, got %v", err)
				}
				return
			}
			// Client auth passed; it fails downstream instead (no real code set
			// up here) — just confirm it's not rejected as client auth.
			if errors.Is(err, ErrInvalidClient) {
				t.Fatalf("client auth should have passed, got ErrInvalidClient")
			}
		})
	}
}

func TestTokenGrantService_authorizationCodeGrant_pkce(t *testing.T) {
	client := &models.Client{ID: "client-1"} // public: skips secret check entirely

	const verifier = "unit-test-code-verifier-value-thats-long-enough"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	validReq := dtos.TokenRequest{
		ClientID:     "client-1",
		Code:         "the-code",
		RedirectURI:  "https://app.example.com/callback",
		CodeVerifier: verifier,
	}

	validAuthCode := &models.AuthCode{
		ClientID:            "client-1",
		RedirectURI:         "https://app.example.com/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}

	tests := []struct {
		name             string
		authCode         *models.AuthCode
		consumeErr       error
		req              dtos.TokenRequest
		wantInvalidGrant bool
	}{
		{
			name:             "code not found",
			consumeErr:       repository.ErrAuthCodeNotFound,
			req:              validReq,
			wantInvalidGrant: true,
		},
		{
			name: "client mismatch",
			authCode: &models.AuthCode{
				ClientID: "other-client", RedirectURI: validAuthCode.RedirectURI,
				CodeChallenge: challenge, CodeChallengeMethod: "S256",
			},
			req:              validReq,
			wantInvalidGrant: true,
		},
		{
			name: "redirect_uri mismatch",
			authCode: &models.AuthCode{
				ClientID: "client-1", RedirectURI: "https://app.example.com/other",
				CodeChallenge: challenge, CodeChallengeMethod: "S256",
			},
			req:              validReq,
			wantInvalidGrant: true,
		},
		{
			name:             "verifier mismatch",
			authCode:         validAuthCode,
			req:              dtos.TokenRequest{ClientID: "client-1", Code: "the-code", RedirectURI: "https://app.example.com/callback", CodeVerifier: "wrong-verifier-wrong-verifier-wrong-verifier"},
			wantInvalidGrant: true,
		},
		// The success case (correct verifier) is covered by
		// TestTokenGrantService_authorizationCodeGrant_success below, since
		// passing PKCE now continues into minting tokens.
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clients := NewMockClientRepo(t)
			clients.EXPECT().GetByID(mock.Anything, "client-1").Return(client, nil)

			authCodes := NewMockAuthCodeRepo(t)
			authCodes.EXPECT().Consume(mock.Anything, tc.req.Code).Return(tc.authCode, tc.consumeErr)

			svc := NewTokenGrantService(clients, nil, authCodes, nil, nil)
			_, err := svc.authorizationCodeGrant(context.Background(), tc.req)

			if !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("want ErrInvalidGrant, got %v", err)
			}
		})
	}
}

func TestTokenGrantService_authorizationCodeGrant_success(t *testing.T) {
	const rawSecret = "s3cr3t-value"
	hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword: %v", err)
	}
	client := &models.Client{ID: "client-1", ClientSecretHash: string(hash)}

	const verifier = "unit-test-code-verifier-value-thats-long-enough"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authCode := &models.AuthCode{
		ClientID:            "client-1",
		UserID:              "user-1",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               []string{"openid", "profile"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}
	user := &models.User{ID: "user-1", Email: "user@example.com"}

	clients := NewMockClientRepo(t)
	clients.EXPECT().GetByID(mock.Anything, "client-1").Return(client, nil)

	authCodes := NewMockAuthCodeRepo(t)
	authCodes.EXPECT().Consume(mock.Anything, "the-code").Return(authCode, nil)

	users := NewMockUserRepo(t)
	users.EXPECT().GetByID(mock.Anything, "user-1").Return(user, nil)

	tokens := NewMockTokenIssuer(t)
	tokens.EXPECT().
		IssueAccessToken("user-1", "user@example.com", "client-1", "openid profile").
		Return(&models.AccessToken{AccessTokenString: "signed-jwt", AccessTokenExpiresIn: 900}, nil)
	tokens.EXPECT().IssueRefreshToken().Return("raw-refresh-token", time.Now().Add(7*24*time.Hour))

	var stored *models.RefreshToken
	refreshTokens := NewMockRefreshTokenRepo(t)
	refreshTokens.EXPECT().Create(mock.Anything, mock.Anything).
		Run(func(_ context.Context, t *models.RefreshToken) { stored = t }).
		Return(nil)

	svc := NewTokenGrantService(clients, users, authCodes, refreshTokens, tokens)
	resp, err := svc.authorizationCodeGrant(context.Background(), dtos.TokenRequest{
		ClientID:     "client-1",
		ClientSecret: rawSecret,
		Code:         "the-code",
		RedirectURI:  "https://app.example.com/callback",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.AccessToken != "signed-jwt" || resp.TokenType != "Bearer" || resp.ExpiresIn != 900 {
		t.Fatalf("unexpected token response: %+v", resp)
	}
	if resp.Scope != "openid profile" {
		t.Fatalf("want scope %q, got %q", "openid profile", resp.Scope)
	}
	if resp.RefreshToken != "raw-refresh-token" {
		t.Fatalf("want refresh token %q, got %q", "raw-refresh-token", resp.RefreshToken)
	}

	if stored.UserID != "user-1" || stored.ClientID != "client-1" {
		t.Fatalf("stored refresh token has wrong owner/client: %+v", stored)
	}
	if len(stored.Scope) != 2 || stored.Scope[0] != "openid" || stored.Scope[1] != "profile" {
		t.Fatalf("stored refresh token has wrong scope: %+v", stored.Scope)
	}
	if stored.TokenHash == "" || stored.TokenHash == "raw-refresh-token" {
		t.Fatalf("refresh token must be stored hashed, got %q", stored.TokenHash)
	}
}
