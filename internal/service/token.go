package service

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
)

type TokenService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewTokenService creates a new TokenService with RSA keys.
func NewTokenService(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *TokenService {
	return &TokenService{privateKey: privateKey, publicKey: publicKey}
}

// IssueAccessToken creates a JWT access token valid for 15 minutes. clientID and
// scope are empty for the legacy /auth/refresh flow, which predates OAuth clients.
func (s *TokenService) IssueAccessToken(userID, email, clientID, scope string) (*models.AccessToken, error) {

	tokenExpiresIn := jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
	claims := models.IamClaims{
		UserID:   userID,
		Email:    email,
		ClientID: clientID,
		Scope:    scope,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(), // jti — unique token id
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: tokenExpiresIn,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, err
	}
	return &models.AccessToken{
		AccessTokenString:    signedToken,
		AccessTokenExpiresIn: 15 * 60,
	}, nil
}

// IssueRefreshToken returns a raw refresh token string and its expiry time (7 days).
// The caller is responsible for hashing it before storage.
func (s *TokenService) IssueRefreshToken() (string, time.Time) {
	expiresAt := time.Now().Add(7 * 24 * time.Hour)
	token := uuid.NewString()
	return token, expiresAt
}

// Validate parses and validates a JWT token.
func (s *TokenService) Validate(raw string) (*models.IamClaims, error) {
	token, err := jwt.ParseWithClaims(raw, &models.IamClaims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return s.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*models.IamClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// JWKS returns the public signing key as a JSON Web Key Set, for
// GET /.well-known/jwks.json. This is what lets a gateway or resource API
// verify access-token signatures locally, without ever calling this service.
// Only one active key today — no rotation yet, so there is exactly one entry.
func (s *TokenService) JWKS() dtos.JWKSResponse {
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())

	return dtos.JWKSResponse{
		Keys: []dtos.JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: rsaThumbprint(n, e),
				N:   n,
				E:   e,
			},
		},
	}
}

// rsaThumbprint computes the RFC 7638 JWK thumbprint (SHA-256 over the
// canonical {"e","kty","n"} member set, lexicographically ordered, no
// whitespace). Used as kid so a verifier can match a token's key once
// rotation introduces more than one.
func rsaThumbprint(n, e string) string {
	canonical := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`, e, n)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
