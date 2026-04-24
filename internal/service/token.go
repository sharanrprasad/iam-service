package service

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

// IssueAccessToken creates a JWT access token valid for 15 minutes.
func (s *TokenService) IssueAccessToken(userID, email string) (*models.AccessToken, error) {

	tokenExpiresIn := jwt.NewNumericDate(time.Now().Add(15 * time.Minute))
	claims := models.IamClaims{
		UserID: userID,
		Email:  email,
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
