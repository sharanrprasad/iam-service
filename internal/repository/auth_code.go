package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sharanrprasad/iam-service/internal/cache"
	"github.com/sharanrprasad/iam-service/internal/models"
)

// ErrAuthCodeNotFound is returned when an authorization code has expired, was
// already used, or never existed.
var ErrAuthCodeNotFound = errors.New("authorization code not found")

const (
	// authCodeTTL is how long an authorization code is valid. RFC 6749 §4.1.2
	// caps this at 10 minutes and recommends much shorter.
	authCodeTTL = 60 * time.Second
	// authCodeKeyPrefix namespaces authorization-code keys in Redis.
	authCodeKeyPrefix = "authcode:"
)

// AuthCodeRepository issues and redeems single-use OAuth authorization codes,
// stored in Redis.
type AuthCodeRepository struct {
	cache *cache.RedisClient
}

// NewAuthCodeRepository creates a new AuthCodeRepository.
func NewAuthCodeRepository(c *cache.RedisClient) *AuthCodeRepository {
	return &AuthCodeRepository{cache: c}
}

// Create generates a cryptographically random code, stores data under it with a
// short TTL, and returns the code. The code carries no meaning on its own — all
// state lives in the Redis entry.
func (s *AuthCodeRepository) Create(ctx context.Context, data models.AuthCode) (string, error) {
	raw := make([]byte, 32) // 256 bits
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("AuthCodeRepository.Create random: %w", err)
	}
	code := base64.RawURLEncoding.EncodeToString(raw)

	data.CreatedAt = time.Now()
	payload, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("AuthCodeRepository.Create marshal: %w", err)
	}

	if err := s.cache.Set(ctx, authCodeKeyPrefix+code, payload, authCodeTTL); err != nil {
		return "", fmt.Errorf("AuthCodeRepository.Create: %w", err)
	}
	return code, nil
}

// Consume returns the data behind a code and deletes it in the same operation so
// it can never be redeemed twice. Returns ErrAuthCodeNotFound when the code is
// unknown, expired, or already consumed.
func (s *AuthCodeRepository) Consume(ctx context.Context, code string) (*models.AuthCode, error) {
	raw, err := s.cache.GetDel(ctx, authCodeKeyPrefix+code)
	if errors.Is(err, cache.ErrRedisKeyNotFound) {
		return nil, ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("AuthCodeRepository.Consume: %w", err)
	}

	var data models.AuthCode
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return nil, fmt.Errorf("AuthCodeRepository.Consume unmarshal: %w", err)
	}
	return &data, nil
}
