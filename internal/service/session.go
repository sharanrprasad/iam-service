package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/cache"
	"github.com/sharanrprasad/iam-service/internal/models"
)

// ErrSessionNotFound is returned when a session ID has no live session behind it
// (expired, deleted, or never existed).
var ErrSessionNotFound = errors.New("session not found")

const (
	// sessionTTL is how long a login session stays valid without re-authentication.
	sessionTTL = 30 * 24 * time.Hour
	// sessionKeyPrefix namespaces session keys in Redis.
	sessionKeyPrefix = "session:"
)

// SessionService creates and looks up browser login sessions in Redis.
type SessionService struct {
	cache *cache.RedisClient
}

// NewSessionService creates a new SessionService.
func NewSessionService(c *cache.RedisClient) *SessionService {
	return &SessionService{cache: c}
}

// Create stores a new session for the user and returns its opaque ID and the
// absolute time it expires. The ID is what goes into the session cookie.
func (s *SessionService) Create(ctx context.Context, userID, email string) (id string, expiresAt time.Time, err error) {
	sessionID := uuid.NewString()
	payload, err := json.Marshal(models.Session{
		UserID:    userID,
		Email:     email,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("SessionService.Create marshal: %w", err)
	}

	if err := s.cache.Set(ctx, sessionKeyPrefix+sessionID, payload, sessionTTL); err != nil {
		return "", time.Time{}, fmt.Errorf("SessionService.Create: %w", err)
	}

	return sessionID, time.Now().Add(sessionTTL), nil
}

// Get returns the session behind a session ID, or ErrSessionNotFound if it has
// expired or never existed.
func (s *SessionService) Get(ctx context.Context, sessionID string) (*models.Session, error) {
	raw, err := s.cache.Get(ctx, sessionKeyPrefix+sessionID)
	if errors.Is(err, cache.ErrRedisKeyNotFound) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("SessionService.Get: %w", err)
	}

	var sess models.Session
	if err := json.Unmarshal([]byte(raw), &sess); err != nil {
		return nil, fmt.Errorf("SessionService.Get unmarshal: %w", err)
	}
	return &sess, nil
}

// Destroy removes a session. Used by logout. Deleting a missing key is a no-op.
func (s *SessionService) Destroy(ctx context.Context, sessionID string) error {
	if err := s.cache.Delete(ctx, sessionKeyPrefix+sessionID); err != nil {
		return fmt.Errorf("SessionService.Destroy: %w", err)
	}
	return nil
}
