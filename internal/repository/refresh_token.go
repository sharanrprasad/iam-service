package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/sharanrprasad/iam-service/internal/models"
)

// RefreshTokenRepository provides access to the refresh_tokens table.
type RefreshTokenRepository struct {
	db *sqlx.DB
}

// NewRefreshTokenRepository creates a new RefreshTokenRepository.
func NewRefreshTokenRepository(db *sqlx.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create inserts a new refresh token.
func (r *RefreshTokenRepository) Create(ctx context.Context, t *models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (:id, :user_id, :token_hash, :expires_at)`
	_, err := r.db.NamedExecContext(ctx, query, t)
	if err != nil {
		return fmt.Errorf("RefreshTokenRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a refresh token by primary key.
func (r *RefreshTokenRepository) GetByID(ctx context.Context, id string) (*models.RefreshToken, error) {
	var t models.RefreshToken
	err := r.db.GetContext(ctx, &t, `SELECT * FROM refresh_tokens WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("RefreshTokenRepository.GetByID: %w", err)
	}
	return &t, nil
}

// GetActiveByUserID returns all non-revoked, non-expired tokens for a user.
func (r *RefreshTokenRepository) GetActiveByUserID(ctx context.Context, userID string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	err := r.db.SelectContext(ctx, &tokens,
		`SELECT * FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("RefreshTokenRepository.GetActiveByUserID: %w", err)
	}
	return tokens, nil
}

// Revoke marks a token as revoked at the current time.
func (r *RefreshTokenRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = ?`,
		id,
	)
	if err != nil {
		return fmt.Errorf("RefreshTokenRepository.Revoke: %w", err)
	}
	return nil
}

// RevokeAllForUser revokes all tokens for a given user.
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("RefreshTokenRepository.RevokeAllForUser: %w", err)
	}
	return nil
}

// DeleteExpired removes tokens whose expiry has passed.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return fmt.Errorf("RefreshTokenRepository.DeleteExpired: %w", err)
	}
	return nil
}

func (r *RefreshTokenRepository) GetTokenByHash(ctx context.Context, hash string) (*models.RefreshToken, error) {
	var t models.RefreshToken
	err := r.db.GetContext(ctx, &t, `SELECT * FROM refresh_tokens WHERE hash = ?`, hash)
	if err != nil {
		return nil, fmt.Errorf("RefreshTokenRepository.GetTokenByHash: %w", err)
	}
	return &t, nil
}
