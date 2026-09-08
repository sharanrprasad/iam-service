package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/sharanrprasad/iam-service/internal/models"
)

// ClientRepository provides access to the clients table.
type ClientRepository struct {
	db *sqlx.DB
}

func NewClientRepository(db *sqlx.DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// Create inserts a new OAuth client.
func (r *ClientRepository) Create(ctx context.Context, c *models.Client) error {
	query := `INSERT INTO clients (id, name, client_secret_hash, redirect_uris, scopes, grant_types, is_first_party)
	          VALUES (:id, :name, :client_secret_hash, :redirect_uris, :scopes, :grant_types, :is_first_party)`
	_, err := r.db.NamedExecContext(ctx, query, c)
	if err != nil {
		return fmt.Errorf("ClientRepository.Create: %w", err)
	}
	return nil
}

// GetByID retrieves a client by its client_id.
func (r *ClientRepository) GetByID(ctx context.Context, id string) (*models.Client, error) {
	var c models.Client
	err := r.db.GetContext(ctx, &c, `SELECT * FROM clients WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ClientRepository.GetByID: %w", err)
	}
	return &c, nil
}

