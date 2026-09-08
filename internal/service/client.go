package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// ClientService handles OAuth client registration business logic.
type ClientService struct {
	clients *repository.ClientRepository
}

func NewClientService(clients *repository.ClientRepository) *ClientService {
	return &ClientService{clients: clients}
}

// RegisterClient creates a new OAuth client, returning the raw secret exactly once.
func (s *ClientService) RegisterClient(ctx context.Context, req dtos.RegisterClientRequest) (*dtos.RegisterClientResponse, error) {
	// Generate a cryptographically random client secret (32 bytes → 43-char base64url string).
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, fmt.Errorf("ClientService.RegisterClient generating secret: %w", err)
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(rawBytes)

	// Hash the secret before storage — bcrypt so it's slow to brute-force.
	secretHash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("ClientService.RegisterClient hashing secret: %w", err)
	}

	client := &models.Client{
		ID:               uuid.NewString(),
		Name:             req.Name,
		ClientSecretHash: string(secretHash),
		RedirectURIs:     models.StringSlice(req.RedirectURIs),
		Scopes:           models.StringSlice(req.Scopes),
		GrantTypes:       models.StringSlice(req.GrantTypes),
		IsFirstParty:     req.IsFirstParty,
	}

	if err = s.clients.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("ClientService.RegisterClient: %w", err)
	}

	return &dtos.RegisterClientResponse{
		ClientID:     client.ID,
		ClientSecret: rawSecret, // returned ONCE — never stored in plaintext
		Name:         client.Name,
	}, nil
}
