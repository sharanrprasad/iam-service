package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/oauth"
	"golang.org/x/crypto/bcrypt"
)

// ErrUnsupportedGrantType is returned when a client is registered with a
// grant_type this server does not implement.
var ErrUnsupportedGrantType = errors.New("unsupported grant_type")

// ClientService handles OAuth client registration business logic.
type ClientService struct {
	clients clientRepo
}

func NewClientService(clients clientRepo) *ClientService {
	return &ClientService{clients: clients}
}

// RegisterClient creates a new OAuth client, returning the raw secret exactly once.
func (s *ClientService) RegisterClient(ctx context.Context, req dtos.RegisterClientRequest) (*dtos.RegisterClientResponse, error) {
	// Random 32-byte client secret.
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, fmt.Errorf("ClientService.RegisterClient generating secret: %w", err)
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(rawBytes)

	// Reject grant_types this server can't run.
	for _, gt := range req.GrantTypes {
		if !oauth.SupportedGrantTypes[gt] {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedGrantType, gt)
		}
	}

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
