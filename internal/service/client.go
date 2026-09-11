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

// ErrPublicClientCredentialsGrant is returned when a public client is
// registered for grant_type=client_credentials. That grant authenticates the
// client itself with its secret (RFC 6749 §4.4); a public client has none.
var ErrPublicClientCredentialsGrant = errors.New("client_credentials requires a confidential client")

// ClientService handles OAuth client registration business logic.
type ClientService struct {
	clients clientRepo
}

func NewClientService(clients clientRepo) *ClientService {
	return &ClientService{clients: clients}
}

// RegisterClient creates a new OAuth client, returning the raw secret exactly
// once. Public clients (req.IsPublic) get no secret at all — they authenticate
// with PKCE alone.
func (s *ClientService) RegisterClient(ctx context.Context, req dtos.RegisterClientRequest) (*dtos.RegisterClientResponse, error) {
	for _, gt := range req.GrantTypes {
		// Categorical mismatch, checked ahead of the supported-grants gate so it
		// still applies once client_credentials is actually implemented.
		if req.IsPublic && gt == oauth.GrantClientCredentials {
			return nil, ErrPublicClientCredentialsGrant
		}
		if !oauth.SupportedGrantTypes[gt] {
			return nil, fmt.Errorf("%w: %q", ErrUnsupportedGrantType, gt)
		}
	}

	var rawSecret, secretHash string
	if !req.IsPublic {
		rawBytes := make([]byte, 32)
		if _, err := rand.Read(rawBytes); err != nil {
			return nil, fmt.Errorf("ClientService.RegisterClient generating secret: %w", err)
		}
		rawSecret = base64.RawURLEncoding.EncodeToString(rawBytes)

		hash, err := bcrypt.GenerateFromPassword([]byte(rawSecret), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("ClientService.RegisterClient hashing secret: %w", err)
		}
		secretHash = string(hash)
	}

	client := &models.Client{
		ID:               uuid.NewString(),
		Name:             req.Name,
		ClientSecretHash: secretHash, // "" for public clients
		RedirectURIs:     models.StringSlice(req.RedirectURIs),
		Scopes:           models.StringSlice(req.Scopes),
		GrantTypes:       models.StringSlice(req.GrantTypes),
		IsFirstParty:     req.IsFirstParty,
	}

	if err := s.clients.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("ClientService.RegisterClient: %w", err)
	}

	return &dtos.RegisterClientResponse{
		ClientID:     client.ID,
		ClientSecret: rawSecret, // returned ONCE — empty for public clients
		Name:         client.Name,
	}, nil
}
