package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/stretchr/testify/mock"
)

func TestClientService_RegisterClient_publicClient(t *testing.T) {
	t.Run("client_credentials rejected for a public client", func(t *testing.T) {
		clients := NewMockClientRepo(t) // Create must not be called
		svc := NewClientService(clients)

		_, err := svc.RegisterClient(context.Background(), dtos.RegisterClientRequest{
			Name:         "cli-tool",
			RedirectURIs: []string{"https://example.com/cb"},
			GrantTypes:   []string{"client_credentials"},
			IsPublic:     true,
		})

		if !errors.Is(err, ErrPublicClientCredentialsGrant) {
			t.Fatalf("want ErrPublicClientCredentialsGrant, got %v", err)
		}
	})

	t.Run("public client gets no secret", func(t *testing.T) {
		clients := NewMockClientRepo(t)
		var stored *models.Client
		clients.EXPECT().Create(mock.Anything, mock.Anything).
			Run(func(_ context.Context, c *models.Client) { stored = c }).
			Return(nil)

		svc := NewClientService(clients)
		resp, err := svc.RegisterClient(context.Background(), dtos.RegisterClientRequest{
			Name:         "spa",
			RedirectURIs: []string{"https://app.example.com/cb"},
			GrantTypes:   []string{"authorization_code"},
			IsPublic:     true,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.ClientSecret != "" {
			t.Fatalf("want empty client secret for a public client, got %q", resp.ClientSecret)
		}
		if stored.ClientSecretHash != "" {
			t.Fatalf("want empty stored secret hash for a public client, got %q", stored.ClientSecretHash)
		}
	})

	t.Run("confidential client gets a secret", func(t *testing.T) {
		clients := NewMockClientRepo(t)
		var stored *models.Client
		clients.EXPECT().Create(mock.Anything, mock.Anything).
			Run(func(_ context.Context, c *models.Client) { stored = c }).
			Return(nil)

		svc := NewClientService(clients)
		resp, err := svc.RegisterClient(context.Background(), dtos.RegisterClientRequest{
			Name:         "backend",
			RedirectURIs: []string{"https://backend.example.com/cb"},
			GrantTypes:   []string{"authorization_code"},
			IsPublic:     false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.ClientSecret == "" {
			t.Fatalf("want a client secret for a confidential client")
		}
		if stored.ClientSecretHash == "" {
			t.Fatalf("want a stored secret hash for a confidential client")
		}
	})
}
