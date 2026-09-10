package handler

import (
	"context"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// ports.go declares the service-layer methods the handlers call. The concrete
// *service.AuthService / *service.ClientService satisfy these structurally.
// Mocks are generated into mocks_test.go by `make mocks`.
//
// One interface per collaborator, defined once here and nowhere else.

type authService interface {
	Login(ctx context.Context, r dtos.LoginRequest) (*service.LoginResult, error)
	Logout(ctx context.Context, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken string) (*dtos.RefreshResponse, error)
	Authorize(ctx context.Context, in service.AuthorizeInput) (service.AuthorizeResult, error)
	TokenAuthorizationFlow(ctx context.Context, r dtos.TokenRequest) (*dtos.TokenResponse, error)
}

type clientService interface {
	RegisterClient(ctx context.Context, r dtos.RegisterClientRequest) (*dtos.RegisterClientResponse, error)
}
