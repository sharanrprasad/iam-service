package handler

import (
	"context"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// ports.go declares the service methods the handlers call. Concrete *service.*
// types satisfy these; mocks come from `make mocks`. One interface per
// collaborator, here only.

type authService interface {
	Login(ctx context.Context, r dtos.LoginRequest) (*service.LoginResult, error)
	Logout(ctx context.Context, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken string) (*dtos.RefreshResponse, error)
	Authorize(ctx context.Context, in service.AuthorizeInput) (service.AuthorizeResult, error)
}

type clientService interface {
	RegisterClient(ctx context.Context, r dtos.RegisterClientRequest) (*dtos.RegisterClientResponse, error)
}

type tokenGrantService interface {
	Exchange(ctx context.Context, req dtos.TokenRequest) (*dtos.TokenResponse, error)
}
