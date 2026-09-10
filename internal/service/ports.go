package service

import (
	"context"
	"time"

	"github.com/sharanrprasad/iam-service/internal/models"
)

// ports.go declares the collaborators the service layer depends on. Each is the
// minimal method set this package actually calls; the concrete types in
// internal/repository satisfy them structurally. Mocks are generated into
// mocks_test.go by `make mocks`.
//
// One interface per collaborator, defined once here and nowhere else.

type userRepo interface {
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByID(ctx context.Context, id string) (*models.User, error)
	Create(ctx context.Context, u *models.User) error
}

type clientRepo interface {
	GetByID(ctx context.Context, id string) (*models.Client, error)
	Create(ctx context.Context, c *models.Client) error
}

type refreshTokenRepo interface {
	GetTokenByHash(ctx context.Context, hash string) (*models.RefreshToken, error)
	Create(ctx context.Context, t *models.RefreshToken) error
}

type sessionRepo interface {
	Create(ctx context.Context, userID, email string) (string, time.Time, error)
	Get(ctx context.Context, sessionID string) (*models.Session, error)
	Destroy(ctx context.Context, sessionID string) error
}

type authCodeRepo interface {
	Create(ctx context.Context, data models.AuthCode) (string, error)
	Consume(ctx context.Context, code string) (*models.AuthCode, error)
}

type tokenIssuer interface {
	IssueAccessToken(userID, email string) (*models.AccessToken, error)
	IssueRefreshToken() (string, time.Time)
}
