// Package app is the dependency-injection / composition root. It builds the
// infrastructure (database, Redis), the repositories, and the transport-agnostic
// services, and hands them to whichever cmd/ binary asked (API, CLI, webhook).
//
// It deals only in concrete types — the consumer-side interfaces live in the
// packages that consume them (service/ports.go, handler/ports.go).
package app

import (
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/sharanrprasad/iam-service/internal/cache"
	"github.com/sharanrprasad/iam-service/internal/database"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// App holds the constructed, ready-to-use services plus the infra handles it
// owns for shutdown. Transport code (routers, CLI commands) reads the services;
// nothing outside app touches db / rdb.
type App struct {
	Cfg Config

	Auth        *service.AuthService
	Clients     *service.ClientService
	Tokens      *service.TokenService
	TokenGrants *service.TokenGrantService

	db  *sqlx.DB
	rdb *cache.RedisClient
}

// New wires the whole graph. On any failure it closes whatever it already
// opened and returns the error.
func New(cfg Config) (*App, error) {
	db, err := database.Connect(database.Config{
		Host:     cfg.DBHost,
		Port:     cfg.DBPort,
		User:     cfg.DBUser,
		Password: cfg.DBPassword,
		Name:     cfg.DBName,
	})
	if err != nil {
		return nil, fmt.Errorf("app.New: database: %w", err)
	}

	rdb, err := cache.NewRedisClient(cache.Config{
		Addrs:    []string{cfg.RedisAddr},
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("app.New: redis: %w", err)
	}

	privateKey, publicKey, err := loadRSAKeys(cfg.RSAPrivateKeyPath, cfg.RSAPublicKeyPath)
	if err != nil {
		_ = rdb.Close()
		_ = db.Close()
		return nil, fmt.Errorf("app.New: rsa keys: %w", err)
	}

	// Repositories
	userRepo := repository.NewUserRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(db)
	clientRepo := repository.NewClientRepository(db)
	sessionRepo := repository.NewSessionRepository(rdb)
	authCodeRepo := repository.NewAuthCodeRepository(rdb)

	// Services
	tokenSvc := service.NewTokenService(privateKey, publicKey)
	authSvc := service.NewAuthService(userRepo, refreshTokenRepo, clientRepo, tokenSvc, sessionRepo, authCodeRepo)
	clientSvc := service.NewClientService(clientRepo)
	tokenGrantSvc := service.NewTokenGrantService(clientRepo, userRepo, authCodeRepo, refreshTokenRepo, tokenSvc)

	return &App{
		Cfg:         cfg,
		Auth:        authSvc,
		Clients:     clientSvc,
		Tokens:      tokenSvc,
		TokenGrants: tokenGrantSvc,
		db:          db,
		rdb:         rdb,
	}, nil
}

// Close releases the database and Redis connections. Safe to call once.
func (a *App) Close() error {
	return errors.Join(a.rdb.Close(), a.db.Close())
}
