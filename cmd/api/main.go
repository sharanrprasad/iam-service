package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/sharanrprasad/iam-service/internal/cache"
	"github.com/sharanrprasad/iam-service/internal/database"
	"github.com/sharanrprasad/iam-service/internal/handler"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"github.com/sharanrprasad/iam-service/internal/service"
)

func main() {
	port, _ := strconv.Atoi(envOrDefault("DB_PORT", "3306"))

	// clients
	db, err := database.Connect(database.Config{
		Host:     envOrDefault("DB_HOST", "localhost"),
		Port:     port,
		User:     envOrDefault("DB_USER", "iam"),
		Password: envOrDefault("DB_PASSWORD", "secret"),
		Name:     envOrDefault("DB_NAME", "iam_db"),
	})
	if err != nil {
		log.Fatalf("database.Connect: %v", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Printf("db.Close: %v", closeErr)
		}
	}()

	// Redis — backs login sessions and (later) OAuth authorization codes.
	redisDB, _ := strconv.Atoi(envOrDefault("REDIS_DB", "0"))
	redisClient, err := cache.NewRedisClient(cache.Config{
		Addrs:    []string{envOrDefault("REDIS_ADDR", "localhost:6379")},
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       redisDB,
	})
	if err != nil {
		log.Fatalf("cache.NewRedisClient: %v", err)
	}
	defer func() {
		if closeErr := redisClient.Close(); closeErr != nil {
			log.Printf("redis.Close: %v", closeErr)
		}
	}()

	// Repositories
	userRepo := repository.NewUserRepository(db)
	refreshTokenRepo := repository.NewRefreshTokenRepository(db)
	clientRepo := repository.NewClientRepository(db)
	sessionRepo := repository.NewSessionRepository(redisClient)   // Redis-backed
	authCodeRepo := repository.NewAuthCodeRepository(redisClient) // Redis-backed

	privateKey, publicKey, err := loadRSAKeys(filepath.Join(".rsa", "private.pem"), filepath.Join(".rsa", "public.pem"))
	if err != nil {
		log.Fatalf("loadRSAKeys: %v", err)
	}
	tokenSvc := service.NewTokenService(privateKey, publicKey)

	// Services
	authSvc := service.NewAuthService(userRepo, refreshTokenRepo, clientRepo, tokenSvc, sessionRepo, authCodeRepo)
	clientSvc := service.NewClientService(clientRepo)

	// Handlers
	secureCookies := envOrDefault("COOKIE_SECURE", "true") == "true"
	loginURL := envOrDefault("LOGIN_URL", "/login")
	authHandler := handler.NewAuthHandler(authSvc, clientSvc, secureCookies, loginURL)

	// Router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	r.Post("/login", authHandler.Login)
	r.Post("/logout", authHandler.Logout)
	r.Post("/refresh", authHandler.Refresh)

	// OAuth endpoints
	r.Route("/oauth", func(r chi.Router) {
		r.Get("/authorize", authHandler.Authorize)
		r.Post("/token", authHandler.Token)
	})

	// Admin routes
	r.Route("/admin", func(r chi.Router) {
		r.Post("/clients", authHandler.RegisterClient)
	})

	addr := fmt.Sprintf(":%s", envOrDefault("PORT", "8080"))
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("ListenAndServe: %v", err)
		}
	}()

	<-done
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server shutdown: %v", err)
	}
	log.Println("server stopped")
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadRSAKeys(privateKeyPath, publicKeyPath string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("private key not found at %q: %w", privateKeyPath, err)
		}
		return nil, nil, fmt.Errorf("read private key: %w", err)
	}

	privateBlock, _ := pem.Decode(privateKeyPEM)
	if privateBlock == nil {
		return nil, nil, fmt.Errorf("decode private key PEM: no PEM block found")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateBlock.Bytes)
	if err != nil {
		parsedKey, pkcs8Err := x509.ParsePKCS8PrivateKey(privateBlock.Bytes)
		if pkcs8Err != nil {
			return nil, nil, fmt.Errorf("parse private key: %w", err)
		}

		rsaPrivateKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("parse private key: unsupported key type %T", parsedKey)
		}
		privateKey = rsaPrivateKey
	}

	publicKeyPEM, err := os.ReadFile(publicKeyPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil, fmt.Errorf("public key not found at %q: %w", publicKeyPath, err)
		}
		return nil, nil, fmt.Errorf("read public key: %w", err)
	}

	publicBlock, _ := pem.Decode(publicKeyPEM)
	if publicBlock == nil {
		return nil, nil, fmt.Errorf("decode public key PEM: no PEM block found")
	}

	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse public key: %w", err)
	}

	publicKey, ok := parsedPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("parse public key: unsupported key type %T", parsedPublicKey)
	}

	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 || privateKey.PublicKey.E != publicKey.E {
		return nil, nil, fmt.Errorf("private/public RSA keys do not match")
	}

	return privateKey, publicKey, nil
}
