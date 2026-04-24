package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// ErrEmailTaken is returned when the email address is already registered.
var ErrEmailTaken = errors.New("email already in use")
var ErrEmailOrPasswordWrong = errors.New("email or password wrong")

// AuthService handles authentication business logic.
type AuthService struct {
	users         *repository.UserRepository
	refreshTokens *repository.RefreshTokenRepository
	tokenService  *TokenService
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	users *repository.UserRepository,
	refreshTokens *repository.RefreshTokenRepository,
	tokenService *TokenService,
) *AuthService {
	return &AuthService{
		users:         users,
		refreshTokens: refreshTokens,
		tokenService:  tokenService,
	}
}

// RegisterInput is the data required to register a new user.
type RegisterInput struct {
	Email    string
	Password string
}

// Register creates a new user after validating uniqueness and hashing the password.
func (s *AuthService) Register(ctx context.Context, in RegisterInput) (*models.User, error) {
	existing, err := s.users.GetByEmail(ctx, in.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Register: %w", err)
	}
	if existing != nil {
		return nil, ErrEmailTaken
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Register bcrypt: %w", err)
	}

	user := &models.User{
		ID:           uuid.NewString(),
		Email:        in.Email,
		PasswordHash: string(hash),
	}

	if err = s.users.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("AuthService.Register: %w", err)
	}

	return user, nil
}

// Login validates credentials and returns access and refresh tokens.
func (s *AuthService) Login(ctx context.Context, loginRequest dtos.LoginRequest) (*dtos.LoginResponse, error) {
	// Find user by email
	user, err := s.users.GetByEmail(ctx, loginRequest.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("AuthService.Login: %w", ErrEmailOrPasswordWrong)
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginRequest.Password))
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login: %w", ErrEmailOrPasswordWrong)
	}

	// Generate access token (JWT)
	accessToken, err := s.tokenService.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login issuing access token: %w", err)
	}

	// Generate refresh token (opaque string + hash for storage)
	refreshTokenRaw, expiresAt := s.tokenService.IssueRefreshToken()

	// Hash the refresh token before storing in DB
	refreshTokenHash := hashToken(refreshTokenRaw)

	// Store the refresh token in the database
	refreshToken := &models.RefreshToken{
		ID:        uuid.NewString(),
		UserID:    user.ID,
		TokenHash: refreshTokenHash,
		ExpiresAt: expiresAt,
	}

	if err = s.refreshTokens.Create(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("AuthService.Login creating refresh token: %w", err)
	}

	// Return the response with the unhashed refresh token (for client to store)
	return &dtos.LoginResponse{
		AccessToken:         accessToken.AccessTokenString,
		RefreshToken:        refreshTokenRaw,
		AccessTokenExpiryIn: accessToken.AccessTokenExpiresIn,
		RefreshTokenExpiry:  expiresAt,
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshTokenHash string) (*dtos.RefreshResponse, error) {
	refreshToken, err := s.refreshTokens.GetTokenByHash(ctx, refreshTokenHash)
	if err != nil {
		return nil, fmt.Errorf("AuthService.RefreshToken: %w", err)
	}

	if refreshToken.ExpiresAt.Before(time.Now()) {
		// TODO - Look in to regenerating the refresh token as well.
		return nil, errors.New("refresh token expired")
	}

	user, err := s.users.GetByID(ctx, refreshToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("AuthService.RefreshToken, user not found: %w", err)
	}

	// Generate access token (JWT)
	accessToken, err := s.tokenService.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login issuing access token: %w", err)
	}

	return &dtos.RefreshResponse{
		AccessToken:         accessToken.AccessTokenString,
		AccessTokenExpiryIn: accessToken.AccessTokenExpiresIn,
	}, nil

}

// hashToken hashes a token using SHA256 for storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}
