package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
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
var ClientNotFoundError = errors.New("client not found")

// RedirectURIMismatchError means the request's redirect_uri is not one this
// client registered. Like ClientNotFoundError, the caller must NOT redirect the
// error back — it can only be shown directly (open-redirect / phishing guard).
var RedirectURIMismatchError = errors.New("redirect_uri does not match a registered URI for this client")

var ErrRedirectToLogin = errors.New("redirect to login")

// AuthService handles authentication business logic.
type AuthService struct {
	users            *repository.UserRepository
	refreshTokens    *repository.RefreshTokenRepository
	clientRepository *repository.ClientRepository
	tokenService     *TokenService
	sessionService   *SessionService
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	users *repository.UserRepository,
	refreshTokens *repository.RefreshTokenRepository,
	clientRepository *repository.ClientRepository,
	tokenService *TokenService,
	sessions *SessionService,
) *AuthService {
	return &AuthService{
		users:            users,
		refreshTokens:    refreshTokens,
		clientRepository: clientRepository,
		tokenService:     tokenService,
		sessionService:   sessions,
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

// LoginResult is what a successful password login produces: a session, not tokens.
//
// Per the single-token-issuance design, /login never mints JWTs or refresh
// tokens. It only establishes a login session that GET /oauth/authorize can
// later consume to issue an authorization code. Tokens are minted solely at
// POST /oauth/token.
type LoginResult struct {
	SessionID string
	ExpiresAt time.Time
}

// Login verifies an email/password pair and, on success, creates a login session
// in Redis. The caller (HTTP handler) is responsible for putting SessionID into
// the session cookie.
func (s *AuthService) Login(ctx context.Context, loginRequest dtos.LoginRequest) (*LoginResult, error) {
	user, err := s.users.GetByEmail(ctx, loginRequest.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login: %w", err)
	}
	if user == nil {
		// Same error whether the email is unknown or the password is wrong —
		// don't leak which emails are registered.
		return nil, ErrEmailOrPasswordWrong
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(loginRequest.Password)); err != nil {
		return nil, ErrEmailOrPasswordWrong
	}

	sessionID, expiresAt, err := s.sessionService.Create(ctx, user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login creating session: %w", err)
	}

	return &LoginResult{SessionID: sessionID, ExpiresAt: expiresAt}, nil
}

// Logout destroys a login session. Safe to call with an unknown/empty ID.
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	return s.sessionService.Destroy(ctx, sessionID)
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

func (s *AuthService) Authorize(ctx context.Context, req *dtos.AuthorizeRequest) error {
	// Validate client exists.
	client, err := s.clientRepository.GetByID(ctx, req.ClientID)
	if err != nil {
		return fmt.Errorf("AuthService.Authorize: %w", err)
	}

	if client == nil {
		return fmt.Errorf("AuthService.Authorize: client not found %w", ClientNotFoundError)
	}

	// Validate redirect_uri — it must EXACTLY match one the client registered.
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return fmt.Errorf("AuthService.Authorize: %w", RedirectURIMismatchError)
	}

	// Validate scopes are with in what is allowed.
	
	//  Is the user already logged in? Check session cookie (session id from cookie but session data in Redis), if not send back to /login.

	// Generate authorization code and store in Redis.

	// Redirect back to the app with the code.

	return nil
}

// hashToken hashes a token using SHA256 for storage.
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", hash)
}
