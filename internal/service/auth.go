package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/models"
	"github.com/sharanrprasad/iam-service/internal/repository"
	"github.com/sharanrprasad/iam-service/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

// ErrEmailTaken is returned when the email address is already registered.
var ErrEmailTaken = errors.New("email already in use")
var ErrEmailOrPasswordWrong = errors.New("email or password wrong")

// AuthorizeInput is everything AuthService.Authorize needs from the transport.
type AuthorizeInput struct {
	Request   dtos.AuthorizeRequest
	SessionID string // raw session-cookie value; "" when absent
}

// AuthorizeResult is the decision the handler must carry out. Only the fields
// relevant to Action are populated.
type AuthorizeResult struct {
	Action AuthorizeAction

	RedirectURI string // ActionIssueCode, ActionErrorToClient
	State       string // ActionIssueCode, ActionErrorToClient
	Code        string // ActionIssueCode
	OAuthError  string // ActionErrorToClient, e.g. "invalid_scope"
	Message     string // ActionRejectDirect
}

// RegisterInput is the data required to register a new user.
type RegisterInput struct {
	Email    string
	Password string
}

// AuthorizeAction tells the /oauth/authorize handler which HTTP response to
// produce. Every expected branch of the protocol is one of these; the error
// return of Authorize is reserved for infrastructure failures (DB, cache).
type AuthorizeAction string

const (
	// ActionIssueCode — request valid and user authenticated: 302 to
	// RedirectURI with ?code=Code&state=State.
	ActionIssueCode AuthorizeAction = "issue_code"
	// ActionRequireLogin — request valid but no login session: send the user
	// to the login page, then back to /oauth/authorize.
	ActionRequireLogin AuthorizeAction = "require_login"
	// ActionErrorToClient — client_id and redirect_uri are trusted but another
	// parameter is bad: 302 to RedirectURI with ?error=OAuthError&state=State.
	ActionErrorToClient AuthorizeAction = "error_to_client"
	// ActionRejectDirect — client_id or redirect_uri itself is untrusted: show
	// Message directly with a 400, never redirect.
	ActionRejectDirect AuthorizeAction = "reject_direct"
)

// AuthService handles authentication business logic. Its collaborators are the
// interfaces in ports.go.
type AuthService struct {
	users              userRepo
	refreshTokens      refreshTokenRepo
	clientRepository   clientRepo
	tokenService       tokenIssuer
	sessionRepository  sessionRepo
	authCodeRepository authCodeRepo
}

// NewAuthService creates a new AuthService.
func NewAuthService(
	users userRepo,
	refreshTokens refreshTokenRepo,
	clientRepository clientRepo,
	tokenService tokenIssuer,
	sessions sessionRepo,
	authCodes authCodeRepo,
) *AuthService {
	return &AuthService{
		users:              users,
		refreshTokens:      refreshTokens,
		clientRepository:   clientRepository,
		tokenService:       tokenService,
		sessionRepository:  sessions,
		authCodeRepository: authCodes,
	}
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

// LoginResult is what a password login produces: a session, never tokens. Tokens
// are minted only at POST /oauth/token (single token-issuance point).
type LoginResult struct {
	SessionID string
	ExpiresAt time.Time
}

// Login verifies an email/password pair and creates a Redis-backed login
// session. The handler puts SessionID into the cookie.
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

	sessionID, expiresAt, err := s.sessionRepository.Create(ctx, user.ID, user.Email)
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
	return s.sessionRepository.Destroy(ctx, sessionID)
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

	accessToken, err := s.tokenService.IssueAccessToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("AuthService.Login issuing access token: %w", err)
	}

	return &dtos.RefreshResponse{
		AccessToken:         accessToken.AccessTokenString,
		AccessTokenExpiryIn: accessToken.AccessTokenExpiresIn,
	}, nil

}

// Authorize runs the /oauth/authorize checks in order — client, redirect_uri,
// scope, session — and returns the action the handler should take. It returns a
// non-nil error only for infrastructure failures; every protocol outcome is an
// AuthorizeResult.
func (s *AuthService) Authorize(ctx context.Context, in AuthorizeInput) (AuthorizeResult, error) {
	req := in.Request

	client, err := s.clientRepository.GetByID(ctx, req.ClientID)
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("AuthService.Authorize: %w", err)
	}
	if client == nil {
		return AuthorizeResult{Action: ActionRejectDirect, Message: "unknown client_id"}, nil
	}

	// redirect_uri must EXACTLY match one the client registered.
	if !slices.Contains(client.RedirectURIs, req.RedirectURI) {
		return AuthorizeResult{Action: ActionRejectDirect, Message: "redirect_uri is not registered for this client"}, nil
	}

	// scope: SPACE-delimited
	requested := strings.Fields(req.Scope)
	if len(requested) == 0 || !utils.ContainsAll(client.Scopes, requested) {
		return errorToClient(req, "invalid_scope"), nil
	}

	// prompt is space-delimited (OIDC). "none" must appear alone; it means
	// "don't show a login screen" — a silent auth attempt.
	prompts := strings.Fields(req.Prompt)
	promptNone := slices.Contains(prompts, "none")
	if promptNone && len(prompts) > 1 {
		return errorToClient(req, "invalid_request"), nil
	}

	// Require a live login session; otherwise send the user to /login.
	session, err := s.SessionByID(ctx, in.SessionID)
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("AuthService.Authorize: %w", err)
	}
	if session == nil {
		if promptNone {
			// Silent request, nobody logged in — hand it back, don't show login.
			return errorToClient(req, "login_required"), nil
		}
		return AuthorizeResult{Action: ActionRequireLogin}, nil
	}

	// Consent check would go here (prompt=consent) — not supported yet.

	// Mint the single-use code; redeemed with the PKCE verifier at /oauth/token.
	code, err := s.authCodeRepository.Create(ctx, models.AuthCode{
		ClientID:            client.ID,
		UserID:              session.UserID,
		RedirectURI:         req.RedirectURI,
		Scope:               requested,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
	})
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("AuthService.Authorize: %w", err)
	}

	return AuthorizeResult{
		Action:      ActionIssueCode,
		RedirectURI: req.RedirectURI,
		State:       req.State,
		Code:        code,
	}, nil
}

// errorToClient builds an ActionErrorToClient result — an OAuth error sent back
// to a redirect_uri that has already been validated against the registry.
func errorToClient(req dtos.AuthorizeRequest, oauthError string) AuthorizeResult {
	return AuthorizeResult{
		Action:      ActionErrorToClient,
		RedirectURI: req.RedirectURI,
		State:       req.State,
		OAuthError:  oauthError,
	}
}

// SessionByID resolves a session cookie value to its session, returning
// (nil, nil) when the id is empty or has no live session behind it — the caller
// treats that as "not logged in".
func (s *AuthService) SessionByID(ctx context.Context, sessionID string) (*models.Session, error) {
	if sessionID == "" {
		return nil, nil
	}
	sess, err := s.sessionRepository.Get(ctx, sessionID)
	if errors.Is(err, repository.ErrSessionNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("AuthService.SessionByID: %w", err)
	}
	return sess, nil
}

// The POST /oauth/token grant flows moved to TokenGrantService (token_grant.go).
