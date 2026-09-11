package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/httpx"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// SessionCookieName is the cookie that carries the opaque login session ID.
// Path=/ so GET /oauth/authorize (and future OAuth endpoints) can read it.
const SessionCookieName = "session_id"

// AuthHandler handles auth and OAuth client HTTP requests. Its collaborators are
// the interfaces in ports.go.
type AuthHandler struct {
	authService   authService
	clientService clientService
	tokenGrant    tokenGrantService
	tokenService  tokenService
	// secureCookies sets the Secure flag on the session cookie. Off for local
	// http development, on everywhere else.
	secureCookies bool
	// loginURL is where /oauth/authorize sends an unauthenticated user. Usually
	// the SPA's login route; it receives ?next= to return here after login.
	loginURL string
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(auth authService, client clientService, tokenGrant tokenGrantService, token tokenService, secureCookies bool, loginURL string) *AuthHandler {
	return &AuthHandler{
		authService:   auth,
		clientService: client,
		tokenGrant:    tokenGrant,
		tokenService:  token,
		secureCookies: secureCookies,
		loginURL:      loginURL,
	}
}

// Login handles POST /login: verify credentials, set the session cookie, return
// the path to resume (normally /oauth/authorize). It never returns tokens —
// those are minted only at POST /oauth/token.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dtos.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		httpx.WriteError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Post-login redirect target, validated to an internal path (open-redirect guard).
	next := safeNext(r.URL.Query().Get("next"))

	result, err := h.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrEmailOrPasswordWrong) {
			httpx.WriteError(w, http.StatusUnauthorized, "email or password wrong")
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    result.SessionID,
		Path:     "/",
		Expires:  result.ExpiresAt,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	httpx.WriteJSON(w, http.StatusOK, dtos.LoginResponse{
		Next:             next,
		SessionExpiresAt: result.ExpiresAt,
	})
}

// Logout handles POST /logout. Destroys the session server-side and clears the
// cookie. Always returns 204, even without a valid session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		if err := h.authService.Logout(r.Context(), c.Value); err != nil {
			httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
			return
		}
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})

	w.WriteHeader(http.StatusNoContent)
}

// safeNext validates a post-login redirect target: only a root-relative path to
// /oauth/authorize is allowed (open-redirect guard); anything else becomes "/".
func safeNext(next string) string {
	if next == "" {
		return "/"
	}
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	if u.Path != "/oauth/authorize" {
		return "/"
	}
	return u.String()
}

// Refresh handles POST /refresh.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req dtos.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		httpx.WriteError(w, http.StatusBadRequest, "refresh token is required")
		return
	}

	refreshTokenResponse, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	httpx.WriteJSON(w, http.StatusOK, refreshTokenResponse)
}

// RegisterClient handles POST /admin/clients.
// The raw client_secret is returned exactly once in the response — it is never retrievable again.
func (h *AuthHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req dtos.RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		httpx.WriteError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.RedirectURIs) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one redirect_uri is required")
		return
	}
	if len(req.GrantTypes) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "at least one grant_type is required")
		return
	}

	resp, err := h.clientService.RegisterClient(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrUnsupportedGrantType) || errors.Is(err, service.ErrPublicClientCredentialsGrant) {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	httpx.WriteJSON(w, http.StatusCreated, resp)
}

// Authorize handles GET /oauth/authorize — the front door of the OAuth flow. It
// validates the request, checks for a login session, and either issues a
// short-lived authorization code (redeemed at /oauth/token) or redirects to
// login. Authorization Code + PKCE only.
func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	// Parameters arrive on the query string (RFC 6749 §3.1 — GET only here).
	req := dtos.ParseAuthorizeRequest(r.URL.Query())

	if errs := req.Validate(); errs != nil {
		writeValidationError(w, errs)
		return
	}

	res, err := h.authService.Authorize(r.Context(), service.AuthorizeInput{
		Request:   req,
		SessionID: httpx.CookieValue(r, SessionCookieName),
	})
	if err != nil {
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	switch res.Action {
	case service.ActionIssueCode:
		httpx.RedirectWith(w, r, res.RedirectURI, "code", res.Code, "state", res.State)
	case service.ActionRequireLogin:
		httpx.RedirectWith(w, r, h.loginURL, "next", r.URL.RequestURI())
	case service.ActionErrorToClient:
		httpx.RedirectWith(w, r, res.RedirectURI, "error", res.OAuthError, "state", res.State)
	case service.ActionRejectDirect:
		httpx.WriteError(w, http.StatusBadRequest, res.Message)
	default:
		httpx.WriteError(w, http.StatusInternalServerError, "internal server error")
	}
}

// writeValidationError reports field-level validation failures as a 400 using
// OAuth's invalid_request error code, with a "fields" map for the caller to fix.
func writeValidationError(w http.ResponseWriter, fields map[string]string) {
	httpx.WriteJSON(w, http.StatusBadRequest, map[string]any{
		"error":             "invalid_request",
		"error_description": "one or more parameters failed validation",
		"fields":            fields,
	})
}
