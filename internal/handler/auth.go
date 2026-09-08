package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// SessionCookieName is the cookie that carries the opaque login session ID.
// Path=/ so GET /oauth/authorize (and future OAuth endpoints) can read it.
const SessionCookieName = "session_id"

// AuthHandler handles auth and OAuth client HTTP requests.
type AuthHandler struct {
	authService   *service.AuthService
	clientService *service.ClientService
	// secureCookies sets the Secure flag on the session cookie. Off for local
	// http development, on everywhere else.
	secureCookies bool
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(auth *service.AuthService, client *service.ClientService, secureCookies bool) *AuthHandler {
	return &AuthHandler{authService: auth, clientService: client, secureCookies: secureCookies}
}

// Login handles POST /login.
//
// It is called by the login *page* — which the SPA lands on after GET
// /oauth/authorize found no session — not by an API client directly. On success,
// it sets the session cookie and returns the internal path to continue to
// (normally back to /oauth/authorize). It never returns tokens; token issuance
// happens only at POST /oauth/token.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req dtos.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	// Where to send the browser after login — almost always back into the OAuth
	// flow. Validated to an internal path so ?next= can't become an open redirect.
	next := safeNext(r.URL.Query().Get("next"))

	result, err := h.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrEmailOrPasswordWrong) {
			writeError(w, http.StatusUnauthorized, "email or password wrong")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal server error")
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

	writeJSON(w, http.StatusOK, dtos.LoginResponse{
		Next:             next,
		SessionExpiresAt: result.ExpiresAt,
	})
}

// Logout handles POST /logout. Destroys the session server-side and clears the
// cookie. Always returns 204, even without a valid session.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookieName); err == nil {
		if err := h.authService.Logout(r.Context(), c.Value); err != nil {
			writeError(w, http.StatusInternalServerError, "internal server error")
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

// safeNext validates a post-login redirect target. To prevent an open redirect
// it accepts only a root-relative path to /oauth/authorize (query string kept);
// anything else — absolute URLs, protocol-relative "//host", other paths —
// falls back to "/".
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
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh token is required")
		return
	}

	refreshTokenResponse, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusOK, refreshTokenResponse)
}

// RegisterClient handles POST /admin/clients.
// The raw client_secret is returned exactly once in the response — it is never retrievable again.
func (h *AuthHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req dtos.RegisterClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeError(w, http.StatusBadRequest, "at least one redirect_uri is required")
		return
	}
	if len(req.GrantTypes) == 0 {
		writeError(w, http.StatusBadRequest, "at least one grant_type is required")
		return
	}

	resp, err := h.clientService.RegisterClient(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// Authorize - GET /oauth/authorize. This is where OAUTH flow begins. Anything involving user login + consent UI comes through here
// Has the following flows -
// Authorization Code Flow → /authorize authenticates user and returns an authorization code. For servers which can store client secret safely.
// ** Authorization Code + PKCE → Same as above, but includes PKCE challenge for added security. For use with SPA and Mobile APPs.
// Implicit Flow → /authorize directly returns access token in redirect (deprecated and not used).
// Client Credentials Flow → Directly hits /token, no user interaction. This is the Personal token flow like in Github.
// Supporting only Authorization Code + PKCE flow to begin with.
func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	var req dtos.AuthorizeRequest

	// This endpoint never issues tokens — it only issues a short-lived CODE which can be exchanged for tokens with /token endpoint later.
	// STEP 1 — Validate the client - look up client_id in the database
	// STEP 2 — Validate redirect_uri → must exactly match a URI registered by this client
	// STEP 3 — Validate scopes → requested scopes must be a subset of what the client is allowed
	//
	// STEP 4 — Store the PKCE challenge → save code_challenge + code_challenge_method in Redis against a session key
	//   → the verifier (the "key") arrives later at /token — never here
	//
	// STEP 5 — Check if user is already authenticated → look for a session cookie set by a previous login, if no redirect to /login. (SPA)
	// Ends here if no login found.

	// STEP 6 — Issue authorization code → generate a random opaque string (uuid) → store in Redis: { userID, clientID, scopes, challenge, redirect_uri }
	// STEP 8 — Redirect back to the client

	q := r.URL.Query()

	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	challengeMethod := q.Get("code_challenge_method")

	req.ClientID = clientID
	req.RedirectURI = redirectURI
	req.Scope = scope
	req.State = state
	req.CodeChallenge = challenge
	req.CodeChallengeMethod = challengeMethod

}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
