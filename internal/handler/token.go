package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/httpx"
	"github.com/sharanrprasad/iam-service/internal/service"
)

// Token handles POST /oauth/token — the API that creates access and refresh tokens.
// It is called by the client's own code (never a browser), takes an application/x-www-form-urlencoded body, and always answers with JSON plus the
// no-store caching headers (RFC 6749 §5.1/§5.2). It never redirects.
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Body only, not the query string.
	tokenRequestDto := dtos.ParseTokenRequest(r.PostForm)

	// Client auth: credentials from the Basic header or the body, whichever was used.
	id, secret, oauthErr := resolveClient(r, tokenRequestDto)
	if oauthErr != "" {
		status := http.StatusBadRequest
		if oauthErr == "invalid_client" {
			status = http.StatusUnauthorized
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		}
		writeTokenError(w, status, oauthErr, "")
		return
	}
	tokenRequestDto.ClientID, tokenRequestDto.ClientSecret = id, secret

	if errs := tokenRequestDto.Validate(); errs != nil {
		log.Printf("invalid request for token endpoint %v\n", errs)
		noStore(w)
		writeValidationError(w, errs)
		return
	}

	// Supports different grant types.
	resp, err := h.tokenGrant.Exchange(r.Context(), tokenRequestDto)
	if err != nil {
		writeTokenExchangeError(w, err)
		return
	}
	noStore(w)
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// writeTokenExchangeError maps a TokenGrantService error to the RFC 6749 §5.2
// JSON error body and status.
func writeTokenExchangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrUnsupportedGrantType):
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
	case errors.Is(err, service.ErrInvalidClient):
		w.Header().Set("WWW-Authenticate", `Basic realm="oauth2"`)
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "")
	case errors.Is(err, service.ErrUnauthorizedClient):
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "")
	case errors.Is(err, service.ErrInvalidScope):
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "")
	case errors.Is(err, service.ErrInvalidGrant):
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "")
	default:
		// Unknown / not-yet-implemented — don't leak internals.
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "the authorization grant is invalid")
	}
}

// writeTokenError writes an RFC 6749 §5.2 error body with the no-store headers.
// status is 400 for most codes, 401 for invalid_client.
func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	noStore(w)
	httpx.WriteJSON(w, status, dtos.TokenErrorResponse{
		Error:            code,
		ErrorDescription: description,
	})
}

// noStore sets the caching headers RFC 6749 §5.1 requires on every /oauth/token
// response, success or error.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// resolveClient reads the client's credentials from an /oauth/token request and
// returns them along with an OAuth error code, "" on success:
//
//   - "invalid_request" — credentials supplied in BOTH the Authorization header and the body
//   - "invalid_client"  — no client_id anywhere, or a malformed Authorization header
//
// A client authenticates in exactly one place: an Authorization: Basic header
// (client_secret_basic) or the body's client_id/client_secret
// (client_secret_post). Public clients (SPAs) send only a client_id and prove
// themselves with PKCE, so an empty secret is valid.
func resolveClient(r *http.Request, req dtos.TokenRequest) (id, secret, oauthErr string) {
	basicID, basicSecret, okBasic := r.BasicAuth()
	hasAuthHeader := r.Header.Get("Authorization") != ""
	hasBody := req.ClientID != "" || req.ClientSecret != ""

	switch {
	case hasAuthHeader && !okBasic:
		return "", "", "invalid_client" // header present but not valid Basic
	case okBasic && hasBody:
		return "", "", "invalid_request" // two auth methods at once
	case okBasic:
		return basicID, basicSecret, ""
	case req.ClientID != "":
		return req.ClientID, req.ClientSecret, "" // came in on the body
	default:
		return "", "", "invalid_client" // no client_id at all
	}
}
