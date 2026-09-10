package handler

import (
	"log"
	"net/http"

	"github.com/sharanrprasad/iam-service/internal/dtos"
	"github.com/sharanrprasad/iam-service/internal/httpx"
)

// Token handles POST /oauth/token — the back-channel exchange that mints tokens.
// It is called by the client's own code (never a browser), takes an
// application/x-www-form-urlencoded body, and always answers with JSON plus the
// no-store caching headers (RFC 6749 §5.1/§5.2). It never redirects.
func (h *AuthHandler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	// Token parameters must be in the body, not the query string.
	tokenRequestDto := dtos.ParseTokenRequest(r.PostForm)

	// Client authentication: credentials may arrive in the Authorization: Basic header or the body. resolveClient reads whichever was used; the handler writes the result onto req.
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

	// Validate the request
	if errs := tokenRequestDto.Validate(); errs != nil {
		log.Printf("invalid request for token endpoint %v\n", errs)
		noStore(w)
		writeValidationError(w, errs) // 400, error=invalid_request, with per-field detail
		return
	}

	switch tokenRequestDto.GrantType {
	case "authorization_code":
		resp, err := h.authService.TokenAuthorizationFlow(r.Context(), tokenRequestDto)
		if err != nil {
			// TODO: once TokenAuth returns typed errors (invalid_grant,
			// invalid_client, unauthorized_client, ...), errors.Is() each and map
			// it to the right RFC 6749 §5.2 code + status. Until then, invalid_grant.
			writeTokenError(w, http.StatusBadRequest, "invalid_grant",
				"the authorization code is invalid, expired, or already used")
			return
		}
		noStore(w)
		httpx.WriteJSON(w, http.StatusOK, resp)

	// TODO: case "refresh_token": exchange a refresh token for a fresh access token.

	default:
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "")
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
//
// It only reads the request — the caller decides what to do with id/secret. It
// does not check that the client exists or that the secret is correct; that is a
// registry lookup the service performs.
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
