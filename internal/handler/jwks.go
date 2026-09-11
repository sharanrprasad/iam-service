package handler

import (
	"net/http"

	"github.com/sharanrprasad/iam-service/internal/httpx"
)

// JWKS handles GET /.well-known/jwks.json — exposes the RSA public key(s) used
// to verify RS256 access tokens (RFC 7517). Public, unauthenticated, and
// cacheable: this is what lets a gateway or resource API verify JWT signatures
// locally instead of calling this service on every request.
func (h *AuthHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	httpx.WriteJSON(w, http.StatusOK, h.tokenService.JWKS())
}
