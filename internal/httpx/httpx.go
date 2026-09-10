// Package httpx holds small, handler-agnostic helpers for reading HTTP requests
// and writing HTTP responses. Nothing here knows about the domain.
package httpx

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// WriteJSON writes v as a JSON body with the given status code.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError writes {"error": msg} with the given status code.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"error": msg})
}

// CookieValue returns the named cookie's value, or "" when it is not set.
func CookieValue(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

// RedirectWith sends a 302 to base with the given key/value pairs merged into
// its query string (base may already carry one). Pairs whose value is "" are
// skipped. On a malformed base it writes a 500.
func RedirectWith(w http.ResponseWriter, r *http.Request, base string, kv ...string) {
	u, err := url.Parse(base)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
