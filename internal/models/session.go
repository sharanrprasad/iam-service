package models

import "time"

// Session represents a browser login session for a user.
//
// Sessions live in Redis (not MySQL), keyed by an opaque session ID. The ID
// travels in an httpOnly cookie and lets GET /oauth/authorize skip the login
// page on repeat visits. A session is NOT an access token — it grants no API
// access on its own; it only proves "this browser has authenticated as this
// user" to the OAuth authorize endpoint.
type Session struct {
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}
