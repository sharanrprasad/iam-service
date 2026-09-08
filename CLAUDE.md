# iam-service

## Project Purpose

A custom OAuth 2.0 + RBAC identity service built from scratch in Go — **not** a product,
a learning project. The explicit goal is deep, job-relevant understanding of auth
internals, so **do not suggest replacing hand-rolled logic with high-level libraries**
(no Passport-style wrappers, no drop-in OAuth server frameworks). Prefer explaining
the mechanism over abstracting it away.

End goals this service is being built toward:
1. Own SPA logs in through it as a first-party OAuth client.
2. Third-party apps can request scoped access to a user's data, with user consent.
3. (Deferred, optional) Add an OIDC identity layer if "Sign in with [this app]" ever
   becomes a real requirement.

---

## Tech Stack

- **Language:** Go
- **DB:** MySQL (`database/sql` + `go-sql-driver/mysql`) — not Postgres
  - Use `?` placeholders, not `$1`
  - UUIDs generated in Go (`uuid.NewString()`), not in SQL
  - DSN must include `parseTime=true`
- **Cache/session store:** Redis
- **Router:** chi (or equivalent lightweight router)
- **JWT:** `golang-jwt/jwt/v5`, signed with **RS256** (asymmetric — never HS256)
- **Password hashing:** bcrypt

---

## Architecture

```
Frontend (SPA)  <---->  Auth Server (this repo)  <---->  Resource API
 first-party            owns login, sessions,            validates JWTs
 OAuth client            tokens, OAuth flows              via JWKS only
```

- The auth server is the **only** place that touches passwords or mints tokens.
- The frontend is a registered OAuth client like any third party (`client_id`,
  no client secret — it's a public client). It only skips the **consent screen**
  because it's flagged `is_first_party`, not the OAuth flow itself.

---

## Endpoints — Built

| Endpoint | Purpose |
|---|---|
| `POST /auth/register` | Create user, bcrypt-hash password |
| `POST /auth/login` | Verify credentials, create session (see constraint below) |
| `POST /auth/refresh` | Rotate access token via stored refresh token |
| `POST /auth/logout` | Revoke refresh token, clear cookies |

## Endpoints — Not Yet Built

| Endpoint | Purpose |
|---|---|
| `POST /admin/clients` | Register OAuth clients (client_id/secret, redirect_uris, scopes) |
| `GET /oauth/authorize` | Front door of OAuth — validates client, checks session, issues auth code |
| `POST /oauth/token` | Exchanges auth code (+ PKCE verifier) or refresh token for JWTs — **the only place tokens are minted** |
| `GET /.well-known/jwks.json` | Public key exposure for external JWT verification |
| Consent screen + storage | "App X wants to access: read:transactions" |
| Scope enforcement middleware | Distinct from RBAC — see constraints |
| RBAC middleware | Role → permission checks (Phase 2, designed not built) |

**Immediate next step:** OAuth client registry (schema + `POST /admin/clients`), since
`/oauth/authorize` and `/oauth/token` both depend on client lookup.

---

## Token Model

- **Access token:** RS256 JWT, 15 min TTL, stateless — verified by signature only,
  no DB hit. Custom claims (userID, email) are fine since this service is both
  issuer and sole verifier for now.
- **Refresh token:** opaque UUID (not a JWT), 7 day TTL, **hashed** in DB (revocable),
  sent as an **httpOnly cookie scoped to `/auth/refresh`** only.
- **Session cookie** (separate from refresh token): scoped to `Path=/`, lets
  `/oauth/authorize` recognize an already-logged-in user and skip the login page.
  Holds only a session ID — session data itself lives in Redis.

---

## Key Design Decisions (do not silently change these)

1. **Single token-issuance point.** `/auth/login` only authenticates and creates a
   session — it must **never** issue a JWT directly, even for the first-party SPA.
   `/oauth/token` is the sole place tokens are minted, for every client type.
2. **PKCE is mandatory** for the SPA's Authorization Code flow — no client secret
   for public clients, ever.
3. **Scopes ≠ Roles.** Roles (RBAC) = what a user can do system-wide. Scopes (OAuth)
   = what a specific token is allowed to do. A token's real permission is the
   intersection of both — scope is a ceiling on role, not a replacement for it.
4. **`?next=` redirect validation is required.** Any redirect target read from a
   query param (used to resume `/oauth/authorize` after login) must be restricted
   to internal paths — unvalidated redirects are an open-redirect vector.
5. **API keys vs. OAuth Client Credentials — undecided, don't assume.** For
   "let a user's own service call this API," plain long-lived API keys were judged
   the more conventional fit; OAuth Client Credentials only matters at larger scale.
   No implementation chosen yet either way.
6. **OIDC is explicitly deferred**, not rejected. Adding it later is expected to be
   a small lift (second JWT + `/userinfo` + discovery doc) on top of a correctly
   built OAuth layer — don't restructure OAuth code preemptively "for OIDC."

---

## Cross-Origin / Cookie Notes

- Same root domain (`app.x.com` / `api.x.com`): use `Domain=".x.com"` cookie +
  CORS with an exact allowed origin (never `*` with credentials) +
  `credentials: "include"` on the frontend.
- Fully different domains: prefer proxying through the frontend's own domain over
  dropping cookies for a bearer-session-ID pattern.
- Local dev: use a dev-server proxy (e.g. Vite) to avoid CORS entirely, or
  explicitly whitelist `localhost` behind an env flag.

---

## Explicitly Out of Scope For Now

- No production deployment concerns yet (this is a learning build).
- No frontend framework decisions made — backend-first.
- No OIDC implementation — see decision #6 above.
