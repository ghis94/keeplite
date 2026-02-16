# KeepLite V2 (Secure-by-default)

KeepLite V2 is a multi-tenant notes app with authentication, RBAC, secure session handling, and import/export adapters.

## Security Model

### Authentication & Session Security
- Register/login with bcrypt password hashing (`bcryptjs`, cost configurable)
- JWT access tokens (short-lived)
- JWT refresh tokens (long-lived) with rotation and revocation persisted in SQLite `sessions`
- Refresh token delivered via `httpOnly` cookie by default
- Authorization header fallback is supported (`Bearer` access token + body refresh token)
- Logout revokes active refresh sessions

### Authorization
- RBAC roles: `user`, `admin`
- First registered account is promoted to `admin`, later accounts default to `user`
- Notes are strictly user-scoped (`notes.user_id` + ownership checks on every note route)
- Admin-only endpoint example: `GET /admin/users`

### Hardening Controls
- `helmet` for secure HTTP headers
- CORS allowlist (`CLIENT_ORIGIN`)
- Global + auth-specific rate limiting
- Strict payload limit for JSON bodies
- Input validation via `zod`
- Parameterized SQL queries everywhere (`?` placeholders)
- Centralized error handling with non-sensitive responses
- Audit logging for auth success/failure/logout/refresh/register events

## Threat Assumptions
- Designed for trusted deployment under HTTPS in production
- Protects against accidental multi-tenant data leakage via route-level ownership checks
- Reduces brute-force and token replay risk via rate limiting + refresh token rotation
- Does **not** include full SOC-grade controls (WAF, SIEM integration, anomaly ML, MFA, email verification)

## Stack
- Backend: Node.js + Express + SQLite
- Frontend: React + Vite
- Docker Compose for local/prod-like deployment

## Environment
Copy and edit:

```bash
cp .env.example .env
```

Important variables:
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET` (required strong secrets in production)
- `CLIENT_ORIGIN` (comma-separated CORS allowlist)
- `COOKIE_SECURE=true` under HTTPS

## Run with Docker

```bash
docker compose up --build
```

Endpoints:
- Frontend: `http://localhost:5173`
- Backend: `http://localhost:4000`
- Health: `http://localhost:4000/health`

## Dev (without Docker)

### Backend
```bash
cd backend
npm install
npm run dev
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

## API Overview

### Auth
- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`

### Notes (authenticated)
- `GET /notes?archived=true|false&q=term`
- `GET /notes/:id`
- `POST /notes`
- `PUT /notes/:id`
- `DELETE /notes/:id`

### Admin
- `GET /admin/users`

### Import/Export (authenticated, per user)
- `GET /export/json`
- `POST /import/json`
- `GET /export/markdown` (markdown-folder adapter / Nextcloud-friendly)
- `POST /import/markdown`
- `POST /import/keep` (minimal Keep JSON mapping)

## DB Schema / Migration
On startup, backend runs SQLite migrations and creates:
- `schema_migrations`
- `users`
- `sessions`
- `notes`
- `audit_logs`

Indexes are included for sessions and per-user note lookups.

## Tests / Lint / Build

Backend:
```bash
cd backend
npm run lint
npm test
```

Frontend:
```bash
cd frontend
npm run build
```

## Next Hardening Steps
- Move from bcrypt to `argon2id`
- Add CSRF protection strategy when using cookie auth in browsers
- Add MFA + verified email flows
- Add structured audit log shipping and alerting
- Add encryption-at-rest and secret manager integration
- Expand integration tests for refresh token replay + race conditions
