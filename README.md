# Zero-Trust API Gateway

A zero-trust API gateway built in Go that enforces layered security: request validation, API key authentication, RBAC, policy evaluation, rate limiting, and audit logging before proxying to upstream services.

## Prerequisites

- Go 1.21+

## Quick Start

### 1. Start the upstream backend

The gateway proxies to `http://localhost:9000`. Start a simple backend:

```powershell
# Option A: Use the included demo upstream (recommended)
go run ./cmd/upstream/main.go
```

Or use any HTTP server on port 9000, e.g. Python:

```powershell
python -m http.server 9000
```

### 2. Start the gateway

**Important:** Run from the project root so `./policies/policies.yaml` and `./audit.log` resolve correctly.

```powershell
go run ./backend/cmd/gateway/main.go
```

You should see: `Zero-Trust API Gateway listening on :8080`

## Demo API Keys

| Key ID     | Roles  | API Key | Use Case                  |
|------------|--------|---------|---------------------------|
| demo-admin | admin  | `deef0admin0000000000000000000000000000000000000000000000000000` | POST/DELETE /api/admin |
| demo-user  | user   | `deef0us3r0000000000000000000000000000000000000000000000000000` | GET /api/public        |

## Demo Commands

### Health check (no auth required)

```powershell
curl -H "User-Agent: curl" http://localhost:8080/health
```

### GET /api/public (requires user or admin role)

```powershell
curl -H "User-Agent: curl" -H "X-API-Key: deef0us3r0000000000000000000000000000000000000000000000000000" http://localhost:8080/api/public
```

### POST /api/admin (requires admin role)

```powershell
curl -H "User-Agent: curl" -H "X-API-Key: deef0admin0000000000000000000000000000000000000000000000000000" -X POST -H "Content-Type: application/json" -d "{\"test\": true}" http://localhost:8080/api/admin
```

### DELETE /api/admin (requires admin role)

```powershell
curl -H "User-Agent: curl" -H "X-API-Key: deef0admin0000000000000000000000000000000000000000000000000000" -X DELETE http://localhost:8080/api/admin
```

### Security demo: requests that get blocked

**Missing API key (401 Unauthorized):**
```powershell
curl -H "User-Agent: curl" http://localhost:8080/api/public
```

**Wrong role (403 Forbidden) — user key cannot access admin:**
```powershell
curl -H "User-Agent: curl" -H "X-API-Key: deef0us3r0000000000000000000000000000000000000000000000000000" -X POST -H "Content-Type: application/json" -d "{}" http://localhost:8080/api/admin
```

**Invalid API key (401 Unauthorized):**
```powershell
curl -H "User-Agent: curl" -H "X-API-Key: invalid-key" http://localhost:8080/api/public
```

## Generate custom API keys

To generate new test keys (you must add them to the store to use them):

```powershell
go run ./cmd/generate-testkey/main.go
```

## Policy configuration

Policies are defined in `policies/policies.yaml` and hot-reloaded every 3 seconds:

| Method | Path        | Allowed roles |
|--------|-------------|---------------|
| GET    | /api/public | user, admin   |
| POST   | /api/admin  | admin         |
| DELETE | /api/admin  | admin         |

`/health` is always public (no auth required).

## Dashboard

A read-only dashboard is available at `http://localhost:8080/dashboard`. It displays:

- **Request statistics** — allowed vs denied counts, uptime
- **Recent audit log** — last 50 entries with timestamp, method, path, decision
- **Active policies** — current RBAC rules

The dashboard refreshes every 3 seconds. No authentication required (read-only).

## Project structure

```
backend/cmd/gateway/   Gateway entry point
cmd/generate-testkey/ API key generator
cmd/upstream/          Demo upstream server
internal/
  auth/                API key and JWT auth
  dashboard/           Stats collector and dashboard API
  middleware/          Request validation
  policy/              YAML policy engine
  rbac/                Role-based access control
  ratelimit/           Token bucket rate limiting
  audit/               Tamper-evident audit logging
policies/              Policy definitions
```
