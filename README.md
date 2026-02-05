![Logo](https://github.com/user-attachments/assets/3a9872cf-113e-4a0b-8be8-23f4f5b562e4)

# Gouserfy

Secure user management backend for Go applications.

## Quick Start

```bash
chmod +x setup.sh
./setup.sh
```

## Manual Setup

```bash
cp .env.example .env
# Edit .env with your settings

# Start PostgreSQL
docker run -d --name gouserfy-postgres \
  -e POSTGRES_USER=gouserfy \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=gouserfy \
  -p 5432:5432 postgres:18-alpine

# Run migrations
go install github.com/pressly/goose/v3/cmd/goose@latest
goose -dir migrations postgres "postgres://gouserfy:secret@localhost:5432/gouserfy?sslmode=disable" up

# Start server
go run cmd/gouserfy/main.go
```

## Docker

```bash
docker-compose up -d
```

## API Endpoints

### Auth

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/login/2fa` | Complete 2FA login |
| POST | `/api/v1/auth/refresh` | Refresh tokens |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/logout/all` | Logout all sessions |
| POST | `/api/v1/auth/verify-email` | Verify email |
| POST | `/api/v1/auth/forgot-password` | Request password reset |
| POST | `/api/v1/auth/reset-password` | Reset password |
| POST | `/api/v1/auth/change-password` | Change password |
| POST | `/api/v1/auth/2fa/enable` | Enable 2FA |
| POST | `/api/v1/auth/2fa/confirm` | Confirm 2FA setup |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA |

### Users (Authenticated)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me` | Get current user |
| GET | `/api/v1/users/{id}` | Get user by ID |
| DELETE | `/api/v1/users/me` | Delete account |
| GET | `/api/v1/users/me/profile` | Get profile |
| PUT | `/api/v1/users/me/profile` | Update profile |
| GET | `/api/v1/users/me/preferences` | Get preferences |
| PUT | `/api/v1/users/me/preferences` | Update preferences |
| GET | `/api/v1/users/me/roles` | Get roles |
| PUT | `/api/v1/users/me/username` | Update username |

## Request/Response Examples

### Register

```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

### Login

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}'
```

Response:
```json
{
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "abc123...",
    "expires_at": "2026-02-05T12:30:00Z"
  },
  "user": {
    "id": "019...",
    "email": "user@example.com",
    "status": "active"
  }
}
```

### Authenticated Request

```bash
curl http://localhost:8080/api/v1/users/me \
  -H "Authorization: Bearer eyJhbG..."
```

## Configuration

All configuration via environment variables. See `.env.example`.

### Required

- `JWT_SECRET` - JWT signing key (min 32 chars)

### Database

- `DB_HOST` - PostgreSQL host
- `DB_PORT` - PostgreSQL port
- `DB_USER` - Database user
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name

### OAuth (Optional)

Set `OAUTH_ENABLED=true` and configure providers:

```env
OAUTH_GOOGLE_ENABLED=true
OAUTH_GOOGLE_CLIENT_ID=xxx
OAUTH_GOOGLE_CLIENT_SECRET=xxx
```

## Security Features

- Argon2id password hashing
- JWT with short expiry + refresh tokens
- Rate limiting
- Account lockout after failed attempts
- 2FA with TOTP
- Token revocation
- Soft delete

## Database Schema

Uses PostgreSQL 18 with native UUIDv7 support.

Tables:
- `users` - Core user data
- `user_auth` - Authentication data
- `user_oauth` - OAuth providers
- `user_profiles` - Profile data
- `user_preferences` - User settings
- `user_verification` - Email/phone verification
- `user_tokens` - Temporary tokens
- `roles` - Role definitions
- `user_roles` - User-role assignments
- `refresh_tokens` - Active sessions

## Project Structure

```
gouserfy/
├── cmd/gouserfy/     # Entry point
├── config/           # Configuration
├── database/         # DB connection & repository
├── handlers/         # HTTP handlers
├── migrations/       # SQL migrations
├── models/           # Data models
├── server/           # HTTP server
├── services/         # Business logic
├── setup.sh          # Interactive setup
├── docker-compose.yml
└── Dockerfile
```

## License

MIT
