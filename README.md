# auth-service

Issues RS256 JWTs for the platform. Other services verify locally via the JWKS endpoint.

## Endpoints
- `POST /register` — `{email, password, display_name}` → `201 {user_id}`
- `POST /login` — `{email, password}` → `200 {access_token, token_type, expires_in}`
- `GET /validate` — Bearer JWT → `200 {user_id, email}`
- `GET /.well-known/jwks.json` — RS256 public key (JWKS)
- `GET /health/live`, `GET /health/ready`

## Local dev

```bash
# 1. generate an RS256 keypair (one-time)
mkdir -p keys
openssl genrsa -out keys/jwt_private.pem 2048
openssl rsa -in keys/jwt_private.pem -pubout -out keys/jwt_public.pem

# 2. copy env
cp .env.example .env

# 3. start postgres + service
docker-compose up --build

# 4. run migrations (in another shell)
docker-compose exec api alembic upgrade head
```

## Tests

```bash
poetry install
poetry run pytest
```
