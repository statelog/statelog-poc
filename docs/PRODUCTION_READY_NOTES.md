# Production-ready notes for vol.12

Changes added in vol.12:

- Production startup now fails fast if weak/default secrets are used.
- Production startup now fails if the database URL still uses the default `postgres:postgres` password.
- `/metrics` now requires `X-Metrics-API-Key` in production.
- FastAPI Swagger/ReDoc/OpenAPI public endpoints are disabled in production.
- Security headers are added to all responses.
- `docker-compose.prod.yml` reads Postgres credentials from `.env` instead of hardcoding them.
- `env.production.example` shows the required production variables.
- `scripts/generate_production_secrets.py` generates safe random values for `.env`.

Recommended deploy steps:

```bash
cp env.production.example .env
python scripts/generate_production_secrets.py
# paste generated values into .env and make DATABASE_URL use the same Postgres password

docker compose -f docker-compose.prod.yml --env-file .env up --build -d
curl http://localhost:8000/readyz
```

For production, put Caddy, Nginx, Cloudflare Tunnel, or another HTTPS reverse proxy in front of the app.
