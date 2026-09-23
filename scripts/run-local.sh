#!/usr/bin/env bash
# Run dauth locally against a Postgres challenge store.
#
# On first run it generates throwaway RSA signing keys under .local/, brings up
# Postgres via docker compose (host port 5433), and runs cmd/dauth with local
# env. Sign-in needs a running DID directory (DIRECTORY_URL) and the exchange a
# running org host (ORG_HOST_URL); both default to the did-directory repo's
# local ports. The org host must list DAUTH_DID in its ISSUER_DIDS and read
# this dauth's keys from http://localhost:8080/signin/keys.
set -euo pipefail
cd "$(dirname "$0")/.."

keys_dir=.local
mkdir -p "$keys_dir"
for name in signin exchange; do
  if [[ ! -f "$keys_dir/$name.pem" ]]; then
    echo "→ generating $keys_dir/$name.pem"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keys_dir/$name.pem" 2>/dev/null
  fi
done

echo "→ starting Postgres (docker compose)…"
docker compose up -d --wait db

export ENVIRONMENT=local LOG_LEVEL=debug
export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-http://localhost:8080}"
export DIRECTORY_URL="${DIRECTORY_URL:-http://localhost:8082}"
export SIGNIN_ISSUER="${SIGNIN_ISSUER:-http://localhost:8080/signin}"
export JWT_AUDIENCE="${JWT_AUDIENCE:-dimo}"
export SIGNIN_SIGNING_KEY_1="$(cat "$keys_dir/signin.pem")"
export EXCHANGE_ISSUER="${EXCHANGE_ISSUER:-http://localhost:8080/exchange}"
export EXCHANGE_SIGNING_KEY_1="$(cat "$keys_dir/exchange.pem")"
export ORG_HOST_URL="${ORG_HOST_URL:-http://localhost:8081}"
export DAUTH_DID="${DAUTH_DID:-did:dimo:dauth}"

# Postgres challenge store — matches docker-compose.yml (host port 5433).
export DATABASE_URL="${DATABASE_URL:-postgres://dauth:dauth@localhost:5433/dauth?sslmode=disable}"

echo "→ dauth: http://localhost:8080  (ops :8089)"
echo "  sign in with: dimocli signin --did <did> --dauth http://localhost:8080"
export OPS_ADDRESS="${OPS_ADDRESS:-0.0.0.0:8089}"
exec go run ./cmd/dauth
