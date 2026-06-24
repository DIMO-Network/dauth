#!/usr/bin/env bash
# Run the merged dauth binary locally against a Postgres challenge store.
#
# On first run it generates throwaway RSA signing keys under .local/, brings up
# Postgres via docker compose (host port 5433), and runs cmd/dauth with sane
# local env. The /siwe sign-in flow works fully offline — drive it from another
# shell with `make signin` (scripts/signin.sh). The /permissions exchange boots
# but needs real identity-api / RPC / IPFS backends to complete an actual
# exchange; point BLOCKCHAIN_NODE_URL / IDENTITY_URL / IPFS_BASE_URL at them.
set -euo pipefail
cd "$(dirname "$0")/.."

keys_dir=.local
mkdir -p "$keys_dir"
for name in siwe permissions; do
  if [[ ! -f "$keys_dir/$name.pem" ]]; then
    echo "→ generating $keys_dir/$name.pem"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keys_dir/$name.pem" 2>/dev/null
  fi
done

echo "→ starting Postgres (docker compose)…"
docker compose up -d --wait db

export ENVIRONMENT=local LOG_LEVEL=debug
export PUBLIC_BASE_URL=http://localhost:8080
export SIWE_ISSUER=https://auth.local.dimo.zone
export JWT_AUDIENCE=dimo
export SIWE_SIGNING_KEY_1="$(cat "$keys_dir/siwe.pem")"
export PERMISSIONS_ISSUER=https://auth-roles-rights.local.dimo.zone
export PERMISSIONS_SIGNING_KEY_1="$(cat "$keys_dir/permissions.pem")"

# Backend dependencies of the /permissions exchange. The defaults are
# placeholders so the process boots; override to exercise a real exchange.
export BLOCKCHAIN_NODE_URL="${BLOCKCHAIN_NODE_URL:-http://localhost:8545}"
export IDENTITY_URL="${IDENTITY_URL:-http://localhost:3001/query}"
export IPFS_BASE_URL="${IPFS_BASE_URL:-http://localhost:3002}"

# Postgres challenge store — matches docker-compose.yml.
export DB_HOST=localhost DB_PORT="${DB_PORT:-5433}" DB_USER=dauth DB_PASSWORD=dauth DB_NAME=dauth DB_SSL_MODE=disable

echo "→ dauth: http://localhost:8080  (ops :8081, grpc :8086)"
echo "  sign-in demo:  make signin"
exec go run ./cmd/dauth
