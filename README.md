# dauth

This repository houses DIMO's Web3 auth pipeline as two small, single-purpose
services that together replace the heavily-forked Dex (DEX) previously used for
Web3 login. They are two stages of one flow:

1. **dauth** proves *"I control this Ethereum address."* A client signs a
   [Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361) (EIP-4361)
   challenge and receives a short-lived RS256 JWT carrying its address.
2. **token-exchange-api** proves *"this address may access this asset with these
   permissions."* It takes a dauth address-control token from a registered
   developer license and, after checking on-chain/SACD access, mints a permission
   token scoped to a DIMO asset.

Both are stateless and offline-verifiable: each service publishes its own JWKS
and OIDC discovery document, and any service validates tokens against those — no
shared secret, no callback. There is no OAuth2 authorization-code flow, refresh
tokens, or connector framework.

## Services

| Service | Binary | Issues | Default `iss` | Surface |
|---------|--------|--------|---------------|---------|
| [dauth](#dauth--address-control-tokens) | `cmd/dauth` | Address-control token (`ethereum_address`) | `https://auth.dimo.zone` | HTTP |
| [token-exchange-api](#token-exchange-api) | `cmd/token-exchange-api` | Permission token (`asset` / `permissions` / `cloud_events`) | `https://auth-roles-rights.dimo.zone` | HTTP + gRPC |

Each service has its own RSA signing key, its own Helm chart (`charts/dauth`,
`charts/token-exchange-api`), and its own image. They share Go packages —
`internal/keyset` (signing), `internal/oidc` (JWKS + discovery), and
`internal/httpmw` (middleware) — but keep separate claims, issuers, and config.
The public packages `pkg/tokenclaims` and `pkg/grpc` are consumed by downstream
repos.

The two services are documented in full below: dauth first, then
token-exchange-api, followed by shared deployment and development notes.

---

# dauth — address-control tokens

SIWE challenge → signature verify → JWT, plus a standard validation surface. The
canonical SIWE message is generated and stored server-side; the issued JWT is
stateless.

## Sign-in flow

```
client                              dauth
  │  POST /auth/challenge {address}   │
  │ ─────────────────────────────────▶  generate single-use nonce,
  │                                   │  build EIP-4361 message, store it
  │  ◀───────────────────────────────  { challenge, nonce, expires_at }
  │                                   │
  │  wallet personal_sign(challenge)  │
  │                                   │
  │  POST /auth/token {nonce, sig}    │
  │ ─────────────────────────────────▶  look up by nonce, consume
  │                                   │  (single-use), verify sig (EOA/1271),
  │                                   │  mint RS256 JWT
  │  ◀───────────────────────────────  { token, token_type, expires_in }
```

The canonical SIWE message is generated and stored server-side, keyed by its
nonce, so the bytes the wallet signs are exactly the bytes dauth verifies. The
client returns the nonce; dauth looks up the stored entry, verifies the
signature against the stored copy, and consumes the entry (single-use) — giving
true replay protection. The store is the only server-side state; the issued JWT
is stateless and offline-verifiable.

## API

### `POST /auth/challenge`

```json
{ "address": "0x6E4…A1b" }
```
The chain is fixed by the `CHAIN_ID` config. Response:
```json
{
  "challenge": "auth.dimo.zone wants you to sign in with your Ethereum account:\n0x6E4…A1b\n\nSign in to DIMO.\n\nURI: https://auth.dimo.zone\nVersion: 1\nChain ID: 137\nNonce: …\nIssued At: …\nExpiration Time: …",
  "nonce": "…",
  "expires_at": "2026-06-14T17:25:00Z"
}
```

### `POST /auth/token`

```json
{ "nonce": "…", "signature": "0x1c8f…" }
```
The wallet must `personal_sign` the exact `challenge` string; the client returns
the `nonce` from step 1 to identify it. Response:
```json
{ "token": "eyJ…", "token_type": "Bearer", "expires_in": 600 }
```

Errors use OAuth-style codes: `{ "error": "invalid_grant", "error_description": "…" }`.
`invalid_request` → 400, `invalid_grant` → 401, `server_error` → 503/500, 429 on
rate limit.

### Validation surface

- `GET /.well-known/openid-configuration` — OIDC discovery metadata.
- `GET /keys` (alias `GET /.well-known/jwks.json`) — JWKS (RFC 7517).
- `GET /swagger/` — interactive OpenAPI docs for the sign-in endpoints.

### Ops server (separate port)

- `GET /ping`, `GET /ready` — health probes.
- `GET /metrics` — Prometheus metrics.

## Tokens

RS256, with `kid` in the header. Claims:

| claim | value |
|-------|-------|
| `iss` | configured issuer |
| `sub` | EIP-55 checksummed address |
| `aud` | configured audience(s) |
| `iat` / `nbf` / `exp` | now / now / now + `TOKEN_TTL` |
| `jti` | random UUID |
| `ethereum_address` | EIP-55 checksummed address |

`ethereum_address` is the canonical claim downstream services read.

### Validating tokens downstream

Point any validator at the issuer and JWKS. For example, `din`'s attestation
server is configured with:

```
TOKEN_EXCHANGE_ISSUER=https://auth.dimo.zone
TOKEN_EXCHANGE_KEY_SET_URL=https://auth.dimo.zone/keys
```

and validates `iss`, RS256, and the `ethereum_address` claim — no dauth-specific
code required.

## Signer support

- **EOA** — ECDSA recovery (`ecrecover`), verified locally.
- **Deployed smart accounts** — [EIP-1271](https://eips.ethereum.org/EIPS/eip-1271)
  `isValidSignature`, checked against the account contract via `RPC_URL`.

EIP-1271 requires `RPC_URL`. Without it, dauth verifies EOA signatures only.
Counterfactual (undeployed) smart accounts (EIP-6492) are not supported.

## Configuration (environment)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `ISSUER` | yes | — | Absolute URL, e.g. `https://auth.dimo.zone`. Also the JWT `iss` and SIWE `uri`. |
| `JWT_AUDIENCE` | yes | — | Comma-separated `aud` value(s). |
| `SIGNING_KEY_1`, `SIGNING_KEY_2`, … | yes | — | PEM RSA private keys, in order. `_1` is the active signer. |
| `CHAIN_ID` | no | `137` | Chain the sign-in is bound to (in the SIWE message). |
| `SIWE_DOMAIN` | no | issuer host | Domain shown in the SIWE message. |
| `SIWE_STATEMENT` | no | `Sign in to DIMO.` | Statement shown in the wallet. |
| `RPC_URL` | no | — | Ethereum RPC for EIP-1271; empty disables smart-account login. |
| `RPC_TIMEOUT` | no | `3s` | Bounds each EIP-1271 call. |
| `CHALLENGE_TTL` | no | `5m` | Challenge lifetime. |
| `TOKEN_TTL` | no | `1h` | Access-token lifetime. |
| `ALLOWABLE_TIME_SKEW` | no | `5m` | Clock skew tolerance. |
| `AUTH_ADDRESS` | no | `0.0.0.0:8080` | Public listen address. |
| `OPS_ADDRESS` | no | `0.0.0.0:8081` | Ops listen address. |
| `MAX_BODY_BYTES` | no | `16384` | Request body cap. |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | no | `0` / `20` | Per-IP limit; `0` disables. |
| `LOG_LEVEL` | no | `info` | zerolog level. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | no | — | In-process TLS; omit to terminate at the ingress. |

## Signing keys

Generate an RSA key (2048-bit minimum):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.pem
```

Store its PEM contents in `SIGNING_KEY_1`. The `kid` is derived deterministically
as the RFC 7638 JWK thumbprint of the public key.

### Rotation (zero-downtime overlap)

1. Add the new key as `SIGNING_KEY_2` and deploy. The JWKS now publishes both;
   the new key is not yet signing.
2. After validators refresh their JWKS cache, promote the new key to
   `SIGNING_KEY_1` (and demote the old to `SIGNING_KEY_2`) and deploy. New tokens
   are signed by the new key; the old key still verifies outstanding tokens.
3. After `TOKEN_TTL` elapses (no tokens from the old key remain valid), drop the
   old key and deploy.

The same `SIGNING_KEY_*` convention and rotation procedure apply to
token-exchange-api, which carries its own independent key.

---

# token-exchange-api

Exchanges a dauth address-control token for a permission token scoped to a DIMO
asset, after validating on-chain/SACD access. It serves both an HTTP API and a
gRPC `TokenExchangeService`, and publishes its own JWKS/discovery (taking over
the endpoints DEX used to serve for the roles-rights issuer).

## Exchange flow

```
caller                                  token-exchange-api
  │ POST /v1/tokens/exchange               │
  │   Authorization: Bearer <dauth token>  │  verify dauth token signature (JWKS),
  │   { asset, permissions, cloudEvents }  │  require registered dev license,
  │ ──────────────────────────────────────▶  read ethereum_address from the token,
  │                                        │  check SACD/on-chain access for the asset,
  │ ◀──────────────────────────────────────  mint permission token
  │   { token }                            │
```

The inbound token must be a valid dauth token (`JWT_KEY_SET_URL` points at
dauth's `/keys`), signature-checked, whose `ethereum_address` belongs to an
address registered as a developer license in identity-api. Authorization (the
SACD/on-chain grantee check) reads that same `ethereum_address` claim.

## API

### `POST /v1/tokens/exchange`

Requires `Authorization: Bearer <dauth token>`. Request:

```json
{
  "asset": "did:erc721:137:0xbA5738…:7",
  "permissions": ["…"],
  "cloudEvents": { "events": [ … ] },
  "audience": ["dimo.zone"]
}
```

`audience` is optional (defaults to `["dimo.zone"]`). The legacy `tokenId`,
`privileges`, and `nftContractAddress` fields are still accepted but
**deprecated** in favor of `asset` and `permissions`. Response:

```json
{ "token": "eyJ…" }
```

The minted token's claims include `asset`, `permissions`, and `cloud_events`
alongside the standard `iss` / `sub` / `aud` / `exp` / `nbf` / `iat` / `jti`.

### Other HTTP endpoints

- `GET /` — health check (`{"data":"Server is up and running"}`).
- `GET /v1/swagger/` — interactive OpenAPI docs.
- `GET /keys` (alias `GET /.well-known/jwks.json`) — JWKS for the permission-token
  signing key.
- `GET /.well-known/openid-configuration` — OIDC discovery metadata.

### gRPC

`TokenExchangeService` is served on `GRPC_PORT` for the on-chain access-check
client (`pkg/grpc`).

### Ops server (separate port, `MON_PORT`)

- `GET /ping`, `GET /ready` — health probes.
- `GET /metrics` — Prometheus metrics.
- `/debug/pprof/*` — enabled only when `ENABLE_PPROF=true`.

## Configuration (environment)

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `ISSUER` | yes | — | `iss` on minted tokens, e.g. `https://auth-roles-rights.dimo.zone`. Also the host of its JWKS. |
| `JWT_KEY_SET_URL` | yes | — | JWKS used to validate the inbound dauth token (point at dauth's `/keys`). |
| `BLOCKCHAIN_NODE_URL` | yes | — | Ethereum RPC for SACD/contract reads. |
| `IDENTITY_URL` | yes | — | identity-api GraphQL endpoint (dev-license + SACD lookups). |
| `IPFS_BASE_URL` | yes | — | IPFS gateway for template/permission documents. |
| `SIGNING_KEY_1`, `SIGNING_KEY_2`, … | yes | — | PEM RSA private keys (independent of dauth's). `_1` is the active signer. |
| `TOKEN_EXPIRATION` | no | `10m` | Permission-token lifetime. |
| `CONTRACT_ADDRESS_SACD` | no | — | SACD contract address. |
| `CONTRACT_ADDRESS_TEMPLATE` | no | — | Permission-template contract address. |
| `CONTRACT_ADDRESS_MANUFACTURER` | no | — | Manufacturer NFT contract address. |
| `CONTRACT_ADDRESS_VEHICLE` | no | — | Vehicle NFT contract address. |
| `DIMO_REGISTRY_CHAIN_ID` | no | `137` | Chain id for on-chain registry reads. |
| `IPFS_TIMEOUT` | no | `30s` | Bounds each IPFS fetch. |
| `PORT` | no | `8080` | HTTP listen port. |
| `GRPC_PORT` | no | `8086` | gRPC listen port. |
| `MON_PORT` | no | `8888` | Ops listen port. |
| `ENABLE_PPROF` | no | `false` | Exposes `/debug/pprof/*` on the ops server. |
| `ENVIRONMENT` | no | `local` | Deployment environment label. |
| `SERVICE_NAME` | no | `token-exchange-api` | Service name label. |
| `LOG_LEVEL` | no | `info` | zerolog level. |

---

# Deployment

- Containers: `docker build -f docker/dockerfile .` (dauth) and
  `docker build -f docker/dockerfile.token-exchange-api .` (token-exchange-api).
  Both are static binaries on `distroless/static`.
- Helm: `charts/dauth/` and `charts/token-exchange-api/`, each with `values.yaml`
  (dev) and `values-prod.yaml`. Signing keys (and dauth's `RPC_URL`) are pulled
  via an `ExternalSecret`; each service references its own key at
  `<ns>/dauth/signing_key_1` and `<ns>/token-exchange-api/signing_key_1`
  respectively.
- **Run dauth as a single replica.** Its nonce store is in-memory, so a challenge
  must be redeemed on the pod that issued it. To scale out, back the `nonce.Store`
  with a shared store (e.g. Redis) first. token-exchange-api is stateless and
  scales independently.
- token-exchange-api's `JWT_KEY_SET_URL` must point at the dauth deployment's
  `/keys`; downstream consumers of the permission token point their JWKS URL at
  token-exchange-api's `/keys`.

# Development

```sh
go test ./...
go build ./cmd/dauth
go build ./cmd/token-exchange-api
```

With a dauth instance running, `scripts/signin.sh` drives the full SIWE flow —
it generates a throwaway key, requests a challenge, signs it with Foundry's
`cast`, exchanges it for a token, and prints the decoded claims (requires `cast`,
`curl`, and `jq`):

```sh
BASE_URL=http://localhost:8080 scripts/signin.sh
```
