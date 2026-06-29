# dauth

This repository houses DIMO's Web3 auth pipeline: one binary (`cmd/dauth`)
serving two surfaces on one host (e.g. `dauth.dimo.zone`), together replacing the
heavily-forked Dex (DEX) previously used for Web3 login. The two surfaces are two
stages of one flow, routed by path prefix:

1. **`/siwe`** proves *"I control this Ethereum address."* A client signs a
   [Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361) (EIP-4361)
   challenge and receives a short-lived RS256 JWT carrying its address.
2. **`/exchange`** proves *"this address may access this asset with these
   permissions."* It takes a `/siwe` address-control token from a registered
   developer license and, after checking on-chain/SACD access, mints a permission
   token scoped to a DIMO asset.

Both surfaces issue **stateless, offline-verifiable** tokens: each publishes its
**own** JWKS and OIDC discovery document under its prefix, signs with its **own**
RSA key, and keeps a **distinct** `iss` claim. Two separate keysets are the
security boundary — a token of one kind never verifies against the other
surface's JWKS. The only server-side state is sign-in's short-lived challenge
(nonce) store — kept in memory, or in Postgres to run multiple replicas (see
[deployment](#deployment)); the exchange holds no state, and validating a token
never needs a server round-trip. The shared host is pure transport; nothing here
uses an OAuth2 authorization-code flow, refresh tokens, or a connector framework.

## Surfaces

| Surface | Prefix | Issues | Default `iss` | Published at |
|---------|--------|--------|---------------|--------------|
| [Sign-in](#siwe--address-control-tokens) | `/siwe` | Address-control token (`ethereum_address`) | `https://dauth.dimo.zone/siwe` | `…/siwe/keys` |
| [Exchange](#exchange--permission-tokens) | `/exchange` | Permission token (`asset` / `permissions` / `cloud_events`) | `https://dauth.dimo.zone/exchange` | `…/exchange/keys` |

The exchange also exposes a gRPC `TokenExchangeService` on its own port. The two
surfaces share Go packages — `internal/keyset` (signing), `internal/oidc` (JWKS +
discovery), and `internal/httpmw` (middleware) — but keep separate claims,
issuers, signing keys, and config (sign-in config is namespaced `SIWE_*`, the
exchange `EXCHANGE_*`). The public packages `pkg/tokenclaims` and `pkg/grpc`
are consumed by downstream repos.

`PUBLIC_BASE_URL` (e.g. `https://dauth.dimo.zone`) is the host both surfaces are
reachable at; it is the base of each published `jwks_uri`, decoupled from the
`iss` claims. The two surfaces are documented in full below: sign-in first, then
the exchange, followed by deployment and development notes.

---

# /siwe — address-control tokens

SIWE challenge → signature verify → JWT, plus a standard validation surface. The
canonical SIWE message is generated and stored server-side; the issued JWT is
stateless.

## Sign-in flow

```
client                              dauth
  │  POST /siwe/challenge {address}   │
  │ ─────────────────────────────────▶  generate single-use nonce,
  │                                   │  build EIP-4361 message, store it
  │  ◀───────────────────────────────  { challenge, nonce, expires_at }
  │                                   │
  │  wallet personal_sign(challenge)  │
  │                                   │
  │  POST /siwe/token {nonce, sig}    │
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

### `POST /siwe/challenge`

```json
{ "address": "0x6E4…A1b" }
```
The chain is fixed by the `CHAIN_ID` config.

An optional `audience` (string array) requests a specific `aud` for the issued
token, e.g. `{ "address": "0x6E4…A1b", "audience": ["step-ca"] }`. Every value
must be on the `SIWE_ALLOWED_AUDIENCES` allow-list, or the challenge is rejected
with `invalid_request` (400). The audience is bound to the nonce at challenge
time and cannot be changed at `/siwe/token`. Omit it to receive the configured
default (`JWT_AUDIENCE`). This unblocks clients — e.g. step-ca certificate
enrollment — that validate the sign-in token as an `id_token` and require their
own client ID in `aud`. Response:
```json
{
  "challenge": "dauth.dimo.zone wants you to sign in with your Ethereum account:\n0x6E4…A1b\n\nSign in to DIMO.\n\nURI: https://dauth.dimo.zone\nVersion: 1\nChain ID: 137\nNonce: …\nIssued At: …\nExpiration Time: …",
  "nonce": "…",
  "expires_at": "2026-06-14T17:25:00Z"
}
```

### `POST /siwe/token`

```json
{ "nonce": "…", "signature": "0x1c8f…" }
```
The wallet must `personal_sign` the exact `challenge` string; the client returns
the `nonce` from step 1 to identify it. Response:
```json
{ "token": "eyJ…", "token_type": "Bearer", "expires_in": 3600 }
```

Errors use OAuth-style codes: `{ "error": "invalid_grant", "error_description": "…" }`.
`invalid_request` → 400, `invalid_grant` → 401, `server_error` → 503/500, 429 on
rate limit.

### Validation surface

- `GET /siwe/.well-known/openid-configuration` — OIDC discovery metadata.
- `GET /siwe/keys` (alias `GET /siwe/.well-known/jwks.json`) — JWKS (RFC 7517).
- `GET /siwe/swagger/` — interactive OpenAPI docs for the sign-in endpoints.

### Ops server (separate port)

- `GET /ping`, `GET /ready` — health probes.
- `GET /metrics` — Prometheus metrics.

## Tokens

RS256, with `kid` in the header. Claims:

| claim | value |
|-------|-------|
| `iss` | configured issuer |
| `sub` | EIP-55 checksummed address |
| `aud` | configured audience(s), or an allow-listed value requested at `/siwe/challenge` (see below) |
| `iat` / `nbf` / `exp` | now / now / now + `TOKEN_TTL` |
| `jti` | random UUID |
| `ethereum_address` | EIP-55 checksummed address |

`ethereum_address` is the canonical claim downstream services read.

### Validating tokens downstream

Point any validator at the issuer and JWKS. For example, `din`'s attestation
server is configured with:

```
TOKEN_EXCHANGE_ISSUER=https://dauth.dimo.zone/siwe
TOKEN_EXCHANGE_KEY_SET_URL=https://dauth.dimo.zone/siwe/keys
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

The variables below configure the sign-in surface and the process as a whole.
The exchange surface's variables are namespaced `EXCHANGE_*` (see its own
section); a few process-wide variables (`PUBLIC_BASE_URL`, `HTTP_ADDRESS`,
`OPS_ADDRESS`, `LOG_LEVEL`, `ENVIRONMENT`, `DATABASE_URL`) are shared.

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `PUBLIC_BASE_URL` | yes | — | Externally reachable origin, e.g. `https://dauth.dimo.zone`. Base of each surface's `jwks_uri`; also the SIWE `uri` and default `SIWE_DOMAIN` host. |
| `SIWE_ISSUER` | yes | — | Absolute URL, e.g. `https://dauth.dimo.zone/siwe`. The sign-in JWT `iss`. |
| `JWT_AUDIENCE` | yes | — | Comma-separated default `aud` value(s). |
| `SIWE_ALLOWED_AUDIENCES` | no | — | Comma-separated allow-list of `aud` values a caller may request at `/siwe/challenge`. Empty means no override is permitted. |
| `SIWE_SIGNING_KEY_1`, `SIWE_SIGNING_KEY_2`, … | yes | — | PEM RSA private keys, in order. `_1` is the active signer. |
| `CHAIN_ID` | no | `137` | Chain the sign-in is bound to (in the SIWE message). |
| `SIWE_DOMAIN` | no | `PUBLIC_BASE_URL` host | Domain shown in the SIWE message. |
| `SIWE_STATEMENT` | no | `Sign in to DIMO.` | Statement shown in the wallet. |
| `RPC_URL` | no | — | Ethereum RPC for EIP-1271; empty disables smart-account login. |
| `RPC_TIMEOUT` | no | `3s` | Bounds each EIP-1271 call. |
| `CHALLENGE_TTL` | no | `5m` | Challenge lifetime. |
| `TOKEN_TTL` | no | `1h` | Access-token lifetime. |
| `ALLOWABLE_TIME_SKEW` | no | `5m` | Clock skew tolerance. |
| `HTTP_ADDRESS` | no | `0.0.0.0:8080` | Public listen address (both prefixes). |
| `OPS_ADDRESS` | no | `0.0.0.0:8081` | Ops listen address. |
| `MAX_BODY_BYTES` | no | `16384` | Request body cap. |
| `RATE_LIMIT_RPS` / `RATE_LIMIT_BURST` | no | `0` / `20` | Per-IP limit; `0` disables. |
| `LOG_LEVEL` | no | `info` | zerolog level. |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | no | — | In-process TLS; omit to terminate at the ingress. |
| `DATABASE_URL` | no | — | Postgres challenge store as a `postgres://user:pass@host:5432/dauth?sslmode=require` URL; enables multiple replicas. Tune pool sizing inline, e.g. `?pool_max_conns=10`. Empty uses the in-memory single-replica store. See [deployment](#deployment). |

## Signing keys

Generate an RSA key (2048-bit minimum):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.pem
```

Store its PEM contents in `SIWE_SIGNING_KEY_1`. The `kid` is derived
deterministically as the RFC 7638 JWK thumbprint of the public key.

### Rotation (zero-downtime overlap)

1. Add the new key as `SIWE_SIGNING_KEY_2` and deploy. The JWKS now publishes
   both; the new key is not yet signing.
2. After validators refresh their JWKS cache, promote the new key to
   `SIWE_SIGNING_KEY_1` (and demote the old to `SIWE_SIGNING_KEY_2`) and deploy.
   New tokens are signed by the new key; the old key still verifies outstanding
   tokens.
3. After `TOKEN_TTL` elapses (no tokens from the old key remain valid), drop the
   old key and deploy.

The same convention and rotation procedure apply to the `/exchange` surface
under `EXCHANGE_SIGNING_KEY_*`, which carries its own independent key.

---

# /exchange — permission tokens

Exchanges a `/siwe` address-control token for a permission token scoped to a DIMO
asset, after validating on-chain/SACD access. It serves both an HTTP API and a
gRPC `TokenExchangeService`, and publishes its own JWKS/discovery (taking over
the endpoints DEX used to serve for the roles-rights issuer).

## Exchange flow

```
caller                                  /exchange
  │ POST /exchange/tokens/exchange      │
  │   Authorization: Bearer <siwe token>   │  verify sign-in token signature (JWKS),
  │   { asset, permissions, cloudEvents }  │  require registered dev license,
  │ ──────────────────────────────────────▶  read ethereum_address from the token,
  │                                        │  check SACD/on-chain access for the asset,
  │ ◀──────────────────────────────────────  mint permission token
  │   { token }                            │
```

The inbound token must be a valid sign-in token, signature-checked, whose
`ethereum_address` belongs to an address registered as a developer license in
identity-api. Because both surfaces run in one process, the exchange validates
that token against the `/siwe` keyset **in memory** — there is no HTTP fetch of
its own `/siwe/keys` (which wouldn't be listening yet at startup). Authorization
(the SACD/on-chain grantee check) reads that same `ethereum_address` claim.

## API

### `POST /exchange/tokens/exchange`

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

- `GET /` — health check (`{"data":"Server is up and running"}`), served at the
  process root (shared by both surfaces).
- `GET /exchange/swagger/` — interactive OpenAPI docs.
- `GET /exchange/keys` (alias `…/exchange/.well-known/jwks.json`) — JWKS for
  the permission-token signing key.
- `GET /exchange/.well-known/openid-configuration` — OIDC discovery metadata.

### gRPC

`TokenExchangeService` is served on `GRPC_PORT` for the on-chain access-check
client (`pkg/grpc`).

### Ops server (shared, `OPS_ADDRESS`)

- `GET /ping`, `GET /ready` — health probes.
- `GET /metrics` — Prometheus metrics.
- `/debug/pprof/*` — enabled only when `ENABLE_PPROF=true`.

## Configuration (environment)

These configure the `/exchange` surface (the inbound token is validated
against the `/siwe` keyset in-process, so there is no JWKS-URL variable). HTTP and
ops listeners are shared with the sign-in surface (`HTTP_ADDRESS`, `OPS_ADDRESS`).

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `EXCHANGE_ISSUER` | yes | — | `iss` on minted tokens, e.g. `https://dauth.dimo.zone/exchange`. |
| `BLOCKCHAIN_NODE_URL` | yes | — | Ethereum RPC for SACD/contract reads. |
| `IDENTITY_URL` | yes | — | identity-api GraphQL endpoint (dev-license + SACD lookups). |
| `IPFS_BASE_URL` | yes | — | IPFS gateway for template/permission documents. |
| `EXCHANGE_SIGNING_KEY_1`, `EXCHANGE_SIGNING_KEY_2`, … | yes | — | PEM RSA private keys (independent of the sign-in surface's). `_1` is the active signer. |
| `TOKEN_EXPIRATION` | no | `10m` | Permission-token lifetime. |
| `CONTRACT_ADDRESS_SACD` | no | — | SACD contract address. |
| `CONTRACT_ADDRESS_TEMPLATE` | no | — | Permission-template contract address. |
| `CONTRACT_ADDRESS_MANUFACTURER` | no | — | Manufacturer NFT contract address. |
| `CONTRACT_ADDRESS_VEHICLE` | no | — | Vehicle NFT contract address. |
| `DIMO_REGISTRY_CHAIN_ID` | no | `137` | Chain id for on-chain registry reads. |
| `IPFS_TIMEOUT` | no | `30s` | Bounds each IPFS fetch. |
| `GRPC_PORT` | no | `8086` | gRPC listen port. |
| `ENABLE_PPROF` | no | `false` | Exposes `/debug/pprof/*` on the ops server. |

---

# Deployment

- Container: `docker build -f docker/dockerfile .` — one static binary on
  `distroless/static`, exposing the public HTTP port, the ops port, and the gRPC
  port.
- Helm: `charts/dauth/` with `values.yaml` (dev) and `values-prod.yaml`. The two
  surfaces' signing keys (plus the RPC URLs) are pulled via one `ExternalSecret`,
  referencing the distinct keys at `<ns>/dauth/signing_key_1` (sign-in) and
  `<ns>/token-exchange-api/signing_key_1` (permissions).
- **Challenge store and replicas.** By default the sign-in surface keeps issued
  challenges in an in-memory `nonce.Store`, so a challenge must be redeemed on the
  pod that issued it — keep `replicaCount: 1`. To scale out, enable the Postgres
  store (`postgres.enabled` in the chart, or set `DATABASE_URL`): challenges
  become shared across pods (single-use
  enforced by an atomic `DELETE ... RETURNING`), and you can raise the replica
  count. The schema self-applies at startup, so no migration step is needed.
- Downstream consumers of the **permission** token point their JWKS URL at
  `…/exchange/keys`; consumers validating the **sign-in** token point at
  `…/siwe/keys`. The exchange validates the inbound sign-in token in-process, so
  no JWKS URL needs wiring between the two surfaces.

# Development

```sh
go test ./...
go build ./cmd/dauth
```

## Running locally

`make run` brings up Postgres (via `docker-compose.yml`, on host port 5433 to
avoid clashing with a local Postgres on 5432), generates throwaway signing keys
under `.local/` on first run, and starts the merged binary with sane local env:

```sh
make run                 # dauth on :8080 (ops :8081, grpc :8086)
make signin              # in another shell — drives the full /siwe flow
make db-down             # stop Postgres and wipe its volume
```

The **`/siwe` sign-in surface works fully offline** — EOA signing needs no
backends (set `RPC_URL` only to test smart-account / EIP-1271 login). The
**`/exchange` exchange boots but can't complete a real exchange** without
identity-api, an Ethereum RPC, and IPFS; point `IDENTITY_URL`,
`BLOCKCHAIN_NODE_URL`, and `IPFS_BASE_URL` at real (or mocked) services to
exercise it. To run without Docker, start any Postgres and set `DATABASE_URL`
yourself (or leave it unset to use the in-memory single-replica store).

The gRPC stubs in `pkg/grpc` are regenerated from `pkg/grpc/*.proto` with
[`buf`](https://buf.build) (`buf generate`); the plugin versions are pinned via
`go install` of `protoc-gen-go`/`protoc-gen-go-grpc` (see `buf.gen.yaml`).

With a dauth instance running, `scripts/signin.sh` drives the full SIWE flow —
it generates a throwaway key, requests a challenge, signs it with Foundry's
`cast`, exchanges it for a token, and prints the decoded claims (requires `cast`,
`curl`, and `jq`):

```sh
BASE_URL=http://localhost:8080 scripts/signin.sh
```

With a dauth instance running, `scripts/signin.sh` drives the full SIWE flow —
it generates a throwaway key, requests a challenge, signs it with Foundry's
`cast`, exchanges it for a token, and prints the decoded claims (requires `cast`,
`curl`, and `jq`):

```sh
BASE_URL=http://localhost:8080 scripts/signin.sh
```
