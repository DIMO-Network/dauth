# dauth

DIMO authentication service. Clients prove control of an Ethereum account by
signing a [Sign-In With Ethereum](https://eips.ethereum.org/EIPS/eip-4361)
(EIP-4361) challenge; in return they receive a short-lived RS256 JWT identifying
their address. Any service can validate those tokens offline against the JWKS
and OIDC discovery document dauth publishes — no shared secret, no callback to
dauth.

It replaces the heavily-forked Dex previously used for Web3 login with a small,
purpose-built service: SIWE challenge → signature verify → JWT, plus a standard
validation surface. No OAuth2 authorization-code flow, refresh tokens, or
connector framework.

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
| `TOKEN_TTL` | no | `10m` | Access-token lifetime. |
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

## Deployment

- Container: `docker build -f docker/dockerfile .` — a static binary on
  `distroless/static`.
- Helm: `charts/dauth/`, with `values.yaml` (dev) and `values-prod.yaml`.
  Signing keys and `RPC_URL` are pulled via an `ExternalSecret`.
- **Run a single replica.** The nonce store is in-memory, so a challenge must be
  redeemed on the pod that issued it. To scale out, back the `nonce.Store` with a
  shared store (e.g. Redis) first.

## Development

```sh
go test ./...
go build ./cmd/dauth
```
