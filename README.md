# dauth

dauth is DIMO's identity and access token service: one binary (`cmd/dauth`)
serving two surfaces on one host (e.g. `dauth.dimo.zone`), routed by path
prefix. The two surfaces are two stages of one flow:

1. **`/signin`** proves *"I am this DID."* A client signs a challenge with a
   key its DID document lists in the DID directory and receives a short-lived
   RS256 **identity token** whose `sub` is the DID. The org host accepts these
   as member identity (org host plan, decision B).
2. **`/exchange`** proves *"this DID may act on this vehicle under this
   delegation."* It takes an identity token plus a DPoP proof, asks the org
   host's `POST /authorize` whether the caller may exercise the named
   delegation for the named vehicle and abilities, and mints a DPoP-bound
   **access token** carrying the coverage the host computed (design spec
   §11.1). dauth authenticates; the org host authorizes.

Both surfaces issue **stateless, offline-verifiable** tokens: each publishes
its **own** JWKS and OIDC discovery document under its prefix, signs with its
**own** RSA key, and keeps a **distinct** `iss` claim. Two separate keysets are
the security boundary: a token of one kind never verifies against the other
surface's JWKS. The only server-side state is sign-in's short-lived challenge
(nonce) store, kept in memory or in Postgres to run multiple replicas, and the
DPoP replay cache.

| Surface | Prefix | Issues | Default `iss` | Published at |
|---------|--------|--------|---------------|--------------|
| [Sign-in](#signin--identity-tokens) | `/signin` | Identity token (`sub` = DID) | `https://dauth.dimo.zone/signin` | `…/signin/keys` |
| [Exchange](#exchange--access-tokens) | `/exchange` | Access token (`grants`, `cnf`) | `https://dauth.dimo.zone/exchange` | `…/exchange/keys` |

The public packages `pkg/tokenclaims` (the access token claim set, with the
window arithmetic dq clamps by) and `pkg/dpop` (proof creation and
verification) are consumed by downstream repos.

---

# /signin — identity tokens

## Flow

```
client                                     dauth                          DID directory
  │  POST /signin/challenge {did}            │                                  │
  │ ────────────────────────────────────────▶  single-use nonce, challenge text  │
  │  ◀────────────────────────────────────── { challenge, nonce, expires_at }    │
  │                                          │                                  │
  │  sign SHA-256(challenge) with the DID's  │                                  │
  │  #signing key (ECDSA, base64url r||s)    │                                  │
  │                                          │                                  │
  │  POST /signin/token {nonce, signature}   │                                  │
  │ ────────────────────────────────────────▶  consume nonce                    │
  │                                          │  GET /:did ──────────────────────▶
  │                                          │  ◀── DID document                │
  │                                          │  verify against #signing         │
  │  ◀────────────────────────────────────── { token, token_type, expires_in }  │
```

The signature is the one the directory itself checks on DID operations: ECDSA
over the SHA-256 of the exact challenge bytes, encoded as base64url `r||s`, by
a P-256 or secp256k1 key. `dimocli signin --did <did>` does the whole flow for
a DID whose key is in the CLI keystore. The key is resolved at token time, so
a rotated-out key stops signing in immediately. `#dimo_org`, an org's
repository commit key, is never accepted as a login key.

## API

### `POST /signin/challenge`

```json
{ "did": "did:dimo:…", "audience": ["org-host"] }
```

`audience` is optional and must be on `SIGNIN_ALLOWED_AUDIENCES`; omitted, the
token carries `JWT_AUDIENCE`. Returns `{ challenge, nonce, expires_at }`.

### `POST /signin/token`

```json
{ "nonce": "…", "signature": "<base64url r||s>", "key": "signing" }
```

`key` is the verification method fragment, default `signing`. Returns
`{ token, token_type: "Bearer", expires_in }`. Errors are OAuth-style
`{ error, error_description }`: `invalid_request` (400), `invalid_grant` (401:
bad nonce, bad signature, unknown DID or key), `server_error` (503 when the
directory or challenge store is unavailable; get a fresh challenge and retry).

### Validation surface

`GET /signin/keys`, `GET /signin/.well-known/jwks.json`,
`GET /signin/.well-known/openid-configuration`.

## Token

Registered claims only: `iss`, `sub` (the DID), `aud`, `iat`, `nbf`, `exp`,
`jti`. RS256, `kid` = RFC 7638 thumbprint of the signing key.

---

# /exchange — access tokens

## Flow

```
client                                dauth                               org host
  │  POST /exchange                     │                                      │
  │  Authorization: Bearer <identity>   │                                      │
  │  DPoP: <proof for POST /exchange>   │                                      │
  │  {grant, vehicle, abilities}        │                                      │
  │ ───────────────────────────────────▶  verify identity token (sub = caller) │
  │                                     │  verify DPoP proof → jkt             │
  │                                     │  POST /authorize as DAUTH_DID ───────▶
  │                                     │  {uri, caller, vehicle, abilities}   │
  │                                     │  ◀── coverage | 403 {code}           │
  │                                     │  group abilities by window, sign     │
  │  ◀───────────────────────────────── { token, token_type: "DPoP", … }       │
```

dauth calls the host with an identity token for its own DID (`DAUTH_DID`),
minted by the sign-in issuer; the host lists that DID in `ISSUER_DIDS` and
reads dauth's keys from `…/signin/keys`.

## API

### `POST /exchange`

Headers: `Authorization: Bearer <identity token>` and `DPoP: <proof>`. The
proof is an RFC 9449 proof JWT (ES256 or RS256, `typ: dpop+jwt`, public key in
`jwk`, claims `jti`, `htm: POST`, `htu: <PUBLIC_BASE_URL>/exchange`, `iat`
within five minutes). `pkg/dpop.Key.Proof` makes one.

```json
{
  "grant": "at://did:dimo:avis/network.dimo.delegation/booking1:history",
  "vehicle": "did:dimo:veh…",
  "abilities": ["telemetry:read", "location:precise"],
  "audience": ["dq"]
}
```

Returns `{ token, token_type: "DPoP", expires_in, expires_at }`. Refusals:
`invalid_token` (401), `invalid_dpop_proof` (400), `invalid_request` (400),
the host's own code (403: `not_covered`, `exclusive_hold` with `suspended`,
`unauthorized`, `revoked`, `not_valid`, …; 404 `not_found`), `server_error`
(502 when the host is unreachable).

### Validation surface

`GET /exchange/keys`, `GET /exchange/.well-known/jwks.json`,
`GET /exchange/.well-known/openid-configuration`.

## Token

```json
{
  "iss": "https://dauth.dimo.zone/exchange",
  "sub": "did:dimo:renter…",
  "aud": ["dq"],
  "cnf": { "jkt": "…" },
  "exp": 1789600000,
  "grants": [
    {
      "subject": "did:dimo:veh…",
      "abilities": ["location:precise", "telemetry:read"],
      "windows": [["2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z"]],
      "chain": ["at://…/booking1:history", "at://…/root"]
    },
    { "subject": "did:dimo:veh…", "abilities": ["command:unlock"], "chain": ["…"] }
  ]
}
```

One grant per (subject, window set): historical abilities carry the
data-timestamp windows the host computed, live abilities carry none. Suspended
abilities (somebody else holds custody) are left out. Lifetime is 15 minutes
when any live ability is present, 2 hours otherwise. A resource server checks
the signature against `…/exchange/keys`, verifies the request's DPoP proof
(with `ath`) and compares its thumbprint to `cnf.jkt`, then reads `grants`;
`pkg/tokenclaims.Token.Holds` and `Windows.Clamp` do the lookup and the range
arithmetic.

---

# Configuration (environment)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `PUBLIC_BASE_URL` | yes | | Public origin; base of both `jwks_uri` values and the DPoP `htu` of `/exchange` |
| `DIRECTORY_URL` | yes | | DID directory sign-in resolves documents from |
| `SIGNIN_ISSUER` | yes | | `iss` of identity tokens |
| `SIGNIN_DOMAIN` | | host of `PUBLIC_BASE_URL` | Shown in the challenge text |
| `JWT_AUDIENCE` | yes | | Default `aud` of identity tokens (comma-separated) |
| `SIGNIN_ALLOWED_AUDIENCES` | | | Audiences a challenge may request instead |
| `SIGNIN_SIGNING_KEY_1…N` | yes | | PEM RSA keys, first active |
| `CHALLENGE_TTL`, `TOKEN_TTL` | | `5m`, `1h` | Lifetimes |
| `DATABASE_URL` | | | Postgres challenge store; unset = in-memory, single replica |
| `EXCHANGE_ISSUER` | yes | | `iss` of access tokens |
| `EXCHANGE_AUDIENCE` | | `dq` | Default `aud` of access tokens |
| `EXCHANGE_SIGNING_KEY_1…N` | yes | | PEM RSA keys, first active |
| `ORG_HOST_URL` | yes | | Org host that answers `/authorize` |
| `ORG_HOST_TIMEOUT` | | `10s` | Per-call timeout |
| `DAUTH_DID` | yes | | DID dauth presents to the host |
| `EXCHANGE_LIVE_TTL`, `EXCHANGE_HISTORICAL_TTL` | | `15m`, `2h` | Access token lifetimes |
| `HTTP_ADDRESS`, `OPS_ADDRESS` | | `:8080`, `:8081` | Listeners |
| `ENABLE_PPROF`, `LOG_LEVEL`, `ENVIRONMENT` | | | Ops |

## Signing keys

Each surface loads numbered PEM RSA keys (PKCS#1 or PKCS#8, 2048 bits or
more). The first signs; the rest stay in the JWKS so their tokens keep
verifying through a rotation: add the new key as `_2`, deploy, swap it to `_1`,
deploy, drop the old one after its longest token lifetime.

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.pem
```

# Deployment

`charts/dauth` deploys the binary with `.Values.env` rendered into a ConfigMap
and the signing keys and `DATABASE_URL` expected from a Secret. Probes are on
the ops port (`/ping`, `/ready`, `/metrics`).

# Development

```
make run      # keys under .local/, Postgres via docker compose, dauth on :8080
make test
```

`make run` expects a DID directory on `DIRECTORY_URL` (default
`http://localhost:8082`) and an org host on `ORG_HOST_URL` (default
`http://localhost:8081`) configured with `ISSUER_DIDS=did:dimo:dauth` and
`IDENTITY_JWKS_URL=http://localhost:8080/signin/keys`. Then, from the
did-directory repo, `dimocli signin --did <did> --dauth http://localhost:8080`
prints an identity token.
