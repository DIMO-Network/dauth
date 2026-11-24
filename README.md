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

The public package `pkg/tokenclaims` (the access token claim set, with the
window arithmetic dq clamps by) is consumed by downstream repos. DPoP proofs
are made and checked with did-directory's `pkg/dpop`.

---

# /signin — identity tokens

## Flow

```
client                                     dauth                          DID directory
  │  POST /signin/challenge                  │                                  │
  │    {did, audience, scope, jkt}           │                                  │
  │ ────────────────────────────────────────▶  single-use nonce, challenge text  │
  │  ◀────────────────────────────────────── { challenge, nonce, expires_at }    │
  │                                          │                                  │
  │  sign SHA-256(challenge) with the DID's  │                                  │
  │  #signing key (ECDSA, base64url r||s)    │                                  │
  │                                          │                                  │
  │  POST /signin/token {nonce, signature}   │                                  │
  │  DPoP: <proof from the jkt key>          │                                  │
  │ ────────────────────────────────────────▶  check proof                      │
  │                                          │  GET /:did ──────────────────────▶
  │                                          │  ◀── DID document                │
  │                                          │  verify against #signing         │
  │                                          │  consume nonce                   │
  │  ◀────────────────────────────────────── { token, token_type, expires_in }  │
```

The signature is the one the directory itself checks on DID operations: ECDSA
over the SHA-256 of the exact challenge bytes, encoded as base64url `r||s`, by
a P-256 or secp256k1 key. `dimocli signin --did <did>` does the whole flow for
a DID whose key is in the CLI keystore. The key is resolved at token time, so
a rotated-out key stops signing in immediately. `#dimo_org`, an org's
repository commit key, is never accepted as a login key.

A token is good for what the DID signed for and only in the hands of one key.
The challenge text names the audience, the scope and the thumbprint of a DPoP
key, so the signature covers all three; `/signin/token` takes a proof from that
key; and every service that accepts the token wants it under the `DPoP` scheme
with a fresh proof from the same key. A copied token is useless without the
key, and a dashboard that only reads signs in with `read` and cannot write.
The profile is did-directory's `pkg/identity`; proofs are its `pkg/dpop`.

## API

### `POST /signin/challenge`

```json
{ "did": "did:dimo:…", "audience": ["https://orghost.dimo.zone"], "scope": "read write", "jkt": "<RFC 7638 thumbprint>" }
```

`scope` is required: one or more of `read` (reads, `/authorize`, and what the
exchange requires), `write` (record writes, withdrawing a pending write) and
`approve` (approving a pending write, `revoke-authored-by`, registering a
repository), space-separated. `approve` is issued only to a key that could
also sign the DID's next operation: the verification method that signs in
must be one of the rotation keys of the DID's head. A person gets it by
signing in with `#wallet`, an org with `#signing` (its root); a device key
signs in for `read` and `write` only. `jkt` is required: the thumbprint of
the DPoP key the token will be bound to. An unknown scope is
`invalid_scope`.

`audience` names the service the token is for, and every service that takes
these tokens checks it: the exchange accepts only `<PUBLIC_BASE_URL>/exchange`,
the org host only its own URL. Those two may always be requested; anything
else must be on `SIGNIN_ALLOWED_AUDIENCES`. At most 10 values, none repeated
(`invalid_request` otherwise); they are kept in the order sent, and the
challenge's `For:` line lists them in that order. Omitted, the token carries
`JWT_AUDIENCE`, which neither the exchange nor the org host accepts. The
audience is fixed when the challenge is issued: the token's `aud` is exactly
the `For:` line. Returns `{ challenge, nonce, expires_at }`.

### `POST /signin/token`

```json
{ "nonce": "…", "signature": "<base64url r||s>", "key": "signing" }
```

`key` is the verification method fragment, default `signing`. The request
carries `DPoP: <proof>` for `POST <PUBLIC_BASE_URL>/signin/token` from the key
the challenge named. An unknown, used or expired nonce is refused before the
proof is checked, and so is a proof whose header `jwk` is not the named key:
neither is verified, so neither records a `jti`, and neither (nor a missing
proof, nor one that fails to verify) spends the challenge, so whoever has only
the nonce cannot burn it. Once the proof verifies as the named key, the
attempt counts: a bad signature, an unknown key, or a DID the directory does
not hold or will not serve spends the challenge, and the client starts again
with a new one. So does an `approve` challenge signed by a key that is not a
rotation key: 403 `key_not_allowed`, "approve needs a rotation key" (dauth
reads the rotation keys from the directory's `GET /<did>/data` only for
`approve`). A directory that does not answer spends nothing. Of concurrent
requests that verify, exactly one gets the token. Returns
`{ token, token_type: "DPoP", expires_in, scope }`: `TOKEN_TTL`, or
`APPROVE_TOKEN_TTL` when the scope includes `approve`. Errors are OAuth-style
`{ error, error_description }`: `invalid_request` (400), `invalid_dpop_proof`
(400, also for a proof over 4 KiB or from another key), `invalid_grant` (401:
bad nonce, bad signature, unknown key, or a DID the directory does not hold
(404) or will not serve (400, 410, 422)), `key_not_allowed` (403: `approve`
from a key that is not a rotation key), `server_error` (503 with
`Retry-After: 1` when the challenge store is unavailable, the DPoP proof could
not be checked, or the directory does not answer: a timeout, 408, 429, any
other 4xx or a 5xx; the challenge is not spent, so retry `/token` with the
same nonce and signature and a fresh DPoP proof). `/signin/challenge` answers
the same 503 when the challenge store is unavailable. Either
endpoint may also answer `rate_limited` (see below).

### Rate limit

`POST /signin/challenge` and `POST /signin/token` share one token bucket per
client: `SIGNIN_RATE_LIMIT_PER_SECOND` requests a second (default 5), with a
burst of twice that (10 by default), so a sign-in, which takes one of each,
costs two. A client is an IPv4 address, or an IPv6 /64 (one subscriber is
usually given a whole /64). `0` turns the limit off. The discovery and JWKS
routes are not limited, and neither is `/exchange`.

For integrators: either endpoint may answer

```
HTTP/1.1 429 Too Many Requests
Retry-After: 1

{ "error": "rate_limited", "error_description": "too many sign-in requests from this address, retry shortly" }
```

Wait at least `Retry-After` seconds and retry; a challenge already issued
stays valid until it expires. The buckets live in each dauth pod, so with
several replicas the limit applies per pod, not across the service. Everyone
behind one egress address (an office NAT, a carrier-grade NAT, a server that
signs in on behalf of many users) shares that address's bucket.

The client IP is the TCP peer, unless the peer is in `SIGNIN_TRUSTED_PROXIES`.
Then `X-Forwarded-For` is read from the right, and the first address that is
not itself a trusted proxy is the client, so a client cannot pick its own
bucket by sending the header. An entry may carry a port (`203.0.113.9:4123`,
`[2001:db8::1]:4123`); one that does not parse, or carries an IPv6 zone, stops
the walk and the peer is used. The chart trusts loopback (the Linkerd sidecar
dauth's traffic arrives from) and the private ranges (the ingress); without
that, every client shares one address and so one bucket. The limiter tracks
at most 50,000 clients; when full it drops idle buckets first.

The challenge store budgets by client as well, keyed the same way. One
client holds at most 32 outstanding challenges, and a new one past that
replaces its oldest. The in-memory store holds 50,000, so a flood from fewer
than about 1,560 addresses (50,000 / 32) cannot fill it and displaces only
its own challenges. Above that, a new challenge replaces the oldest one of
the client holding the most. That is usually a flooding address, but once a
flood is spread thin enough, an address many users share (a carrier or
office NAT, a server signing in for others) can hold the most and lose its
oldest first. The Postgres store keeps the same per-client budget and has no
overall cap. A client that starts more than 32 sign-ins from one address
without finishing them loses the oldest, whose `/signin/token` then answers
`invalid_grant`.

Before prod, add a Cloudflare or ingress rate-limit rule on
`/signin/challenge` as well. The budget keeps honest challenges in the
store, but it does not limit request load: every challenge can still be
taken to `/signin/token` once, and each attempt there costs a verified DPoP
proof and a directory resolve.

### Validation surface

`GET /signin/keys`, `GET /signin/.well-known/jwks.json`,
`GET /signin/.well-known/openid-configuration`.

### Browsers

Browsers may call `/signin` from the origins in `SIGNIN_CORS_ORIGINS`: an
allowed origin's preflight is answered with `GET, POST, OPTIONS` and the
`Content-Type` and `DPoP` headers. With origins configured, every `/signin`
response carries `Vary: Origin`, whether or not the request had an `Origin`.
Any other origin gets no CORS headers, and `/exchange` sends none.

## Token

`iss`, `sub` (the DID), `aud`, `iat`, `nbf`, `exp`, `jti`, `scope`
(space-separated), `cnf: {jkt}` and `vm`, the fragment of the verification
method that signed in, without `#` (`"wallet"`, `"signing"`). The token dauth
mints for itself to call the org host (see below) was not signed in for and
has no `vm`. RS256, `kid` = RFC 7638 thumbprint of the signing key.

---

# /exchange — access tokens

## Flow

```
client                                dauth                               org host
  │  POST /exchange                     │                                      │
  │  Authorization: DPoP <identity>     │                                      │
  │  DPoP: <proof, ath = identity>      │                                      │
  │  {grant, vehicle, abilities}        │                                      │
  │ ───────────────────────────────────▶  verify identity token (sub = caller, │
  │                                     │    aud = <PUBLIC_BASE_URL>/exchange) │
  │                                     │  verify DPoP proof → jkt = cnf.jkt   │
  │                                     │  POST /authorize as DAUTH_DID ───────▶
  │                                     │  {uri, caller, vehicle, abilities}   │
  │                                     │  ◀── coverage | 403 {code}           │
  │                                     │  group abilities by window, sign     │
  │  ◀───────────────────────────────── { token, token_type: "DPoP", … }       │
```

dauth calls the host with an identity token for its own DID (`DAUTH_DID`),
minted by the sign-in issuer with the `read` scope and bound to a key dauth
generates at startup; the host lists that DID in `ISSUER_DIDS` and reads
dauth's keys from `…/signin/keys`.

## API

### `POST /exchange`

Headers: `Authorization: DPoP <identity token>`, addressed to
`<PUBLIC_BASE_URL>/exchange` and carrying the `read` scope, and
`DPoP: <proof>`. The proof is an RFC 9449 proof JWT (ES256 or RS256,
`typ: dpop+jwt`, public key in `jwk`, claims `jti`, `htm: POST`,
`htu: <PUBLIC_BASE_URL>/exchange`, `iat` within five minutes, and `ath`, the
identity token's hash) from the key the identity token is bound to; the access
token is bound to it too. did-directory's `pkg/dpop.Key.Proof` makes one.

```json
{
  "grant": "at://did:dimo:avis/network.dimo.delegation/booking1:history",
  "vehicle": "did:dimo:veh…",
  "abilities": ["telemetry:read", "location:precise"],
  "audience": ["dq"],
  "client_assertion": "<JWT signed by the app's DID key>"
}
```

`client_assertion` is optional and names the app the caller is using. It is
an RFC 7523-style assertion the app signs with a key its DID document lists:

```
header  {"alg": "ES256", "kid": "<app DID>#signing"}
claims  {"iss": <app DID>, "sub": <app DID>, "aud": "<PUBLIC_BASE_URL>/exchange",
         "iat", "exp" (at most 5 minutes after iat), "jti",
         "cnf": {"jkt": <thumbprint of the caller's DPoP key>}}
```

dauth checks the signature against the app's DID document, refuses a `jti` it
has seen, and requires `cnf.jkt` to be the key of this request's DPoP proof,
so an assertion the app made for one caller cannot be used by another. It
passes the app's DID to the host as `clientId`, which is what a delegation's
`clientAllowlist` is checked against. Without one no client is claimed, and a
delegation with an allowlist refuses. An identity token is not an assertion:
it would let whoever held it sign in as the app.

The token carries only the abilities asked for, of those the host covers.

Returns `{ token, token_type: "DPoP", expires_in, expires_at }`. Refusals:
`invalid_token` (401, including a token addressed elsewhere), `invalid_client`
(401 for a bad assertion, 400 when it names the caller), `invalid_dpop_proof`
(400), `invalid_request` (400, also when the host cannot read the request),
the host's own code (403: `not_covered`, `exclusive_hold` with `suspended`,
`unauthorized`, `revoked`, `not_valid`, …; 404 `not_found`), `server_error`
(502 when the host is unreachable; 503 with `Retry-After: 1` when the
directory does not answer for the app's DID: a timeout, 408, 429, any other
4xx or a 5xx, or when the DPoP proof could not be checked). An app DID the
directory does not hold or will not serve (404, 400, 410, 422) is
`invalid_client`.

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
| `SIGNIN_ALLOWED_AUDIENCES` | | | Audiences a challenge may request instead; none may end in `/` |
| `SIGNIN_CORS_ORIGINS` | | | Browser origins allowed to call `/signin` (comma-separated), each exactly as a browser sends `Origin`: lowercase `scheme://host[:port]`, no path, trailing `/`, `*` or default port (`:443`, `:80`); empty sends no CORS headers |
| `SIGNIN_RATE_LIMIT_PER_SECOND` | | `5` | Per-client limit (IPv4 address or IPv6 /64, per pod) on the two `/signin` POSTs, burst twice the rate; `0` turns it off |
| `SIGNIN_TRUSTED_PROXIES` | | | CIDRs or addresses whose `X-Forwarded-For` names the client (comma-separated) |
| `SIGNIN_SIGNING_KEY_1…N` | yes | | PEM RSA keys, first active; must differ from the `/exchange` keys |
| `CHALLENGE_TTL`, `TOKEN_TTL`, `APPROVE_TOKEN_TTL` | | `5m`, `15m`, the shorter of `5m` and `TOKEN_TTL` | Lifetimes, each above 0; `APPROVE_TOKEN_TTL` is for tokens carrying `approve` and, when set, may not exceed `TOKEN_TTL` |
| `DATABASE_URL` | | | Postgres challenge store; unset = in-memory, single replica |
| `EXCHANGE_ISSUER` | yes | | `iss` of access tokens |
| `EXCHANGE_AUDIENCE` | | `dq` | Default `aud` of access tokens |
| `EXCHANGE_SIGNING_KEY_1…N` | yes | | PEM RSA keys, first active |
| `ORG_HOST_URL` | yes | | Org host that answers `/authorize` |
| `ORG_HOST_TIMEOUT` | | `10s` | Per-call timeout |
| `DAUTH_DID` | yes | | DID dauth presents to the host |
| `EXCHANGE_LIVE_TTL`, `EXCHANGE_HISTORICAL_TTL` | | `15m`, `2h` | Access token lifetimes |
| `HTTP_ADDRESS`, `OPS_ADDRESS` | | `:8080`, `:8081` | Listeners |
| `ENABLE_PPROF`, `LOG_LEVEL` | | | Ops |

## Signing keys

Each surface loads numbered PEM RSA keys (PKCS#1 or PKCS#8, 2048 bits or
more). The first signs; the rest stay in the JWKS so their tokens keep
verifying through a rotation. The two surfaces' keys must all differ: startup
fails if a `/signin` key is also an `/exchange` key.

To rotate a surface's key:

1. Add the new key as `_2` and deploy. The JWKS now lists both; `_1` still
   signs.
2. Wait at least the JWKS `max-age` (5 minutes) plus any downstream caches, so
   every validator has fetched the new key.
3. Swap the order (new key to `_1`, old to `_2`) and deploy. New tokens are
   signed by the new key.
4. Wait at least the surface's longest token lifetime (`TOKEN_TTL` for
   `/signin`), so no token from the old key is still valid, then remove the
   old key and deploy.
5. After a removal, refresh or restart every verifier that caches the JWKS
   (the org host refetches every 5 minutes; accounts and other relying
   parties follow their own cache). A removed key keeps verifying wherever a
   cache still holds it, so for a compromised key, restart them all at once.

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing.pem
```

# Deployment

`charts/dauth` deploys the binary with `.Values.env` rendered into a ConfigMap
and the signing keys and `DATABASE_URL` expected from a Secret. Probes are on
the ops port (`/ping`, `/ready`, `/metrics`). Rendering fails when
`replicaCount` is above 1 and `postgres.enabled` is false: the in-memory
challenge store is per pod, so more replicas need the Postgres store. The
in-memory store holds at most 50,000 challenges, sized to the chart's 256 MiB
memory limit. With Postgres disabled, a rolling deploy also drops every
challenge in flight: the new pod starts with an empty store, so a client that
asked the old pod for a challenge gets `invalid_grant` at `/signin/token` and
must start again. The chart's ingress sets no rate limit; the per-IP limit on
the `/signin` POSTs is dauth's own, and the chart sets
`SIGNIN_TRUSTED_PROXIES` to loopback and the private ranges so it sees client
addresses. After deploying to dev, check that the `remote` field on `/signin`
log lines (a failed sign-in logs one) shows distinct public client IPs, not
`127.0.0.1` or one private address; if it does not, every client shares one
bucket, so fix the client-IP path (the load balancer must preserve source
addresses) or set `SIGNIN_RATE_LIMIT_PER_SECOND` to `0` before prod.

Sign-in failure logs (`sign-in key not found`, `invalid signature`) record the
client IP (`remote`) next to the DID (`did`). Together they link a person's
DID to a network address, so treat these logs as personal data in retention
and access.

`values-prod.yaml` sets `requireExchangeConfig: true`: rendering fails unless
`env.ORG_HOST_URL` and `env.DAUTH_DID` are set to real values (no
`REPLACE_WITH` placeholder). It also sets both to `null`, so prod never
inherits dev's values from `values.yaml` through Helm's merge.

Prod's image is promoted by PR. `buildpushdev` writes each main push's SHA to
`values.yaml`'s `image.tag` only, for dev. `values-prod.yaml` sets an empty
`image.tag` with `image.requireTag: true`, so prod fails to render until a PR
sets that tag to a SHA already running in dev.

# Development

```
make run      # keys under .local/, Postgres via docker compose, dauth on :8080
make test
```

`make run` expects a DID directory on `DIRECTORY_URL` (default
`http://localhost:8082`) and an org host on `ORG_HOST_URL` (default
`http://localhost:8081`) configured with `ISSUER_DIDS=did:dimo:dauth`,
`IDENTITY_JWKS_URL=http://localhost:8080/signin/keys`,
`IDENTITY_ISSUER=http://localhost:8080/signin` and
`IDENTITY_AUDIENCE=http://localhost:8081`. Then, from the did-directory repo,
`dimocli signin --did <did> --dauth http://localhost:8080 --audience
http://localhost:8081` prints an identity token the host accepts.
