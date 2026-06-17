# Folding token-exchange-api into dauth (and retiring DEX)

Status: Draft / RFC
Owner: dylan@dimo.zone
Last updated: 2026-06-17

## Motivation

Two goals:

1. **Retire DEX from the token-exchange path.** token-exchange-api today leans on DEX
   for two things: signing its output permission tokens (`SignToken` gRPC) and
   validating the inbound credential (DEX-issued, `dex.User`-encoded subject). dauth
   already owns the "prove control of an Ethereum address" role and the signing
   machinery (RSA keyset + JWKS). Folding token-exchange in lets it sign locally with
   its own key via dauth's signing code and consume dauth tokens on the way in —
   removing DEX entirely.
2. **Fewer services, one repo.** dauth becomes a small monorepo hosting both stages of
   the auth pipeline, with shared signing code, shared CI, and a single place to reason
   about token issuance and key rotation.

This is **not** a merged request flow and **not** a unified claim schema. The two
services remain conceptually distinct stages with distinct issuers and threat models.

## Background: the two stages

| | dauth (`cmd/dauth`) | token-exchange (`cmd/token-exchange-api`) |
|---|---|---|
| Proves | "I control this address" (SIWE) | "this address may access this asset with these permissions" |
| Input | EIP-4361 signed message | address-control JWT for a dev-license address + asset DID + permissions |
| Output | RS256 JWT, `ethereum_address` claim | RS256 JWT, `asset`/`permissions`/`cloud_events` |
| Issuer | `https://auth.dimo.zone` | `https://auth-roles-rights.dimo.zone` |
| Signs with | own RSA keyset, publishes JWKS | **today: DEX. After: own RSA key via shared keyset code** |
| State | in-memory nonce (single replica) | stateless; calls identity-api / IPFS / chain RPC |
| Stack | Go stdlib `net/http` | Fiber + gRPC |

## End-state architecture

One Go module (`github.com/DIMO-Network/dauth`, Go 1.26), two binaries, two charts,
two images.

```
dauth/
  cmd/dauth/                       # unchanged: SIWE -> address-control JWT
  cmd/token-exchange-api/          # moved in: permission token
  internal/keyset/                 # SHARED: key loading + JWKS rendering
  internal/token/                  # dauth's ethereum_address issuer (thin wrapper over signing core)
  internal/<signing core>/         # SHARED: sign registered+custom claims with active key, set kid/alg
  internal/nonce, siwe, server,    # dauth-specific, unchanged
  internal/tokenexchange/          # moved in: api, app, autheval, config, contracts,
                                   #   controllers, middleware, models, services, signature, docs
  pkg/tokenclaims/                 # moved in (public) -> consumers re-import from dauth path
  pkg/grpc/                        # moved in (public AccessCheck client) -> re-import
  charts/dauth/, charts/token-exchange-api/
```

### Topology rationale

Two binaries, not one process. dauth stays tiny, single-replica (in-memory nonce
store), near-zero deps. token-exchange keeps its heavier dependency surface and scales
independently (HPA). They share only the signing package and the module.

### Key material & issuers

- token-exchange gets its **own RSA signing key** (distinct from dauth's), loaded via the
  shared `keyset` code, and **self-hosts its own `/keys` + discovery** at the
  `auth-roles-rights` host — taking over the JWKS endpoint DEX serves today.
- Issuers stay **distinct**: token-exchange keeps `iss = https://auth-roles-rights.dimo.zone`.
- The security boundary between the two token types is the **separate key + separate
  JWKS**, not the `iss` string. A dauth address-control token (different key, not in the
  permission JWKS) fails signature validation at a permission consumer regardless of
  whether `iss` is checked.

## DEX retirement: the two swaps

1. **Output signing.** Replace the `SignToken` gRPC call
   (`internal/services/dex_service.go`) with local signing through the shared signing
   core, using token-exchange's own key. Output keeps `iss=auth-roles-rights.dimo.zone`,
   default `aud=dimo.zone`, and the identical claim shape (incl. legacy
   `contract_address`/`token_id`/`privilege_ids`). Drop the `dexidp/dex/api/v2`
   dependency and its `replace` directive once unreferenced.

2. **Inbound validation.** The Fiber `jwtware` on the inbound is **signature-only**, so
   the only change is repointing `JWT_KEY_SET_URL` to dauth's JWKS. The
   `valid_dev_license` middleware collapses to:

   ```
   addr := ethereum_address claim      // same claim GetUserEthAddr already reads
   IsDevLicense(addr)                  // gate now applies to everyone, incl. mobile
   responseSubject = addr              // output sub = real address
   ```

   Delete the base64 / `proto.Unmarshal` / `dex.User` decode, the `dimo-driver`
   constant, and the `internal/middleware/dex` package.

### Mobile

The `aud == "dimo-driver"` passthrough is **deleted**. Mobile users/app carry dev
licenses like any integrator and pass the same `IsDevLicense` gate. Authorization
already rests on the `ethereum_address` claim + the on-chain/SACD access check, which
dauth tokens satisfy unchanged. Mobile's output token `sub` becomes the real address
instead of the literal `dimo-driver` (a legacy mode the code already flagged for
removal).

## Consumers and the cutover

Permission-token consumers (`telemetry-api`, `dq`, `fetch-api`) validate via auth0's
`validator`, which **does** enforce `iss` + `aud=dimo.zone`. `din` consumes the
address-control token (already on dauth) and is unaffected. `vehicle-triggers-api`
consumes the gRPC `AccessCheck` client (signature-only Fiber `jwtware` for any JWT).

### Public package move (chosen approach: move + update all importers)

`pkg/tokenclaims` (31 import sites) and `pkg/grpc` (AccessCheck client) move to
`github.com/DIMO-Network/dauth/pkg/...`. The four importers (`telemetry-api`, `dq`,
`fetch-api`, `vehicle-triggers-api`) bump their import path + `go.mod`. This is
**build-time only** — the runtime claim contract is unchanged — so it can land
independently of the auth cutover.

### Flag-day sequence (brief downtime acceptable)

1. Ship the folded repo: token-exchange binary signs locally, serves its own JWKS at
   the `auth-roles-rights` host, consumes dauth inbound tokens.
2. Provision token-exchange's signing key (own secret), confirm it appears in its JWKS.
3. Repoint consumers' `TOKEN_EXCHANGE_JWK_KEY_SET_URL` off the dying DEX pod
   (`dex-roles-rights-prod:5556/keys`) to the new token-exchange `/keys`. `iss` is
   **unchanged** (`auth-roles-rights.dimo.zone`), so the issuer check keeps passing.
4. Move mobile + dev login to dauth.
5. Retire the DEX `dex-roles-rights` instance.

Consumer Go import-path bumps can land before/independently of the runtime cutover.

## Open implementation details

- **Git history on the move.** Decide whether to bring token-exchange's history via
  `git subtree` / `--allow-unrelated-histories`, or accept a clean copy. (Initial
  implementation uses a copy; can be redone as a history-preserving merge before
  finalizing.)
- **CI merge.** Build two images from one repo; reconcile lint config and the `tool`
  directive (abigen/swag/mockgen/protoc-gen).
- **Config style.** Keep each binary's existing mechanism for now (dauth = env,
  token-exchange = `settings.yaml`).
- **Dependency reconciliation.** Module takes the union of both dependency trees; verify
  go-ethereum / golang-jwt version bumps don't regress either binary.
- **`sub == "dimo-driver"` downstream.** Grep consumers for any special-casing of the
  literal mobile subject before flipping mobile output to real addresses.
```
