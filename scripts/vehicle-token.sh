#!/usr/bin/env bash
#
# vehicle-token.sh — private key to a vehicle-scoped permission JWT, in one step.
#
# signin.sh stops at the /siwe sign-in token, which no data API accepts. This
# carries on through /exchange/tokens/exchange to the permission token that dq
# and friends actually validate, so getting a usable token is one command
# instead of four curls and a hand-run `cast wallet sign`.
#
# The token goes to STDOUT and nothing else does, so it composes:
#
#   TOKEN=$(PK=0xabc… TOKEN_ID=192641 scripts/vehicle-token.sh)
#   curl -H "authorization: Bearer $TOKEN" https://dq.gcp.dimo.xyz/query …
#
# Progress and errors go to stderr. Pass -v to also dump the decoded claims
# there (useful for checking which permissions the chain actually granted —
# the exchange silently returns a token carrying only the permissions your
# license holds, so asking for more than you have is not an error).
#
# Requires: cast (Foundry), curl, jq.
#
# Environment:
#   PK            (required) signer private key, 0x-prefixed
#   TOKEN_ID      (required) vehicle NFT token id, e.g. 192641
#   BASE_URL      dauth base URL           (default https://dauth.gcp.dimo.xyz)
#   NFT_CONTRACT  vehicle NFT address      (default Polygon DIMO vehicle NFT)
#   PRIVILEGES    space-separated ids      (default "1 2 3 4 5 6 7")
#   AUDIENCE      space-separated audience (default none)
set -euo pipefail

BASE_URL="${BASE_URL:-https://dauth.gcp.dimo.xyz}"
NFT_CONTRACT="${NFT_CONTRACT:-0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF}"
PRIVILEGES="${PRIVILEGES:-1 2 3 4 5 6 7}"
AUDIENCE="${AUDIENCE:-}"
VERBOSE=0
[[ "${1:-}" == "-v" ]] && VERBOSE=1

note() { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

for tool in cast curl jq; do
  command -v "$tool" >/dev/null 2>&1 || fail "'$tool' is required but not installed"
done
[[ -n "${PK:-}" ]]       || fail "PK is required (signer private key, 0x-prefixed)"
[[ -n "${TOKEN_ID:-}" ]] || fail "TOKEN_ID is required (vehicle NFT token id)"

ADDR="$(cast wallet address --private-key "$PK")" || fail "PK is not a valid private key"
note "signer $ADDR → vehicle $TOKEN_ID @ $BASE_URL"

# --- 1. challenge ------------------------------------------------------------
CH="$(curl -fsS -X POST "$BASE_URL/siwe/challenge" \
  -H 'content-type: application/json' \
  -d "$(jq -nc --arg a "$ADDR" '{address:$a}')")" \
  || fail "challenge request failed — is $BASE_URL reachable?"

# jq -r un-escapes the JSON \n back into the real newlines that were signed.
MSG="$(jq -r .challenge <<<"$CH")"
NONCE="$(jq -r .nonce <<<"$CH")"
[[ -n "$NONCE" && "$NONCE" != null ]] || fail "no nonce in challenge response: $CH"

# --- 2. sign (EIP-191 personal_sign) ----------------------------------------
SIG="$(cast wallet sign --private-key "$PK" "$MSG")" || fail "signing failed"

# --- 3. sign-in token --------------------------------------------------------
SIWE="$(curl -fsS -X POST "$BASE_URL/siwe/token" \
  -H 'content-type: application/json' \
  -d "$(jq -nc --arg n "$NONCE" --arg s "$SIG" '{nonce:$n, signature:$s}')")" \
  || fail "sign-in failed — is $ADDR a registered signer?"
SIWE_JWT="$(jq -r .token <<<"$SIWE")"
[[ -n "$SIWE_JWT" && "$SIWE_JWT" != null ]] || fail "no token in sign-in response: $SIWE"
note "signed in"

# --- 4. exchange for a vehicle permission token ------------------------------
# privileges/tokenId are the deprecated-but-still-served fields; they avoid
# depending on the newer asset-DID + named-permissions path being deployed.
# read -ra rather than relying on unquoted word-splitting: this is bash-only
# behaviour and the script is sourced/copied around enough that being explicit
# is worth two lines.
read -ra PRIV_ARR <<<"$PRIVILEGES"
PRIV_JSON="$(printf '%s\n' "${PRIV_ARR[@]}" | jq -Rn '[inputs|select(length>0)|tonumber]')" \
  || fail "PRIVILEGES must be space-separated integers, got: $PRIVILEGES"

REQ="$(jq -nc \
  --argjson t "$TOKEN_ID" \
  --arg c "$NFT_CONTRACT" \
  --argjson p "$PRIV_JSON" \
  '{tokenId:$t, privileges:$p, nftContractAddress:$c}')"
if [[ -n "$AUDIENCE" ]]; then
  read -ra AUD_ARR <<<"$AUDIENCE"
  AUD_JSON="$(printf '%s\n' "${AUD_ARR[@]}" | jq -Rn '[inputs|select(length>0)]')"
  REQ="$(jq -c --argjson a "$AUD_JSON" '.audience=$a' <<<"$REQ")"
fi

EX="$(curl -fsS -X POST "$BASE_URL/exchange/tokens/exchange" \
  -H "authorization: Bearer $SIWE_JWT" \
  -H 'content-type: application/json' -d "$REQ")" \
  || fail "exchange failed — does this signer's license hold permissions on vehicle $TOKEN_ID?"

JWT="$(jq -r .token <<<"$EX")"
[[ -n "$JWT" && "$JWT" != null ]] || fail "no token in exchange response: $EX"

if (( VERBOSE )); then
  seg="$(cut -d. -f2 <<<"$JWT")"; seg="${seg//-/+}"; seg="${seg//_//}"
  case $(( ${#seg} % 4 )) in 2) seg+='==';; 3) seg+='=';; esac
  note "claims:"
  printf '%s' "$seg" | base64 -d 2>/dev/null | jq . >&2 || true
fi

note "permission token acquired"
printf '%s\n' "$JWT"
