#!/usr/bin/env bash
#
# signin.sh — demo dauth's SIWE sign-in end to end.
#
# Generates a throwaway Ethereum key (or uses $PK), requests a challenge,
# personal_signs it with Foundry's `cast`, exchanges it for a token, and prints
# the decoded JWT claims.
#
# Requires: cast (Foundry), curl, jq. Needs a running dauth.
#
# Usage:
#   scripts/signin.sh                  # against http://localhost:8080
#   BASE_URL=http://localhost:8099 scripts/signin.sh
#   PK=0xabc... scripts/signin.sh      # reuse a specific key instead of a throwaway
#
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"

# --- preflight ---------------------------------------------------------------
for tool in cast curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: '$tool' is required but not installed" >&2; exit 1; }
done

note() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# --- 0. wallet ---------------------------------------------------------------
if [[ -n "${PK:-}" ]]; then
  note "Using key from \$PK"
else
  note "Generating a throwaway wallet"
  PK="$(cast wallet new --json | jq -r '.[0].private_key')"
fi
ADDR="$(cast wallet address --private-key "$PK")"
echo "    address: $ADDR"

# --- 1. challenge ------------------------------------------------------------
note "POST $BASE_URL/siwe/challenge"
CH="$(curl -fsS -X POST "$BASE_URL/siwe/challenge" \
  -H 'content-type: application/json' \
  -d "$(jq -nc --arg a "$ADDR" '{address:$a}')")" \
  || fail "challenge request failed — is dauth running at $BASE_URL?"

# jq -r un-escapes the JSON \n back into the real newlines that were signed.
MSG="$(jq -r .challenge <<<"$CH")"
NONCE="$(jq -r .nonce <<<"$CH")"
[[ -n "$NONCE" && "$NONCE" != null ]] || fail "no nonce in response: $CH"
echo "    nonce:   $NONCE"

# --- 2. sign -----------------------------------------------------------------
note "personal_sign the challenge with cast (EIP-191)"
SIG="$(cast wallet sign --private-key "$PK" "$MSG")"
echo "    sig:     ${SIG:0:24}…"

# --- 3. exchange -------------------------------------------------------------
note "POST $BASE_URL/siwe/token"
TOK="$(curl -fsS -X POST "$BASE_URL/siwe/token" \
  -H 'content-type: application/json' \
  -d "$(jq -nc --arg n "$NONCE" --arg s "$SIG" '{nonce:$n, signature:$s}')")" \
  || fail "token request failed (the nonce is single-use; a failed attempt burns it — rerun for a fresh one)"

JWT="$(jq -r .token <<<"$TOK")"
[[ -n "$JWT" && "$JWT" != null ]] || fail "no token in response: $TOK"

# --- 4. show the token -------------------------------------------------------
# base64url-decode the JWT payload (second segment), padding to a multiple of 4.
decode_segment() {
  local seg="${1//-/+}"; seg="${seg//_//}"
  case $(( ${#seg} % 4 )) in 2) seg+='==';; 3) seg+='=';; esac
  printf '%s' "$seg" | base64 -d 2>/dev/null
}

note "Token acquired — decoded claims:"
CLAIMS="$(decode_segment "$(cut -d. -f2 <<<"$JWT")")"
jq . <<<"$CLAIMS"

# Human-readable expiry from the exp claim (date(1) differs on macOS vs GNU).
EXP="$(jq -r .exp <<<"$CLAIMS")"
EXP_HUMAN="$(date -r "$EXP" 2>/dev/null || date -d "@$EXP" 2>/dev/null || echo "epoch $EXP")"
note "Expires: $EXP_HUMAN ($(jq -r .expires_in <<<"$TOK")s after issue)"

echo
note "Raw token:"
echo "$JWT"
