package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/nonce"
	"github.com/DIMO-Network/dauth/internal/signer"
	"github.com/DIMO-Network/dauth/internal/siwe"
	"github.com/DIMO-Network/dauth/internal/token"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
)

// Handlers serves the sign-in endpoints.
type Handlers struct {
	Store    nonce.Store
	Verifier *signer.Verifier
	Issuer   *token.Issuer

	Domain       string // SIWE domain shown in the message
	URI          string // SIWE uri (the issuer URL)
	Statement    string // SIWE statement
	ChainID      uint64 // chain the sign-in is bound to
	ChallengeTTL time.Duration

	Log zerolog.Logger
	Now func() time.Time // injectable clock; nil uses time.Now
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

type challengeRequest struct {
	Address string `json:"address" example:"0x6E4...A1b"`
}

type challengeResponse struct {
	Challenge string `json:"challenge" example:"dauth.dimo.zone wants you to sign in with your Ethereum account:..."`
	Nonce     string `json:"nonce" example:"a1b2c3..."`
	ExpiresAt string `json:"expires_at" example:"2026-06-14T17:25:00Z"`
}

type tokenRequest struct {
	Nonce     string `json:"nonce" example:"a1b2c3..."`
	Signature string `json:"signature" example:"0x1c8f..."`
}

type tokenResponse struct {
	Token     string `json:"token" example:"eyJ..."`
	TokenType string `json:"token_type" example:"Bearer"`
	ExpiresIn int    `json:"expires_in" example:"600"`
}

// errorResponse is the OAuth-style error body returned on failure. Clients
// branch on the stable `error` code rather than parsing the description.
type errorResponse struct {
	Error            string `json:"error" example:"invalid_grant"`
	ErrorDescription string `json:"error_description" example:"challenge not found, already used, or expired"`
}

// Challenge issues a SIWE message for the requested address and records its
// single-use nonce.
//
// @Summary     Request a SIWE challenge
// @Description Generates an EIP-4361 (Sign-In With Ethereum) message for the given address and records its single-use nonce. The client signs the returned `challenge` string with its wallet and submits it to POST /auth/token. The chain is fixed by server config.
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       request body server.challengeRequest true "Address to sign in"
// @Success     200 {object} server.challengeResponse
// @Failure     400 {object} server.errorResponse "invalid_request"
// @Failure     429 {object} server.errorResponse "rate limited"
// @Failure     500 {object} server.errorResponse "server_error"
// @Failure     503 {object} server.errorResponse "challenge store unavailable"
// @Router      /challenge [post]
func (h *Handlers) Challenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req challengeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
			return
		}

		if !common.IsHexAddress(req.Address) {
			writeError(w, http.StatusBadRequest, "invalid_request", "address is not a valid Ethereum address")
			return
		}
		addr := common.HexToAddress(req.Address)
		if addr == (common.Address{}) {
			writeError(w, http.StatusBadRequest, "invalid_request", "address must not be the zero address")
			return
		}

		id, err := nonce.New()
		if err != nil {
			h.Log.Error().Err(err).Msg("generating nonce")
			writeError(w, http.StatusInternalServerError, "server_error", "could not generate challenge")
			return
		}

		now := h.now().UTC()
		expiresAt := now.Add(h.ChallengeTTL)
		msg := siwe.Message{
			Domain:         h.Domain,
			Address:        addr,
			Statement:      h.Statement,
			URI:            h.URI,
			ChainID:        h.ChainID,
			Nonce:          id,
			IssuedAt:       now,
			ExpirationTime: expiresAt,
		}.String()

		// The store is keyed by the nonce, which the client returns to /token.
		if err := h.Store.Put(r.Context(), id, nonce.Challenge{
			Message:   msg,
			Address:   addr,
			ExpiresAt: expiresAt,
		}); err != nil {
			h.Log.Warn().Err(err).Msg("storing challenge")
			writeError(w, http.StatusServiceUnavailable, "server_error", "challenge store unavailable, retry shortly")
			return
		}

		writeJSON(w, http.StatusOK, challengeResponse{
			Challenge: msg,
			Nonce:     id,
			ExpiresAt: expiresAt.Format(time.RFC3339),
		})
	})
}

// Token verifies a signed challenge and returns an access token.
//
// @Summary     Exchange a signed challenge for an access token
// @Description Looks up the stored challenge by nonce, consumes it (single-use), and verifies the signature over the canonical SIWE message — EOA via ecrecover, or a deployed smart account via EIP-1271. On success, mints a short-lived RS256 JWT carrying the address.
// @Tags        auth
// @Accept      json
// @Produce     json
// @Param       request body server.tokenRequest true "Nonce and 0x-prefixed signature"
// @Success     200 {object} server.tokenResponse
// @Failure     400 {object} server.errorResponse "invalid_request"
// @Failure     401 {object} server.errorResponse "invalid_grant"
// @Failure     500 {object} server.errorResponse "server_error"
// @Failure     503 {object} server.errorResponse "verification backend unavailable"
// @Router      /token [post]
func (h *Handlers) Token() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
			return
		}
		if req.Nonce == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "nonce is required")
			return
		}
		sig, err := hexutil.Decode(req.Signature)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "signature must be 0x-prefixed hex")
			return
		}

		// Look the challenge up by nonce and consume it. Single-use: a replayed
		// nonce, an expired challenge, or an unknown nonce all surface
		// identically as invalid_grant.
		ch, err := h.Store.Consume(r.Context(), req.Nonce)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid_grant", "challenge not found, already used, or expired")
			return
		}

		// Verify against the stored canonical message.
		valid, err := h.Verifier.Verify(r.Context(), ch.Address, []byte(ch.Message), sig)
		if err != nil {
			// The signature could not be checked because the Ethereum backend
			// was unavailable. The nonce is already consumed; the client must
			// request a fresh challenge and retry.
			h.Log.Warn().Err(err).Str("address", ch.Address.Hex()).Msg("signature verification backend error")
			if errors.Is(err, signer.ErrBackend) {
				writeError(w, http.StatusServiceUnavailable, "server_error", "could not verify signature, retry shortly")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", "could not verify signature")
			return
		}
		if !valid {
			h.Log.Warn().Str("address", ch.Address.Hex()).Str("remote", httpmw.RemoteIP(r)).Msg("invalid signature")
			writeError(w, http.StatusUnauthorized, "invalid_grant", "signature does not match address")
			return
		}

		tok, _, err := h.Issuer.Issue(ch.Address)
		if err != nil {
			h.Log.Error().Err(err).Msg("issuing token")
			writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
			return
		}

		writeJSON(w, http.StatusOK, tokenResponse{
			Token:     tok,
			TokenType: "Bearer",
			ExpiresIn: int(h.Issuer.TTL().Seconds()),
		})
	})
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError emits an OAuth-style error body so clients can branch on a stable
// code without parsing prose.
func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, errorResponse{Error: code, ErrorDescription: description})
}
