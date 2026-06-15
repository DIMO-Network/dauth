package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

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
	Address string `json:"address"`
}

type challengeResponse struct {
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

type tokenRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

// Challenge issues a SIWE message for the requested address and records its
// single-use nonce.
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
		if err := h.Store.Put(id, nonce.Challenge{
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
		ch, err := h.Store.Consume(req.Nonce)
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
			h.Log.Warn().Str("address", ch.Address.Hex()).Str("remote", remoteIPKey(r)).Msg("invalid signature")
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
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}
