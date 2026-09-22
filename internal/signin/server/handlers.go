package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/DIMO-Network/dauth/internal/httpmw"
	"github.com/DIMO-Network/dauth/internal/signin/nonce"
	"github.com/DIMO-Network/dauth/internal/signin/token"
	"github.com/rs/zerolog"
)

// defaultKeyFragment is the verification method a sign-in uses when the
// request names none: the #signing key dimocli publishes on every DID it
// creates.
const defaultKeyFragment = "signing"

// fragmentPattern bounds a verification method fragment to what a DID
// document fragment can be.
var fragmentPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Handlers serves the sign-in endpoints.
type Handlers struct {
	Store    nonce.Store
	Verifier *Verifier
	Issuer   *token.Issuer

	Domain       string // shown in the challenge text
	ChallengeTTL time.Duration

	// AllowedAudiences is the allow-list of non-default `aud` values a caller may
	// request on POST /challenge. A requested audience is honored only if every
	// value is in this list; empty means no override is permitted. When a caller
	// omits `audience`, the issuer's configured default audience is used.
	AllowedAudiences []string

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
	// DID is the DID signing in. Its document in the directory must list the
	// key that will sign the challenge.
	DID string `json:"did"`
	// Audience optionally requests a specific `aud` for the issued token. Every
	// value must be on the server's allow-list (SIGNIN_ALLOWED_AUDIENCES) or the
	// challenge is rejected. Omit it to receive the configured default audience.
	Audience []string `json:"audience,omitempty"`
}

type challengeResponse struct {
	// Challenge is the text to sign: SHA-256 of these exact bytes, ECDSA,
	// signature encoded as base64url r||s.
	Challenge string `json:"challenge"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expires_at"`
}

type tokenRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
	// Key is the fragment of the verification method that signed, without the
	// '#'. Defaults to "signing".
	Key string `json:"key,omitempty"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

// errorResponse is the OAuth-style error body returned on failure. Clients
// branch on the stable `error` code rather than parsing the description.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Challenge issues a challenge for the requested DID and records its
// single-use nonce.
func (h *Handlers) Challenge() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req challengeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
			return
		}
		if !isDID(req.DID) {
			writeError(w, http.StatusBadRequest, "invalid_request", "did is not a valid DID")
			return
		}

		// Validate any requested audience against the allow-list and bind it to
		// the nonce now, so the `aud` is fixed at challenge time and cannot be
		// swapped at /token. An empty Audience falls through to the issuer's
		// default. Reject before a nonce is created so a disallowed request never
		// yields a usable challenge.
		if !h.audienceAllowed(req.Audience) {
			writeError(w, http.StatusBadRequest, "invalid_request", "requested audience is not allowed")
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
		msg := challengeText(h.Domain, req.DID, id, now, expiresAt)

		// The store is keyed by the nonce, which the client returns to /token.
		if err := h.Store.Put(r.Context(), id, nonce.Challenge{
			Message:   msg,
			DID:       req.DID,
			ExpiresAt: expiresAt,
			Audience:  req.Audience,
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

// challengeText is what the key signs. It names the domain, the DID, the
// nonce and the validity so a signature cannot be repurposed for another
// service, another identity or a later time.
func challengeText(domain, did, nonce string, issued, expires time.Time) string {
	return fmt.Sprintf("%s wants you to sign in as\n%s\n\nNonce: %s\nIssued At: %s\nExpiration Time: %s",
		domain, did, nonce, issued.Format(time.RFC3339), expires.Format(time.RFC3339))
}

// Token verifies a signed challenge and returns an identity token.
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
		if req.Signature == "" {
			writeError(w, http.StatusBadRequest, "invalid_request", "signature is required")
			return
		}
		fragment := strings.TrimPrefix(req.Key, "#")
		if fragment == "" {
			fragment = defaultKeyFragment
		}
		if !fragmentPattern.MatchString(fragment) {
			writeError(w, http.StatusBadRequest, "invalid_request", "key is not a valid verification method fragment")
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

		// Verify against the stored canonical message and the DID's current
		// document. A key rotated out since the challenge was issued no longer
		// signs in, which is the point of resolving at token time.
		err = h.Verifier.Verify(r.Context(), ch.DID, fragment, []byte(ch.Message), req.Signature)
		switch {
		case err == nil:
		case errors.Is(err, ErrDirectory):
			// The nonce is already consumed; the client must request a fresh
			// challenge and retry.
			h.Log.Warn().Err(err).Str("did", ch.DID).Msg("directory unavailable during sign-in")
			writeError(w, http.StatusServiceUnavailable, "server_error", "could not resolve the DID, retry shortly")
			return
		case errors.Is(err, ErrDIDNotFound), errors.Is(err, ErrNoSuchKey):
			h.Log.Warn().Err(err).Str("did", ch.DID).Str("remote", httpmw.RemoteIP(r)).Msg("sign-in key not found")
			writeError(w, http.StatusUnauthorized, "invalid_grant", err.Error())
			return
		default:
			h.Log.Warn().Err(err).Str("did", ch.DID).Str("remote", httpmw.RemoteIP(r)).Msg("invalid signature")
			writeError(w, http.StatusUnauthorized, "invalid_grant", "signature does not verify against the DID's key")
			return
		}

		tok, _, err := h.Issuer.Issue(ch.DID, ch.Audience)
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

// audienceAllowed reports whether a requested audience may be honored. An empty
// request is always allowed (the issuer falls back to its default audience); a
// non-empty request is allowed only if every value appears on the configured
// allow-list. With no allow-list configured, only the empty (default) request
// passes.
func (h *Handlers) audienceAllowed(requested []string) bool {
	for _, want := range requested {
		if !contains(h.AllowedAudiences, want) {
			return false
		}
	}
	return true
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
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
