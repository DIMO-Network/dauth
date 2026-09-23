// Package exchange is dauth's /exchange surface (design spec §11.1, plan §5):
// a caller holding an identity token and a DPoP key names a delegation, a
// vehicle and the abilities it wants; dauth asks the org host whether that
// caller may exercise that delegation (plan §1 decision A: dauth
// authenticates, the org host authorizes) and mints a DPoP-bound access token
// carrying the coverage the host computed.
package exchange

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/pkg/dpop"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Request is the body of POST /exchange.
type Request struct {
	// Grant is the at:// URI of the delegation the caller is exercising.
	Grant string `json:"grant"`
	// Vehicle is the vehicle DID the token is for.
	Vehicle string `json:"vehicle"`
	// Abilities are the abilities asked for; the token carries the subset the
	// host covers.
	Abilities []string `json:"abilities"`
	// Audience optionally narrows aud; every value must be in the configured
	// audience list.
	Audience []string `json:"audience,omitempty"`
	// ClientAssertion identifies the app the caller is using: a short JWT the
	// app signs with its own DID's key, addressed to this exchange and bound to
	// the caller's DPoP key (see AssertionVerifier). Its iss is what the host
	// checks a delegation's clientAllowlist against. Without one no client is
	// claimed, and a delegation with an allowlist refuses.
	ClientAssertion string `json:"client_assertion,omitempty"`
}

// Response is the body of a successful exchange.
type Response struct {
	Token     string    `json:"token"`
	TokenType string    `json:"token_type"`
	ExpiresIn int       `json:"expires_in"`
	ExpiresAt time.Time `json:"expires_at"`
}

type errorResponse struct {
	Error            string   `json:"error"`
	ErrorDescription string   `json:"error_description"`
	Suspended        []string `json:"suspended,omitempty"`
}

// Handler serves the exchange.
type Handler struct {
	Config Config
	Keys   *keyset.KeySet
	// Host answers /authorize.
	Host Authorizer
	// Assertions verifies client assertions; the caller's own identity token
	// was verified by the middleware.
	Assertions *AssertionVerifier
	// DPoP verifies proofs; ExchangeURL is the htu a proof must name.
	DPoP        *dpop.Verifier
	ExchangeURL string
	Log         zerolog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ServeHTTP handles POST /exchange. The identity middleware has already put
// the caller's DID in the context.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	caller, ok := CallerFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid_token", "no authenticated caller")
		return
	}

	// The DPoP proof binds the token to a key only the caller holds (spec
	// §11.1: tokens are always DPoP-bound). It is checked before the body so
	// a proof-less request costs nothing downstream.
	proof := r.Header.Get(dpop.HeaderName)
	if proof == "" {
		writeError(w, http.StatusBadRequest, "invalid_dpop_proof", "a DPoP proof header is required")
		return
	}
	jkt, err := h.DPoP.Verify(proof, http.MethodPost, h.ExchangeURL, "")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_dpop_proof", err.Error())
		return
	}

	var req Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not parse request body")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	for _, aud := range req.Audience {
		if !slices.Contains(h.Config.Audience, aud) {
			writeError(w, http.StatusBadRequest, "invalid_request", "requested audience is not allowed")
			return
		}
	}

	// dauth vouches for nothing more than that the app holds its key and
	// signed for this request; whether the delegation admits that app is the
	// host's call.
	var clientID string
	if req.ClientAssertion != "" {
		did, err := h.Assertions.Verify(r.Context(), req.ClientAssertion, jkt)
		switch {
		case errors.Is(err, ErrAssertionKeys):
			h.Log.Warn().Err(err).Msg("resolving the app's keys")
			writeError(w, http.StatusServiceUnavailable, "server_error", "could not resolve the app's DID, retry shortly")
			return
		case err != nil:
			writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
			return
		}
		if did == caller {
			writeError(w, http.StatusBadRequest, "invalid_client", "client_assertion must identify an app, not the caller")
			return
		}
		clientID = did
	}

	cov, err := h.Host.Authorize(r.Context(), AuthorizeRequest{
		URI: req.Grant, Caller: caller, ClientID: clientID, Vehicle: req.Vehicle, Abilities: req.Abilities,
	})
	if err != nil {
		var refusal *Refusal
		switch {
		case errors.As(err, &refusal):
			h.Log.Info().Str("caller", caller).Str("grant", req.Grant).Str("vehicle", req.Vehicle).Str("code", refusal.Code).Msg("exchange refused")
			status := http.StatusForbidden
			if refusal.Status == http.StatusNotFound || refusal.Status == http.StatusBadRequest {
				status = refusal.Status
			}
			writeJSON(w, status, errorResponse{Error: refusal.Code, ErrorDescription: refusal.Message, Suspended: refusal.Suspended})
		case errors.Is(err, ErrOrgHost):
			h.Log.Error().Err(err).Str("grant", req.Grant).Msg("org host unavailable")
			writeError(w, http.StatusBadGateway, "server_error", "the org host could not be reached, retry shortly")
		default:
			h.Log.Error().Err(err).Str("grant", req.Grant).Msg("authorize failed")
			writeError(w, http.StatusInternalServerError, "server_error", "could not authorize")
		}
		return
	}

	// The token carries what was asked for, of what the host covers, and never
	// more: a host answering for another vehicle or with abilities nobody
	// requested is not believed.
	if cov.Vehicle != req.Vehicle {
		h.Log.Error().Str("grant", req.Grant).Str("asked", req.Vehicle).Str("answered", cov.Vehicle).Msg("org host answered for another vehicle")
		writeError(w, http.StatusBadGateway, "server_error", "the org host answered for another vehicle")
		return
	}
	cov = cov.restrictTo(req.Abilities)
	grants := grantsFor(cov)
	if len(grants) == 0 {
		// The host answers 403 for empty coverage; this is belt and braces.
		writeError(w, http.StatusForbidden, "not_covered", "the delegation covers none of the requested abilities")
		return
	}
	ttl := h.Config.HistoricalTTL
	if len(cov.Live) > 0 {
		ttl = h.Config.LiveTTL
	}
	now := h.now().UTC()
	exp := now.Add(ttl)
	aud := h.Config.Audience
	if len(req.Audience) > 0 {
		aud = req.Audience
	}
	claims := tokenclaims.Token{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.Config.Issuer,
			Subject:   caller,
			Audience:  jwt.ClaimStrings(aud),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
		Confirmation: &tokenclaims.Confirmation{JKT: jkt},
		Grants:       grants,
	}
	signed, err := h.Keys.Sign(claims)
	if err != nil {
		h.Log.Error().Err(err).Msg("signing access token")
		writeError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}

	log := h.Log.Info().Str("caller", caller).Str("grant", req.Grant).Str("vehicle", req.Vehicle).
		Strs("abilities", req.Abilities).Str("jkt", jkt).Time("exp", exp)
	if clientID != "" {
		log = log.Str("client", clientID)
	}
	if cov.RecoveryUsed {
		// The one operation that overrides somebody's custody (spec §12.2).
		log = log.Bool("recoveryUsed", true)
	}
	log.Msg("access token issued")
	writeJSON(w, http.StatusOK, Response{Token: signed, TokenType: dpop.TokenType, ExpiresIn: int(ttl.Seconds()), ExpiresAt: exp})
}

func (r *Request) validate() error {
	if !strings.HasPrefix(r.Grant, "at://") {
		return errors.New("grant must be an at:// record URI")
	}
	if !isDID(r.Vehicle) {
		return errors.New("vehicle must be a DID")
	}
	if len(r.Abilities) == 0 {
		return errors.New("abilities must not be empty")
	}
	if slices.Contains(r.Abilities, "") {
		return errors.New("abilities must not contain an empty string")
	}
	return nil
}

// restrictTo returns the coverage narrowed to the requested abilities.
func (c *Coverage) restrictTo(abilities []string) *Coverage {
	out := *c
	out.Historical = map[string]tokenclaims.Windows{}
	for a, ws := range c.Historical {
		if slices.Contains(abilities, a) {
			out.Historical[a] = ws
		}
	}
	out.Live = nil
	for _, a := range c.Live {
		if slices.Contains(abilities, a) {
			out.Live = append(out.Live, a)
		}
	}
	return &out
}

// grantsFor turns coverage into token grants: one for the live abilities,
// with no windows, and one per distinct window set for the historical ones,
// so the token stays a flat list of what may be read when. Suspended
// abilities are held but not usable now and are left out.
func grantsFor(cov *Coverage) []tokenclaims.Grant {
	var grants []tokenclaims.Grant
	byWindows := map[string][]string{}
	for ability, ws := range cov.Historical {
		if len(ws) == 0 {
			continue
		}
		key, _ := json.Marshal(ws)
		byWindows[string(key)] = append(byWindows[string(key)], ability)
	}
	for _, abilities := range byWindows {
		sort.Strings(abilities)
		grants = append(grants, tokenclaims.Grant{
			Subject: cov.Vehicle, Abilities: abilities, Windows: cov.Historical[abilities[0]], Chain: cov.Chain,
		})
	}
	// Earliest window first, a bounded window before an unbounded one that
	// starts at the same time, then by ability, so the same coverage always
	// mints the same token.
	sort.Slice(grants, func(i, j int) bool {
		a, b := grants[i].Windows[0], grants[j].Windows[0]
		if c := compareTimes(a.Start, b.Start, true); c != 0 {
			return c < 0
		}
		if c := compareTimes(a.End, b.End, false); c != 0 {
			return c < 0
		}
		return grants[i].Abilities[0] < grants[j].Abilities[0]
	})
	if len(cov.Live) > 0 {
		live := slices.Clone(cov.Live)
		sort.Strings(live)
		grants = append(grants, tokenclaims.Grant{Subject: cov.Vehicle, Abilities: live, Chain: cov.Chain})
	}
	return grants
}

// compareTimes orders two optional times; nil is the earliest when nilFirst
// (an unbounded start) and the latest otherwise (an unbounded end).
func compareTimes(a, b *time.Time, nilFirst bool) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		if nilFirst {
			return -1
		}
		return 1
	case b == nil:
		if nilFirst {
			return 1
		}
		return -1
	default:
		return a.Compare(*b)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, errorResponse{Error: code, ErrorDescription: description})
}
