package exchange

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/internal/oidc"
	"github.com/DIMO-Network/dauth/internal/signin/token"
	"github.com/DIMO-Network/dauth/pkg/dpop"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	signinIssuer   = "https://auth.test/signin"
	exchangeIssuer = "https://auth.test/exchange"
	callerDID      = "did:dimo:renter"
	vehicleDID     = "did:dimo:car"
	grantURI       = "at://did:dimo:avis/network.dimo.delegation/booking1:history"
	exchangeURL    = "https://auth.test/exchange"
)

// errDirectoryDown stands in for the directory being unreachable.
var errDirectoryDown = errors.New("directory down")

// didKeys is a KeyVerifier over keys registered in the test, standing in for
// DID documents in the directory.
type didKeys struct {
	mu   sync.Mutex
	keys map[string]*ecdsa.PublicKey // did#fragment
	down bool
}

func (d *didKeys) Verify(_ context.Context, did, fragment string, data []byte, sig string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.down {
		return errDirectoryDown
	}
	pub, ok := d.keys[did+"#"+fragment]
	if !ok {
		return errors.New("no such verification method")
	}
	raw, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 {
		return errors.New("bad signature encoding")
	}
	sum := sha256.Sum256(data)
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		return errors.New("invalid signature")
	}
	return nil
}

// app is an app DID with a #signing key the fake directory lists.
type app struct {
	did string
	key *ecdsa.PrivateKey
}

func (e *env) newApp(t *testing.T, did string) *app {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	e.keys.mu.Lock()
	e.keys.keys[did+"#signing"] = &key.PublicKey
	e.keys.mu.Unlock()
	return &app{did: did, key: key}
}

// assertion signs a client assertion for the request whose DPoP key is jkt,
// with any claim in override replacing the default.
func (a *app) assertion(t *testing.T, jkt string, override map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss": a.did, "sub": a.did, "aud": exchangeURL, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(big.NewInt(now.UnixNano()).Bytes()), "cnf": map[string]string{"jkt": jkt},
	}
	for k, v := range override {
		claims[k] = v
	}
	b64 := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": a.did + "#signing"})
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	r, sv, err := ecdsa.Sign(rand.Reader, a.key, sum[:])
	require.NoError(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sv.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

func newKeySet(t *testing.T) (*keyset.KeySet, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	ks, err := keyset.Load([]string{string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	require.NoError(t, err)
	return ks, &key.PublicKey
}

// fakeHost is an org host that answers /authorize with a canned response and
// records what it was asked.
type fakeHost struct {
	t        *testing.T
	status   int
	body     any
	requests []AuthorizeRequest
	auth     []string
}

func (f *fakeHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	require.Equal(f.t, "/authorize", r.URL.Path)
	var req AuthorizeRequest
	require.NoError(f.t, json.NewDecoder(r.Body).Decode(&req))
	f.requests = append(f.requests, req)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.status)
	_ = json.NewEncoder(w).Encode(f.body)
}

type env struct {
	ts          *httptest.Server
	host        *fakeHost
	hostSrv     *httptest.Server
	signin      *token.Issuer
	exchangePub *rsa.PublicKey
	key         *dpop.Key
	keys        *didKeys
	now         time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	signinKeys, _ := newKeySet(t)
	exchangeKeys, exchangePub := newKeySet(t)
	signinJWKS, err := signinKeys.JWKS()
	require.NoError(t, err)
	identity, err := NewIdentityVerifier(signinJWKS, signinIssuer, exchangeURL)
	require.NoError(t, err)
	wk, err := oidc.NewWellKnown(oidc.Config{Issuer: exchangeIssuer, JWKSURI: exchangeIssuer + "/keys", Keys: exchangeKeys})
	require.NoError(t, err)

	host := &fakeHost{t: t, status: http.StatusOK}
	keys := &didKeys{keys: map[string]*ecdsa.PublicKey{}}
	hostSrv := httptest.NewServer(host)
	t.Cleanup(hostSrv.Close)

	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	signin := token.NewIssuer(token.Config{Keys: signinKeys, Issuer: signinIssuer, Audience: []string{"dimo"}, TTL: time.Hour})
	cfg := Config{
		Issuer: exchangeIssuer, Audience: []string{"dq", "din"}, DauthDID: "did:dimo:dauth",
		LiveTTL: 15 * time.Minute, HistoricalTTL: 2 * time.Hour,
	}
	h := &Handler{
		Config: cfg, Keys: exchangeKeys,
		Host: &OrgHost{BaseURL: hostSrv.URL, Identity: func(ctx context.Context) (string, error) {
			tok, _, err := signin.IssueFor(cfg.DauthDID, []string{hostSrv.URL}, 5*time.Minute)
			return tok, err
		}},
		Assertions: &AssertionVerifier{
			Keys: keys, Audience: exchangeURL,
			IsUnavailable: func(err error) bool { return errors.Is(err, errDirectoryDown) },
		},
		DPoP: dpop.NewVerifier(), ExchangeURL: exchangeURL, Log: zerolog.Nop(),
		Now: func() time.Time { return now },
	}
	surface := NewSurface(h, identity, wk)
	mux := http.NewServeMux()
	mux.Handle("POST /exchange", surface.Exchange)
	mux.Handle("/exchange/", http.StripPrefix("/exchange", surface.WellKnown))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	key, err := dpop.GenerateKey()
	require.NoError(t, err)
	return &env{ts: ts, host: host, hostSrv: hostSrv, signin: signin, exchangePub: exchangePub, key: key, keys: keys, now: now}
}

// identity is did's identity token addressed to the exchange.
func (e *env) identity(t *testing.T, did string) string {
	t.Helper()
	tok, _, err := e.signin.Issue(did, []string{exchangeURL})
	require.NoError(t, err)
	return tok
}

// exchange posts body with the identity token and a fresh proof (or none
// when proof is false).
func (e *env) exchange(t *testing.T, identity string, proof bool, body any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+"/exchange", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if identity != "" {
		req.Header.Set("Authorization", "Bearer "+identity)
	}
	if proof {
		p, err := e.key.Proof(http.MethodPost, "https://auth.test/exchange", "", time.Now())
		require.NoError(t, err)
		req.Header.Set(dpop.HeaderName, p)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(data, &out), string(data))
	return resp.StatusCode, out
}

func (e *env) parse(t *testing.T, signed string) *tokenclaims.Token {
	t.Helper()
	var claims tokenclaims.Token
	_, err := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(exchangeIssuer), jwt.WithAudience("dq"),
		jwt.WithTimeFunc(func() time.Time { return e.now.Add(time.Minute) })).
		ParseWithClaims(signed, &claims, func(*jwt.Token) (any, error) { return e.exchangePub, nil })
	require.NoError(t, err)
	require.NoError(t, claims.Validate())
	return &claims
}

var request = map[string]any{"grant": grantURI, "vehicle": vehicleDID, "abilities": []string{"telemetry:read", "location:precise", "command:unlock"}}

func TestExchangeMintsGrantsFromCoverage(t *testing.T) {
	e := newEnv(t)
	e.host.body = map[string]any{
		"vehicle": vehicleDID,
		"historical": map[string]any{
			"telemetry:read":   [][]any{{"2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z"}},
			"location:precise": [][]any{{"2026-09-01T00:00:00Z", "2026-09-08T00:00:00Z"}},
			"events:read":      [][]any{{"2026-09-01T00:00:00Z", nil}},
		},
		"live":  []string{"command:unlock"},
		"chain": []string{grantURI, "at://did:dimo:avis/network.dimo.delegation/root"},
		"at":    e.now,
	}

	status, body := e.exchange(t, e.identity(t, callerDID), true, request)
	require.Equal(t, http.StatusOK, status, body)
	assert.Equal(t, "DPoP", body["token_type"])
	assert.EqualValues(t, 900, body["expires_in"], "a live ability makes it a 15 minute token")

	claims := e.parse(t, body["token"].(string))
	assert.Equal(t, callerDID, claims.Subject)
	require.NotNil(t, claims.Confirmation)
	assert.Equal(t, e.key.Thumbprint(), claims.Confirmation.JKT)
	// The host also answered for events:read, which nobody asked for; the
	// token carries only what was requested.
	require.Len(t, claims.Grants, 2)
	assert.Equal(t, []string{"location:precise", "telemetry:read"}, claims.Grants[0].Abilities)
	assert.Equal(t, []string{"command:unlock"}, claims.Grants[1].Abilities)
	assert.Nil(t, claims.Grants[1].Windows)
	_, held := claims.Holds(vehicleDID, "events:read")
	assert.False(t, held)
	for _, g := range claims.Grants {
		assert.Equal(t, vehicleDID, g.Subject)
		assert.Len(t, g.Chain, 2)
	}
	ws, ok := claims.Holds(vehicleDID, "telemetry:read")
	require.True(t, ok)
	assert.Len(t, ws, 1)

	// What the host was asked.
	require.Len(t, e.host.requests, 1)
	asked := e.host.requests[0]
	assert.Equal(t, grantURI, asked.URI)
	assert.Equal(t, callerDID, asked.Caller)
	assert.Equal(t, vehicleDID, asked.Vehicle)
	assert.Equal(t, []string{"telemetry:read", "location:precise", "command:unlock"}, asked.Abilities)
	assert.Empty(t, asked.ClientID)

	// Authenticated to the host as dauth's own DID.
	var self jwt.RegisteredClaims
	_, _, err := jwt.NewParser().ParseUnverified(e.host.auth[0][len("Bearer "):], &self)
	require.NoError(t, err)
	assert.Equal(t, "did:dimo:dauth", self.Subject)
	assert.Equal(t, jwt.ClaimStrings{e.hostSrv.URL}, self.Audience)
}

func TestExchangeHistoricalLifetime(t *testing.T) {
	e := newEnv(t)
	e.host.body = map[string]any{
		"vehicle":    vehicleDID,
		"historical": map[string]any{"telemetry:read": [][]any{{nil, nil}}},
		"chain":      []string{grantURI},
		"at":         e.now,
	}
	status, body := e.exchange(t, e.identity(t, callerDID), true, request)
	require.Equal(t, http.StatusOK, status, body)
	assert.EqualValues(t, 7200, body["expires_in"])
	claims := e.parse(t, body["token"].(string))
	require.Len(t, claims.Grants, 1)
	assert.Equal(t, tokenclaims.Windows{{}}, claims.Grants[0].Windows, "unbounded window, not absent")
}

func TestExchangeRefusals(t *testing.T) {
	e := newEnv(t)
	e.host.body = map[string]any{"vehicle": vehicleDID, "live": []string{"command:unlock"}, "chain": []string{grantURI}, "at": e.now}
	identity := e.identity(t, callerDID)

	t.Run("no identity token", func(t *testing.T) {
		status, body := e.exchange(t, "", true, request)
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("identity token from another issuer", func(t *testing.T) {
		otherKeys, _ := newKeySet(t)
		other := token.NewIssuer(token.Config{Keys: otherKeys, Issuer: signinIssuer, Audience: []string{"dimo"}, TTL: time.Hour})
		tok, _, err := other.Issue(callerDID, nil)
		require.NoError(t, err)
		status, body := e.exchange(t, tok, true, request)
		assert.Equal(t, http.StatusUnauthorized, status, body)
	})

	t.Run("identity token for another audience", func(t *testing.T) {
		tok, _, err := e.signin.Issue(callerDID, []string{"https://orghost.test"})
		require.NoError(t, err)
		status, body := e.exchange(t, tok, true, request)
		assert.Equal(t, http.StatusUnauthorized, status, body)
		tok, _, err = e.signin.Issue(callerDID, nil)
		require.NoError(t, err)
		status, body = e.exchange(t, tok, true, request)
		assert.Equal(t, http.StatusUnauthorized, status, body, "the default audience is not the exchange")
	})

	t.Run("no DPoP proof", func(t *testing.T) {
		status, body := e.exchange(t, identity, false, request)
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Equal(t, "invalid_dpop_proof", body["error"])
	})

	t.Run("bad request", func(t *testing.T) {
		status, body := e.exchange(t, identity, true, map[string]any{"grant": "nope", "vehicle": vehicleDID, "abilities": []string{"a"}})
		assert.Equal(t, http.StatusBadRequest, status, body)
		status, body = e.exchange(t, identity, true, map[string]any{"grant": grantURI, "vehicle": vehicleDID})
		assert.Equal(t, http.StatusBadRequest, status, body)
		status, body = e.exchange(t, identity, true, map[string]any{"grant": grantURI, "vehicle": vehicleDID, "abilities": []string{"a"}, "audience": []string{"evil"}})
		assert.Equal(t, http.StatusBadRequest, status, body)
	})

	t.Run("host refuses", func(t *testing.T) {
		e.host.status = http.StatusForbidden
		e.host.body = map[string]any{"error": "custody: somebody else is driving", "code": "exclusive_hold", "suspended": []string{"command:unlock"}}
		defer func() { e.host.status = http.StatusOK }()
		status, body := e.exchange(t, identity, true, request)
		assert.Equal(t, http.StatusForbidden, status, body)
		assert.Equal(t, "exclusive_hold", body["error"])
		assert.Equal(t, []any{"command:unlock"}, body["suspended"])
	})

	t.Run("host does not hold the delegation", func(t *testing.T) {
		e.host.status = http.StatusNotFound
		e.host.body = map[string]any{"error": "no such record", "code": "not_found"}
		defer func() { e.host.status = http.StatusOK }()
		status, body := e.exchange(t, identity, true, request)
		assert.Equal(t, http.StatusNotFound, status, body)
		assert.Equal(t, "not_found", body["error"])
	})

	t.Run("host cannot read the request", func(t *testing.T) {
		e.host.status = http.StatusBadRequest
		e.host.body = map[string]any{"error": "uri: not a record URI"}
		defer func() { e.host.status = http.StatusOK }()
		status, body := e.exchange(t, identity, true, request)
		assert.Equal(t, http.StatusBadRequest, status, body)
		assert.Equal(t, "invalid_request", body["error"])
	})

	t.Run("host answers for another vehicle", func(t *testing.T) {
		saved := e.host.body
		e.host.body = map[string]any{"vehicle": "did:dimo:other", "live": []string{"command:unlock"}, "chain": []string{grantURI}, "at": e.now}
		defer func() { e.host.body = saved }()
		status, body := e.exchange(t, identity, true, request)
		assert.Equal(t, http.StatusBadGateway, status, body)
	})

	t.Run("host down", func(t *testing.T) {
		e.host.status = http.StatusInternalServerError
		e.host.body = map[string]any{"error": "internal error"}
		defer func() { e.host.status = http.StatusOK }()
		status, body := e.exchange(t, identity, true, request)
		assert.Equal(t, http.StatusBadGateway, status, body)
	})
}

func TestExchangeClientAssertion(t *testing.T) {
	e := newEnv(t)
	e.host.body = map[string]any{"vehicle": vehicleDID, "live": []string{"command:unlock"}, "chain": []string{grantURI}, "at": e.now}
	identity := e.identity(t, callerDID)
	fleetApp := e.newApp(t, "did:dimo:fleet-app")
	jkt := e.key.Thumbprint()
	with := func(assertion string) map[string]any {
		return map[string]any{"grant": grantURI, "vehicle": vehicleDID, "abilities": []string{"command:unlock"}, "client_assertion": assertion}
	}
	refused := func(t *testing.T, assertion string, status int) {
		t.Helper()
		got, resp := e.exchange(t, identity, true, with(assertion))
		assert.Equal(t, status, got, resp)
		assert.Equal(t, "invalid_client", resp["error"])
	}

	t.Run("the app's assertion names the client", func(t *testing.T) {
		status, resp := e.exchange(t, identity, true, with(fleetApp.assertion(t, jkt, nil)))
		require.Equal(t, http.StatusOK, status, resp)
		asked := e.host.requests[len(e.host.requests)-1]
		assert.Equal(t, fleetApp.did, asked.ClientID)
		assert.Equal(t, callerDID, asked.Caller)
	})

	t.Run("no assertion, no client", func(t *testing.T) {
		status, resp := e.exchange(t, identity, true, request)
		require.Equal(t, http.StatusOK, status, resp)
		assert.Empty(t, e.host.requests[len(e.host.requests)-1].ClientID)
	})

	t.Run("an assertion is used once", func(t *testing.T) {
		a := fleetApp.assertion(t, jkt, nil)
		status, resp := e.exchange(t, identity, true, with(a))
		require.Equal(t, http.StatusOK, status, resp)
		refused(t, a, http.StatusUnauthorized)
	})

	t.Run("an assertion made for another caller's key", func(t *testing.T) {
		other, err := dpop.GenerateKey()
		require.NoError(t, err)
		refused(t, fleetApp.assertion(t, other.Thumbprint(), nil), http.StatusUnauthorized)
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"cnf": nil}), http.StatusUnauthorized)
	})

	t.Run("an assertion for somewhere else", func(t *testing.T) {
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"aud": "https://orghost.test"}), http.StatusUnauthorized)
	})

	t.Run("an identity token is not an assertion", func(t *testing.T) {
		tok, _, err := e.signin.Issue(fleetApp.did, []string{exchangeURL})
		require.NoError(t, err)
		refused(t, tok, http.StatusUnauthorized)
	})

	t.Run("lifetimes", func(t *testing.T) {
		now := time.Now()
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"exp": now.Add(time.Hour).Unix()}), http.StatusUnauthorized)
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"iat": now.Add(-10 * time.Minute).Unix(), "exp": now.Add(-6 * time.Minute).Unix()}), http.StatusUnauthorized)
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"jti": ""}), http.StatusUnauthorized)
	})

	t.Run("signed by a key the app's document does not list", func(t *testing.T) {
		impostor := &app{did: fleetApp.did}
		var err error
		impostor.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		refused(t, impostor.assertion(t, jkt, nil), http.StatusUnauthorized)
		refused(t, fleetApp.assertion(t, jkt, map[string]any{"iss": "did:dimo:other-app", "sub": "did:dimo:other-app"}), http.StatusUnauthorized)
	})

	t.Run("the caller cannot be its own app", func(t *testing.T) {
		caller := e.newApp(t, callerDID)
		refused(t, caller.assertion(t, jkt, nil), http.StatusBadRequest)
	})

	t.Run("the directory is down", func(t *testing.T) {
		e.keys.mu.Lock()
		e.keys.down = true
		e.keys.mu.Unlock()
		defer func() { e.keys.mu.Lock(); e.keys.down = false; e.keys.mu.Unlock() }()
		status, resp := e.exchange(t, identity, true, with(fleetApp.assertion(t, jkt, nil)))
		assert.Equal(t, http.StatusServiceUnavailable, status, resp)
	})

	t.Run("the host refuses a client the allowlist does not name", func(t *testing.T) {
		e.host.status = http.StatusForbidden
		e.host.body = map[string]any{"error": "client not allowed", "code": "client_not_allowed"}
		defer func() { e.host.status = http.StatusOK }()
		status, resp := e.exchange(t, identity, true, with(fleetApp.assertion(t, jkt, nil)))
		assert.Equal(t, http.StatusForbidden, status, resp)
		assert.Equal(t, "client_not_allowed", resp["error"])
	})
}

func TestExchangeJWKS(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.ts.URL + "/exchange/keys")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
