package tokenclaims

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ts(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestWindowJSON(t *testing.T) {
	ws := Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-02-01T00:00:00Z")}, {Start: ts("2026-03-01T00:00:00Z")}}
	b, err := json.Marshal(ws)
	require.NoError(t, err)
	assert.JSONEq(t, `[["2026-01-01T00:00:00Z","2026-02-01T00:00:00Z"],["2026-03-01T00:00:00Z",null]]`, string(b))

	var back Windows
	require.NoError(t, json.Unmarshal(b, &back))
	assert.Equal(t, ws, back)
	assert.NoError(t, back.Validate())
}

func TestWindowsValidate(t *testing.T) {
	assert.Error(t, Windows{{Start: ts("2026-02-01T00:00:00Z"), End: ts("2026-01-01T00:00:00Z")}}.Validate(), "empty")
	assert.Error(t, Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-03-01T00:00:00Z")}, {Start: ts("2026-02-01T00:00:00Z")}}.Validate(), "overlap")
	assert.Error(t, Windows{{Start: ts("2026-01-01T00:00:00Z")}, {Start: ts("2026-02-01T00:00:00Z")}}.Validate(), "unbounded then another")
	assert.NoError(t, Windows{{}}.Validate(), "one unbounded window")
	assert.NoError(t, Windows(nil).Validate())
}

func TestClamp(t *testing.T) {
	ws := Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-02-01T00:00:00Z")}, {Start: ts("2026-03-01T00:00:00Z")}}

	inside := ws.Clamp(*ts("2026-01-10T00:00:00Z"), *ts("2026-01-20T00:00:00Z"))
	require.Len(t, inside, 1)
	assert.Equal(t, *ts("2026-01-10T00:00:00Z"), *inside[0].Start)
	assert.Equal(t, *ts("2026-01-20T00:00:00Z"), *inside[0].End)

	straddle := ws.Clamp(*ts("2025-12-01T00:00:00Z"), *ts("2026-04-01T00:00:00Z"))
	require.Len(t, straddle, 2)
	assert.Equal(t, *ts("2026-01-01T00:00:00Z"), *straddle[0].Start)
	assert.Equal(t, *ts("2026-02-01T00:00:00Z"), *straddle[0].End)
	assert.Equal(t, *ts("2026-03-01T00:00:00Z"), *straddle[1].Start)
	assert.Equal(t, *ts("2026-04-01T00:00:00Z"), *straddle[1].End)

	assert.Empty(t, ws.Clamp(*ts("2026-02-01T00:00:00Z"), *ts("2026-03-01T00:00:00Z")), "the gap")
	assert.True(t, ws.Contains(*ts("2026-05-01T00:00:00Z")))
	assert.False(t, ws.Contains(*ts("2026-02-15T00:00:00Z")))
}

func TestHolds(t *testing.T) {
	tok := Token{Grants: []Grant{
		{Subject: "did:dimo:car", Abilities: []string{"telemetry:read"}, Windows: Windows{{Start: ts("2026-03-01T00:00:00Z")}}},
		{Subject: "did:dimo:car", Abilities: []string{"telemetry:read", "events:read"}, Windows: Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-02-01T00:00:00Z")}}},
		{Subject: "did:dimo:car", Abilities: []string{"command:unlock"}},
	}}

	ws, ok := tok.Holds("did:dimo:car", "telemetry:read")
	require.True(t, ok)
	require.Len(t, ws, 2, "unioned and sorted")
	assert.Equal(t, *ts("2026-01-01T00:00:00Z"), *ws[0].Start)
	assert.Nil(t, ws[1].End)

	ws, ok = tok.Holds("did:dimo:car", "command:unlock")
	require.True(t, ok)
	assert.Nil(t, ws, "live: unrestricted")

	_, ok = tok.Holds("did:dimo:car", "location:precise")
	assert.False(t, ok)
	_, ok = tok.Holds("did:dimo:other", "telemetry:read")
	assert.False(t, ok)

	assert.True(t, tok.Covers("did:dimo:car"))
	assert.False(t, tok.Covers("did:dimo:other"))
	assert.Equal(t, []string{"did:dimo:car"}, tok.Subjects())
}

func TestValidate(t *testing.T) {
	good := Token{
		Grants:       []Grant{{Subject: "did:dimo:car", Abilities: []string{"telemetry:read"}, Windows: Windows{{}}}},
		Confirmation: &Confirmation{JKT: "thumbprint"},
	}
	good.Subject = "did:dimo:me"
	good.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Hour))
	assert.NoError(t, good.Validate())

	bad := good
	bad.ExpiresAt = nil
	assert.Error(t, bad.Validate(), "a token without exp never expires")

	bad = good
	bad.Confirmation = nil
	assert.Error(t, bad.Validate(), "a token without cnf is a bearer token")

	bad = good
	bad.Grants = []Grant{{Subject: "did:dimo:car", Abilities: []string{"telemetry:read"}}}
	assert.Error(t, bad.Validate(), "a historical ability without windows would read everything")

	live := good
	live.Grants = []Grant{{Subject: "did:dimo:car", Abilities: []string{"command:unlock"}}}
	assert.NoError(t, live.Validate())

	bad = good
	bad.Subject = ""
	assert.Error(t, bad.Validate())

	bad = good
	bad.Grants = nil
	assert.Error(t, bad.Validate())

	bad = good
	bad.Grants = []Grant{{Subject: "car", Abilities: []string{"telemetry:read"}, Windows: Windows{{}}}}
	assert.Error(t, bad.Validate())

	bad = good
	bad.Grants = []Grant{{Subject: "did:dimo:car"}}
	assert.Error(t, bad.Validate())
}

func TestClampOpen(t *testing.T) {
	ws := Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-02-01T00:00:00Z")}, {Start: ts("2026-03-01T00:00:00Z")}}

	open := ws.ClampOpen(nil, nil)
	require.Len(t, open, 2)
	assert.Equal(t, ws, open)

	after := ws.ClampOpen(ts("2026-03-15T00:00:00Z"), nil)
	require.Len(t, after, 1)
	assert.Equal(t, *ts("2026-03-15T00:00:00Z"), *after[0].Start)
	assert.Nil(t, after[0].End)

	before := ws.ClampOpen(nil, ts("2026-01-15T00:00:00Z"))
	require.Len(t, before, 1)
	assert.Equal(t, *ts("2026-01-01T00:00:00Z"), *before[0].Start)
	assert.Equal(t, *ts("2026-01-15T00:00:00Z"), *before[0].End)

	assert.Empty(t, Windows{{Start: ts("2026-01-01T00:00:00Z"), End: ts("2026-02-01T00:00:00Z")}}.ClampOpen(ts("2026-02-01T00:00:00Z"), nil))
}
