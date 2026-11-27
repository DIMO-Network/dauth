package exchange

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setEnv sets one variable for the test and unsets the rest of the exchange
// config so a developer's shell cannot leak in.
func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for _, k := range []string{
		"EXCHANGE_ISSUER", "EXCHANGE_AUDIENCE", "ORG_HOST_URL", "ORG_HOST_TIMEOUT", "DAUTH_DID",
		"EXCHANGE_LIVE_TTL", "EXCHANGE_HISTORICAL_TTL", "EXCHANGE_SIGNING_KEY_1", "ENABLE_PPROF",
	} {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
}

const (
	testIssuer = "https://dauth.test/exchange"
	testOrg    = "https://org.test"
	testDID    = "did:dimo:dauth"
	testKey    = "not-parsed-by-Load"
)

// Exchange is disabled only when ORG_HOST_URL is unset. Every other
// combination either enables it or fails startup.
func TestLoadEnabledMatrix(t *testing.T) {
	full := func(over map[string]string) map[string]string {
		m := map[string]string{
			"EXCHANGE_ISSUER": testIssuer, "ORG_HOST_URL": testOrg, "DAUTH_DID": testDID,
			"EXCHANGE_SIGNING_KEY_1": testKey,
		}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	tests := []struct {
		name    string
		env     map[string]string
		enabled bool
		wantErr string
	}{
		{"all set", full(nil), true, ""},
		{"nothing set", map[string]string{}, false, ""},
		{"only ORG_HOST_URL unset", full(map[string]string{"ORG_HOST_URL": ""}), false, ""},
		{"ORG_HOST_URL unset, issuer and DID unset too", map[string]string{"EXCHANGE_SIGNING_KEY_1": testKey}, false, ""},
		{"ORG_HOST_URL set, DAUTH_DID empty", full(map[string]string{"DAUTH_DID": ""}), false, "DAUTH_DID"},
		{"ORG_HOST_URL set, DAUTH_DID not a DID", full(map[string]string{"DAUTH_DID": "dauth"}), false, "DAUTH_DID"},
		{"ORG_HOST_URL set, DAUTH_DID is bare prefix", full(map[string]string{"DAUTH_DID": "did:"}), false, "DAUTH_DID"},
		{"ORG_HOST_URL set, EXCHANGE_ISSUER missing", full(map[string]string{"EXCHANGE_ISSUER": ""}), false, "EXCHANGE_ISSUER"},
		{"ORG_HOST_URL set, EXCHANGE_ISSUER relative", full(map[string]string{"EXCHANGE_ISSUER": "/exchange"}), false, "EXCHANGE_ISSUER"},
		{"ORG_HOST_URL set but not a URL", full(map[string]string{"ORG_HOST_URL": "org-host"}), false, "ORG_HOST_URL"},
		{"ORG_HOST_URL set, no signing key", full(map[string]string{"EXCHANGE_SIGNING_KEY_1": ""}), false, "signing key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, tc.env)
			c, err := Load()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.enabled, c.Enabled())
		})
	}
}

// A disabled config carries no exchange settings, but ENABLE_PPROF belongs to
// the ops server and still applies.
func TestLoadDisabledKeepsPprof(t *testing.T) {
	setEnv(t, map[string]string{"ENABLE_PPROF": "true"})
	c, err := Load()
	require.NoError(t, err)
	assert.False(t, c.Enabled())
	assert.True(t, c.EnablePprof)
	assert.Empty(t, c.SigningKeys)
}

func TestEnabledConfigIsComplete(t *testing.T) {
	setEnv(t, map[string]string{
		"EXCHANGE_ISSUER": testIssuer + "/", "ORG_HOST_URL": testOrg + "/", "DAUTH_DID": testDID,
		"EXCHANGE_SIGNING_KEY_1": testKey,
	})
	c, err := Load()
	require.NoError(t, err)
	assert.True(t, c.Enabled())
	assert.Equal(t, testIssuer, c.Issuer)
	assert.Equal(t, testOrg, c.OrgHostURL)
	assert.Equal(t, []string{testKey}, c.SigningKeys)
}
