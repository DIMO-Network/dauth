package services

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/dauth/internal/exchange/models"
	"github.com/DIMO-Network/dauth/internal/exchange/services/access"
	"github.com/DIMO-Network/dauth/internal/keyset"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTokenSigner_WireFormat verifies the locally-signed permission token
// carries exactly the claim shape downstream validators (telemetry/dq/fetch)
// expect from the former DEX-signed token: the new asset/permissions/
// cloud_events fields plus the deprecated contract_address/token_id/
// privilege_ids block, with contract_address as lowercase hex.
func TestTokenSigner_WireFormat(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
	ks, err := keyset.Load([]string{string(pemBytes)})
	require.NoError(t, err)

	const issuer = "https://auth-roles-rights.dimo.zone"
	signer := NewTokenSigner(ks, issuer, 10*time.Minute)

	contract := common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144")
	asset := models.ERC721Asset{ERC721DID: cloudevent.ERC721DID{
		ChainID:         137,
		ContractAddress: contract,
		TokenID:         big.NewInt(123),
	}}
	permName := tokenclaims.PrivilegeIDToName[4]
	subject := common.HexToAddress("0x69F5C4D08F6bC8cD29fE5f004d46FB566270868d").Hex()

	signed, err := signer.SignPrivilegePayload(context.Background(), PrivilegeTokenDTO{
		AccessRequest: &access.AccessRequest{
			Asset:       asset,
			Permissions: []string{permName},
			EventFilters: []models.EventFilter{{
				EventType: cloudevent.TypeAttestation,
				Source:    "*",
				IDs:       []string{"attestation-1"},
				Tags:      []string{"insurance"},
			}},
		},
		Audience:        []string{"dimo.zone"},
		ResponseSubject: subject,
	})
	require.NoError(t, err)

	// Header carries the active key's thumbprint kid so validators select the
	// right JWKS entry.
	tok, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	require.NoError(t, err)
	assert.Equal(t, ks.ActiveKID(), tok.Header["kid"])
	assert.Equal(t, "RS256", tok.Header["alg"])

	claims := tok.Claims.(jwt.MapClaims)

	// Registered claims.
	assert.Equal(t, issuer, claims["iss"])
	assert.Equal(t, subject, claims["sub"])
	// aud serializes as a JSON array; auth0/go-jose validators accept this.
	assert.Equal(t, []any{"dimo.zone"}, claims["aud"])
	assert.Contains(t, claims, "exp")
	assert.Contains(t, claims, "jti")

	// New-style custom claims.
	assert.Equal(t, asset.String(), claims["asset"])
	assert.Equal(t, []any{permName}, claims["permissions"])
	require.Contains(t, claims, "cloud_events")
	events := claims["cloud_events"].(map[string]any)["events"].([]any)
	require.Len(t, events, 1)

	// Unconditional grants mint no scoped_permissions claim at all.
	assert.NotContains(t, claims, "scoped_permissions")

	// Deprecated block, kept for un-migrated consumers. contract_address must be
	// lowercase hex (matching the previous hexutil.Encode output).
	assert.Equal(t, "0x90c4d6113ec88dd4bdf12f26db2b3998fd13a144", claims["contract_address"])
	assert.Equal(t, "123", claims["token_id"])
	assert.Equal(t, []any{float64(4)}, claims["privilege_ids"])
}

// TestTokenSigner_ScopedPermissions verifies the fail-closed claim encoding: a
// permission the decision marks as scoped appears ONLY in scoped_permissions —
// with its constraint atoms verbatim — and is excluded from both the flat
// permissions array and the deprecated privilege_ids, so consumers that do not
// understand constraints cannot mistake it for an unconditional grant.
func TestTokenSigner_ScopedPermissions(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pk),
	})
	ks, err := keyset.Load([]string{string(pemBytes)})
	require.NoError(t, err)

	signer := NewTokenSigner(ks, "https://dauth.dimo.zone/exchange", 10*time.Minute)

	asset := models.ERC721Asset{ERC721DID: cloudevent.ERC721DID{
		ChainID:         137,
		ContractAddress: common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144"),
		TokenID:         big.NewInt(123),
	}}
	scopedName := tokenclaims.PermissionGetLocationHistory  // privilege ID 4
	flatName := tokenclaims.PermissionGetNonLocationHistory // privilege ID 1

	signed, err := signer.SignPrivilegePayload(context.Background(), PrivilegeTokenDTO{
		AccessRequest: &access.AccessRequest{
			Asset:       asset,
			Permissions: []string{scopedName, flatName},
		},
		Decision: &access.Decision{
			ScopedPermissions: []tokenclaims.ScopedPermission{{
				Name: scopedName,
				Constraint: []tokenclaims.Constraint{
					{LeftOperand: tokenclaims.LeftOperandRecordedAt, Operator: tokenclaims.OperatorGteq, RightOperand: "2026-04-01T00:00:00Z"},
					{LeftOperand: tokenclaims.LeftOperandRecordedAt, Operator: tokenclaims.OperatorLt, RightOperand: "2026-07-01T00:00:00Z"},
				},
			}},
		},
		Audience:        []string{"dimo.zone"},
		ResponseSubject: common.HexToAddress("0x69F5C4D08F6bC8cD29fE5f004d46FB566270868d").Hex(),
	})
	require.NoError(t, err)

	tok, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	require.NoError(t, err)
	claims := tok.Claims.(jwt.MapClaims)

	// The scoped permission is invisible to flat-claim consumers.
	assert.Equal(t, []any{flatName}, claims["permissions"])
	assert.Equal(t, []any{float64(1)}, claims["privilege_ids"])

	require.Contains(t, claims, "scoped_permissions")
	scoped := claims["scoped_permissions"].([]any)
	require.Len(t, scoped, 1)
	sp := scoped[0].(map[string]any)
	assert.Equal(t, scopedName, sp["name"])
	constraints := sp["constraint"].([]any)
	require.Len(t, constraints, 2)
	assert.Equal(t, map[string]any{
		"leftOperand":  "dimo:recordedAt",
		"operator":     "gteq",
		"rightOperand": "2026-04-01T00:00:00Z",
	}, constraints[0])
}
