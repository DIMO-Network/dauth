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

	// Deprecated block, kept for un-migrated consumers. contract_address must be
	// lowercase hex (matching the previous hexutil.Encode output).
	assert.Equal(t, "0x90c4d6113ec88dd4bdf12f26db2b3998fd13a144", claims["contract_address"])
	assert.Equal(t, "123", claims["token_id"])
	assert.Equal(t, []any{float64(4)}, claims["privilege_ids"])
}
