//nolint:revive
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DIMO-Network/dauth/internal/exchange/middleware"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGetUserEthAddr(t *testing.T) {
	tests := []struct {
		name         string
		tokenClaims  jwt.MapClaims
		expectedAddr common.Address
		expectingErr bool
	}{
		{
			name: "Token With Ethereum Address",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": "0x20Ca3bE69a8B95D3093383375F0473A8c6341727",
			},
			expectedAddr: common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727"),
			expectingErr: false,
		},
		{
			name: "Token with Ethereum address claim, wrong type",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": 5,
			},
			expectingErr: true,
		},
		{
			name: "Token with Ethereum address claim, string that isn't a Hex address",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": "k5",
			},
			expectingErr: true,
		},
		{
			name:         "Token Without Ethereum Address",
			tokenClaims:  jwt.MapClaims{},
			expectingErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req = req.WithContext(middleware.WithToken(req.Context(), &jwt.Token{Claims: tc.tokenClaims}))

			result, err := GetUserEthAddr(req)

			if tc.expectingErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedAddr, result)
			}
		})
	}
}
