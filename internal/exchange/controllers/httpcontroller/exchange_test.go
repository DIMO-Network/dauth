package httpcontroller_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/dauth/internal/exchange/config"
	"github.com/DIMO-Network/dauth/internal/exchange/controllers/httpcontroller"
	"github.com/DIMO-Network/dauth/internal/exchange/middleware"
	"github.com/DIMO-Network/dauth/internal/exchange/models"
	"github.com/DIMO-Network/dauth/internal/exchange/services"
	"github.com/DIMO-Network/dauth/internal/exchange/services/access"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"go.uber.org/mock/gomock"
)

var defaultAudience = []string{"dimo.zone"}

var contractAddressManufacturer = common.HexToAddress("0xAbc")
var assetContractAddress = common.HexToAddress("0x90C4D6113Ec88dd4BDf12f26DB2b3998fd13A144")

//go:generate go tool mockgen -source ./exchange.go -destination ./exchange_mock_test.go -package httpcontroller_test
//go:generate go tool mockgen -source ../../middleware/valid_dev_license.go -destination ./identity_service_mock_test.go -package httpcontroller_test
func TestExchangeController_ExchangeToken(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	signer := NewMockTokenSigner(mockCtrl)
	mockIdent := NewMockIdentityService(mockCtrl)
	mockAccess := NewMockAccessService(mockCtrl)

	// setup app and route req
	c, err := httpcontroller.NewExchangeController(&config.Config{
		DIMORegistryChainID:         1,
		ContractAddressManufacturer: contractAddressManufacturer,
	}, signer, mockAccess)
	require.NoError(t, err, "Failed to initialize SACD controller")

	userEthAddr := common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")

	devLicenseAddr := common.HexToAddress("0x69F5C4D08F6bC8cD29fE5f004d46FB566270868d")

	tests := []struct {
		name                   string
		tokenClaims            jwt.MapClaims
		userEthAddr            *common.Address
		permissionTokenRequest *httpcontroller.TokenRequest
		mockSetup              func()
		expectedCode           int
	}{
		{
			name: "auth jwt with ethereum addr",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: assetContractAddress.String(),
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), userEthAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.AccessRequest{
					Asset: models.ERC721Asset{
						ERC721DID: cloudevent.ERC721DID{
							ContractAddress: assetContractAddress,
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, userEthAddr).Return(nil)
				signer.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					AccessRequest: &access.AccessRequest{
						Asset: models.ERC721Asset{
							ERC721DID: cloudevent.ERC721DID{
								ContractAddress: assetContractAddress,
								TokenID:         big.NewInt(123),
								ChainID:         1,
							},
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        defaultAudience,
					ResponseSubject: userEthAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "valid request from developer license",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": devLicenseAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              devLicenseAddr.Hex(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: assetContractAddress.String(),
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), devLicenseAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.AccessRequest{
					Asset: models.ERC721Asset{
						ERC721DID: cloudevent.ERC721DID{
							ContractAddress: assetContractAddress,
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, devLicenseAddr).Return(nil)
				signer.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					AccessRequest: &access.AccessRequest{
						Asset: models.ERC721Asset{
							ERC721DID: cloudevent.ERC721DID{
								ContractAddress: assetContractAddress,
								TokenID:         big.NewInt(123),
								ChainID:         1,
							},
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        defaultAudience,
					ResponseSubject: devLicenseAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "valid request from developer license for manufacturer",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": devLicenseAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              devLicenseAddr.Hex(),
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{6},
				NFTContractAddress: contractAddressManufacturer.Hex(),
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), devLicenseAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.AccessRequest{
					Asset: models.ERC721Asset{
						ERC721DID: cloudevent.ERC721DID{
							ContractAddress: contractAddressManufacturer,
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
					},
					Permissions: []string{tokenclaims.ManufacturerPrivilegeIDToName[6]},
				}, devLicenseAddr).Return(nil)
				signer.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					AccessRequest: &access.AccessRequest{
						Asset: models.ERC721Asset{
							ERC721DID: cloudevent.ERC721DID{
								ContractAddress: contractAddressManufacturer,
								TokenID:         big.NewInt(123),
								ChainID:         1,
							},
						},
						Permissions: []string{tokenclaims.ManufacturerPrivilegeIDToName[6]},
					},
					Audience:        defaultAudience,
					ResponseSubject: devLicenseAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "eth token, multiple perms, success on SACD",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{1, 2, 4, 5},
				NFTContractAddress: assetContractAddress.String(),
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), userEthAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.AccessRequest{
					Asset: models.ERC721Asset{
						ERC721DID: cloudevent.ERC721DID{
							ContractAddress: assetContractAddress,
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[1], tokenclaims.PrivilegeIDToName[2], tokenclaims.PrivilegeIDToName[4], tokenclaims.PrivilegeIDToName[5]},
				}, userEthAddr).Return(nil)
				signer.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					AccessRequest: &access.AccessRequest{
						Asset: models.ERC721Asset{
							ERC721DID: cloudevent.ERC721DID{
								ContractAddress: assetContractAddress,
								TokenID:         big.NewInt(123),
								ChainID:         1,
							},
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[1], tokenclaims.PrivilegeIDToName[2], tokenclaims.PrivilegeIDToName[4], tokenclaims.PrivilegeIDToName[5]},
					},
					Audience:        defaultAudience,
					ResponseSubject: userEthAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "auth jwt with userId but no ethereum address",
			tokenClaims: jwt.MapClaims{
				"sub": "user-id-123",
				"nbf": time.Now().Unix(),
				"aud": "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: assetContractAddress.String(),
			},
			mockSetup:    func() {},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "auth jwt with audience",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID:            123,
				Privileges:         []int64{4},
				NFTContractAddress: assetContractAddress.String(),
				Audience:           []string{"my-app", "foo"},
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), userEthAddr).Return(true, nil)
				mockAccess.EXPECT().ValidateAccess(gomock.Any(), &access.AccessRequest{
					Asset: models.ERC721Asset{
						ERC721DID: cloudevent.ERC721DID{
							ContractAddress: assetContractAddress,
							TokenID:         big.NewInt(123),
							ChainID:         1,
						},
					},
					Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
				}, userEthAddr).Return(nil)
				signer.EXPECT().SignPrivilegePayload(gomock.Any(), services.PrivilegeTokenDTO{
					AccessRequest: &access.AccessRequest{
						Asset: models.ERC721Asset{
							ERC721DID: cloudevent.ERC721DID{
								ContractAddress: assetContractAddress,
								TokenID:         big.NewInt(123),
								ChainID:         1,
							},
						},
						Permissions: []string{tokenclaims.PrivilegeIDToName[4]},
					},
					Audience:        []string{"my-app", "foo"},
					ResponseSubject: userEthAddr.Hex(),
				}).Return("jwt", nil)
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "Fail: must pass privilege or cloud event request",
			tokenClaims: jwt.MapClaims{
				"ethereum_address": userEthAddr.Hex(),
				"nbf":              time.Now().Unix(),
				"aud":              "dimo-driver",
			},
			userEthAddr: &userEthAddr,
			permissionTokenRequest: &httpcontroller.TokenRequest{
				TokenID: 123,
				CloudEvents: httpcontroller.CloudEvents{
					Events: []models.EventFilter{},
				},
				NFTContractAddress: assetContractAddress.String(),
			},
			mockSetup: func() {
				mockIdent.EXPECT().IsDevLicense(gomock.Any(), userEthAddr).Return(true, nil)
			},
			expectedCode: http.StatusBadRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jsonBytes, _ := json.Marshal(tc.permissionTokenRequest)

			handler := injectToken(tc.tokenClaims)(
				middleware.NewDevLicenseValidator(mockIdent, zerolog.Nop())(
					http.HandlerFunc(c.ExchangeToken)))

			// setup mock expectations
			tc.mockSetup()

			req := httptest.NewRequest(http.MethodPost, "/v1/tokens/exchange", bytes.NewReader(jsonBytes))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equal(t, tc.expectedCode, rec.Code, tc.name)
			if tc.expectedCode == http.StatusOK {
				require.Equal(t, "jwt", gjson.GetBytes(rec.Body.Bytes(), "token").Str)
			}
		})
	}
}

const (
	developerAuthToken = `Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImRkNTFkNDkwYjc1Y2VhOTNlMGI3YWI2YzcwODczNWVlN2FmZDBmMDgifQ.eyJpc3MiOiJodHRwczovL2F1dGguZGltby56b25lIiwicHJvdmlkZXJfaWQiOiJ3ZWIzIiwic3ViIjoiQ2lvd2VEWmxNMlk1Um1FME1VUTFOV1kzTWpZd05UQkRNelZsWVRaQlJtVmtOalZsTURZME1XSTVOVGNTQkhkbFlqTSIsImF1ZCI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyIsImV4cCI6MTcyNDI0NDE3NCwiaWF0IjoxNzIzMDM0NTc0LCJhdF9oYXNoIjoiZVpzS2p5SzB0TGY2UkFNZkxKM1AydyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwiZXRoZXJldW1fYWRkcmVzcyI6IjB4NmUzZjlGYTQxRDU1ZjcyNjA1MEMzNWVhNkFGZWQ2NWUwNjQxYjk1NyJ9.n7w63IvKTBqynVIggMCJAuty7P9nyCWugF0oxjipgzw9P7LvctzEXaheJmrWoP95QZJg9izaFWL2UoE4VpcnR4-_G6R2whZGV2aqlj8FQH1mQuznJZQyZUc6zKMi0wqedGEIYWBRI1zmXHy70_rXYnV4U4loPqKrXxXrhQ6oZWqCb9WxOdX5zf41LuYF6Ez2xk_jiciKxrvjoGtFsJK4fKhKRkzbO0i5IcdmQwrPEN75k8DxtYTHiYO8p_8BXY5Wej3lfEo6ZVtLumxfdkanILiOd-cY793Ru7sFvY6ObAsA9OLM-F1VmiRkCaHTaTK9t3DwPGmuDgduStFDLVX76Q`
)

func TestDevLicenseMiddleware(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	logger := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("app", "token-exchange-api").
		Logger()

	idSvc := NewMockIdentityService(mockCtrl)

	tests := []struct {
		name             string
		token            string
		validDevLicense  bool
		developerLicense common.Address
		expectedCode     int
		identityAPIError error
	}{
		{
			name:             "Developer license",
			token:            developerAuthToken,
			validDevLicense:  true,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     http.StatusOK,
		},
		{
			name:             "Invalid developer license",
			token:            developerAuthToken,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     http.StatusForbidden,
		},
		{
			name:             "Identity API Error",
			token:            developerAuthToken,
			developerLicense: common.HexToAddress("0x6e3f9Fa41D55f726050C35ea6AFed65e0641b957"),
			expectedCode:     http.StatusInternalServerError,
			identityAPIError: errors.New("random identity api error"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var sub string
			final := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				var err error
				sub, err = middleware.GetResponseSubject(r.Context())
				if err != nil {
					require.NoError(t, err, "subject extraction failed")
				}
			})
			handler := parseTokenToContext(middleware.NewDevLicenseValidator(idSvc, logger)(final))

			if tc.validDevLicense {
				idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(true, nil)
			} else if tc.identityAPIError != nil {
				idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(false, tc.identityAPIError)
			} else {
				idSvc.EXPECT().IsDevLicense(gomock.Any(), tc.developerLicense).Return(false, nil)
			}

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", tc.token)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if tc.validDevLicense && tc.identityAPIError == nil {
				assert.Equal(t, tc.developerLicense.Hex(), sub)
			}

			assert.Equal(t, tc.expectedCode, rec.Code)

			if tc.expectedCode == http.StatusForbidden {
				assert.Contains(t, rec.Body.String(), fmt.Sprintf("not a dev license: %s", tc.developerLicense))
			}
		})
	}
}

// injectToken simulates the JWT auth middleware by placing a token with the
// given claims into the request context.
func injectToken(claims jwt.MapClaims) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(middleware.WithToken(r.Context(), &jwt.Token{Claims: claims})))
		})
	}
}

// parseTokenToContext parses the (unverified) Bearer token into the request
// context, standing in for the signature-checking JWT auth middleware.
func parseTokenToContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tk := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, _, _ := new(jwt.Parser).ParseUnverified(tk, jwt.MapClaims{})
		next.ServeHTTP(w, r.WithContext(middleware.WithToken(r.Context(), token)))
	})
}
