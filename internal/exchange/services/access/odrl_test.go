package access

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/dauth/internal/exchange/contracts/sacd"
	"github.com/DIMO-Network/dauth/internal/exchange/models"
	"github.com/DIMO-Network/dauth/internal/exchange/services/template"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var (
	odrlGrantorAddr = common.HexToAddress("0x8Ec8B60a10a03fA3225303cA51fD3d3a7ec48c1a")
	odrlGranteeAddr = common.HexToAddress("0x20Ca3bE69a8B95D3093383375F0473A8c6341727")
)

func odrlAssetDID() models.AssetDID {
	return models.ERC721Asset{
		ERC721DID: cloudevent.ERC721DID{
			ContractAddress: assetContractAddress,
			TokenID:         big.NewInt(123),
			ChainID:         1,
		},
	}
}

// odrlDoc renders a profile v1 agreement JSON with the given permission
// actions and validity constraints, ready for field-level mutation by tests.
func odrlDoc(t *testing.T, mutate func(doc map[string]any)) []byte {
	t.Helper()
	doc := map[string]any{
		"@context": []string{models.ODRLContextIRI, models.DIMOProfileV1IRI},
		"@type":    "Agreement",
		"uid":      "urn:uuid:6f2f2fd0-6d3f-4b3a-9c39-0f2f4a3f4b3a",
		"profile":  models.DIMOProfileV1IRI,
		"assigner": fmt.Sprintf("did:ethr:1:%s", odrlGrantorAddr.Hex()),
		"assignee": fmt.Sprintf("did:ethr:1:%s", odrlGranteeAddr.Hex()),
		"target":   odrlAssetDID().String(),
		"constraint": []map[string]any{
			{"leftOperand": "dateTime", "operator": "gteq", "rightOperand": time.Now().Add(-time.Hour).Format(time.RFC3339)},
			{"leftOperand": "dateTime", "operator": "lteq", "rightOperand": time.Now().Add(time.Hour).Format(time.RFC3339)},
		},
		"permission": []map[string]any{
			{"action": tokenclaims.PermissionGetLocationHistory},
			{"action": tokenclaims.PermissionGetNonLocationHistory},
		},
	}
	if mutate != nil {
		mutate(doc)
	}
	data, err := json.Marshal(doc)
	require.NoError(t, err)
	return data
}

func odrlEnvelope(data []byte) *cloudevent.RawEvent {
	return &cloudevent.RawEvent{
		CloudEventHeader: cloudevent.CloudEventHeader{
			SpecVersion: "1.0",
			ID:          "odrl-grant-1",
			Source:      odrlGrantorAddr.Hex(),
			Type:        models.TypeSACDODRL,
			Time:        time.Now(),
			Signature:   "0xsigned",
		},
		Data: data,
	}
}

func TestValidateAccess_ODRL(t *testing.T) {
	tests := []struct {
		name            string
		permissions     []string
		eventFilters    []models.EventFilter
		mutate          func(doc map[string]any)
		sigValid        bool
		expectedErrCode int
	}{
		{
			name:        "grants requested permissions",
			permissions: []string{tokenclaims.PermissionGetLocationHistory, tokenclaims.PermissionGetNonLocationHistory},
			sigValid:    true,
		},
		{
			name:        "subset of granted permissions",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			sigValid:    true,
		},
		{
			name:            "missing permission",
			permissions:     []string{tokenclaims.PermissionGetRawData},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:            "cloud event access is refused under profile v1",
			permissions:     []string{tokenclaims.PermissionGetLocationHistory},
			eventFilters:    []models.EventFilter{{EventType: cloudevent.TypeAttestation}},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "expired agreement",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["constraint"] = []map[string]any{
					{"leftOperand": "dateTime", "operator": "lteq", "rightOperand": time.Now().Add(-time.Hour).Format(time.RFC3339)},
				}
			},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "agreement not yet effective",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["constraint"] = []map[string]any{
					{"leftOperand": "dateTime", "operator": "gteq", "rightOperand": time.Now().Add(time.Hour).Format(time.RFC3339)},
				}
			},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "no constraints means no validity bounds",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				delete(doc, "constraint")
			},
			sigValid: true,
		},
		{
			name:        "assignee mismatch",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["assignee"] = "did:ethr:1:0x00000000000000000000000000000000DeaDBeef"
			},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:            "invalid signature",
			permissions:     []string{tokenclaims.PermissionGetLocationHistory},
			sigValid:        false,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "target mismatch",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["target"] = "did:erc721:1:0x00000000000000000000000000000000DeaDBeef:999"
			},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "unknown action is rejected outright",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["permission"] = []map[string]any{
					{"action": tokenclaims.PermissionGetLocationHistory},
					{"action": "privilege:LaunchTheMissiles"},
				}
			},
			sigValid:        true,
			expectedErrCode: http.StatusForbidden,
		},
		{
			name:        "vocabulary outside the profile is rejected",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["prohibition"] = []map[string]any{{"action": tokenclaims.PermissionGetRawData}}
			},
			sigValid:        true,
			expectedErrCode: http.StatusBadRequest,
		},
		{
			name:        "wrong policy type",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["@type"] = "Offer"
			},
			sigValid:        true,
			expectedErrCode: http.StatusBadRequest,
		},
		{
			name:        "unexpected context is rejected unprocessed",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["@context"] = []string{models.ODRLContextIRI, "https://evil.example/remap.jsonld"}
			},
			sigValid:        true,
			expectedErrCode: http.StatusBadRequest,
		},
		{
			name:        "unsupported constraint operator",
			permissions: []string{tokenclaims.PermissionGetLocationHistory},
			mutate: func(doc map[string]any) {
				doc["constraint"] = []map[string]any{
					{"leftOperand": "dateTime", "operator": "isAnyOf", "rightOperand": time.Now().Format(time.RFC3339)},
				}
			},
			sigValid:        true,
			expectedErrCode: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			defer mockCtrl.Finish()

			mockSacd := NewMockSACDInterface(mockCtrl)
			mockTemplate := NewMockTemplate(mockCtrl)
			mockipfs := NewMockIPFSClient(mockCtrl)
			mockSigValidator := NewMockSignatureValidator(mockCtrl)

			templateService, err := template.NewTemplateService(mockTemplate, mockipfs, nil)
			require.NoError(t, err)

			accessService, err := NewAccessService(mockipfs, mockSacd, templateService, nil, contractAddressManufacturer)
			require.NoError(t, err)
			accessService.sigValidator = mockSigValidator

			doc := odrlDoc(t, tc.mutate)
			record := odrlEnvelope(doc)

			mockSacd.EXPECT().CurrentPermissionRecord(gomock.Any(), assetContractAddress, big.NewInt(123), odrlGranteeAddr).
				Return(nonEmptyPermRecordODRL(), nil)
			mockipfs.EXPECT().GetValidSacdDoc(gomock.Any(), "ipfs://odrl-grant").Return(record, nil)
			mockSigValidator.EXPECT().ValidateSignature(gomock.Any(), json.RawMessage(doc), record.Signature, odrlGrantorAddr).
				Return(tc.sigValid, nil).AnyTimes()

			// ValidateAccessViaSourceDoc rather than ValidateAccess: the latter
			// masks doc-path rejections behind the legacy on-chain fallback for
			// permission-only requests, and the doc path is what's under test.
			err = accessService.ValidateAccessViaSourceDoc(context.Background(), &AccessRequest{
				Asset:        odrlAssetDID(),
				Permissions:  tc.permissions,
				EventFilters: tc.eventFilters,
			}, odrlGranteeAddr)

			if tc.expectedErrCode == 0 {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			var richErr richerrors.Error
			require.ErrorAs(t, err, &richErr)
			require.Equal(t, tc.expectedErrCode, richErr.Code)
		})
	}
}

func nonEmptyPermRecordODRL() sacd.ISacdPermissionRecord {
	return sacd.ISacdPermissionRecord{
		Permissions: big.NewInt(0),
		Expiration:  big.NewInt(0),
		Source:      "ipfs://odrl-grant",
	}
}
