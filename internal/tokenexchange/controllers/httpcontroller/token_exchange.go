package httpcontroller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/DIMO-Network/cloudevent"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/api"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/config"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/middleware"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/models"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services"
	"github.com/DIMO-Network/dauth/internal/tokenexchange/services/access"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
	"github.com/DIMO-Network/server-garage/pkg/richerrors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
)

type TokenSigner interface {
	SignPrivilegePayload(ctx context.Context, req services.PrivilegeTokenDTO) (string, error)
}
type AccessService interface {
	ValidateAccess(ctx context.Context, req *access.AccessRequest, ethAddr common.Address) error
}

var defaultAudience = []string{"dimo.zone"}

type TokenExchangeController struct {
	chainID                     uint64
	contractAddressManufacturer common.Address
	signer                      TokenSigner
	accessService               AccessService
}

type TokenRequest struct {
	// Asset DID of the asset that permissions are being requested for currently either did:erc721 or did:ethr
	Asset string `json:"asset"`
	// CloudEvents contains requests for access to CloudEvents attached to the specified NFT.
	CloudEvents CloudEvents `json:"cloudEvents"`
	// Permissions is a list of the desired permissions.
	Permissions []string `json:"permissions"`
	// Audience is the intended audience for the token.
	Audience []string `json:"audience" validate:"optional"`

	// TokenID is the NFT token id.
	// If asset is provided, this is ignored.
	// Deprecated: Use Asset instead.
	TokenID int64 `json:"tokenId" example:"7"`
	// Privileges is a list of the desired privileges. It must not be empty.
	// If Permissions are provided, this is ignored.
	// Deprecated: Use Permissions instead.
	Privileges []int64 `json:"privileges" example:"1,2,3,4"`
	// NFTContractAddress is the address of the NFT contract. Privileges will be checked
	// on-chain at this address. Address must be in the 0x format e.g. 0x5FbDB2315678afecb367f032d93F642f64180aa3.
	// Varying case is okay.
	// If asset is provided, this is ignored.
	// Deprecated: Use Asset instead.
	NFTContractAddress string `json:"nftContractAddress" example:"0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF"`
}
type CloudEvents struct {
	Events []models.EventFilter `json:"events"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func NewTokenExchangeController(settings *config.Settings, signer TokenSigner, accessService AccessService) (*TokenExchangeController, error) {
	return &TokenExchangeController{
		chainID:                     settings.DIMORegistryChainID,
		contractAddressManufacturer: settings.ContractAddressManufacturer,
		signer:                      signer,
		accessService:               accessService,
	}, nil
}

// ExchangeToken godoc
// @Description Returns a signed token with the requested privileges.
// @Summary     The authenticated user must have a confirmed Ethereum address with those
// @Summary     privileges on the correct token.
// @Accept      json
// @Param       tokenRequest body httpcontroller.TokenRequest true "Requested privileges: must include address, token id, and privilege ids"
// @Produce     json
// @Success     200 {object} httpcontroller.TokenResponse
// @Security    BearerAuth
// @Router      /tokens/exchange [post]
func (t *TokenExchangeController) ExchangeToken(w http.ResponseWriter, r *http.Request) {
	tokenReq := &TokenRequest{}
	if err := json.NewDecoder(r.Body).Decode(tokenReq); err != nil {
		writeError(r.Context(), w, badRequest("Couldn't parse request body."))
		return
	}

	accessReq, err := t.tokenReqToAccessReq(tokenReq)
	if err != nil {
		writeError(r.Context(), w, err)
		return
	}

	if len(accessReq.Permissions) == 0 && len(accessReq.EventFilters) == 0 {
		writeError(r.Context(), w, badRequest("Please provide at least one privilege or cloudevent"))
		return
	}

	addDefaultIdentifiers(accessReq)

	ethAddr, err := api.GetUserEthAddr(r)
	if err != nil {
		writeError(r.Context(), w, richerrors.Error{Code: http.StatusUnauthorized, Err: err, ExternalMsg: err.Error()})
		return
	}

	if err := t.accessService.ValidateAccess(r.Context(), accessReq, ethAddr); err != nil {
		writeError(r.Context(), w, fmt.Errorf("failed to validate access: %w", err))
		return
	}

	t.createAndReturnToken(w, r, tokenReq.Audience, accessReq)
}

// createAndReturnToken signs the permission token and writes it to the response.
func (t *TokenExchangeController) createAndReturnToken(w http.ResponseWriter, r *http.Request, aud []string, accessReq *access.AccessRequest) {
	if len(aud) == 0 {
		aud = defaultAudience
	}

	respSub, err := middleware.GetResponseSubject(r.Context())
	if err != nil {
		writeError(r.Context(), w, err)
		return
	}

	tk, err := t.signer.SignPrivilegePayload(r.Context(), services.PrivilegeTokenDTO{
		AccessRequest:   accessReq,
		Audience:        aud,
		ResponseSubject: respSub,
	})
	if err != nil {
		writeError(r.Context(), w, fmt.Errorf("failed to sign privilege payload: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{Token: tk})
}

func (t *TokenExchangeController) tokenReqToAccessReq(tokenReq *TokenRequest) (*access.AccessRequest, error) {
	assetDID, err := assetDIDFromTokenReq(tokenReq, t.chainID)
	if err != nil {
		return nil, err
	}
	if len(tokenReq.Permissions) == 0 {
		tokenReq.Permissions, err = t.getPermissionsFromPrivileges(tokenReq.Privileges, assetDID.GetContractAddress())
		if err != nil {
			return nil, err
		}
	}
	return &access.AccessRequest{
		Asset:        assetDID,
		Permissions:  tokenReq.Permissions,
		EventFilters: tokenReq.CloudEvents.Events,
	}, nil
}

// addDefaultIdentifiers update tokenReq.CloudEvents.Events so that if any cloud event identifiers are missing assume they want everything.
func addDefaultIdentifiers(tokenReq *access.AccessRequest) {
	for i := range tokenReq.EventFilters {
		ce := &tokenReq.EventFilters[i]
		if ce.EventType == "" {
			ce.EventType = tokenclaims.GlobalIdentifier
		}
		if ce.Source == "" {
			ce.Source = tokenclaims.GlobalIdentifier
		}
		if len(ce.IDs) == 0 {
			ce.IDs = []string{tokenclaims.GlobalIdentifier}
		}
		if len(ce.Tags) == 0 {
			ce.Tags = []string{tokenclaims.GlobalIdentifier}
		}
	}
}

func (t *TokenExchangeController) getPermissionsFromPrivileges(privileges []int64, contractAddress common.Address) ([]string, error) {
	privMap := tokenclaims.PrivilegeIDToName
	if contractAddress == t.contractAddressManufacturer {
		privMap = tokenclaims.ManufacturerPrivilegeIDToName
	}
	permNames := make([]string, len(privileges))
	unknownPrivs := make([]int64, 0)
	for i, privID := range privileges {
		permName, exists := privMap[privID]
		if !exists {
			// If we don't have a mapping for this privilege ID, consider it missing
			unknownPrivs = append(unknownPrivs, privID)
			continue
		}
		permNames[i] = permName
	}

	if len(unknownPrivs) > 0 {
		return nil, richerrors.Error{
			Code:        http.StatusBadRequest,
			Err:         fmt.Errorf("unknown privileges %v", unknownPrivs),
			ExternalMsg: fmt.Sprintf("unknown privileges %v", unknownPrivs),
		}
	}
	return permNames, nil
}

func assetDIDFromTokenReq(tokenReq *TokenRequest, chainID uint64) (models.AssetDID, error) {
	if tokenReq.Asset != "" {
		assetDID, err := models.DecodeAssetDID(tokenReq.Asset)
		if err != nil {
			return nil, badRequest(fmt.Sprintf("Invalid asset DID %q: %v.", tokenReq.Asset, err))
		}
		return assetDID, nil
	}
	if !common.IsHexAddress(tokenReq.NFTContractAddress) {
		return nil, badRequest(fmt.Sprintf("Invalid NFT contract address %q.", tokenReq.NFTContractAddress))
	}
	return models.ERC721Asset{
		ERC721DID: cloudevent.ERC721DID{
			ChainID:         chainID,
			ContractAddress: common.HexToAddress(tokenReq.NFTContractAddress),
			TokenID:         big.NewInt(tokenReq.TokenID),
		},
	}, nil
}

type codeResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// badRequest builds a 400 error carrying a client-safe message.
func badRequest(msg string) error {
	return richerrors.Error{Code: http.StatusBadRequest, Err: errors.New(msg), ExternalMsg: msg}
}

// writeJSON writes v as a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError maps an error to a JSON {code, message} response, honouring a
// richerrors.Error's code and external message and defaulting to 500.
func writeError(ctx context.Context, w http.ResponseWriter, err error) {
	code := http.StatusInternalServerError
	message := "Internal error."

	var richErr richerrors.Error
	if errors.As(err, &richErr) {
		message = richErr.ExternalMsg
		if richErr.Code != 0 {
			code = richErr.Code
		}
	}

	if code != http.StatusNotFound {
		zerolog.Ctx(ctx).Err(err).Int("httpStatusCode", code).Msg("caught an error from http request")
	}

	writeJSON(w, code, codeResp{Code: code, Message: message})
}
