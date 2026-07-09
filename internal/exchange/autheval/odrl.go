package autheval

import (
	"fmt"
	"time"

	"github.com/DIMO-Network/dauth/internal/exchange/models"
	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
)

// odrlActions is the closed action vocabulary of DIMO ODRL profile v1: the
// existing permission names. An agreement granting any action outside this set
// is rejected outright rather than partially honored, so authoring typos fail
// loudly at exchange time instead of silently granting nothing.
var odrlActions = func() map[string]struct{} {
	actions := make(map[string]struct{})
	for name := range tokenclaims.PrivilegeNameToID {
		actions[name] = struct{}{}
	}
	for name := range tokenclaims.ManufacturerPrivilegeNameToID {
		actions[name] = struct{}{}
	}
	return actions
}()

// ODRLGrantMap evaluates a validated profile v1 agreement against the
// requested asset at the given instant and returns the granted permission
// names, in the same shape EvaluatePermissions consumes.
func ODRLGrantMap(agreement *models.ODRLAgreement, assetDID models.AssetDID, now time.Time) (map[string]bool, error) {
	targetDID, err := models.DecodeAssetDID(agreement.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}
	if targetDID.String() != assetDID.String() {
		return nil, fmt.Errorf("target %s does not match requested asset %s", agreement.Target, assetDID.String())
	}
	if !agreement.SatisfiedAt(now) {
		return nil, fmt.Errorf("agreement is outside its validity period")
	}
	grants := make(map[string]bool, len(agreement.Permission))
	for _, perm := range agreement.Permission {
		if _, ok := odrlActions[perm.Action]; !ok {
			return nil, fmt.Errorf("unknown action %q", perm.Action)
		}
		grants[perm.Action] = true
	}
	return grants, nil
}
