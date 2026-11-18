package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
)

// This file defines DIMO ODRL profile v1, the new-style SACD grant format.
//
// A new-style grant is a CloudEvent of type TypeSACDODRL whose data field is a
// W3C ODRL 2.2 Agreement (https://www.w3.org/TR/odrl-model/) constrained to
// the DIMO profile. The profile is deliberately narrow and fail-closed: only
// the vocabulary below is accepted, and any document containing anything
// outside it — unknown fields, prohibitions, duties, unexpected operators or
// contexts — is rejected rather than partially honored. The profile grows by
// widening this parser in later versions, never by interpreting unvetted ODRL.
//
// The document is treated as plain JSON against a fixed, byte-for-byte
// vocabulary. No JSON-LD processing is ever performed: an attacker-supplied
// @context cannot remap what any term means under the grantor's signature.

const (
	// TypeSACDODRL is the CloudEvent type for new-style SACD grants carrying
	// an ODRL Agreement. Candidate for promotion to the cloudevent module
	// alongside TypeSACD once the format settles.
	TypeSACDODRL = "dimo.sacd.odrl"

	// ODRLContextIRI is the W3C ODRL JSON-LD context.
	ODRLContextIRI = "http://www.w3.org/ns/odrl.jsonld"
	// DIMOProfileV1IRI identifies version 1 of the DIMO ODRL profile.
	DIMOProfileV1IRI = "https://ns.dimo.co/odrl/v1"

	// ODRLTypeAgreement is the only policy type profile v1 accepts: an
	// assigner grants an assignee rules over a target asset.
	ODRLTypeAgreement = "Agreement"

	odrlLeftOperandDateTime = "dateTime"
)

// odrlOperators are the constraint operators profile v1 accepts: gteq/gt
// bound the start of a period, lteq/lt the end. The names are shared with the
// token-claims constraint vocabulary.
var odrlOperators = map[string]struct{}{
	tokenclaims.OperatorGteq: {},
	tokenclaims.OperatorGt:   {},
	tokenclaims.OperatorLteq: {},
	tokenclaims.OperatorLt:   {},
}

// ODRLAgreement is an ODRL 2.2 Agreement restricted to DIMO profile v1.
type ODRLAgreement struct {
	Context    json.RawMessage  `json:"@context"`
	Type       string           `json:"@type"`
	UID        string           `json:"uid,omitempty"`
	Profile    string           `json:"profile"`
	Assigner   string           `json:"assigner"`
	Assignee   string           `json:"assignee"`
	Target     string           `json:"target"`
	Constraint []ODRLConstraint `json:"constraint,omitempty"`
	Permission []ODRLPermission `json:"permission"`
}

// ODRLPermission grants a single action on the agreement's target. Profile v1
// actions are the existing DIMO permission names (e.g. "privilege:GetRawData");
// the privilege: prefix is declared by the profile context. An optional
// constraint list narrows the data the action may read: profile v1 defines
// dimo:recordedAt, bounding the recording timestamps of readable data points.
// Per-permission constraints are forwarded verbatim into the minted token's
// scoped_permissions claim; they are enforced by the data services, not here.
type ODRLPermission struct {
	Action     string           `json:"action"`
	Constraint []ODRLConstraint `json:"constraint,omitempty"`
}

// ODRLConstraint is an ODRL constraint atom. At the policy level profile v1
// accepts only dateTime comparisons bounding the agreement's validity period;
// on a permission it accepts only dimo:recordedAt comparisons bounding the
// data window. RightOperand is a plain RFC 3339 timestamp, not a JSON-LD
// @value object. The type is shared with the token claims so grant documents
// and minted tokens speak one constraint vocabulary.
type ODRLConstraint = tokenclaims.Constraint

// ParseODRLAgreement parses and structurally validates a DIMO profile v1
// agreement. It is strict: unknown fields anywhere in the document are an
// error, as is any value outside the profile vocabulary.
func ParseODRLAgreement(data []byte) (*ODRLAgreement, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var agreement ODRLAgreement
	if err := dec.Decode(&agreement); err != nil {
		return nil, fmt.Errorf("failed to parse ODRL agreement: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after ODRL agreement")
	}
	if err := agreement.validate(); err != nil {
		return nil, err
	}
	return &agreement, nil
}

func (a *ODRLAgreement) validate() error {
	if err := validateODRLContext(a.Context); err != nil {
		return err
	}
	if a.Type != ODRLTypeAgreement {
		return fmt.Errorf("@type must be %q, got %q", ODRLTypeAgreement, a.Type)
	}
	if a.Profile != DIMOProfileV1IRI {
		return fmt.Errorf("profile must be %q, got %q", DIMOProfileV1IRI, a.Profile)
	}
	if a.Assigner == "" {
		return fmt.Errorf("assigner is required")
	}
	if a.Assignee == "" {
		return fmt.Errorf("assignee is required")
	}
	if a.Target == "" {
		return fmt.Errorf("target is required")
	}
	if len(a.Permission) == 0 {
		return fmt.Errorf("at least one permission is required")
	}
	seenActions := make(map[string]struct{}, len(a.Permission))
	for i, perm := range a.Permission {
		if perm.Action == "" {
			return fmt.Errorf("permission[%d]: action is required", i)
		}
		// Under the ODRL model, two permission entries naming the same action
		// are independent grants — a union. Profile v1 defines no union
		// semantics, so rather than silently honoring only one entry (partial
		// honoring, which this profile never does), the document is rejected.
		if _, dup := seenActions[perm.Action]; dup {
			return fmt.Errorf("permission[%d]: duplicate action %q; profile v1 defines no union semantics", i, perm.Action)
		}
		seenActions[perm.Action] = struct{}{}
		for j, c := range perm.Constraint {
			if err := validateODRLConstraint(c, tokenclaims.LeftOperandRecordedAt, fmt.Sprintf("permission[%d].constraint[%d]", i, j)); err != nil {
				return err
			}
		}
	}
	for i, c := range a.Constraint {
		if err := validateODRLConstraint(c, odrlLeftOperandDateTime, fmt.Sprintf("constraint[%d]", i)); err != nil {
			return err
		}
	}
	return nil
}

// validateODRLConstraint checks a single constraint atom against the profile
// vocabulary at its position: policy-level constraints compare dateTime (the
// grant's validity period), per-permission constraints compare
// dimo:recordedAt (the data window). Anything else rejects the document.
func validateODRLConstraint(c ODRLConstraint, wantLeftOperand, path string) error {
	if c.LeftOperand != wantLeftOperand {
		return fmt.Errorf("%s: leftOperand must be %q, got %q", path, wantLeftOperand, c.LeftOperand)
	}
	if _, ok := odrlOperators[c.Operator]; !ok {
		return fmt.Errorf("%s: unsupported operator %q", path, c.Operator)
	}
	if _, err := time.Parse(time.RFC3339, c.RightOperand); err != nil {
		return fmt.Errorf("%s: rightOperand must be an RFC 3339 timestamp: %w", path, err)
	}
	return nil
}

// validateODRLContext requires the @context to be one of the fixed canonical
// forms: the ODRL context IRI alone, or the ODRL context IRI followed by the
// DIMO profile IRI. The context is never dereferenced or processed.
func validateODRLContext(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("@context is required")
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		if single == ODRLContextIRI {
			return nil
		}
		return fmt.Errorf("@context must be %q", ODRLContextIRI)
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("@context must be the ODRL context IRI or [ODRL, DIMO profile] IRIs")
	}
	if len(list) == 1 && list[0] == ODRLContextIRI {
		return nil
	}
	if len(list) == 2 && list[0] == ODRLContextIRI && list[1] == DIMOProfileV1IRI {
		return nil
	}
	return fmt.Errorf("@context must be [%q] or [%q, %q]", ODRLContextIRI, ODRLContextIRI, DIMOProfileV1IRI)
}

// SatisfiedAt reports whether every constraint on the agreement holds at the
// given instant. Constraints are conjunctive per the ODRL model. Must only be
// called on a validated agreement.
func (a *ODRLAgreement) SatisfiedAt(now time.Time) bool {
	for _, c := range a.Constraint {
		bound, err := time.Parse(time.RFC3339, c.RightOperand)
		if err != nil {
			return false
		}
		var ok bool
		switch c.Operator {
		case tokenclaims.OperatorGteq:
			ok = !now.Before(bound)
		case tokenclaims.OperatorGt:
			ok = now.After(bound)
		case tokenclaims.OperatorLteq:
			ok = !now.After(bound)
		case tokenclaims.OperatorLt:
			ok = now.Before(bound)
		}
		if !ok {
			return false
		}
	}
	return true
}
