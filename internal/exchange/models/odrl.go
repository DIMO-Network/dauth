package models

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
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

// odrlOperators are the constraint operators profile v1 accepts, all over the
// dateTime left operand: gteq/gt bound the start of the validity period,
// lteq/lt bound the end.
var odrlOperators = map[string]struct{}{
	"gteq": {},
	"gt":   {},
	"lteq": {},
	"lt":   {},
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
// the privilege: prefix is declared by the profile context.
type ODRLPermission struct {
	Action string `json:"action"`
}

// ODRLConstraint is an ODRL constraint restricted to profile v1: a dateTime
// comparison bounding the agreement's validity period. RightOperand is a plain
// RFC 3339 timestamp, not a JSON-LD @value object.
type ODRLConstraint struct {
	LeftOperand  string `json:"leftOperand"`
	Operator     string `json:"operator"`
	RightOperand string `json:"rightOperand"`
}

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
	for i, perm := range a.Permission {
		if perm.Action == "" {
			return fmt.Errorf("permission[%d]: action is required", i)
		}
	}
	for i, c := range a.Constraint {
		if c.LeftOperand != odrlLeftOperandDateTime {
			return fmt.Errorf("constraint[%d]: leftOperand must be %q, got %q", i, odrlLeftOperandDateTime, c.LeftOperand)
		}
		if _, ok := odrlOperators[c.Operator]; !ok {
			return fmt.Errorf("constraint[%d]: unsupported operator %q", i, c.Operator)
		}
		if _, err := time.Parse(time.RFC3339, c.RightOperand); err != nil {
			return fmt.Errorf("constraint[%d]: rightOperand must be an RFC 3339 timestamp: %w", i, err)
		}
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
		case "gteq":
			ok = !now.Before(bound)
		case "gt":
			ok = now.After(bound)
		case "lteq":
			ok = !now.After(bound)
		case "lt":
			ok = now.Before(bound)
		}
		if !ok {
			return false
		}
	}
	return true
}
