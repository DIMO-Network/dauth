package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/DIMO-Network/dauth/pkg/tokenclaims"
)

// AuthorizeRequest is the body of the org host's POST /authorize (plan §3.3).
type AuthorizeRequest struct {
	URI       string   `json:"uri"`
	Caller    string   `json:"caller"`
	ClientID  string   `json:"clientId,omitempty"`
	Vehicle   string   `json:"vehicle"`
	Abilities []string `json:"abilities"`
}

// Coverage is the host's answer: delegation.Coverage plus the time it was
// evaluated at. Historical windows decode straight into token windows, since
// both are [start|null, end|null] pairs.
type Coverage struct {
	Vehicle      string                         `json:"vehicle"`
	Historical   map[string]tokenclaims.Windows `json:"historical"`
	Live         []string                       `json:"live"`
	Suspended    []string                       `json:"suspended"`
	RecoveryUsed bool                           `json:"recoveryUsed"`
	Chain        []string                       `json:"chain"`
	At           time.Time                      `json:"at"`
}

// Refusal is the host declining to authorize: a 403 with a code naming the
// evaluator's error, a 404 for a delegation the host does not hold, or a 400
// for a request the host could not read, such as a grant URI it cannot parse.
type Refusal struct {
	Status    int
	Code      string
	Message   string
	Suspended []string
}

func (r *Refusal) Error() string {
	return fmt.Sprintf("org host refused: %s (%s)", r.Message, r.Code)
}

// ErrOrgHost wraps any failure to get an answer from the host: unreachable,
// a 5xx, or a body that does not parse. The exchange answers 502 for these.
var ErrOrgHost = errors.New("org host unavailable")

// Authorizer asks the org host whether a caller may exercise a delegation.
type Authorizer interface {
	Authorize(ctx context.Context, req AuthorizeRequest) (*Coverage, error)
}

// OrgHost is an Authorizer over HTTP.
type OrgHost struct {
	// BaseURL is the host, without a trailing slash.
	BaseURL string
	// Identity supplies dauth's own identity token for the call; the host
	// admits it because its sub is in the host's ISSUER_DIDS.
	Identity func(ctx context.Context) (string, error)
	// HTTP is the client to send with; nil means http.DefaultClient.
	HTTP *http.Client
}

// Authorize implements Authorizer.
func (h *OrgHost) Authorize(ctx context.Context, req AuthorizeRequest) (*Coverage, error) {
	token, err := h.Identity(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: issuing dauth's own identity: %v", ErrOrgHost, err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.BaseURL+"/authorize", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	client := h.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOrgHost, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response: %v", ErrOrgHost, err)
	}

	switch {
	case resp.StatusCode == http.StatusOK:
		var cov Coverage
		if err := json.Unmarshal(data, &cov); err != nil {
			return nil, fmt.Errorf("%w: parsing coverage: %v", ErrOrgHost, err)
		}
		return &cov, nil
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		var body struct {
			Error     string   `json:"error"`
			Code      string   `json:"code"`
			Suspended []string `json:"suspended"`
		}
		if err := json.Unmarshal(data, &body); err != nil || body.Code == "" {
			return nil, fmt.Errorf("%w: %s: %s", ErrOrgHost, resp.Status, string(data))
		}
		return nil, &Refusal{Status: resp.StatusCode, Code: body.Code, Message: body.Error, Suspended: body.Suspended}
	case resp.StatusCode == http.StatusBadRequest:
		// The caller's request, relayed, did not parse on the host: the caller's
		// error, not an outage.
		var body struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &body)
		if body.Error == "" {
			body.Error = string(data)
		}
		return nil, &Refusal{Status: resp.StatusCode, Code: "invalid_request", Message: body.Error}
	default:
		return nil, fmt.Errorf("%w: %s: %s", ErrOrgHost, resp.Status, string(data))
	}
}
