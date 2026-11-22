package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/DIMO-Network/did-directory/pkg/client"
	"github.com/DIMO-Network/did-directory/pkg/didkey"
)

// ErrNoSuchKey means the DID document lists no verification method with the
// requested id.
var ErrNoSuchKey = errors.New("no such verification method")

// ErrDIDNotFound means the directory does not hold the DID.
var ErrDIDNotFound = errors.New("DID not found")

// ErrDirectory means the directory could not be reached or answered badly;
// the sign-in should be retried, not refused.
var ErrDirectory = errors.New("directory unavailable")

// VerificationMethod is one key a DID document publishes.
type VerificationMethod struct {
	// ID is the full id, <did>#<fragment>.
	ID string
	// PublicKeyMultibase is the multikey, a did:key without its prefix.
	PublicKeyMultibase string
}

// Directory answers which keys a DID currently publishes.
type Directory interface {
	// VerificationMethods resolves did and returns its verification methods.
	// It returns ErrDIDNotFound for a DID the directory does not hold (404),
	// wraps ErrDIDUnusable for one it will never serve (400, 410, 422) or
	// that is not a valid DID (isDID; no request is made), and
	// wraps ErrDirectory for any other failure, which a retry may get past.
	VerificationMethods(ctx context.Context, did string) ([]VerificationMethod, error)
	// RotationKeys returns the rotation keys of did's head operation, as
	// did:key strings: the keys that may sign the DID's next operation. It
	// wraps ErrDIDUnusable for a DID that is not valid (no request is made)
	// and ErrDirectory for any failure to read the head.
	RotationKeys(ctx context.Context, did string) ([]string, error)
}

// ErrDIDUnusable means the directory will not serve a document for the DID:
// it was deactivated (410), the directory refused the request as malformed
// (400, 422), or the DID is not syntactically valid and was never sent.
// Retrying cannot help, so the sign-in is refused.
var ErrDIDUnusable = errors.New("DID not usable")

// resolveTimeout bounds one directory resolve.
const resolveTimeout = 5 * time.Second

// DirectoryClient is a Directory over the did-directory HTTP client.
type DirectoryClient struct {
	Client *client.Client
}

// VerificationMethods implements Directory. A DID that fails isDID is
// refused before any request is made, so nothing a caller supplies (an
// /exchange client assertion's iss, say) can rewrite the directory request
// path.
func (d *DirectoryClient) VerificationMethods(ctx context.Context, did string) ([]VerificationMethod, error) {
	if !isDID(did) {
		return nil, fmt.Errorf("%w: not a valid DID", ErrDIDUnusable)
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	doc, err := d.Client.Resolve(ctx, did)
	if err != nil {
		// Only answers that say the DID itself is the problem are terminal.
		// Everything else (a timeout, 408, 429, any other 4xx, a 5xx) is the
		// directory failing to answer, which a retry may get past.
		var se *client.StatusError
		switch {
		case errors.Is(err, client.ErrNotFound):
			return nil, ErrDIDNotFound
		case errors.Is(err, client.ErrGone):
			return nil, fmt.Errorf("%w: %v", ErrDIDUnusable, err)
		case errors.As(err, &se) && (se.Status == http.StatusBadRequest || se.Status == http.StatusUnprocessableEntity):
			return nil, fmt.Errorf("%w: directory answered %d", ErrDIDUnusable, se.Status)
		}
		return nil, fmt.Errorf("%w: %v", ErrDirectory, err)
	}
	out := make([]VerificationMethod, 0, len(doc.VerificationMethod))
	for _, vm := range doc.VerificationMethod {
		out = append(out, VerificationMethod{ID: vm.ID, PublicKeyMultibase: vm.PublicKeyMultibase})
	}
	return out, nil
}

// RotationKeys implements Directory. The DID document does not carry
// rotation keys, so they come from the head the directory serves at
// GET /<did>/data. Only an approve sign-in reads it, after the document has
// resolved and the signature verified, so the DID is known to be served, and
// any failure here (the client's RawGet reports no typed status) is the
// directory failing to answer: ErrDirectory, which the client retries.
func (d *DirectoryClient) RotationKeys(ctx context.Context, did string) ([]string, error) {
	if !isDID(did) {
		return nil, fmt.Errorf("%w: not a valid DID", ErrDIDUnusable)
	}
	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	raw, err := d.Client.RawGet(ctx, d.Client.BaseURL()+"/"+did+"/data")
	if err != nil {
		return nil, fmt.Errorf("%w: reading the DID head: %v", ErrDirectory, err)
	}
	var head struct {
		RotationKeys []string `json:"rotationKeys"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, fmt.Errorf("%w: decoding the DID head: %v", ErrDirectory, err)
	}
	return head.RotationKeys, nil
}

// orgKeyFragment is the org repository commit key (plan §1 decision C). It
// signs commits on the org host and is never a login key: whoever holds it
// may publish records as the org, not act as the org elsewhere.
const orgKeyFragment = "dimo_org"

// Verifier checks that a signature over a challenge was made by a key the
// DID's document lists.
type Verifier struct {
	Directory Directory
}

// Verify checks sig, a base64url r||s ECDSA signature over the SHA-256 hash of
// data (the form the directory itself checks on operations), against the
// verification method <did>#<fragment>. It returns nil when the signature
// verifies, ErrNoSuchKey when the document lists no such method, a
// signature error otherwise, and wraps ErrDirectory when the document could
// not be fetched. ErrDIDNotFound and ErrDIDUnusable come back from the
// directory as they are.
func (v *Verifier) Verify(ctx context.Context, did, fragment string, data []byte, sig string) error {
	_, err := v.VerifyMethod(ctx, did, fragment, data, sig)
	return err
}

// VerifyMethod is Verify, and on success also returns the verification
// method's key as a did:key.
func (v *Verifier) VerifyMethod(ctx context.Context, did, fragment string, data []byte, sig string) (string, error) {
	if fragment == orgKeyFragment {
		return "", fmt.Errorf("%w: #%s is a commit key, not a sign-in key", ErrNoSuchKey, fragment)
	}
	methods, err := v.Directory.VerificationMethods(ctx, did)
	if err != nil {
		return "", err
	}
	want := did + "#" + fragment
	for _, vm := range methods {
		if vm.ID != want {
			continue
		}
		pub, err := didkey.DecodeMultibase(vm.PublicKeyMultibase)
		if err != nil {
			return "", fmt.Errorf("decode %s: %w", vm.ID, err)
		}
		if err := pub.Verify(data, sig); err != nil {
			return "", err
		}
		return pub.DIDKey(), nil
	}
	return "", fmt.Errorf("%w: %s", ErrNoSuchKey, want)
}

// IsRotationKey reports whether didKey is one of the rotation keys of did's
// head. Keys are compared decoded, so two encodings of one key match. Errors
// are the Directory's.
func (v *Verifier) IsRotationKey(ctx context.Context, did, didKey string) (bool, error) {
	want, err := didkey.Decode(didKey)
	if err != nil {
		return false, fmt.Errorf("decode %s: %w", didKey, err)
	}
	keys, err := v.Directory.RotationKeys(ctx, did)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if pub, err := didkey.Decode(k); err == nil && pub.DIDKey() == want.DIDKey() {
			return true, nil
		}
	}
	return false, nil
}

// maxDIDLen caps a DID before it reaches the store or the directory.
const maxDIDLen = 128

// didPattern is DID-core's syntax: the scheme, a lowercase method, and a
// method-specific id of letters, digits, . _ : - and percent-encoded octets
// (% and two hex digits) that does not end in ':' (method-specific-id =
// *( *idchar ":" ) 1*idchar). It admits no / ? # or whitespace, so a DID
// cannot rewrite the directory request path.
var didPattern = regexp.MustCompile(`^did:[a-z0-9]+:(?:[A-Za-z0-9._:-]|%[0-9A-Fa-f]{2})*(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})$`)

// isDID is the syntactic check on a DID, applied before anything is stored or
// resolved. The directory decides whether it exists.
func isDID(s string) bool {
	return len(s) <= maxDIDLen && didPattern.MatchString(s)
}
