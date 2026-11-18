package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	// It returns ErrDIDNotFound for a DID the directory does not hold and
	// wraps ErrDirectory for any other failure.
	VerificationMethods(ctx context.Context, did string) ([]VerificationMethod, error)
}

// DirectoryClient is a Directory over the did-directory HTTP client.
type DirectoryClient struct {
	Client *client.Client
}

// VerificationMethods implements Directory.
func (d *DirectoryClient) VerificationMethods(ctx context.Context, did string) ([]VerificationMethod, error) {
	doc, err := d.Client.Resolve(ctx, did)
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			return nil, ErrDIDNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrDirectory, err)
	}
	out := make([]VerificationMethod, 0, len(doc.VerificationMethod))
	for _, vm := range doc.VerificationMethod {
		out = append(out, VerificationMethod{ID: vm.ID, PublicKeyMultibase: vm.PublicKeyMultibase})
	}
	return out, nil
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
// not be fetched.
func (v *Verifier) Verify(ctx context.Context, did, fragment string, data []byte, sig string) error {
	if fragment == orgKeyFragment {
		return fmt.Errorf("%w: #%s is a commit key, not a sign-in key", ErrNoSuchKey, fragment)
	}
	methods, err := v.Directory.VerificationMethods(ctx, did)
	if err != nil {
		return err
	}
	want := did + "#" + fragment
	for _, vm := range methods {
		if vm.ID != want {
			continue
		}
		pub, err := didkey.DecodeMultibase(vm.PublicKeyMultibase)
		if err != nil {
			return fmt.Errorf("decode %s: %w", vm.ID, err)
		}
		return pub.Verify(data, sig)
	}
	return fmt.Errorf("%w: %s", ErrNoSuchKey, want)
}

// isDID is the loose syntactic check on a DID: the scheme and a non-empty
// method-specific id. The directory decides whether it exists.
func isDID(s string) bool {
	rest, ok := strings.CutPrefix(s, "did:")
	if !ok {
		return false
	}
	method, id, ok := strings.Cut(rest, ":")
	return ok && method != "" && id != "" && !strings.ContainsAny(s, " \t\r\n#")
}
