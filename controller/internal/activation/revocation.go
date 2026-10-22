package activation

import (
	"crypto"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"time"
)

// RevocationList is the set of Licence ids whose activation the vendor has withdrawn (ADR-0036
// amendment of 2026-10-22). The service distributes it signed, so an offline install verifies it
// with a vendor public key and locks the named Licences out at the next heartbeat. The ids are
// sorted, so the same set signs to the same bytes.
type RevocationList struct {
	// IDs are the revoked Licence ids, sorted so the same set signs to the same bytes.
	IDs []string `json:"ids"`
	// Issued is when the vendor signed the list.
	Issued time.Time `json:"issued"`
}

// message is the canonical bytes that the signature covers.
func (l RevocationList) message() ([]byte, error) {
	l.IDs = slices.Clone(l.IDs)
	slices.Sort(l.IDs)
	return json.Marshal(l)
}

// SignRevocations signs the revocation list l through the signer and returns the Ed25519 signature.
func SignRevocations(signer crypto.Signer, l RevocationList) ([]byte, error) {
	msg, err := l.message()
	if err != nil {
		return nil, err
	}
	return signEd25519(signer, msg)
}

// VerifyRevocations reports whether sig is a vendor signature over the revocation list l.
func VerifyRevocations(l RevocationList, sig []byte, vendor []ed25519.PublicKey) bool {
	msg, err := l.message()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(vendor, func(k ed25519.PublicKey) bool { return ed25519.Verify(k, msg, sig) })
}

// contains reports whether the list revokes the Licence id.
func (l RevocationList) contains(id string) bool {
	return slices.Contains(l.IDs, id)
}

// String names the list in a log line.
func (l RevocationList) String() string {
	return fmt.Sprintf("%d revoked licences at %s", len(l.IDs), stamp(l.Issued))
}
