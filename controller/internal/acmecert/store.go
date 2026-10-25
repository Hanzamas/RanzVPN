package acmecert

import (
	"crypto"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

// WindowsStore is the My store of Windows, with the keys in the Microsoft Software Key Storage
// Provider: of the local machine, where the node service finds them, or of the current user. Off
// Windows each call fails, as the packages keys and certgen do there.
type WindowsStore struct {
	Machine bool
}

// NewKey makes the ECDSA P-256 key name in the provider.
func (s WindowsStore) NewKey(name string) (crypto.Signer, error) {
	return keys.CreateKSP(name, s.Machine)
}

// Install puts the certificate der into the My store, linked to the key name, and checks that the
// store finds the key of the certificate, as Schannel does when the node serves with it.
func (s WindowsStore) Install(der []byte, name string) error {
	if err := certgen.InstallInStore(der, name, s.Machine); err != nil {
		return err
	}
	return certgen.CheckStoredKey(certgen.Thumbprint(der), s.Machine)
}

// Has reports whether the My store holds the certificate of the thumbprint with its key.
func (s WindowsStore) Has(thumbprint string) bool {
	return certgen.CheckStoredKey(thumbprint, s.Machine) == nil
}

// Remove takes the certificate of the thumbprint out of the My store and deletes the key name.
func (s WindowsStore) Remove(thumbprint, name string) {
	if thumbprint != "" {
		_ = certgen.RemoveFromStore(thumbprint, s.Machine)
	}
	if name != "" {
		_ = keys.DeleteKSP(name, s.Machine)
	}
}
