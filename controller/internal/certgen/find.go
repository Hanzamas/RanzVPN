package certgen

// StoredCertificate is a certificate of the My store of Windows (FindInStore): its encoding, and the
// key that it is linked to in the Microsoft Software Key Storage Provider.
type StoredCertificate struct {
	// DER is the encoding of the certificate.
	DER []byte
	// Key is the name of its key in the provider, which keys.LoadKSP opens.
	Key string
	// Machine tells whether the key is in the machine key set, and not in the one of the user.
	Machine bool
}
