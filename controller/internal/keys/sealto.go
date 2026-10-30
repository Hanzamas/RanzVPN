package keys

import "errors"

// Sealing to the key of another member (AUD1-DT-16, #501). The members of a controller cluster give each
// other the Cluster key sealed to the public half of the Sealing key of the member that gets it, so that
// only that member opens it (internal/clusterkey). SealTo makes that seal from the public half alone,
// in the form of Seal, and the Sealer of the private half opens it as it opens what it sealed itself.

// Public returns the public half of the key of s: the key that Seal seals to.
func (s *Sealer) Public() []byte {
	return s.key.Public()
}

// SealTo seals plain under label to the X25519 public key public, in the form of Seal: the Sealer of the
// private half of public opens it, under that label, and no other key does. A public key that is no
// X25519 key, or one of low order, fails.
func SealTo(public []byte, label string, plain []byte) ([]byte, error) {
	return NewSealer(publicOnly(public)).Seal(label, plain)
}

// publicOnly is the public half of an X25519 key without its private half: a Sealer of it seals to the
// key and opens nothing.
type publicOnly []byte

func (k publicOnly) Public() []byte {
	return k
}

func (k publicOnly) DH([]byte) ([]byte, error) {
	return nil, errors.New("keys: the public half of a key agrees on nothing")
}
