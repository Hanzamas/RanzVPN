package api

import "fmt"

// FingerprintError is the refusal of a certificate whose public key does not have the TLS fingerprint
// that Pin was given: Got is the fingerprint that it has, Want the one that was asked for. The client has
// sent nothing by then, so no token has left it.
type FingerprintError struct {
	Got, Want string
}

func (e *FingerprintError) Error() string {
	return fmt.Sprintf("the controller's certificate has the TLS fingerprint %s, not %s", e.Got, e.Want)
}
