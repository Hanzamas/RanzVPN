package control

import (
	"context"
	"crypto/tls"

	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
	"github.com/Hanzamas/RanzVPN/controller/internal/nodecontroller"
)

// DialPinned opens a control stream as Dial does, as a Node with Controller settings does
// (SDN-90): the certificate of the controller must have the TLS fingerprint fingerprint, the
// tlsFingerprint that ranz status prints on the controller, before the Noise handshake runs. A
// certificate of another key fails the dial with nodecontroller.ErrFingerprint, so the node sends
// nothing on that session.
func DialPinned(ctx context.Context, addr string, key keys.Static, controllerKey []byte, fingerprint string) (*Conn, error) {
	return dial(ctx, addr, key, controllerKey, func(st tls.ConnectionState) error {
		return nodecontroller.CheckFingerprint(st, fingerprint)
	})
}
