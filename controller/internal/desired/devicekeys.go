package desired

import (
	"bytes"

	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The PresharedKeys of the WireGuard Devices (SDN-82 #377). A PresharedKey is a secret that the intent
// never holds, so Compile does not know it: the controller puts into the Device object of the gateway
// of each Device that has one what it keeps of it (WithPresharedKeys), after the compile, as it puts
// the TLS fingerprints into the NodeConfig. What it keeps is the PresharedKey sealed, so the states
// that it stores and compares hold no PresharedKey in clear, and each Update that it sends to a
// gateway has the sealed PresharedKey opened (internal/controller, devicekeys.go).

// WithPresharedKeys puts keys, the PresharedKey of each Device by Device name, into the Device object
// that holds the public key of the Device, the one in the state of its gateway: no other node gets a
// PresharedKey. The Device object is replaced by a copy, since the states share their objects. states
// are the fresh result of a compile.
func WithPresharedKeys(states map[string]State, keys map[string][]byte) {
	if len(keys) == 0 {
		return
	}
	for node, st := range states {
		for key, obj := range st {
			d := obj.GetDevice()
			if key.Kind != controlpb.Kind_KIND_DEVICE || d == nil || d.GetGateway() != node || len(d.GetPublicKey()) == 0 {
				continue
			}
			psk, ok := keys[d.GetName()]
			if !ok {
				continue
			}
			clone, ok := proto.Clone(d).(*controlpb.Device)
			if !ok {
				continue
			}
			clone.PresharedKey = bytes.Clone(psk)
			st[key] = &controlpb.Object{Kind: &controlpb.Object_Device{Device: clone}}
		}
	}
}
