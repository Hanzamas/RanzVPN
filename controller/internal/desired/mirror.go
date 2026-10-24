package desired

import (
	"fmt"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// mirrors returns the Mirrors of in that select the Node node, as the node applies them (SDN-23,
// ADR-0029 decision 9), ordered by name: the VRF of a Mirror as its id from vrfs, or 0 for every
// VRF of the node when the Mirror names none; its protocol as its number; and its sensor as the
// bytes of its address and its UDP port.
func mirrors(in intent.Intent, node string, vrfs map[string]*controlpb.Vrf) ([]*controlpb.Mirror, error) {
	var out []*controlpb.Mirror
	for _, name := range in.MirrorsOf(node) {
		m := in.Mirrors[name]
		protocol, err := intent.ParseProtocol(m.Protocol)
		if err != nil {
			return nil, fmt.Errorf("Mirror %q: %w", name, err)
		}
		sensor, err := intent.ParseSensor(m.Sensor)
		if err != nil {
			return nil, fmt.Errorf("Mirror %q: %w", name, err)
		}
		mirror := &controlpb.Mirror{Name: name, Protocol: uint32(protocol), Port: uint32(m.Port), Sensor: sensor.Addr().AsSlice(),
			SensorPort: uint32(sensor.Port()), Vni: m.VNI, RateLimit: m.RateLimit}
		if m.VRF != "" {
			mirror.VrfId = vrfs[m.VRF].GetId()
		}
		out = append(out, mirror)
	}
	return out, nil
}
