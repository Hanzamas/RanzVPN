package controller

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The WireGuard Devices (SDN-80 #375). Their gateway reports the last handshake and the traffic of
// each in its Telemetry, which the controller keeps (takeDevices) and lists with the Devices of the
// intent (Devices, `ranz get devices`); and the configuration of a Device names the key of the
// WireGuard interface that its gateway reported with the Capability wireguard (DeviceConfig).

// DeviceStatus is what the controller knows about one Device: where it is in the overlay, and its
// WireGuard end at its gateway as the gateway reported it last.
type DeviceStatus struct {
	Name        string `json:"name"`
	Network     string `json:"network"`
	Gateway     string `json:"gateway"`
	Address     string `json:"address,omitempty"`
	IPv6Address string `json:"ipv6Address,omitempty"`
	// Owner is the User that the Device is a device of, left out for a standalone Device (SDN-82).
	Owner string `json:"owner,omitempty"`
	// PresharedKey says that the Device has a PresharedKey, which the controller showed once when it made
	// the Device and keeps sealed (SDN-82).
	PresharedKey bool `json:"presharedKey,omitempty"`
	// PresharedKeyDoesNotOpen says that the controller cannot open that PresharedKey: neither the sealing
	// key of its host nor the Cluster key of a cluster opens it, as after the restore of a backup on
	// another host, or the key storage provider did not answer. The gateway terminates the Device without
	// it until it opens, or until the Device is made again (devicekeys.go; SDN-82-R1).
	PresharedKeyDoesNotOpen bool `json:"presharedKeyDoesNotOpen,omitempty"`
	// LastHandshake is the time of the last WireGuard handshake of the Device with its gateway,
	// zero before the first one that the gateway reported.
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	// TxBytes went from the gateway to the Device, RxBytes from the Device to the gateway, since the
	// WireGuard interface of the gateway came up.
	TxBytes uint64 `json:"txBytes"`
	RxBytes uint64 `json:"rxBytes"`
	// Reported is when the gateway reported them, zero while it reported none.
	Reported time.Time `json:"reported,omitzero"`
	// Unlicensed is true for a Device above the node cap of the licence in force: no node has it in
	// its desired state.
	Unlicensed bool `json:"unlicensed,omitempty"`
}

// deviceEnd is the WireGuard end of one Device as its gateway reported it last.
type deviceEnd struct {
	gateway       string
	lastHandshake time.Time
	tx, rx        uint64
	reported      time.Time
}

// deviceState holds the ends that the gateways reported, by Device name. Its zero value is ready.
type deviceState struct {
	mu   sync.Mutex
	ends map[string]deviceEnd
}

// takeDevices keeps the counters of the Devices that the node gateway reported in its Telemetry. A
// Device whose gateway the node is not is left out: only its gateway sees its WireGuard end. The
// controller does not hold c.mu.
func (c *Controller) takeDevices(gateway string, counters []*controlpb.DeviceCounters) {
	if len(counters) == 0 {
		return
	}
	c.mu.Lock()
	devices := c.intent.Devices
	c.mu.Unlock()
	now := time.Now().UTC()
	c.dev.mu.Lock()
	defer c.dev.mu.Unlock()
	if c.dev.ends == nil {
		c.dev.ends = map[string]deviceEnd{}
	}
	for _, dc := range counters {
		if d, ok := devices[dc.GetDevice()]; !ok || d.Gateway != gateway {
			continue
		}
		end := deviceEnd{gateway: gateway, tx: dc.GetTxBytes(), rx: dc.GetRxBytes(), reported: now}
		if ms := dc.GetLastHandshakeMs(); ms != 0 {
			end.lastHandshake = time.UnixMilli(int64(ms)).UTC()
		}
		c.dev.ends[dc.GetDevice()] = end
	}
}

// Devices returns the status of every Device of the intent, ordered by name. A Device shows the
// counters that its gateway reported last, and none that another node reported for it.
func (c *Controller) Devices() []DeviceStatus {
	c.mu.Lock()
	in := c.intent
	covered := in.Capped(c.force.Nodes).Devices
	keyed, shut := map[string]bool{}, map[string]bool{}
	for name := range c.dkeys.sealed {
		keyed[name] = true
		shut[name] = c.deviceKeyShut(name)
	}
	c.mu.Unlock()
	c.dev.mu.Lock()
	ends := maps.Clone(c.dev.ends)
	c.dev.mu.Unlock()
	out := []DeviceStatus{}
	for _, name := range slices.Sorted(maps.Keys(in.Devices)) {
		d := in.Devices[name]
		st := DeviceStatus{Name: name, Network: d.Network, Gateway: d.Gateway, Address: d.Address, IPv6Address: d.IPv6Address,
			Owner: d.Owner, PresharedKey: keyed[name], PresharedKeyDoesNotOpen: shut[name]}
		if _, ok := covered[name]; !ok {
			st.Unlicensed = true
		}
		if end, ok := ends[name]; ok && end.gateway == d.Gateway {
			st.LastHandshake, st.TxBytes, st.RxBytes, st.Reported = end.lastHandshake, end.tx, end.rx, end.reported
		}
		out = append(out, st)
	}
	return out
}

// DeviceConfig returns the WireGuard configuration of the Device name (intent.DeviceConfig), with the
// key of the WireGuard interface that its gateway reported. An error that wraps intent.ErrNotFound
// names a Device that does not exist or a gateway that has reported no key yet.
func (c *Controller) DeviceConfig(name string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.intent.Devices[name]
	if !ok {
		return "", fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindDevice, name)
	}
	// The keys of the Device were shown once when it was made (devicekeys.go): this configuration says where they go, and
	// that a PresharedKey does not open (SDN-82-R1)
	return c.intent.DeviceConfigWith(name, c.gatewayKey(d.Gateway), intent.DeviceKeys{HasPreshared: c.hasDeviceKey(name),
		PresharedDoesNotOpen: c.deviceKeyShut(name)})
}
