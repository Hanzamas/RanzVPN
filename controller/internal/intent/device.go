package intent

import (
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// WireGuard Devices (SDN-80 #375, spec #374). A Device is a phone, a laptop or a router that joins
// exactly one Network over standard WireGuard, without ranz.exe: its configuration is a stock
// WireGuard configuration (DeviceConfig), and its traffic enters the overlay at its gateway, a Node
// with a WireGuard end (Node.WireGuard) that terminates WireGuard with WireGuardNT and reports the
// Capability wireguard (ADR-0033). The controller gives a Device one address of each pool of its
// Network, which the Device keeps while it is in that Network, as a Node keeps its own (address.go),
// and no Node is ever given one of them. The policy of the VRF applies to a Device by its addresses
// and its tags, as it does to a Node, so one Device reaches another only when a rule allows it. A
// Device counts as a client node for the licence (Licensed). The word Peer is not used for one: the
// glossary keeps it for the other end of a link.

// KindDevice is the resource kind of a Device.
const KindDevice = "Device"

const (
	// DefaultWireGuardPort is the UDP port of a gateway that declares none.
	DefaultWireGuardPort = 51820
	// DeviceKeepalive is the keepalive of the configuration of a Device, in seconds: a phone on a
	// mobile network keeps the mapping of its NAT open with it. The battery saver turns it off.
	DeviceKeepalive = 25
	// MaxGatewayDevices is the most Devices that one gateway terminates: the Telemetry of the
	// control protocol carries the counters of 64 (proto/ranz/control/v1/control.options).
	MaxGatewayDevices = 64
	// MaxDeviceTags is the most tags of one Device: the Device message of the control protocol
	// carries 16, as NodeConfig does for a Node.
	MaxDeviceTags = 16
	// maxEndpoint is the length of the longest DNS name of a gateway (RFC 1035).
	maxEndpoint = 253
)

// A DNS name of a gateway: labels of letters, digits and hyphens, not starting or ending with a
// hyphen, joined by dots (RFC 1123), in lower case once complete wrote it so.
var endpointRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Device is a WireGuard Device of exactly one Network.
type Device struct {
	// Network is the L3 Network that the Device joins: its addresses come from the pools of the
	// Network, and its configuration routes the prefixes of every Network of the VRF to the gateway.
	Network string `json:"network"`
	// Gateway is the Node that terminates the WireGuard of the Device: a Node of the VRF of the
	// Network with a WireGuard end, which reports the Capability wireguard.
	Gateway string `json:"gateway"`
	// PublicKey is the WireGuard key of the Device, base64 of KeySize bytes, which the administrator
	// supplies, or which the controller makes with the key pair of the Device when it makes the Device
	// (SDN-82, internal/controller devicekeys.go). The controller never holds the private key of a Device.
	PublicKey string `json:"publicKey"`
	// Tags identify the Device to the policy of its VRF, as the tags of a Node do.
	Tags []string `json:"tags,omitempty"`
	// Owner is the User that the Device is a device of (SDN-82, deviceowner.go): the Device carries the
	// name of every Group of that User as a tag besides its own, and counts against the maximum devices
	// of the User. Left out, the Device has no owner: a standalone Device, a router, takes the tags set
	// on it.
	Owner string `json:"owner,omitempty"`
	// BatterySaver turns the keepalive of the configuration off, for a Device that only starts
	// connections and should not wake its radio for one.
	BatterySaver bool `json:"batterySaver,omitempty"`
	// Address is the address of the Device in the IPv4 pool of its Network. One left out is
	// allocated by the controller; a Network without an IPv4 pool gives none.
	Address string `json:"address,omitempty"`
	// IPv6Address is its address in the IPv6 pool of its Network, as Address is in the IPv4 one.
	IPv6Address string `json:"ipv6Address,omitempty"`
}

// WireGuard is the WireGuard end of a gateway Node (SDN-80): the Devices whose gateway it is reach
// it at the DNS name Endpoint, on the UDP port Port.
type WireGuard struct {
	// Endpoint is the DNS name of the gateway that the configuration of its Devices names, so the
	// gateway can move to another address without a change of any Device.
	Endpoint string `json:"endpoint"`
	// Port is the UDP port that the gateway listens on, DefaultWireGuardPort when it is left out.
	Port uint16 `json:"port,omitempty"`
}

// device returns the address of the family f that the Device d holds, "" for none.
func (f addrFamily) device(d Device) string {
	if f == family6 {
		return d.IPv6Address
	}
	return d.Address
}

// storeDevice sets the address of the family f that the Device d holds.
func (f addrFamily) storeDevice(d *Device, s string) {
	if f == family6 {
		d.IPv6Address = s
	} else {
		d.Address = s
	}
}

// DeviceAddress returns the address of the family of a pool (4 or 6) of the Device name in its
// Network, with the length of a host: false when it holds none that is a host address of that pool.
func (in Intent) DeviceAddress(name string, family int) (netip.Prefix, bool) {
	d, ok := in.Devices[name]
	if !ok {
		return netip.Prefix{}, false
	}
	f := family4
	if family == 6 {
		f = family6
	}
	pool, ok := in.pool(d.Network, f)
	if !ok {
		return netip.Prefix{}, false
	}
	a, err := netip.ParseAddr(f.device(d))
	if err != nil || !hostAddress(pool, a) {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}

// Licensed returns how many nodes in counts for the licence (ADR-0036): its Nodes, and its Devices,
// each of which counts as a client node (SDN-80).
func (in Intent) Licensed() int {
	return len(in.Nodes) + len(in.Devices)
}

// AddedDevices returns the Devices of in that prev does not hold, in name order, each as the
// message of a licence refusal names it.
func (in Intent) AddedDevices(prev Intent) []string {
	var out []string
	for _, name := range sortedNames(in.Devices) {
		if _, ok := prev.Devices[name]; !ok {
			out = append(out, KindDevice+" "+strconv.Quote(name))
		}
	}
	return out
}

// capDevices keeps the Devices of in that a licence covers once the Nodes of in took their part of
// its cap: room Devices at most, in name order, and only those whose gateway in still holds (Capped).
func (in Intent) capDevices(room int) {
	kept := 0
	for _, name := range sortedNames(in.Devices) {
		if _, ok := in.Nodes[in.Devices[name].Gateway]; !ok || kept >= room {
			delete(in.Devices, name)
			continue
		}
		kept++
	}
}

// cloneDevices gives each Device of devices slices of its own (Clone).
func cloneDevices(devices map[string]Device) {
	for name, d := range devices {
		d.Tags = slices.Clone(d.Tags)
		devices[name] = d
	}
}

// completeDevices writes the WireGuard end of each gateway Node and the tags of each Device of in in
// their one form: the DNS name of the gateway in lower case, its port DefaultWireGuardPort when it
// declares none, and the tags sorted.
func (in Intent) completeDevices() {
	for name, n := range in.Nodes {
		if n.WireGuard == (WireGuard{}) {
			continue
		}
		n.WireGuard.Endpoint = strings.ToLower(n.WireGuard.Endpoint)
		if n.WireGuard.Port == 0 {
			n.WireGuard.Port = DefaultWireGuardPort
		}
		in.Nodes[name] = n
	}
	for name, d := range in.Devices {
		slices.Sort(d.Tags)
		in.Devices[name] = d
	}
}

// validateDevices checks the WireGuard end of each Node and each Device of a completed intent: the
// Network of a Device is an L3 Network with a pool, its gateway a Node of the VRF of the Network with
// a WireGuard end, which terminates MaxGatewayDevices Devices at most, and its key is the key of no
// other Device. The addresses were checked when they were allocated (allocateDevices).
func (in Intent) validateDevices() []error {
	var problems []error
	for _, name := range sortedNames(in.Nodes) {
		w := in.Nodes[name].WireGuard
		if w == (WireGuard{}) {
			continue
		}
		if len(w.Endpoint) > maxEndpoint || !endpointRule.MatchString(w.Endpoint) {
			problems = append(problems, fmt.Errorf("Node %q: wireguard.endpoint %q is not a DNS name: labels of letters, digits and hyphens joined by dots, at most %d characters", name, w.Endpoint, maxEndpoint))
		}
		if w.Port == 0 {
			problems = append(problems, fmt.Errorf("Node %q: wireguard.port is 0, and a gateway listens on a port from 1 to 65535", name))
		}
	}
	keys := map[string]string{}
	terminated := map[string]int{}
	for _, name := range sortedNames(in.Devices) {
		d := in.Devices[name]
		if k, err := ParseKey(d.PublicKey); err != nil {
			problems = append(problems, fmt.Errorf("Device %q: %w", name, err))
		} else if other, ok := keys[string(k)]; ok {
			problems = append(problems, fmt.Errorf("Device %q: the publicKey is already the key of Device %q", name, other))
		} else {
			keys[string(k)] = name
		}
		if len(d.Tags) > MaxDeviceTags {
			problems = append(problems, fmt.Errorf("Device %q: %d tags, at most %d", name, len(d.Tags), MaxDeviceTags))
		}
		for i, t := range d.Tags {
			if !nameRule.MatchString(t) {
				problems = append(problems, fmt.Errorf("Device %q: tag %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", name, t))
			}
			if i > 0 && d.Tags[i-1] == t {
				problems = append(problems, fmt.Errorf("Device %q: tag %q is listed twice", name, t))
			}
		}
		nw, ok := in.Networks[d.Network]
		switch {
		case d.Network == "":
			problems = append(problems, fmt.Errorf("Device %q: it names no network, and a Device joins exactly one", name))
			continue
		case !ok:
			problems = append(problems, fmt.Errorf("Device %q: Network %q does not exist", name, d.Network))
			continue
		case nw.Mode != ModeL3:
			problems = append(problems, fmt.Errorf("Device %q: Network %q is an %s Network, and a Device joins an L3 Network: WireGuard carries no L2", name, d.Network, nw.Mode))
			continue
		case nw.IPv4Pool == "" && nw.IPv6Pool == "":
			problems = append(problems, fmt.Errorf("Device %q: Network %q has no pool to give the Device an address from", name, d.Network))
		}
		gw, ok := in.Nodes[d.Gateway]
		switch {
		case d.Gateway == "":
			problems = append(problems, fmt.Errorf("Device %q: it names no gateway, the Node that terminates its WireGuard", name))
		case !ok:
			problems = append(problems, fmt.Errorf("Device %q: its gateway, Node %q, does not exist", name, d.Gateway))
		case !slices.Contains(gw.VRFs, nw.VRF):
			problems = append(problems, fmt.Errorf("Device %q: its gateway, Node %q, is not in VRF %q of Network %q", name, d.Gateway, nw.VRF, d.Network))
		case gw.WireGuard == (WireGuard{}):
			problems = append(problems, fmt.Errorf("Device %q: its gateway, Node %q, has no wireguard end: give the Node the DNS name that its Devices reach it at (wireguard.endpoint)", name, d.Gateway))
		default:
			terminated[d.Gateway]++
		}
	}
	for _, gw := range sortedNames(terminated) {
		if terminated[gw] > MaxGatewayDevices {
			problems = append(problems, fmt.Errorf("Node %q: it is the gateway of %d Devices, at most %d", gw, terminated[gw], MaxGatewayDevices))
		}
	}
	// The owner of each Device and its tags with those of the Groups of the owner (deviceowner.go)
	return append(problems, in.validateDeviceOwners()...)
}

// deviceUsers returns the Devices of in that name the Network network or the gateway Node node, as
// the message of a refused delete names them ("" for either matches nothing).
func (in Intent) deviceUsers(network, node string) []string {
	var out []string
	for _, name := range sortedNames(in.Devices) {
		d := in.Devices[name]
		if (network != "" && d.Network == network) || (node != "" && d.Gateway == node) {
			out = append(out, KindDevice+" "+strconv.Quote(name))
		}
	}
	return out
}

// keepDevices takes the first step of the allocation of the addresses of the Devices (allocate):
// every Device keeps the address of each family that it held before while it stays in the same
// Network and the address is still a free host address of the pool, before any Node is given one.
// The addresses that a Device of the document declares are taken out and returned, by Device name
// and family, for allocateDevices to check once the Nodes hold theirs. declared holds kind/name of the
// resources of the document; prev is the intent before it.
func (in Intent) keepDevices(prev Intent, declared map[string]bool) map[string]map[addrFamily]string {
	want := map[string]map[addrFamily]string{}
	for _, f := range []addrFamily{family4, family6} {
		held := map[string]map[netip.Addr]bool{}
		for _, name := range sortedNames(in.Devices) {
			d := in.Devices[name]
			s := f.device(d)
			if declared[KindDevice+"/"+name] {
				// A Device of the document keeps what it held while it stays in its Network; an
				// address that it declares anew is checked once the Nodes hold theirs
				before := ""
				if old, ok := prev.Devices[name]; ok && old.Network == d.Network {
					before = f.device(old)
				}
				switch {
				case s == "":
					s = before
				case s != before:
					if want[name] == nil {
						want[name] = map[addrFamily]string{}
					}
					want[name][f] = s
					s = ""
				}
			}
			f.storeDevice(&d, "")
			pool, ok := in.pool(d.Network, f)
			a, err := netip.ParseAddr(s)
			if ok && err == nil && hostAddress(pool, a) && !within(in.reservedIn(d.Network, pool), a) && !held[d.Network][a] {
				if held[d.Network] == nil {
					held[d.Network] = map[netip.Addr]bool{}
				}
				held[d.Network][a] = true
				f.storeDevice(&d, a.String())
			}
			in.Devices[name] = d
		}
	}
	return want
}

// deviceHolders adds the addresses of the family f that the Devices hold so far to holder, the
// holders of each address by Network, so that no Node is given one (allocateFamily). A holder is
// written as holderName reads it.
func (in Intent) deviceHolders(holder map[string]map[netip.Addr]string, f addrFamily) {
	for _, name := range sortedNames(in.Devices) {
		d := in.Devices[name]
		a, err := netip.ParseAddr(f.device(d))
		if err != nil || holder[d.Network] == nil {
			continue
		}
		holder[d.Network][a] = KindDevice + " " + strconv.Quote(name)
	}
}

// holderName returns the holder of an address as an error message names it: a Node by its name, a
// Device as deviceHolders wrote it.
func holderName(holder string) string {
	if strings.HasPrefix(holder, KindDevice+" ") {
		return holder
	}
	return KindNode + " " + strconv.Quote(holder)
}

// allocateDevices takes the last step of the allocation of the addresses of the Devices, once the
// Nodes hold theirs: an address that a Device of the document declares must be a free host address
// of the pool of its Network that the Network does not reserve, and every Device that holds no
// address of a pool of its Network gets the lowest free host address of it, Devices in name order.
// want holds the declared addresses, which keepDevices took out.
func (in Intent) allocateDevices(want map[string]map[addrFamily]string) []error {
	var problems []error
	for _, f := range []addrFamily{family4, family6} {
		holder := map[string]map[netip.Addr]string{}
		reserved := map[string][]netip.Prefix{}
		for _, network := range sortedNames(in.Networks) {
			pool, ok := in.pool(network, f)
			if !ok {
				continue
			}
			holder[network] = map[netip.Addr]string{}
			reserved[network] = in.reservedIn(network, pool)
		}
		for _, name := range sortedNames(in.Nodes) {
			for network, s := range f.held(in.Nodes[name]) {
				if a, err := netip.ParseAddr(s); err == nil && holder[network] != nil {
					holder[network][a] = name
				}
			}
		}
		in.deviceHolders(holder, f)
		free := func(network string, pool netip.Prefix, a netip.Addr) bool {
			return hostAddress(pool, a) && holder[network][a] == "" && !within(reserved[network], a)
		}
		cursor := map[string]netip.Addr{}
		for _, name := range sortedNames(in.Devices) {
			d := in.Devices[name]
			pool, ok := in.pool(d.Network, f)
			s := want[name][f]
			switch {
			case !ok && s != "":
				problems = append(problems, fmt.Errorf("Device %q: address %q: Network %q has no %s pool", name, s, d.Network, f))
				continue
			case !ok || f.device(d) != "":
				continue
			case s != "":
				a, err := netip.ParseAddr(s)
				switch {
				case err != nil || !f.contains(a):
					problems = append(problems, fmt.Errorf("Device %q: address %q is not an %s address", name, s, f))
				case !hostAddress(pool, a):
					problems = append(problems, fmt.Errorf("Device %q: address %s is not a host address of the pool %s of Network %q", name, a, pool, d.Network))
				case within(reserved[d.Network], a):
					problems = append(problems, fmt.Errorf("Device %q: address %s of Network %q is reserved by the Network", name, a, d.Network))
				case holder[d.Network][a] != "":
					problems = append(problems, fmt.Errorf("Device %q: address %s of Network %q is already the address of %s", name, a, d.Network, holderName(holder[d.Network][a])))
				default:
					holder[d.Network][a] = KindDevice + " " + strconv.Quote(name)
					f.storeDevice(&d, a.String())
					in.Devices[name] = d
				}
				continue
			}
			a, ok := cursor[d.Network]
			if !ok {
				a = pool.Addr()
			}
			for a.IsValid() && pool.Contains(a) && !free(d.Network, pool, a) {
				a = after(reserved[d.Network], a)
			}
			if !a.IsValid() || !pool.Contains(a) {
				problems = append(problems, fmt.Errorf("Network %q: the %s pool %s has no free address for Device %q", d.Network, f, pool, name))
				cursor[d.Network] = a
				continue
			}
			holder[d.Network][a] = KindDevice + " " + strconv.Quote(name)
			f.storeDevice(&d, a.String())
			in.Devices[name] = d
			cursor[d.Network] = a.Next()
		}
	}
	return problems
}

// countDevices counts the addresses that the Devices hold as allocated in out, the pools of Pools,
// whose place index gives by Network name and family.
func (in Intent) countDevices(out []PoolUse, index map[string]int) {
	for _, d := range in.Devices {
		for _, f := range []addrFamily{family4, family6} {
			i, ok := index[d.Network+" "+f.String()]
			a, err := netip.ParseAddr(f.device(d))
			if ok && err == nil && hostAddress(out[i].Pool, a) {
				out[i].Allocated++
			}
		}
	}
}

// DeviceConfig returns the WireGuard configuration of the Device name without a key of the Device
// (DeviceConfigWith), as the controller shows it after the one time that it showed the keys.
func (in Intent) DeviceConfig(name string, gatewayKey []byte) (string, error) {
	return in.DeviceConfigWith(name, gatewayKey, DeviceKeys{})
}

// DeviceConfigWith returns the WireGuard configuration of the Device name, as a stock WireGuard client
// imports it (SDN-80): its addresses, the MTU of its VRF, and its gateway as the one peer of the
// configuration, with the public key gatewayKey of the WireGuard interface of the gateway (what the
// gateway reported with the Capability wireguard), the DNS name and the UDP port of the gateway, the
// prefixes of every Network of the VRF as the allowed IPs (a split tunnel: what the Device reaches of
// them is up to the policy of the VRF) and a keepalive of DeviceKeepalive seconds unless the battery
// saver is on. The controller never holds the private key of a Device, so the configuration says
// where it goes, unless keys carries the key pair that the controller just made for the Device
// (SDN-82): then the configuration is the finished one that the Device imports, with the PrivateKey of
// its [Interface] and the PresharedKey of its [Peer], shown once. The configuration has no DNS line
// yet: a stock client sends every name to the server of its DNS line, and the stub resolver of overlay
// DNS (SDN-11, #187) answers only the names of the zone of its VRF and refuses every other one.
func (in Intent) DeviceConfigWith(name string, gatewayKey []byte, keys DeviceKeys) (string, error) {
	d, ok := in.Devices[name]
	if !ok {
		return "", fmt.Errorf("%w: %s %q", ErrNotFound, KindDevice, name)
	}
	nw := in.Networks[d.Network]
	gw, ok := in.Nodes[d.Gateway]
	if !ok || gw.WireGuard == (WireGuard{}) {
		return "", fmt.Errorf("%w: Device %q: its gateway, Node %q, has no wireguard end", ErrInvalid, name, d.Gateway)
	}
	if len(gatewayKey) != KeySize {
		return "", fmt.Errorf("%w: Device %q: its gateway, Node %q, has not reported the key of its WireGuard interface yet: it does in the Hello of its control stream once wireguard.dll loads there", ErrNotFound, name, d.Gateway)
	}
	var addresses []string
	for _, family := range []int{4, 6} {
		if p, ok := in.DeviceAddress(name, family); ok {
			addresses = append(addresses, p.String())
		}
	}
	var allowed4, allowed6 []netip.Prefix
	for _, network := range sortedNames(in.Networks) {
		if in.Networks[network].VRF != nw.VRF {
			continue
		}
		for _, p := range in.poolsOf(network) {
			if p.Addr().Is4() {
				allowed4 = append(allowed4, p)
			} else {
				allowed6 = append(allowed6, p)
			}
		}
	}
	var allowed []string
	for _, ps := range [][]netip.Prefix{allowed4, allowed6} {
		slices.SortFunc(ps, func(a, b netip.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		for _, p := range ps {
			allowed = append(allowed, p.String())
		}
	}
	mtu := in.VRFs[nw.VRF].MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# Ranz VPN: the WireGuard configuration of Device %s, of Network %s in VRF %s\n", name, d.Network, nw.VRF)
	b.WriteString("[Interface]\n")
	if len(keys.Private) == KeySize {
		fmt.Fprintf(&b, "PrivateKey = %s\n", base64.StdEncoding.EncodeToString(keys.Private))
	} else {
		b.WriteString("# PrivateKey = the private key of this Device, which only the Device holds\n")
	}
	fmt.Fprintf(&b, "Address = %s\n", strings.Join(addresses, ", "))
	fmt.Fprintf(&b, "MTU = %d\n", mtu)
	b.WriteString("\n")
	b.WriteString("[Peer]\n")
	fmt.Fprintf(&b, "# The gateway, Node %s\n", d.Gateway)
	fmt.Fprintf(&b, "PublicKey = %s\n", base64.StdEncoding.EncodeToString(gatewayKey))
	switch {
	case len(keys.Preshared) == KeySize:
		fmt.Fprintf(&b, "PresharedKey = %s\n", base64.StdEncoding.EncodeToString(keys.Preshared))
	case keys.HasPreshared && keys.PresharedDoesNotOpen:
		b.WriteString("# PresharedKey = the PresharedKey of this Device does not open with the key of the controller, so the gateway terminates the Device without it until it opens, or until the Device is made again\n")
	case keys.HasPreshared:
		b.WriteString("# PresharedKey = the PresharedKey of this Device, which the controller showed once when it made the Device\n")
	}
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", gw.WireGuard.Endpoint, gw.WireGuard.Port)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	if !d.BatterySaver {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", DeviceKeepalive)
	}
	return b.String(), nil
}
