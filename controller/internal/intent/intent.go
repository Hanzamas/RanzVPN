// Package intent is the declared network that `ranz apply -f` sends to the controller: the
// resources of #176 "Resource model" that the controller knows (VRF, Network, Node, Policy, the
// Controller members of a controller cluster, and the 1:1 NAT rules of nat.go with the 4via6 of
// the Nodes), their validation, and the values the controller fills in when a resource is first
// applied, the addresses of the Nodes among them (address.go, with the rules of the pools, the
// reservations and the LAN subnets in ipam.go); the revisions of the intent with the diff between
// two (revision.go); and the intent of a first install (defaults.go).
package intent

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The resource kinds.
const (
	KindVRF        = "VRF"
	KindNetwork    = "Network"
	KindNode       = "Node"
	KindPolicy     = "Policy"
	KindController = "Controller"
)

// The actions of a Policy.
const (
	PolicyAllow = "allow"
	PolicyDeny  = "deny"
)

// The network modes.
const (
	ModeL3 = "L3"
	ModeL2 = "L2"
)

const (
	// DefaultMTU is the MTU of a VRF that declares none, and the smallest allowed (#176 "MTU and
	// traffic control").
	DefaultMTU = 1280
	// MaxMTU is the largest MTU of a VRF.
	MaxMTU = 65535
	// KeySize is the size of a Noise static key (X25519).
	KeySize = 32
	// MaxAddress is the length of the longest Controller address; it fits the 256-byte address
	// field of the C node (proto/ranz/control/v1/control.options).
	MaxAddress = 255
)

var (
	// ErrInvalid marks an intent that cannot be applied.
	ErrInvalid = errors.New("invalid intent")
	// ErrNotFound marks a delete of a resource that does not exist.
	ErrNotFound = errors.New("no such resource")
)

// A name is a DNS label: 1 to 63 lower-case letters, digits and hyphens, not starting or ending
// with a hyphen. It fits the 64-byte name fields of the C node (proto/ranz/control/v1/control.options).
var nameRule = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Document is the body of an apply and the file that `ranz apply -f` reads.
type Document struct {
	Resources []Resource `json:"resources"`
}

// Resource is one declared object. Spec holds the fields of its kind: VRF, Network, Node, Policy,
// Controller or NAT.
type Resource struct {
	Kind string          `json:"kind"`
	Name string          `json:"name"`
	Spec json.RawMessage `json:"spec,omitempty"`
}

// VRF is a routing domain (#176 "VRFs and addressing").
type VRF struct {
	// ID is the 32-bit VRF id. Left out, the controller picks the lowest free one.
	ID uint32 `json:"id,omitempty"`
	// ULA is the ULA /48 of the VRF (RFC 4193). Left out, the controller draws a random one.
	ULA string `json:"ula,omitempty"`
	// MTU of the VRF, DefaultMTU when it is left out.
	MTU uint32 `json:"mtu,omitempty"`
	// RateLimit is the rate in bits per second that each Node sends into the overlay in the VRF at
	// most, which a token bucket on the Node keeps (ADR-0025 decision 17, SDN-20). Left out, the
	// VRF has no limit.
	RateLimit uint64 `json:"rateLimit,omitempty"`
	// DNS turns on overlay DNS in the VRF (ADR-0028): a zone of its own, which SDN-11 (#187)
	// serves on its members. The first start sets it for VRF default (ADR-0034).
	DNS bool `json:"dns,omitempty"`
}

// Network belongs to one VRF. Its pools are the controller's to allocate from (ADR-0028,
// ipam.go): the IPv6 pool lies in the ULA /48 of the VRF, and no pool of a VRF overlaps another.
type Network struct {
	VRF      string `json:"vrf"`
	Mode     string `json:"mode,omitempty"` // ModeL3 (the default) or ModeL2
	IPv4Pool string `json:"ipv4Pool,omitempty"`
	IPv6Pool string `json:"ipv6Pool,omitempty"`
	// EnrolSources limits where the Nodes of the Network may open their control stream from
	// (SDN-39, sources.go): the source prefixes, each a CIDR prefix or one address, that the
	// stream of a Node of the VRF may come from. Left out, a Node may enrol from any address.
	EnrolSources []string `json:"enrolSources,omitempty"`
	// Reserved holds prefixes of the pools, or single addresses, that the allocation never gives a
	// Node: the gateway of a LAN, a static host. It counts as in use for the pool event.
	Reserved []string `json:"reserved,omitempty"`
	// PoolThreshold is the percentage of a pool in use at which the controller raises the pool
	// event, from 1 to 100. Left out, it is DefaultPoolThreshold.
	PoolThreshold uint32 `json:"poolThreshold,omitempty"`
	// DHCP is the DHCP responder of an L2 Network (SDN-43, dhcp.go): a Node that answers DHCP from
	// the IPv4 pool when the bridged LAN has no DHCP server. Left out, the responder is off.
	DHCP *DHCP `json:"dhcp,omitempty"`
}

// Node is a node of the overlay, identified by its Noise static key.
type Node struct {
	PublicKey string `json:"publicKey"` // base64 of the KeySize-byte key
	// VRFs are the VRFs the node is a member of. Left out, the node joins VRF default when the
	// intent has it (ADR-0034).
	VRFs []string `json:"vrfs,omitempty"`
	Tags []string `json:"tags,omitempty"`
	// Relay is the address and UDP port that the node's relay role listens on, host:port with an
	// IP address (ADR-0015). Left out, the node is no relay for the others.
	Relay string `json:"relay,omitempty"`
	// Addresses holds the address of the node in each L3 Network of its VRFs that has an IPv4
	// pool, by Network name (ADR-0028, address.go). One left out is allocated by the controller.
	Addresses map[string]string `json:"addresses,omitempty"`
	// IPv6Addresses holds the IPv6 address of the node in each L3 Network of its VRFs that has an
	// IPv6 pool, by Network name, as Addresses holds the IPv4 ones.
	IPv6Addresses map[string]string `json:"ipv6Addresses,omitempty"`
	// LANSubnets holds the LAN subnets behind the node, by VRF name: the node is their gateway and
	// advertises each as a route in that VRF (ADR-0028 decision 4, ipam.go). A LAN subnet is never
	// an allocation, so no pool of the VRF covers one. Two gateways may advertise the same subnet
	// (ADR-0025 decision 12).
	LANSubnets map[string][]string `json:"lanSubnets,omitempty"`
	// RateLimit is the rate in bits per second that the node sends into the overlay at most, in all
	// its VRFs together, which a token bucket on the node keeps (ADR-0025 decision 17, SDN-20).
	// Left out, the node has no limit.
	RateLimit uint64 `json:"rateLimit,omitempty"`
}

// Controller is one member of the controller cluster as nodes reach it (SDN-17, ADR-0026). The
// leader sends the list of them to nodes of control schema version 2, so a node can open its
// stream to any member when it loses the one it has.
type Controller struct {
	Address   string `json:"address"`   // host:port of the member's port, at most MaxAddress long
	PublicKey string `json:"publicKey"` // base64 of the member's Noise static key, KeySize bytes
}

// Policy is one rule of the policy of a VRF (ADR-0029). The policy engine of the nodes is
// default deny, and a rule with the action PolicyAllow lets traffic through; the first start
// creates the starter rule "allow all inside VRF default" (ADR-0034). So far a rule matches
// every flow between the Nodes of its VRF: the tags, protocols and ports it matches, and its
// compilation into the policy engine of the nodes, come with SDN-8 (#184).
type Policy struct {
	VRF    string `json:"vrf"`
	Action string `json:"action"` // PolicyAllow or PolicyDeny
}

// Intent is the whole declared network, by kind and name.
type Intent struct {
	VRFs        map[string]VRF
	Networks    map[string]Network
	Nodes       map[string]Node
	Policies    map[string]Policy
	Controllers map[string]Controller
	NATs        map[string]NAT
}

// New returns an empty intent.
func New() Intent {
	return Intent{VRFs: map[string]VRF{}, Networks: map[string]Network{}, Nodes: map[string]Node{}, Policies: map[string]Policy{},
		Controllers: map[string]Controller{}, NATs: map[string]NAT{}}
}

// Clone returns a copy of in that shares nothing with it.
func (in Intent) Clone() Intent {
	out := Intent{VRFs: maps.Clone(in.VRFs), Networks: map[string]Network{}, Nodes: map[string]Node{}, Policies: maps.Clone(in.Policies),
		Controllers: maps.Clone(in.Controllers), NATs: maps.Clone(in.NATs)}
	if out.VRFs == nil {
		out.VRFs = map[string]VRF{}
	}
	if out.Policies == nil {
		out.Policies = map[string]Policy{}
	}
	if out.Controllers == nil {
		out.Controllers = map[string]Controller{}
	}
	if out.NATs == nil {
		out.NATs = map[string]NAT{}
	}
	for name, n := range in.Networks {
		n.EnrolSources = slices.Clone(n.EnrolSources)
		n.Reserved = slices.Clone(n.Reserved)
		n.DHCP = n.DHCP.clone()
		out.Networks[name] = n
	}
	for name, n := range in.Nodes {
		n.VRFs = slices.Clone(n.VRFs)
		n.Tags = slices.Clone(n.Tags)
		n.Addresses = maps.Clone(n.Addresses)
		n.IPv6Addresses = maps.Clone(n.IPv6Addresses)
		n.LANSubnets = cloneLANs(n.LANSubnets)
		out.Nodes[name] = n
	}
	return out
}

// Capped returns in with only its first n Nodes in name order: the Nodes that a licence with a
// node cap of n covers (internal/licence). in itself is not changed.
func (in Intent) Capped(n int) Intent {
	if len(in.Nodes) <= n {
		return in
	}
	out := in.Clone()
	for _, name := range sortedNames(in.Nodes)[max(n, 0):] {
		delete(out.Nodes, name)
	}
	return out
}

// Apply returns in with the resources of doc added or replaced, completed and validated; in
// itself is not changed. random draws the ULA of a VRF that declares none; crypto/rand when nil.
func Apply(in Intent, doc Document, random io.Reader) (Intent, error) {
	if random == nil {
		random = rand.Reader
	}
	next := in.Clone()
	var problems []error
	seen := map[string]bool{}
	for _, r := range doc.Resources {
		if seen[r.Kind+"/"+r.Name] {
			problems = append(problems, fmt.Errorf("%s %q: declared twice", r.Kind, r.Name))
			continue
		}
		seen[r.Kind+"/"+r.Name] = true
		if !nameRule.MatchString(r.Name) {
			problems = append(problems, fmt.Errorf("%s %q: the name must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", r.Kind, r.Name))
			continue
		}
		var err error
		switch r.Kind {
		case KindVRF:
			var v VRF
			if err = decodeSpec(r.Spec, &v); err == nil {
				next.VRFs[r.Name] = v
			}
		case KindNetwork:
			var n Network
			if err = decodeSpec(r.Spec, &n); err == nil {
				next.Networks[r.Name] = n
			}
		case KindNode:
			var n Node
			if err = decodeSpec(r.Spec, &n); err == nil {
				next.Nodes[r.Name] = n
			}
		case KindPolicy:
			var p Policy
			if err = decodeSpec(r.Spec, &p); err == nil {
				next.Policies[r.Name] = p
			}
		case KindController:
			var c Controller
			if err = decodeSpec(r.Spec, &c); err == nil {
				next.Controllers[r.Name] = c
			}
		case KindNAT:
			var n NAT
			if err = decodeSpec(r.Spec, &n); err == nil {
				next.NATs[r.Name] = n
			}
		default:
			err = fmt.Errorf("the kind must be %s, %s, %s, %s, %s or %s", KindVRF, KindNetwork, KindNode, KindPolicy, KindController, KindNAT)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s %q: %w", r.Kind, r.Name, err))
		}
	}
	if len(problems) == 0 {
		problems = next.complete(in, random)
	}
	if len(problems) == 0 {
		problems = next.allocate(in, seen)
	}
	if len(problems) == 0 {
		problems = next.validate()
	}
	if len(problems) > 0 {
		return in, fmt.Errorf("%w:\n%w", ErrInvalid, errors.Join(problems...))
	}
	return next, nil
}

// Delete returns in without the resource kind/name; in itself is not changed. A VRF that a
// Network, a Node, a Policy or a NAT uses cannot be deleted, nor can a Node that a NAT uses or that
// answers DHCP for a Network. The Nodes lose their addresses in a deleted Network.
func Delete(in Intent, kind, name string) (Intent, error) {
	next := in.Clone()
	switch kind {
	case KindVRF:
		if _, ok := next.VRFs[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		var users []string
		for _, n := range sortedNames(next.Networks) {
			if next.Networks[n].VRF == name {
				users = append(users, KindNetwork+" "+strconv.Quote(n))
			}
		}
		for _, n := range sortedNames(next.Nodes) {
			if slices.Contains(next.Nodes[n].VRFs, name) {
				users = append(users, KindNode+" "+strconv.Quote(n))
			}
		}
		for _, n := range sortedNames(next.Policies) {
			if next.Policies[n].VRF == name {
				users = append(users, KindPolicy+" "+strconv.Quote(n))
			}
		}
		users = append(users, next.natUsers(name, "")...)
		if len(users) > 0 {
			return in, fmt.Errorf("%w: VRF %q is used by %s", ErrInvalid, name, strings.Join(users, ", "))
		}
		delete(next.VRFs, name)
	case KindNetwork:
		if _, ok := next.Networks[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.Networks, name)
		next.release(name)
	case KindNode:
		if _, ok := next.Nodes[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		if users := next.natUsers("", name); len(users) > 0 {
			return in, fmt.Errorf("%w: Node %q is used by %s", ErrInvalid, name, strings.Join(users, ", "))
		}
		// The DHCP responder of a Network (SDN-43, dhcp.go)
		if users := next.dhcpUsers(name); len(users) > 0 {
			return in, fmt.Errorf("%w: Node %q answers DHCP for %s", ErrInvalid, name, strings.Join(users, ", "))
		}
		delete(next.Nodes, name)
	case KindPolicy:
		if _, ok := next.Policies[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.Policies, name)
	case KindController:
		if _, ok := next.Controllers[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.Controllers, name)
	case KindNAT:
		if _, ok := next.NATs[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.NATs, name)
	default:
		return in, fmt.Errorf("%w: the kind must be %s, %s, %s, %s, %s or %s, not %q", ErrInvalid, KindVRF, KindNetwork, KindNode, KindPolicy, KindController, KindNAT, kind)
	}
	return next, nil
}

// Resources returns every resource of in: the VRFs, then the Networks, then the Nodes, then the
// Policies, then the Controllers, then the NATs, each ordered by name.
func (in Intent) Resources() []Resource {
	var out []Resource
	for _, name := range sortedNames(in.VRFs) {
		out = append(out, resource(KindVRF, name, in.VRFs[name]))
	}
	for _, name := range sortedNames(in.Networks) {
		out = append(out, resource(KindNetwork, name, in.Networks[name]))
	}
	for _, name := range sortedNames(in.Nodes) {
		out = append(out, resource(KindNode, name, in.Nodes[name]))
	}
	for _, name := range sortedNames(in.Policies) {
		out = append(out, resource(KindPolicy, name, in.Policies[name]))
	}
	for _, name := range sortedNames(in.Controllers) {
		out = append(out, resource(KindController, name, in.Controllers[name]))
	}
	for _, name := range sortedNames(in.NATs) {
		out = append(out, resource(KindNAT, name, in.NATs[name]))
	}
	return out
}

// FromResources rebuilds an intent from the resources that Resources returned (the stored
// intent, which Apply completed and validated).
func FromResources(rs []Resource) (Intent, error) {
	in := New()
	for _, r := range rs {
		var err error
		switch r.Kind {
		case KindVRF:
			var v VRF
			err = decodeSpec(r.Spec, &v)
			in.VRFs[r.Name] = v
		case KindNetwork:
			var n Network
			err = decodeSpec(r.Spec, &n)
			in.Networks[r.Name] = n
		case KindNode:
			var n Node
			err = decodeSpec(r.Spec, &n)
			in.Nodes[r.Name] = n
		case KindPolicy:
			var p Policy
			err = decodeSpec(r.Spec, &p)
			in.Policies[r.Name] = p
		case KindController:
			var c Controller
			err = decodeSpec(r.Spec, &c)
			in.Controllers[r.Name] = c
		case KindNAT:
			var n NAT
			err = decodeSpec(r.Spec, &n)
			in.NATs[r.Name] = n
		default:
			err = errors.New("unknown kind")
		}
		if err != nil {
			return Intent{}, fmt.Errorf("stored %s %q: %w", r.Kind, r.Name, err)
		}
	}
	return in, nil
}

// Changed compares two intents: put holds the resources of next that are new or differ from
// prev, gone the resources of prev that next no longer has (kind and name only).
func Changed(prev, next Intent) (put, gone []Resource) {
	old := map[string]Resource{}
	for _, r := range prev.Resources() {
		old[r.Kind+"/"+r.Name] = r
	}
	for _, r := range next.Resources() {
		if o, ok := old[r.Kind+"/"+r.Name]; !ok || !bytes.Equal(o.Spec, r.Spec) {
			put = append(put, r)
		}
		delete(old, r.Kind+"/"+r.Name)
	}
	for _, r := range prev.Resources() {
		if _, ok := old[r.Kind+"/"+r.Name]; ok {
			gone = append(gone, Resource{Kind: r.Kind, Name: r.Name})
		}
	}
	return put, gone
}

// ParseULA parses the ULA of a VRF: a /48 inside fd00::/8.
func ParseULA(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("ula: %w", err)
	}
	a := p.Addr().As16()
	if !p.Addr().Is6() || p.Addr().Is4In6() || p.Bits() != 48 || a[0] != 0xfd || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("ula %q is not a ULA /48 (inside fd00::/8, RFC 4193)", s)
	}
	return p, nil
}

// ParsePool parses the IPv4 (family 4) or IPv6 (family 6) pool of a Network.
func ParsePool(s string, family int) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("pool: %w", err)
	}
	if (family == 4 && !p.Addr().Is4()) || (family == 6 && (!p.Addr().Is6() || p.Addr().Is4In6())) {
		return netip.Prefix{}, fmt.Errorf("pool %q is not an IPv%d prefix", s, family)
	}
	if p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("pool %q has host bits set, the prefix is %s", s, p.Masked())
	}
	return p, nil
}

// ParseKey parses the public key of a Node or a Controller.
func ParseKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != KeySize {
		return nil, fmt.Errorf("publicKey %q is not the base64 of a %d-byte key", s, KeySize)
	}
	return k, nil
}

// complete fills in what the resources of in leave out: the id, ULA and MTU of a VRF, the mode
// of a Network, the VRFs of a Node that names none (VRF default, when in has it), the order of a
// Node's VRFs and tags, the form of its relay address, and the one form of the reservations of a
// Network and of the LAN subnets of a Node. A VRF keeps the id and ULA it got when prev first held
// it; they cannot change while it exists. The addresses of the Nodes follow (allocate).
func (in Intent) complete(prev Intent, random io.Reader) []error {
	var problems []error
	names := sortedNames(in.VRFs)
	for _, name := range names {
		v := in.VRFs[name]
		if p, err := netip.ParsePrefix(v.ULA); err == nil {
			v.ULA = p.String()
		}
		if old, ok := prev.VRFs[name]; ok {
			if v.ID == 0 {
				v.ID = old.ID
			} else if v.ID != old.ID {
				problems = append(problems, fmt.Errorf("VRF %q: the id is %d and cannot change to %d", name, old.ID, v.ID))
			}
			if v.ULA == "" {
				v.ULA = old.ULA
			} else if v.ULA != old.ULA {
				problems = append(problems, fmt.Errorf("VRF %q: the ula is %s and cannot change to %s", name, old.ULA, v.ULA))
			}
		}
		if v.MTU == 0 {
			v.MTU = DefaultMTU
		}
		in.VRFs[name] = v
	}
	used := map[uint32]bool{}
	for _, v := range in.VRFs {
		used[v.ID] = true
	}
	free := uint32(1)
	for _, name := range names {
		v := in.VRFs[name]
		if v.ID == 0 {
			for used[free] {
				free++
			}
			v.ID = free
			used[free] = true
		}
		if v.ULA == "" {
			p, err := randomULA(random)
			if err != nil {
				problems = append(problems, fmt.Errorf("VRF %q: drawing a ULA: %w", name, err))
				continue
			}
			v.ULA = p.String()
		}
		in.VRFs[name] = v
	}
	for name, n := range in.Networks {
		if n.Mode == "" {
			n.Mode = ModeL3
		}
		// The source prefixes as prefixes, in order (sources.go)
		n.EnrolSources = normalizeSources(n.EnrolSources)
		n.Reserved = canonicalReserved(n.Reserved)
		in.Networks[name] = n
	}
	_, hasDefault := in.VRFs[DefaultVRF]
	for name, n := range in.Nodes {
		if len(n.VRFs) == 0 && hasDefault {
			n.VRFs = []string{DefaultVRF}
		}
		slices.Sort(n.VRFs)
		slices.Sort(n.Tags)
		if ap, err := ParseRelay(n.Relay); err == nil {
			n.Relay = ap.String()
		}
		n.LANSubnets = canonicalLANs(n.LANSubnets)
		in.Nodes[name] = n
	}
	in.completeNAT()
	in.completeDHCP(prev)
	return problems
}

// ParseRelay parses the relay address of a Node: an IP address and a UDP port other than 0. An
// IPv4-mapped IPv6 address is taken as the IPv4 address.
func ParseRelay(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("relay %q is not an IP address and a port: %w", s, err)
	}
	if ap.Port() == 0 || !ap.Addr().IsValid() || ap.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("relay %q needs an IP address without a zone and a port other than 0", s)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

// validate checks a completed intent.
func (in Intent) validate() []error {
	var problems []error
	ids := map[uint32]string{}
	for _, name := range sortedNames(in.VRFs) {
		v := in.VRFs[name]
		if other, ok := ids[v.ID]; ok {
			problems = append(problems, fmt.Errorf("VRF %q: id %d is already the id of VRF %q", name, v.ID, other))
		} else {
			ids[v.ID] = name
		}
		if _, err := ParseULA(v.ULA); err != nil {
			problems = append(problems, fmt.Errorf("VRF %q: %w", name, err))
		}
		if v.MTU < DefaultMTU || v.MTU > MaxMTU {
			problems = append(problems, fmt.Errorf("VRF %q: mtu %d is not between %d and %d", name, v.MTU, DefaultMTU, MaxMTU))
		}
	}
	for _, name := range sortedNames(in.Networks) {
		n := in.Networks[name]
		if _, ok := in.VRFs[n.VRF]; !ok {
			problems = append(problems, fmt.Errorf("Network %q: VRF %q does not exist", name, n.VRF))
		}
		if n.Mode != ModeL3 && n.Mode != ModeL2 {
			problems = append(problems, fmt.Errorf("Network %q: the mode must be %s or %s, not %q", name, ModeL3, ModeL2, n.Mode))
		}
		if n.IPv4Pool != "" {
			if _, err := ParsePool(n.IPv4Pool, 4); err != nil {
				problems = append(problems, fmt.Errorf("Network %q: ipv4Pool: %w", name, err))
			}
		}
		if n.IPv6Pool != "" {
			if _, err := ParsePool(n.IPv6Pool, 6); err != nil {
				problems = append(problems, fmt.Errorf("Network %q: ipv6Pool: %w", name, err))
			}
		}
		if _, err := ParseSources(n.EnrolSources); err != nil {
			problems = append(problems, fmt.Errorf("Network %q: enrolSources: %w", name, err))
		}
	}
	keys := map[string]string{}
	for _, name := range sortedNames(in.Nodes) {
		n := in.Nodes[name]
		if k, err := ParseKey(n.PublicKey); err != nil {
			problems = append(problems, fmt.Errorf("Node %q: %w", name, err))
		} else if other, ok := keys[string(k)]; ok {
			problems = append(problems, fmt.Errorf("Node %q: the publicKey is already the key of Node %q", name, other))
		} else {
			keys[string(k)] = name
		}
		for i, v := range n.VRFs {
			if _, ok := in.VRFs[v]; !ok {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q does not exist", name, v))
			}
			if i > 0 && n.VRFs[i-1] == v {
				problems = append(problems, fmt.Errorf("Node %q: VRF %q is listed twice", name, v))
			}
		}
		for i, t := range n.Tags {
			if !nameRule.MatchString(t) {
				problems = append(problems, fmt.Errorf("Node %q: tag %q must be 1 to 63 lower-case letters, digits and hyphens, not starting or ending with a hyphen", name, t))
			}
			if i > 0 && n.Tags[i-1] == t {
				problems = append(problems, fmt.Errorf("Node %q: tag %q is listed twice", name, t))
			}
		}
		if n.Relay != "" {
			if _, err := ParseRelay(n.Relay); err != nil {
				problems = append(problems, fmt.Errorf("Node %q: %w", name, err))
			}
		}
	}
	for _, name := range sortedNames(in.Policies) {
		p := in.Policies[name]
		if _, ok := in.VRFs[p.VRF]; !ok {
			problems = append(problems, fmt.Errorf("Policy %q: VRF %q does not exist", name, p.VRF))
		}
		if p.Action != PolicyAllow && p.Action != PolicyDeny {
			problems = append(problems, fmt.Errorf("Policy %q: the action must be %s or %s, not %q", name, PolicyAllow, PolicyDeny, p.Action))
		}
	}
	addresses := map[string]string{}
	for _, name := range sortedNames(in.Controllers) {
		c := in.Controllers[name]
		if err := checkAddress(c.Address); err != nil {
			problems = append(problems, fmt.Errorf("Controller %q: %w", name, err))
		} else if other, ok := addresses[c.Address]; ok {
			problems = append(problems, fmt.Errorf("Controller %q: the address is already the address of Controller %q", name, other))
		} else {
			addresses[c.Address] = name
		}
		if _, err := ParseKey(c.PublicKey); err != nil {
			problems = append(problems, fmt.Errorf("Controller %q: %w", name, err))
		}
	}
	problems = append(problems, in.validateNAT()...)
	problems = append(problems, in.validateDHCP()...)
	return append(problems, in.validateIPAM()...)
}

// checkAddress checks the address of a Controller: host:port, with a host and a port number.
func checkAddress(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err == nil && host == "" {
		err = errors.New("there is no host")
	}
	if err == nil {
		if p, perr := strconv.ParseUint(port, 10, 16); perr != nil || p == 0 {
			err = fmt.Errorf("the port %q is not a number from 1 to 65535", port)
		}
	}
	if err == nil && len(s) > MaxAddress {
		err = fmt.Errorf("it is longer than %d characters", MaxAddress)
	}
	if err != nil {
		return fmt.Errorf("address %q is not host:port: %w", s, err)
	}
	return nil
}

// randomULA draws a ULA /48: fd00::/8 followed by a 40-bit random global id (RFC 4193 section 3.2).
func randomULA(random io.Reader) (netip.Prefix, error) {
	var a [16]byte
	a[0] = 0xfd
	if _, err := io.ReadFull(random, a[1:6]); err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(netip.AddrFrom16(a), 48), nil
}

// decodeSpec decodes the spec of a resource and refuses fields its kind does not have.
func decodeSpec(spec json.RawMessage, v any) error {
	if len(spec) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(spec))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("spec: %w", err)
	}
	return nil
}

// resource returns the Resource of kind/name with spec as its JSON.
func resource(kind, name string, spec any) Resource {
	// The spec types hold only strings, numbers, booleans, string slices and string maps, so
	// Marshal cannot fail.
	b, _ := json.Marshal(spec)
	return Resource{Kind: kind, Name: name, Spec: b}
}

func sortedNames[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
