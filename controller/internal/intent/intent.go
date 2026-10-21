// Package intent is the declared network that `ranz apply -f` sends to the controller: the
// resources of #176 "Resource model" that the controller skeleton knows (VRF, Network and Node),
// their validation, and the values the controller fills in when a resource is first applied.
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
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The resource kinds.
const (
	KindVRF     = "VRF"
	KindNetwork = "Network"
	KindNode    = "Node"
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

// Resource is one declared object. Spec holds the fields of its kind: VRF, Network or Node.
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
}

// Network belongs to one VRF.
type Network struct {
	VRF      string `json:"vrf"`
	Mode     string `json:"mode,omitempty"` // ModeL3 (the default) or ModeL2
	IPv4Pool string `json:"ipv4Pool,omitempty"`
	IPv6Pool string `json:"ipv6Pool,omitempty"`
}

// Node is a node of the overlay, identified by its Noise static key.
type Node struct {
	PublicKey string   `json:"publicKey"` // base64 of the KeySize-byte key
	VRFs      []string `json:"vrfs,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// Intent is the whole declared network, by kind and name.
type Intent struct {
	VRFs     map[string]VRF
	Networks map[string]Network
	Nodes    map[string]Node
}

// New returns an empty intent.
func New() Intent {
	return Intent{VRFs: map[string]VRF{}, Networks: map[string]Network{}, Nodes: map[string]Node{}}
}

// Clone returns a copy of in that shares nothing with it.
func (in Intent) Clone() Intent {
	out := Intent{VRFs: maps.Clone(in.VRFs), Networks: maps.Clone(in.Networks), Nodes: map[string]Node{}}
	if out.VRFs == nil {
		out.VRFs = map[string]VRF{}
	}
	if out.Networks == nil {
		out.Networks = map[string]Network{}
	}
	for name, n := range in.Nodes {
		n.VRFs = slices.Clone(n.VRFs)
		n.Tags = slices.Clone(n.Tags)
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
		default:
			err = fmt.Errorf("the kind must be %s, %s or %s", KindVRF, KindNetwork, KindNode)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s %q: %w", r.Kind, r.Name, err))
		}
	}
	if len(problems) == 0 {
		problems = next.complete(in, random)
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
// Network or a Node uses cannot be deleted.
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
		if len(users) > 0 {
			return in, fmt.Errorf("%w: VRF %q is used by %s", ErrInvalid, name, strings.Join(users, ", "))
		}
		delete(next.VRFs, name)
	case KindNetwork:
		if _, ok := next.Networks[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.Networks, name)
	case KindNode:
		if _, ok := next.Nodes[name]; !ok {
			return in, fmt.Errorf("%w: %s %q", ErrNotFound, kind, name)
		}
		delete(next.Nodes, name)
	default:
		return in, fmt.Errorf("%w: the kind must be %s, %s or %s, not %q", ErrInvalid, KindVRF, KindNetwork, KindNode, kind)
	}
	return next, nil
}

// Resources returns every resource of in: the VRFs, then the Networks, then the Nodes, each
// ordered by name.
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

// ParseKey parses the public key of a Node.
func ParseKey(s string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(k) != KeySize {
		return nil, fmt.Errorf("publicKey %q is not the base64 of a %d-byte key", s, KeySize)
	}
	return k, nil
}

// complete fills in what the resources of in leave out: the id, ULA and MTU of a VRF, the mode
// of a Network, and the order of a Node's VRFs and tags. A VRF keeps the id and ULA it got when
// prev first held it; they cannot change while it exists.
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
			in.Networks[name] = n
		}
	}
	for name, n := range in.Nodes {
		slices.Sort(n.VRFs)
		slices.Sort(n.Tags)
		in.Nodes[name] = n
	}
	return problems
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
	}
	return problems
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
	// The spec types hold only strings, numbers and string slices, so Marshal cannot fail.
	b, _ := json.Marshal(spec)
	return Resource{Kind: kind, Name: name, Spec: b}
}

func sortedNames[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
