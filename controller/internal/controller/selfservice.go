package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The self-service portal (SDN-58 #251, ADR-0031 amendment of 2026-10-29): what a User sees and does of its
// own, with the token of its self scope (internal/rbac, self.go) or any other user token. A User lists the
// devices that name it as their owner (intent.DevicesOf) with how each stands now, adds a device by the
// static key that the device shows, removes one, and makes join tokens (jointokens.go). Every change is a
// revision of the intent under the actor user:NAME, like the enrolment of a login (EnrolDevice), so the
// maximum devices of the User and every other rule of the intent hold for it as for `ranz apply`, and a
// User never reaches a device that another User, or no User, owns: a device that is not in DevicesOf of the
// User is a device that does not exist for it.

// The states of a device as the portal says them. A Node whose key ended or that waits for approval has the
// state of its key (KeyExpired, KeyPending).
const (
	// DeviceConnected: the Node has its control stream open and its key is valid.
	DeviceConnected = "connected"
	// DeviceOffline: the Node has no control stream now, and its key is valid.
	DeviceOffline = "offline"
	// DeviceBanned: an operator banned the User, so the Node is held back (bans.go).
	DeviceBanned = "banned"
	// DeviceUnlicensed: the Node is above the node cap of the licence in force, so it has no desired state.
	DeviceUnlicensed = "unlicensed"
)

// SelfInfo is a User as the portal shows it to the User: who it is, and how many devices it has of how many
// it may.
type SelfInfo struct {
	// Name is the name of the User resource.
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	// Expires is when the User cannot authenticate any more, left out for one that never expires.
	Expires time.Time `json:"expires,omitzero"`
	// MaxDevices is the most devices that the User may have, left out for no limit, and Devices how many it has.
	MaxDevices uint32 `json:"maxDevices,omitempty"`
	Devices    int    `json:"devices"`
}

// SelfAddress is the address of a device in one Network.
type SelfAddress struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

// SelfDevice is one device of a User as the portal shows it: a Node, or a WireGuard Device that names the
// User as its owner.
type SelfDevice struct {
	// Kind is intent.KindNode or intent.KindDevice, and Name the name of the resource.
	Kind string `json:"kind"`
	Name string `json:"name"`
	// State says how the device stands: DeviceConnected, DeviceOffline, KeyExpired, KeyPending, DeviceBanned or
	// DeviceUnlicensed. It is left out for a Device, which has no control stream and no key of this kind.
	State string `json:"state,omitempty"`
	// Connected says that the Node has its control stream open, and ConnectedSince is when it was accepted.
	Connected      bool      `json:"connected"`
	ConnectedSince time.Time `json:"connectedSince,omitzero"`
	// Generation is the Generation of the desired state of the Node, and AckedGeneration the last one that it
	// acknowledged.
	Generation      uint64 `json:"generation,omitempty"`
	AckedGeneration uint64 `json:"ackedGeneration,omitempty"`
	// KeyExpires is when the static key of the Node ends, left out for a Node that is marked nonExpiring.
	KeyExpires time.Time `json:"keyExpires,omitzero"`
	// VRFs are the VRFs that the device is in, Tags the tags that policy sees it with, its own and the Groups of
	// its owner, and Addresses its addresses in the Networks of those VRFs.
	VRFs      []string      `json:"vrfs,omitempty"`
	Tags      []string      `json:"tags,omitempty"`
	Addresses []SelfAddress `json:"addresses,omitempty"`
	// LastHandshake is the time of the last WireGuard handshake of a Device that its gateway reported.
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
}

// validUser checks that the User name may act now: the intent holds it, it has not expired and no operator
// banned it. An error that wraps intent.ErrNotFound is a User that the intent does not hold, one that wraps
// ErrUserExpired a User past its expiry, and one that wraps ErrUserBanned a User that is banned.
func (c *Controller) validUser(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.intent.Users[name]
	if !ok {
		return fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(name, maxSubject))
	}
	if u.ExpiredAt(c.keyNow()) {
		return fmt.Errorf("%w: User %q expired at %s", ErrUserExpired, name, u.Expires.Format(time.RFC3339))
	}
	if _, banned := c.live.bans[name]; banned {
		return fmt.Errorf("%w: User %q", ErrUserBanned, name)
	}
	return nil
}

// SelfInfo returns the User user as the portal shows it to the User (GET /api/v1/self). An error that wraps
// intent.ErrNotFound is a User that the intent does not hold.
func (c *Controller) SelfInfo(user string) (SelfInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	u, ok := c.intent.Users[user]
	if !ok {
		return SelfInfo{}, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(user, maxSubject))
	}
	return SelfInfo{Name: user, DisplayName: u.DisplayName, Groups: slices.Clone(u.Groups), Expires: u.Expires, MaxDevices: u.MaxDevices,
		Devices: len(c.intent.DevicesOf(user))}, nil
}

// SelfDevices returns the devices of the User user, the resources that name it as their owner, in name order
// with the Nodes first (GET /api/v1/self/devices), each with how it stands. An error that wraps
// intent.ErrNotFound is a User that the intent does not hold.
func (c *Controller) SelfDevices(user string) ([]SelfDevice, error) {
	c.mu.Lock()
	if _, ok := c.intent.Users[user]; !ok {
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: %s %q", intent.ErrNotFound, intent.KindUser, clip(user, maxSubject))
	}
	now := c.keyNow()
	out := []SelfDevice{}
	wireguard := false
	for _, ref := range c.intent.DevicesOf(user) {
		if ref.Kind == intent.KindNode {
			out = append(out, c.selfNode(ref.Name, now))
			continue
		}
		out = append(out, c.selfOther(ref))
		wireguard = wireguard || ref.Kind == intent.KindDevice
	}
	c.mu.Unlock()
	if wireguard {
		// What the gateways reported of the Devices, which Devices reads without c.mu held
		reported := map[string]DeviceStatus{}
		for _, st := range c.Devices() {
			reported[st.Name] = st
		}
		for i, d := range out {
			if st, ok := reported[d.Name]; ok && d.Kind == intent.KindDevice {
				out[i].LastHandshake = st.LastHandshake
				if st.Unlicensed {
					out[i].State = DeviceUnlicensed
				}
			}
		}
	}
	return out, nil
}

// selfNode returns the Node name of the intent in force as a device of its User, at the instant now. c.mu is
// held.
func (c *Controller) selfNode(name string, now time.Time) SelfDevice {
	n := c.intent.Nodes[name]
	info := c.keyInfo(name, now)
	d := SelfDevice{Kind: intent.KindNode, Name: name, KeyExpires: info.Expires, VRFs: slices.Clone(n.VRFs), Tags: c.intent.NodeTags(name),
		Addresses: selfAddresses(n)}
	rn := c.nodes[name]
	if rn != nil {
		d.Connected = rn.stream != nil
		d.Generation, d.AckedGeneration = rn.gen, rn.ackedGen
		if rn.stream != nil {
			d.ConnectedSince = rn.stream.live.since
		}
	}
	switch _, banned := c.bannedOwner(name); {
	case banned:
		d.State = DeviceBanned
	case rn == nil:
		d.State = DeviceUnlicensed
	case info.State != KeyValid:
		d.State = info.State
	case d.Connected:
		d.State = DeviceConnected
	default:
		d.State = DeviceOffline
	}
	return d
}

// selfOther returns a device of the intent in force that is no Node, as a device of its User: its kind and
// name, and for a WireGuard Device its tags and its addresses in its Network. c.mu is held.
func (c *Controller) selfOther(ref intent.DeviceRef) SelfDevice {
	d := SelfDevice{Kind: ref.Kind, Name: ref.Name}
	if ref.Kind != intent.KindDevice {
		return d
	}
	dev := c.intent.Devices[ref.Name]
	d.Tags = slices.Clone(dev.Tags)
	for _, a := range []string{dev.Address, dev.IPv6Address} {
		if a != "" {
			d.Addresses = append(d.Addresses, SelfAddress{Network: dev.Network, Address: a})
		}
	}
	return d
}

// selfAddresses returns the addresses of the Node n in the Networks of its VRFs, as nodeAddresses orders them
// (the IPv4 addresses, then the IPv6 ones, each by the name of the Network), each with its Network.
func selfAddresses(n intent.Node) []SelfAddress {
	var out []SelfAddress
	for _, network := range slices.Sorted(maps.Keys(n.Addresses)) {
		out = append(out, SelfAddress{Network: network, Address: n.Addresses[network]})
	}
	for _, network := range slices.Sorted(maps.Keys(n.IPv6Addresses)) {
		out = append(out, SelfAddress{Network: network, Address: n.IPv6Addresses[network]})
	}
	return out
}

// AddSelfDevice makes the Node of the device whose static key is key a device of the User user, as one
// revision of the intent under the actor of ctx (POST /api/v1/self/devices): the Node is named name, or, when
// name is empty, the first of user-1, user-2 and so on that no Node has. It is the enrolment of a login
// (EnrolDevice), made by the User from the portal, so the errors are those of EnrolDevice, and one that
// wraps ErrUserExpired or ErrUserBanned is a User that may not act now.
func (c *Controller) AddSelfDevice(ctx context.Context, user, name string, key []byte) (Enrolment, error) {
	if err := c.validUser(user); err != nil {
		return Enrolment{}, err
	}
	return c.EnrolDevice(ctx, user, name, key)
}

// RemoveSelfDevice deletes the device of the User user that has the kind kind and the name name, as one
// revision of the intent under the actor of ctx (DELETE /api/v1/self/devices/{kind}/{name}). A resource that
// is not a device of the User is not found, whoever owns it: the check is made under the lock of the delete,
// against the intent that it changes, so no change slips in between. An error that wraps intent.ErrInvalid is
// a device that the intent keeps, as `ranz delete` is told, and one that wraps intent.ErrNotFound a device that
// the User does not have.
func (c *Controller) RemoveSelfDevice(ctx context.Context, user, kind, name string) (ApplyResult, error) {
	ref := intent.DeviceRef{Kind: kind, Name: name}
	check := func(in intent.Intent) error {
		if !slices.Contains(in.DevicesOf(user), ref) {
			return fmt.Errorf("%w: User %q has no device %s %q", intent.ErrNotFound, user, clip(kind, maxSubject), clip(name, maxSubject))
		}
		return nil
	}
	return c.Delete(withPrecondition(ctx, check), kind, name)
}
