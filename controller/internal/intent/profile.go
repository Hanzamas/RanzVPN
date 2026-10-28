package intent

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Session profiles (SDN-40 #233, spec #224 "Session profiles"). A SessionProfile holds the limits of
// the sessions of people, the successor of the POLICY of a user or a group of the slim fork: the rate
// that a session of a device may upload into the overlay and download from it, the sessions of the
// devices of one User that a Node holds at once, the MAC, IPv4 and IPv6 addresses that one session may
// send from, the idle timeout and the automatic disconnect that end a session, and the flags
// no-bridge, no-routing, no-server and privacy filter.
//
// A User or a Group names one (sessionProfile). The effective profile of a User is its own, else the
// one of the first of its Groups, in name order, that names one: the user over the group, as the slim
// fork took the policy of a user before the one of its group (EffectiveProfile). The devices of the
// User run under it: the controller compiles it into the NodeConfig of each device and into the Peer
// object of the device that every other Node holds (internal/desired, profile.go), and each Node
// enforces the profile of a peer on its session with that peer, and its own flags on itself
// (src/Cedar/NodeProfile.c). `ranz explain` names the effective profile of each end that has one, and
// where it comes from (internal/explain, profile.go).

// KindSessionProfile is the kind of a SessionProfile.
const KindSessionProfile = "SessionProfile"

const (
	// MaxProfileSessions is the largest maximum of the sessions of the devices of one User at one
	// Node.
	MaxProfileSessions = 65535
	// MaxProfileAddresses is the largest maximum of the MAC, IPv4 or IPv6 addresses of one session:
	// the addresses that a member of the policy engine of a Node owns at most (POLICY_MAX_BOUND of
	// src/Core/Policy.h), and those that a Node counts for one session in one VRF.
	MaxProfileAddresses = 64
	// MaxProfileTime is the longest idle timeout and automatic disconnect, in seconds: a week, as for
	// the timeouts of the conntrack of a VRF.
	MaxProfileTime = 604800
)

// SessionProfile holds the limits of the sessions of the devices of the Users that run under it. A
// limit that is left out or 0 is none, and a flag that is left out is off.
type SessionProfile struct {
	// UploadLimit is the rate in bits per second that one session of a device sends into the overlay
	// at most: a Node takes the packets of the session of a peer that is such a device up to it, and
	// drops the rest.
	UploadLimit uint64 `json:"uploadLimit,omitempty"`
	// DownloadLimit is the rate in bits per second that a Node sends to one session of a device at
	// most, and drops the rest.
	DownloadLimit uint64 `json:"downloadLimit,omitempty"`
	// MaxSessions is the most sessions of the devices of one User that one Node holds at once, from 1
	// to MaxProfileSessions: the session of one device more is refused while they are up.
	MaxSessions uint32 `json:"maxSessions,omitempty"`
	// MaxMACs is the most MAC addresses that one session sends from in an L2 Network, MaxIPv4 and
	// MaxIPv6 the most IPv4 and IPv6 addresses in each VRF, from 1 to MaxProfileAddresses each: a
	// packet from one address more is dropped.
	MaxMACs uint32 `json:"maxMacs,omitempty"`
	MaxIPv4 uint32 `json:"maxIpv4,omitempty"`
	MaxIPv6 uint32 `json:"maxIpv6,omitempty"`
	// IdleTimeout ends a session that carried no packet in either direction for that many seconds,
	// from 1 to MaxProfileTime.
	IdleTimeout uint32 `json:"idleTimeout,omitempty"`
	// AutoDisconnect ends a session that many seconds after it came up, whatever it carries, from 1
	// to MaxProfileTime. The device dials again, as after a session that ended for any reason.
	AutoDisconnect uint32 `json:"autoDisconnect,omitempty"`
	// NoBridge forbids bridging: a session sends from one MAC address in an L2 Network, the first it
	// sends from, so a LAN behind the device cannot be bridged into the Network.
	NoBridge bool `json:"noBridge,omitempty"`
	// NoRouting forbids routing, in IPv4 and IPv6: a device sends into the overlay only from its own
	// addresses and takes from it only to them, so no address that it routes (the outside of a 1:1
	// NAT rule, a route that a VRF leaks) passes its session.
	NoRouting bool `json:"noRouting,omitempty"`
	// NoServer forbids a server, in IPv4 and IPv6: a device takes no TCP connection from the overlay,
	// so no SYN goes to it and no SYN-ACK comes from it.
	NoServer bool `json:"noServer,omitempty"`
	// PrivacyFilter isolates the devices that have it from each other (client isolation, the
	// PrivacyFilter of the slim fork): no packet passes between two devices whose profiles both have
	// it, while each reaches the Nodes that run under none.
	PrivacyFilter bool `json:"privacyFilter,omitempty"`
}

// ProfileOf is the effective session profile of a User, and the resource that gives it
// (EffectiveProfile).
type ProfileOf struct {
	// Profile is the SessionProfile, empty when the User runs under none.
	Profile string `json:"profile,omitempty"`
	// Kind and Name are the resource that names it: the User itself (KindUser), or the Group of the
	// User that gives it (KindGroup).
	Kind string `json:"kind,omitempty"`
	Name string `json:"name,omitempty"`
}

// EffectiveProfile returns the session profile that the devices of the User user run under: the one
// that the User names, else the one of the first of its Groups, in name order, that names one; none
// for a User that does not exist or that neither it nor any of its Groups gives a profile.
func (in Intent) EffectiveProfile(user string) ProfileOf {
	u, ok := in.Users[user]
	if !ok {
		return ProfileOf{}
	}
	if u.SessionProfile != "" {
		return ProfileOf{Profile: u.SessionProfile, Kind: KindUser, Name: user}
	}
	groups := slices.Clone(u.Groups)
	slices.Sort(groups)
	for _, g := range groups {
		if p := in.Groups[g].SessionProfile; p != "" {
			return ProfileOf{Profile: p, Kind: KindGroup, Name: g}
		}
	}
	return ProfileOf{}
}

// ProfileUsers returns the Users and the Groups that name the SessionProfile profile, as the error of
// a delete names them: the Groups first, then the Users, each in name order.
func (in Intent) ProfileUsers(profile string) []string {
	var out []string
	for _, name := range sortedNames(in.Groups) {
		if in.Groups[name].SessionProfile == profile {
			out = append(out, KindGroup+" "+strconv.Quote(name))
		}
	}
	for _, name := range sortedNames(in.Users) {
		if in.Users[name].SessionProfile == profile {
			out = append(out, KindUser+" "+strconv.Quote(name))
		}
	}
	return out
}

// cloneProfiles returns a copy of the SessionProfiles of in. A SessionProfile holds no slice or map,
// so a copy of the map shares nothing.
func (in Intent) cloneProfiles() map[string]SessionProfile {
	out := maps.Clone(in.SessionProfiles)
	if out == nil {
		out = map[string]SessionProfile{}
	}
	return out
}

// deleteProfile removes the SessionProfile name from in, which is a copy that Delete made. A
// SessionProfile that a User or a Group names cannot be deleted.
func (in Intent) deleteProfile(name string) error {
	if _, ok := in.SessionProfiles[name]; !ok {
		return fmt.Errorf("%w: %s %q", ErrNotFound, KindSessionProfile, name)
	}
	if users := in.ProfileUsers(name); len(users) > 0 {
		return fmt.Errorf("%w: SessionProfile %q is used by %s", ErrInvalid, name, strings.Join(users, ", "))
	}
	delete(in.SessionProfiles, name)
	return nil
}

// profileResources returns the SessionProfiles of in as resources, ordered by name.
func (in Intent) profileResources() []Resource {
	var out []Resource
	for _, name := range sortedNames(in.SessionProfiles) {
		out = append(out, resource(KindSessionProfile, name, in.SessionProfiles[name]))
	}
	return out
}

// checkProfileLimit checks one limit of a SessionProfile: 0 for none, else at most most.
func checkProfileLimit(problems []error, name, field string, v, most uint32) []error {
	if v > most {
		return append(problems, fmt.Errorf("SessionProfile %q: %s %d is more than %d", name, field, v, most))
	}
	return problems
}

// validateProfiles checks the SessionProfiles of a completed intent, and the profile that each User
// and each Group names: the limits of a profile are in their ranges, and a profile that is named
// exists.
func (in Intent) validateProfiles() []error {
	var problems []error
	for _, name := range sortedNames(in.SessionProfiles) {
		p := in.SessionProfiles[name]
		problems = checkProfileLimit(problems, name, "maxSessions", p.MaxSessions, MaxProfileSessions)
		problems = checkProfileLimit(problems, name, "maxMacs", p.MaxMACs, MaxProfileAddresses)
		problems = checkProfileLimit(problems, name, "maxIpv4", p.MaxIPv4, MaxProfileAddresses)
		problems = checkProfileLimit(problems, name, "maxIpv6", p.MaxIPv6, MaxProfileAddresses)
		problems = checkProfileLimit(problems, name, "idleTimeout", p.IdleTimeout, MaxProfileTime)
		problems = checkProfileLimit(problems, name, "autoDisconnect", p.AutoDisconnect, MaxProfileTime)
	}
	for _, name := range sortedNames(in.Groups) {
		if p := in.Groups[name].SessionProfile; p != "" {
			if _, ok := in.SessionProfiles[p]; !ok {
				problems = append(problems, fmt.Errorf("Group %q: SessionProfile %q does not exist", name, p))
			}
		}
	}
	for _, name := range sortedNames(in.Users) {
		if p := in.Users[name].SessionProfile; p != "" {
			if _, ok := in.SessionProfiles[p]; !ok {
				problems = append(problems, fmt.Errorf("User %q: SessionProfile %q does not exist", name, p))
			}
		}
	}
	return problems
}
