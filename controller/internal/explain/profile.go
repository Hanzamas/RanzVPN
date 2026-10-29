package explain

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The session profiles (SDN-40, #233). A Node that a User owns runs under the effective SessionProfile of that User,
// its own or the one of the first of its Groups that names one (intent.EffectiveProfile), and the data plane of each
// Node judges a packet by the profile of the peer of its next hop and by its own (src/Cedar/NodeProfile.c), after the
// route and before the policy of the VRF: at the Node that sends the packet on its way out of the host, at the Node that
// the route leads to on its way in. Explain names each profile that a packet meets, with the resource that gives it,
// and drops the packet where a flag of a profile drops it: the privacy filter between two devices whose profiles both
// have it, no-routing for an address that is not one of the device itself, no-server for a TCP SYN to the device. The
// limits of a profile, the rates, the counts and the timeouts, count the packets and the sessions of a device, which
// one packet does not show: explain names them and judges nothing by them.

const (
	// StepProfile is a session profile that a Node judges the packet by.
	StepProfile = "profile"
	// DropProfile is a flag of a session profile that drops the packet.
	DropProfile = "profile"
)

// Profile is the session profile of a StepProfile: the effective SessionProfile that a Node runs under as a device of
// a User, and the resource that gives it.
type Profile struct {
	// Device is the Node that runs under the profile: the peer that the Node of the step holds the session of, or the
	// Node of the step itself.
	Device string `json:"device"`
	// Name is the SessionProfile, and User the User that owns Device.
	Name string `json:"name"`
	User string `json:"user"`
	// Kind and From are the resource that gives the profile: the User itself (intent.KindUser), or the Group of the
	// User (intent.KindGroup) that names it when the User names none.
	Kind string `json:"kind"`
	From string `json:"from"`
	// Limits is what the profile holds.
	Limits intent.SessionProfile `json:"limits"`
}

// profileOf returns the Profile of a StepProfile of the device d, whose state carries the profile p.
func (m *Model) profileOf(d string, p *controlpb.SessionProfile) *Profile {
	out := &Profile{Device: d, Name: p.GetName(), User: p.GetUser()}
	if of := m.in.EffectiveProfile(p.GetUser()); of.Profile == p.GetName() {
		out.Kind, out.From = of.Kind, of.Name
	}
	out.Limits = intent.SessionProfile{
		UploadLimit:    p.GetUploadLimit(),
		DownloadLimit:  p.GetDownloadLimit(),
		MaxSessions:    p.GetMaxSessions(),
		MaxMACs:        p.GetMaxMacs(),
		MaxIPv4:        p.GetMaxIpv4(),
		MaxIPv6:        p.GetMaxIpv6(),
		IdleTimeout:    p.GetIdleTimeout(),
		AutoDisconnect: p.GetAutoDisconnect(),
		NoBridge:       p.GetNoBridge(),
		NoRouting:      p.GetNoRouting(),
		NoServer:       p.GetNoServer(),
		PrivacyFilter:  p.GetPrivacyFilter(),
	}
	return out
}

// String says the profile as a step names it: "SessionProfile laptops of User alice, which its Group staff gives:
// no-server, privacy filter".
func (p *Profile) String() string {
	from := "which the User names"
	if p.Kind == intent.KindGroup {
		from = "which its Group " + p.From + " gives"
	}
	var what []string
	l := p.Limits
	for _, x := range []struct {
		v    uint64
		text string
	}{
		{l.UploadLimit, "upload %d bit/s"},
		{l.DownloadLimit, "download %d bit/s"},
		{uint64(l.MaxSessions), "%d sessions of the User at a Node"},
		{uint64(l.MaxMACs), "%d MAC addresses"},
		{uint64(l.MaxIPv4), "%d IPv4 addresses"},
		{uint64(l.MaxIPv6), "%d IPv6 addresses"},
		{uint64(l.IdleTimeout), "idle timeout %d s"},
		{uint64(l.AutoDisconnect), "automatic disconnect after %d s"},
	} {
		if x.v != 0 {
			what = append(what, fmt.Sprintf(x.text, x.v))
		}
	}
	for _, x := range []struct {
		on   bool
		text string
	}{{l.NoBridge, "no-bridge"}, {l.NoRouting, "no-routing"}, {l.NoServer, "no-server"}, {l.PrivacyFilter, "privacy filter"}} {
		if x.on {
			what = append(what, x.text)
		}
	}
	if len(what) == 0 {
		what = []string{"no limit and no flag"}
	}
	return fmt.Sprintf("SessionProfile %s of User %s, %s: %s", p.Name, p.User, from, strings.Join(what, ", "))
}

// profile is the session profiles at the Node n for the packet p of the VRF vrf between its host and the next hop hop, on
// the way out of the host when out is set, as NodeProfileOutbound and NodeProfileInbound judge it: the profile of the peer
// of the hop, then the one of n itself. A step names each, and false when a flag of one drops the packet ends the walk.
func (w *walk) profile(n *node, vrf uint32, p packet, hop uint32, out bool) bool {
	peer := n.peers[n.hops[hop].peer]
	pp, own := peer.GetProfile(), n.self.GetProfile()
	atPeer, atHost := p.dst, p.src
	if !out {
		atPeer, atHost = p.src, p.dst
	}
	if pp != nil {
		prof := w.m.profileOf(peer.GetName(), pp)
		w.step(n, StepProfile, vrf, Step{Profile: prof}, "%s holds the session of %s under %s", n.name, peer.GetName(), prof)
		switch {
		case pp.GetPrivacyFilter() && own.GetPrivacyFilter():
			w.drop(n, DropProfile, "the privacy filter keeps %s and %s apart: the profiles of both have it", n.name, peer.GetName())
			return false
		case pp.GetNoRouting() && !owns(peer.GetAddresses(), vrf, atPeer):
			w.drop(n, DropProfile, "no-routing of SessionProfile %s: %s is no address of %s itself in VRF %s", pp.GetName(), atPeer, peer.GetName(), w.m.vrfName(vrf))
			return false
		case pp.GetNoServer() && opens(p, out):
			w.drop(n, DropProfile, "no-server of SessionProfile %s: no TCP connection to %s", pp.GetName(), peer.GetName())
			return false
		}
	}
	if own != nil {
		prof := w.m.profileOf(n.name, own)
		w.step(n, StepProfile, vrf, Step{Profile: prof}, "%s runs under %s", n.name, prof)
		switch {
		case own.GetNoRouting() && !owns(n.self.GetAddresses(), vrf, atHost):
			w.drop(n, DropProfile, "no-routing of SessionProfile %s: %s is no address of %s itself in VRF %s", own.GetName(), atHost, n.name, w.m.vrfName(vrf))
			return false
		case own.GetNoServer() && opens(p, !out):
			w.drop(n, DropProfile, "no-server of SessionProfile %s: no TCP connection to %s", own.GetName(), n.name)
			return false
		}
	}
	return true
}

// owns reports whether a is one of the addresses list in the VRF vrf: an address of the device itself, which no-routing
// lets through.
func owns(list []*controlpb.Address, vrf uint32, a netip.Addr) bool {
	for _, x := range list {
		if p, ok := hostPrefix(x.GetPrefix()); ok && x.GetVrfId() == vrf && p.Addr() == a {
			return true
		}
	}
	return false
}

// opens reports whether the packet p, to a device under no-server when to is set or from it, opens a TCP connection to
// the device: the packet of a TCP flow of a walk is the SYN that opens it, so it does when it goes to the device. A
// SYN-ACK of the device, which no-server drops too, is no packet of a walk.
func opens(p packet, to bool) bool {
	return p.proto == protoTCP && to
}
