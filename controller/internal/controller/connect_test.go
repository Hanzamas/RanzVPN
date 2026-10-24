package controller_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/desired"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// connectJSON is two VRFs that share no Node, each with a Network and a Node.
const connectJSON = `{"resources": [
  {"kind": "VRF", "name": "corp", "spec": {"id": 10, "ula": "fd00:10::/48"}},
  {"kind": "VRF", "name": "lab", "spec": {"id": 20, "ula": "fd00:20::/48"}},
  {"kind": "Network", "name": "corp-lan", "spec": {"vrf": "corp", "ipv4Pool": "10.10.0.0/24"}},
  {"kind": "Network", "name": "lab-lan", "spec": {"vrf": "lab", "ipv4Pool": "10.20.0.0/24"}},
  {"kind": "Node", "name": "branch-1", "spec": {"publicKey": "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "vrfs": ["corp"]}},
  {"kind": "Node", "name": "lab-1", "spec": {"publicKey": "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk=", "vrfs": ["lab"]}}
]}`

// peerRoutes returns the routes of the Peer peer in the state of s as "vrf prefix > peer vrf",
// "no peer" when the state has none.
func peerRoutes(s *sim, peer string) string {
	_, st := s.State()
	o, ok := st[desired.Key{Kind: controlpb.Kind_KIND_PEER, Name: peer}]
	if !ok {
		return "no peer"
	}
	var out []string
	for _, r := range o.GetPeer().GetRoutes() {
		a, _ := netip.AddrFromSlice(r.GetPrefix().GetAddress())
		out = append(out, fmt.Sprintf("%d %s > %d", r.GetVrfId(), netip.PrefixFrom(a, int(r.GetPrefix().GetLength())), r.GetPeerVrfId()))
	}
	return strings.Join(out, "; ")
}

// The "connect VRF" shortcut of the API (SDN-7 #183) makes one revision of the two route-target
// edits of a two-way leak: each VRF exports its id under 64512 and imports the other's, the two
// Nodes, which share no VRF, become peers of each other, and each gets the address of the other
// as a route that goes into the VRF of the other. Connecting a VRF to itself or to one that does
// not exist is refused.
func TestConnectVRFs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	doc, err := intent.ParseDocument([]byte(connectJSON))
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.api.Apply(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	b1 := h.sim("branch-1", keyBranch1)
	b1.update(t)
	l1 := h.sim("lab-1", keyLab1)
	l1.update(t)
	h.waitNode("branch-1", 1, true)
	h.waitNode("lab-1", 1, true)
	if got := peerRoutes(b1, "lab-1"); got != "no peer" {
		t.Fatalf("before the VRFs are connected, the Peer lab-1 of branch-1 is %q", got)
	}

	res, err := h.api.Connect(ctx, "corp", "lab")
	if err != nil {
		t.Fatal(err)
	}
	if want := []controller.NodeGeneration{{Name: "branch-1", Generation: 2}, {Name: "lab-1", Generation: 2}}; res.Revision != first.Revision+1 || !equalGenerations(res.Nodes, want) {
		t.Errorf("the shortcut made revision %d with %+v, want revision %d with %+v", res.Revision, res.Nodes, first.Revision+1, want)
	}
	b1.update(t)
	l1.update(t)
	h.waitNode("branch-1", 2, true)
	h.waitNode("lab-1", 2, true)
	h.checkState(b1)
	h.checkState(l1)
	if got, want := peerRoutes(b1, "lab-1"), "10 10.20.0.1/32 > 20"; got != want {
		t.Errorf("the routes of the Peer lab-1 of branch-1 are %q, want %q", got, want)
	}
	if got, want := peerRoutes(l1, "branch-1"), "20 10.10.0.1/32 > 10"; got != want {
		t.Errorf("the routes of the Peer branch-1 of lab-1 are %q, want %q", got, want)
	}

	rs, err := h.api.Resources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	in, err := intent.FromResources(rs)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][2]string{"corp": {"64512:20", "64512:10"}, "lab": {"64512:10", "64512:20"}} {
		v := in.VRFs[name]
		if !slices.Equal(v.ImportTargets, want[:1]) || !slices.Equal(v.ExportTargets, want[1:]) {
			t.Errorf("VRF %s imports %v and exports %v, want %v and %v", name, v.ImportTargets, v.ExportTargets, want[:1], want[1:])
		}
	}

	for _, c := range []struct {
		a, b   string
		status int
	}{
		{"corp", "corp", http.StatusBadRequest},
		{"corp", "nowhere", http.StatusNotFound},
	} {
		_, err := h.api.Connect(ctx, c.a, c.b)
		var e *api.Error
		if !errors.As(err, &e) || e.Status != c.status {
			t.Errorf("connecting %s and %s gave %v, want status %d", c.a, c.b, err, c.status)
		}
	}
}
