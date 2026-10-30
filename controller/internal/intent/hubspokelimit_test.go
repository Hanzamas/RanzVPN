package intent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// spokeKey is the static key of the Node i of branchSpokes: the hub is 0.
func spokeKey(i int) string {
	return base64.StdEncoding.EncodeToString(append([]byte{byte(0x60 + i)}, make([]byte, KeySize-1)...))
}

// branchSpokes is VRF branch of topology hub-and-spoke with the hub hub, one L3 Network of an IPv4
// and an IPv6 pool and no 1:1 NAT rule, and the spokes s01 to s<spokes>, each with a LAN subnet of
// its own; with hubLAN the hub has one too.
func branchSpokes(spokes int, hubLAN bool) Document {
	hub := `{"publicKey": "` + spokeKey(0) + `", "vrfs": ["branch"]}`
	if hubLAN {
		hub = `{"publicKey": "` + spokeKey(0) + `", "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.100.0/24"]}}`
	}
	rs := []Resource{
		res(KindVRF, "branch", `{"id": 20, "ula": "fd00:20::/48", "topology": "hub-and-spoke", "hub": "hub"}`),
		res(KindNetwork, "branch-lan", `{"vrf": "branch", "ipv4Pool": "10.20.0.0/24", "ipv6Pool": "fd00:20:0:1::/64"}`),
		res(KindNode, "hub", hub),
	}
	for i := 1; i <= spokes; i++ {
		spec := fmt.Sprintf(`{"publicKey": %q, "vrfs": ["branch"], "lanSubnets": {"branch": ["192.168.%d.0/24"]}}`, spokeKey(i), i)
		rs = append(rs, res(KindNode, fmt.Sprintf("s%02d", i), spec))
	}
	return doc(rs...)
}

// A Peer carries MaxPeerRoutes routes, and a spoke reaches every prefix of its VRF of topology
// hub-and-spoke but its own LAN subnet through the hub, its only peer there (SDN-19-R1 #507, the
// limit that topology.go and control.proto write down). The two pools of the L3 Network leave 14
// routes for the LAN subnets that a spoke reaches through the hub: the VRF holds 15 spokes of one LAN
// subnet each, or 14 when the hub has a LAN subnet too, and an Intent with one more is refused.
func TestHubAndSpokeBranchLANs(t *testing.T) {
	for _, c := range []struct {
		hubLAN bool
		most   int
	}{{false, 15}, {true, 14}} {
		in, err := Apply(New(), branchSpokes(c.most, c.hubLAN), nil)
		if err != nil {
			t.Errorf("%d spokes, a LAN subnet behind the hub %v: %v", c.most, c.hubLAN, err)
			continue
		}
		if got := len(in.GatewayRoutes("s01", "hub")); got != MaxPeerRoutes {
			t.Errorf("%d spokes, a LAN subnet behind the hub %v: %d routes lead s01 to the hub, want %d", c.most, c.hubLAN, got, MaxPeerRoutes)
		}
		want := fmt.Sprintf(`Node "s01": %d routes lead to its peer "hub"`, MaxPeerRoutes+1)
		if _, err := Apply(New(), branchSpokes(c.most+1, c.hubLAN), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
			t.Errorf("%d spokes, a LAN subnet behind the hub %v: %v, want an error with %q", c.most+1, c.hubLAN, err, want)
		}
	}
}
