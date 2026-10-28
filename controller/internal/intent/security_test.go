package intent

import (
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
)

// securityBase is an intent with VRF corp and its Nodes branch-1 and branch-2, and lab-1 in VRF
// lab, for the security of an L2 Network of corp.
func securityBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "branch-2", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(KindNode, "lab-1", `{"publicKey": "`+key3+`", "vrfs": ["lab"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// secured returns the L2 Network dmz of VRF corp with the pool 10.20.0.0/24, the security
// security (a JSON object) and the DHCP responder dhcp (a JSON object, or "" for none).
func secured(security, dhcp string) Resource {
	spec := `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "security": ` + security
	if dhcp != "" {
		spec += `, "dhcp": ` + dhcp
	}
	return res(KindNetwork, "dmz", spec+`}`)
}

// The controller fills in the limit of each check that is on and puts the gateways in name order;
// the gateways of the Network are those of its security and the Node that answers DHCP for it.
func TestSecurityCompletes(t *testing.T) {
	in, err := Apply(securityBase(t), doc(secured(`{"checkMac": true, "checkIp": true, "arpDhcpOnly": true, "dhcpGuard": true, "raGuard": true,
		"gateways": ["branch-2", "branch-1"]}`, "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := in.Networks["dmz"].Security
	if !s.On() || s.MaxMACs != DefaultSecurityMACs || s.MaxIPs != DefaultSecurityIPs || !slices.Equal(s.Gateways, []string{"branch-1", "branch-2"}) {
		t.Fatalf("the security is %+v, want the limits %d and %d and the gateways in name order", s, DefaultSecurityMACs, DefaultSecurityIPs)
	}
	c := in.Clone()
	c.Networks["dmz"].Security.Gateways[0] = "branch-9"
	if in.Networks["dmz"].Security.Gateways[0] != "branch-1" {
		t.Errorf("a change of the gateways of a clone changed the intent it was cloned from")
	}

	// The limits that it sets stay; the Node that answers DHCP for the Network is a gateway of it
	in, err = Apply(in, doc(secured(`{"checkMac": true, "maxMacs": 4, "checkIp": true, "maxIps": 16, "gateways": ["branch-2"]}`,
		`{"mode": "pool", "node": "branch-1"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := in.Networks["dmz"].Security; s.MaxMACs != 4 || s.MaxIPs != 16 {
		t.Errorf("the security is %+v, want the limits 4 and 16 that it sets", s)
	}
	if got := in.SecurityGateways("dmz"); !slices.Equal(got, []string{"branch-1", "branch-2"}) {
		t.Errorf("the gateways of dmz are %v, want branch-1, which answers DHCP for it, and branch-2", got)
	}

	// A check that is off gets no limit, and a security that turns no protection on is off
	in, err = Apply(in, doc(secured(`{"dhcpGuard": true}`, "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if s := in.Networks["dmz"].Security; !s.On() || s.MaxMACs != 0 || s.MaxIPs != 0 {
		t.Errorf("with the DHCP guard alone the security is %+v, want it on without limits", s)
	}
	if (&Security{Gateways: []string{"branch-1"}}).On() || (*Security)(nil).On() {
		t.Errorf("a security without a protection, or none at all, is on")
	}
}

// What a security cannot be: one of an L3 Network, a limit out of its bounds or of a check that is
// off, a gateway that is no Node, one outside the VRF of the Network or listed twice, and more
// gateways than a node holds.
func TestSecurityRejects(t *testing.T) {
	base := securityBase(t)
	for _, c := range []struct {
		r    Resource
		want string
	}{
		{res(KindNetwork, "lan", `{"vrf": "corp", "security": {"checkMac": true}}`), `Network "lan": security: only an L2 Network has security`},
		{secured(`{"checkMac": true, "maxMacs": 65}`, ""), `maxMacs 65 is not between 1 and 64`},
		{secured(`{"checkIp": true, "maxIps": 100}`, ""), `maxIps 100 is not between 1 and 64`},
		{secured(`{"maxMacs": 2}`, ""), `maxMacs limits the addresses that a client owns under checkMac, which is off`},
		{secured(`{"checkMac": true, "maxIps": 2}`, ""), `maxIps limits the addresses that a client owns under checkIp, which is off`},
		{secured(`{"dhcpGuard": true, "gateways": ["nobody"]}`, ""), `gateway "nobody" is not a Node: a gateway is a Node of VRF "corp"`},
		{secured(`{"dhcpGuard": true, "gateways": ["lab-1"]}`, ""), `gateway "lab-1" is not in VRF "corp" of the Network`},
		{secured(`{"dhcpGuard": true, "gateways": ["branch-1", "branch-1"]}`, ""), `gateway "branch-1" is listed twice`},
		{secured(`{"raGuard": true, "rateLimit": 1}`, ""), `unknown field "rateLimit"`},
	} {
		refuses(t, base, c.want, c.r)
	}

	// MaxSecurityGateways and one more are one too many for a node
	in := base
	var gateways []string
	for i := range MaxSecurityGateways + 1 {
		name := "gw-" + string(rune('a'+i))
		key := base64.StdEncoding.EncodeToString(append([]byte{byte(0x40 + i)}, make([]byte, KeySize-1)...))
		var err error
		if in, err = Apply(in, doc(res(KindNode, name, `{"publicKey": "`+key+`", "vrfs": ["corp"]}`)), nil); err != nil {
			t.Fatal(err)
		}
		gateways = append(gateways, `"`+name+`"`)
	}
	refuses(t, in, `9 gateways with the Node that answers DHCP, and a Network has at most 8`,
		secured(`{"raGuard": true, "gateways": [`+strings.Join(gateways, ", ")+`]}`, ""))
	refuses(t, in, `9 gateways with the Node that answers DHCP, and a Network has at most 8`,
		secured(`{"raGuard": true, "gateways": [`+strings.Join(gateways[1:], ", ")+`]}`, `{"mode": "pool", "node": "branch-1"}`))
}

// A Node that is a gateway of the security of a Network cannot be deleted while it is one.
func TestDeleteSecurityGateway(t *testing.T) {
	in, err := Apply(securityBase(t), doc(secured(`{"dhcpGuard": true, "gateways": ["branch-2"]}`, "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Delete(in, KindNode, "branch-2")
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Node "branch-2" is a gateway of Network "dmz"`) {
		t.Errorf("deleting the gateway gave %v", err)
	}
	without, err := Apply(in, doc(secured(`{"dhcpGuard": true}`, "")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Delete(without, KindNode, "branch-2"); err != nil {
		t.Errorf("deleting the Node once no security names it: %v", err)
	}
}
