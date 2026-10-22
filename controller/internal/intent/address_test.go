package intent

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	key2 = "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="
	key3 = "JE/juWPomd0pW6/84kjTUw86mnR5ugYwAmgOv+etrUk="
)

// addressesOf returns the addresses of the Node name as "network=address" pairs, in Network
// order.
func addressesOf(in Intent, name string) string {
	var out []string
	for _, network := range sortedNames(in.Nodes[name].Addresses) {
		out = append(out, network+"="+in.Nodes[name].Addresses[network])
	}
	return strings.Join(out, ",")
}

// A Node gets the lowest free host address of the pool of each L3 Network of its VRFs, Nodes in
// name order, and keeps it: a Node added later, or applied again without it, does not move it.
// An L2 Network allocates nothing.
func TestApplyAllocatesAddresses(t *testing.T) {
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.1.0.0/24"}`),
		res(KindNode, "branch-2", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"branch-1": "lan=10.0.0.1", "branch-2": "lan=10.0.0.2"} {
		if got := addressesOf(in, name); got != want {
			t.Errorf("%s holds %q, want %q", name, got, want)
		}
	}
	next, err := Apply(in, doc(
		res(KindNode, "branch-0", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "tags": ["branch"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"branch-0": "lan=10.0.0.3", "branch-1": "lan=10.0.0.1", "branch-2": "lan=10.0.0.2"} {
		if got := addressesOf(next, name); got != want {
			t.Errorf("after the second apply %s holds %q, want %q", name, got, want)
		}
	}
	p, ok := next.NodeAddress("branch-0", "lan")
	if !ok || p.String() != "10.0.0.3/24" {
		t.Errorf("the address of branch-0 in lan is %v (%v), want 10.0.0.3/24", p, ok)
	}
	if _, ok := next.NodeAddress("branch-0", "dmz"); ok {
		t.Error("branch-0 holds an address in the L2 Network dmz")
	}
}

// A declared address is a reservation: it must be a free host address of the pool of an L3
// Network of the Node's VRFs. A Node that leaves the VRF, or whose Network is deleted, loses its
// address there.
func TestReservedAddresses(t *testing.T) {
	base, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindVRF, "lab", `{"id": 20, "ula": "fd12:3456:789b::/48"}`),
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/24"}`),
		res(KindNetwork, "lab-lan", `{"vrf": "lab", "ipv4Pool": "10.2.0.0/24"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"], "addresses": {"lan": "10.0.0.10"}}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(base, "branch-1"); got != "lan=10.0.0.10" {
		t.Errorf("branch-1 holds %q, want its reservation lan=10.0.0.10", got)
	}
	for _, c := range []struct {
		spec, want string
	}{
		{`{"publicKey": "` + key2 + `", "vrfs": ["corp"], "addresses": {"lan": "10.0.0.10"}}`, `address 10.0.0.10 of Network "lan" is already the address of Node "branch-1"`},
		{`{"publicKey": "` + key2 + `", "vrfs": ["corp"], "addresses": {"lan": "10.0.0.255"}}`, `address 10.0.0.255 is not a host address of the pool 10.0.0.0/24`},
		{`{"publicKey": "` + key2 + `", "vrfs": ["corp"], "addresses": {"lan": "10.9.0.1"}}`, `is not a host address of the pool`},
		{`{"publicKey": "` + key2 + `", "vrfs": ["corp"], "addresses": {"lan": "fd00::1"}}`, `is not an IPv4 address`},
		{`{"publicKey": "` + key2 + `", "vrfs": ["corp"], "addresses": {"lab-lan": "10.2.0.1"}}`, `"lab-lan" is not an L3 Network with an IPv4 pool in a VRF of the node`},
	} {
		if _, err := Apply(base, doc(res(KindNode, "branch-2", c.spec)), nil); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the error is %v, want one with %q", c.spec, err, c.want)
		}
	}

	moved, err := Apply(base, doc(res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["lab"]}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(moved, "branch-1"); got != "lab-lan=10.2.0.1" {
		t.Errorf("branch-1 in lab holds %q, want lab-lan=10.2.0.1 alone", got)
	}
	gone, err := Delete(moved, KindNetwork, "lab-lan")
	if err != nil {
		t.Fatal(err)
	}
	if got := addressesOf(gone, "branch-1"); got != "" {
		t.Errorf("after the delete of lab-lan branch-1 holds %q", got)
	}
	if addressesOf(moved, "branch-1") != "lab-lan=10.2.0.1" {
		t.Error("Delete changed the addresses of the intent it was given")
	}
}

// A pool with no free host address left refuses the Node that would need one.
func TestPoolRunsOut(t *testing.T) {
	_, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNetwork, "tiny", `{"vrf": "corp", "ipv4Pool": "10.0.0.0/30"}`),
		res(KindNode, "a", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
		res(KindNode, "b", `{"publicKey": "`+key2+`", "vrfs": ["corp"]}`),
		res(KindNode, "c", `{"publicKey": "`+key3+`", "vrfs": ["corp"]}`),
	), nil)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Network "tiny": the IPv4 pool 10.0.0.0/30 has no free address for Node "c"`) {
		t.Errorf("three Nodes in a /30: %v", err)
	}
}

// The intent of a first install is VRF default with overlay DNS on, its Network with the
// automatic pool and the starter rule; a Node that names no VRF joins VRF default and gets the
// first address of the pool.
func TestFirstInstall(t *testing.T) {
	in, err := Apply(New(), FirstInstall(), bytes.NewReader([]byte{0x12, 0x34, 0x56, 0x78, 0x9a}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range in.Resources() {
		got = append(got, r.Kind+" "+r.Name+" "+string(r.Spec))
	}
	want := []string{
		`VRF default {"id":1,"ula":"fd12:3456:789a::/48","mtu":1280,"dns":true}`,
		`Network default {"vrf":"default","mode":"L3","ipv4Pool":"100.64.0.0/10"}`,
		`Policy default-allow-all {"vrf":"default","action":"allow"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the first install is\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	next, err := Apply(in, doc(res(KindNode, "node-a", `{"publicKey": "`+key1+`"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := next.Nodes["node-a"]; strings.Join(n.VRFs, ",") != DefaultVRF || addressesOf(next, "node-a") != "default=100.64.0.1" {
		t.Errorf("node-a is in %v with %q, want VRF default with default=100.64.0.1", n.VRFs, addressesOf(next, "node-a"))
	}
	if _, err := Delete(next, KindVRF, DefaultVRF); err == nil || !strings.Contains(err.Error(), `Policy "default-allow-all"`) {
		t.Errorf("deleting VRF default, which the starter rule uses: %v", err)
	}
}
