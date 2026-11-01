package intent

import "testing"

// splitBase is an intent with VRF corp and its Node branch-1, for the TCP splitting of a Network of
// corp.
func splitBase(t *testing.T) Intent {
	t.Helper()
	in, err := Apply(New(), doc(
		res(KindVRF, "corp", `{"id": 10, "ula": "fd12:3456:789a::/48"}`),
		res(KindNode, "branch-1", `{"publicKey": "`+key1+`", "vrfs": ["corp"]}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// TCP splitting is off by default, and an L3 Network turns it on for itself alone.
func TestSplitPerL3Network(t *testing.T) {
	in, err := Apply(splitBase(t), doc(
		res(KindNetwork, "lan", `{"vrf": "corp", "ipv4Pool": "10.20.0.0/24"}`),
		res(KindNetwork, "fast", `{"vrf": "corp", "mode": "L3", "ipv4Pool": "10.21.0.0/24", "tcpSplit": true}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Networks["lan"].TCPSplit {
		t.Errorf("Network lan splits TCP without tcpSplit: it is off by default")
	}
	if !in.Networks["fast"].TCPSplit || in.Networks["fast"].Mode != ModeL3 {
		t.Errorf("Network fast is %+v, want an L3 Network that splits TCP", in.Networks["fast"])
	}
	if c := in.Clone(); !c.Networks["fast"].TCPSplit || c.Networks["lan"].TCPSplit {
		t.Errorf("a clone of the intent changed the TCP splitting of its Networks")
	}

	// It goes off again with a spec that leaves it out
	in, err = Apply(in, doc(res(KindNetwork, "fast", `{"vrf": "corp", "ipv4Pool": "10.21.0.0/24"}`)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if in.Networks["fast"].TCPSplit {
		t.Errorf("Network fast still splits TCP once its spec leaves tcpSplit out")
	}
}

// An L2 Network carries Ethernet frames, which no node terminates: it cannot split TCP.
func TestSplitRejectsL2(t *testing.T) {
	refuses(t, splitBase(t), `Network "dmz": tcpSplit: only an L3 Network splits TCP`,
		res(KindNetwork, "dmz", `{"vrf": "corp", "mode": "L2", "ipv4Pool": "10.20.0.0/24", "tcpSplit": true}`))
}
