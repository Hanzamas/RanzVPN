package sidecar

import (
	"bytes"
	"net/netip"
	"testing"
)

// The fuzz test of the sidecar package (ADR-0040 item 1, .github/quality/fuzz-targets.txt), which
// the ranz workflow runs with go test -fuzz.

// FuzzRead reads the input as what the node writes into the pipe (Reader.Read), message after
// message until the first error, and checks the settings of each start message as the session
// does before BGP starts (parseStart, and parseEVPN for the EVPN of a gateway).
func FuzzRead(f *testing.F) {
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","peers":[{"address":"192.0.2.2","asn":65002,"passive":true}],"accept":["198.51.100.0/24","2001:db8::/32"]}` + "\n" +
		"\r\n" + `{"type":"announce","prefix":"203.0.113.0/24","next_hop":"192.0.2.1"}` + "\n" + `{"type":"withdraw","prefix":"203.0.113.0/24"}` + "\n"))
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","listen_port":-1,"listen_addresses":["192.0.2.1"],"peers":[{"address":"2001:db8::2","asn":65002,"port":1179}]}`))
	// The peering of the standard mode (SDN-77 #357): a start with the node's address, peers messages with more, and ping
	// (SDN-77-R1 #531)
	f.Add([]byte(`{"type":"start","asn":4200000000,"router_id":"192.0.2.2","address":"127.0.0.2","peers":[{"address":"127.0.0.3","asn":4200000000,"hold_time":9,"vrfs":[{"id":101,"accept":["10.0.0.3/32","192.168.2.0/24"]}]}]}` + "\n" +
		`{"type":"peers","more":true,"peers":[{"address":"127.0.0.4","asn":4200000000,"vrfs":[{"id":102,"accept":["fd00::4/128"]}]}]}` + "\n" +
		`{"type":"peers"}` + "\n" + `{"type":"announce","vrf":101,"prefix":"192.168.1.0/24"}` + "\n" + `{"type":"ping"}` + "\n"))
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","listen_port":-1,"peers":[{"address":"192.0.2.2","asn":65010}],` +
		`"evpn":{"vtep":"192.0.2.1","router_mac":"02:52:5a:00:00:05","vrfs":[{"vrf":101,"vni":10101,"rd":"192.0.2.1:101","import":["65000:10101"],"export":["65000:10101"],"accept":["172.16.0.0/12"]},` +
		`{"vrf":102,"vni":10102,"import":["192.0.2.1:102","1.2:102"],"export":["65000:10102"]}]}}` + "\n" + `{"type":"announce","prefix":"10.10.0.0/24","vrf":101}` + "\n"))
	// The stretches of a gateway (SDN-64 #291): a start that stretches two L2 VNIs, and stretch messages of a full resync and
	// of a delta, MAC only and MAC plus IP
	f.Add([]byte(`{"type":"start","asn":65001,"router_id":"192.0.2.1","listen_port":-1,"peers":[{"address":"192.0.2.2","asn":65010}],` +
		`"evpn":{"vtep":"192.0.2.1","stretches":[{"vni":5010,"route_targets":["65000:5010"]},{"vni":100010,"rd":"65000:10","route_targets":["65000:10","192.0.2.1:10"]}]}}` + "\n" +
		`{"type":"stretch","full":true,"more":true,"routes":[{"vni":5010,"mac":"02:52:5a:64:00:01"},{"vni":5010,"mac":"02:52:5a:64:00:01","ip":"10.50.0.1"}]}` + "\n" +
		`{"type":"stretch","full":false,"routes":[{"vni":100010,"mac":"02:52:5a:64:00:02","ip":"fd50::2"}]}` + "\n" +
		`{"type":"stretch","routes":[{"vni":5010,"mac":"02:52:5a:64:00:01","withdraw":true},{"vni":5010,"mac":"01:00:5e:00:00:01"}]}` + "\n"))

	f.Fuzz(func(t *testing.T, b []byte) {
		var evpn *evpnState
		r := NewReader(bytes.NewReader(b))
		// Every message takes at least one byte of the input
		for i := 0; i <= len(b); i++ {
			m, err := r.Read()
			if err != nil {
				return
			}
			if m.Type == "" {
				t.Fatal("Read returned a message without a type")
			}
			if m.Type == TypeStart {
				// Only the peering of the standard mode, which has an address, may start without peers: its node may be
				// alone in its VRFs
				cfg, err := parseStart(m)
				if err == nil && len(cfg.peers) == 0 && !cfg.address.IsValid() {
					t.Fatalf("a start without peers or an address is accepted: %+v", m)
				}
				if err == nil {
					evpn = checkEVPN(t, m.EVPN, cfg.routerID)
				}
			}
			if m.Type == TypeStretch && evpn != nil && evpn.stretch != nil {
				checkStretch(t, evpn, m)
			}
		}
		t.Fatalf("Read returned more messages than the %d bytes of the input hold", len(b))
	})
}

// checkEVPN checks the evpn object of a start as parseEVPN takes it: an evpn that it takes has VRFs or stretches, each with
// a VNI of 24 bits that no other VRF or stretch has, its route distinguisher and its route targets, and a VTEP and a router
// MAC. It returns what parseEVPN made, nil for none.
func checkEVPN(t *testing.T, e *EVPN, routerID netip.Addr) *evpnState {
	st, err := parseEVPN(e, routerID)
	if err != nil || st == nil {
		if e == nil && (err != nil || st != nil) {
			t.Fatalf("a start without evpn: %v, %+v", err, st)
		}
		return nil
	}
	if (len(st.vrfs) == 0 && st.stretch == nil) || len(st.vrfs) != len(st.byID) || !st.vtep.IsValid() || st.mac == "" {
		t.Fatalf("an evpn that parseEVPN took: %+v", st)
	}
	vnis := make(map[uint32]bool)
	for _, v := range st.vrfs {
		if v.id == 0 || v.vni == 0 || v.vni > maxVNI || vnis[v.vni] || v.rd == nil || len(v.imports) == 0 || len(v.exports) == 0 {
			t.Fatalf("a VRF of an evpn that parseEVPN took: %+v", v)
		}
		vnis[v.vni] = true
		if _, err := st.evpnPath(v, netip.MustParsePrefix("10.10.0.0/24")); err != nil {
			t.Fatalf("no IP prefix route of VRF %d: %v", v.id, err)
		}
	}
	if st.stretch == nil {
		return st
	}
	for _, v := range st.stretch.list {
		if v.vni == 0 || v.vni > maxVNI || vnis[v.vni] || v.rd == nil || len(v.targets) == 0 || len(v.targets) > maxStretchTargets || len(v.imports) == 0 ||
			st.stretch.byVNI[v.vni] != v {
			t.Fatalf("a stretch of an evpn that parseEVPN took: %+v", v)
		}
		vnis[v.vni] = true
		if _, err := st.imetPath(v); err != nil {
			t.Fatalf("no type-3 route of vni %d: %v", v.vni, err)
		}
	}
	return st
}

// checkStretch checks the routes of a stretch message as the session takes them (keyOf): a route that it takes is of the VNI
// of a stretch, with the MAC of one host and, in the MAC plus IP form, the address of one host, and has a type-2 route.
func checkStretch(t *testing.T, e *evpnState, m Message) {
	for _, r := range m.Routes {
		v, key, err := e.stretch.keyOf(r)
		if err != nil {
			continue
		}
		if v == nil || key.vni != v.vni || v.vni != r.VNI || key.mac == "" || (r.IP == "") != !key.ip.IsValid() || key.ip.Is4In6() {
			t.Fatalf("a route that keyOf took: %+v, %+v", r, key)
		}
		if _, err := e.macPath(v, key); err != nil {
			t.Fatalf("no type-2 route of %+v: %v", key, err)
		}
	}
}
