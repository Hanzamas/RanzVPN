package sidecar

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The row SM-11 of the threat model, the fabric edge of an EVPN gateway (SDN-25-R1 #549), as a test. The page is written for a
// person, so the test looks for what the criterion names in the row, with the white space of the row folded into one space,
// and ties what the row points at to what exists: the functions of the node, its counter, the tests and the fuzz target. A
// row that loses a phrase, or that names code or a test that is gone, fails here until the page and the code agree again.

// repoText returns the text of a file of the repository, which is three levels up from this package, with the line endings
// that a checkout on Windows may have changed (core.autocrlf) made into line feeds.
func repoText(t *testing.T, elem ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", ".."}, elem...)...))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// TestThreatModelFabricEdge is the fourth criterion of SDN-25-R1: the row of the threat model for the fabric edge of an EVPN
// gateway says what the gateway checks of a frame of the fabric, its outer source among it, and what is left, a VTEP that the
// fabric owns and that is spoofed at the underlay; and the code, the counter and the tests that it names exist. Since SDN-25-R3
// (#571, its first criterion) the row and the comments of the counters in NodeEvpn.h say what each counter counts, as the code
// does: the module counts UnknownVni and the datagrams of Malformed from any address, before the outer source is checked.
func TestThreatModelFabricEdge(t *testing.T) {
	row := ""
	for _, l := range strings.Split(repoText(t, "docs", "threat-model.md"), "\n") {
		if strings.HasPrefix(l, "| SM-11 |") {
			row = strings.Join(strings.Fields(l), " ")
		}
	}
	if row == "" {
		t.Fatal("the threat model has no row SM-11, the fabric edge of an EVPN gateway")
	}

	for _, want := range []string{
		"Forges a frame of the fabric to an EVPN gateway, at the fabric edge",
		"The gateway takes a frame of the fabric only from a VTEP that it knows for the VRF of its VNI: the next hop of an IP prefix route of the VRF that it learned",
		"so a frame of an L3 VNI from any other address is dropped and counted as `UnknownVtep`, whatever it holds",
		"The module reads the VXLAN header of each datagram before that check, whatever its source: it drops a datagram that holds no frame, counted as `Malformed`, and one on a VNI of no EVPN VRF, counted as `UnknownVni` (`VxlanInput`), so a host that is no VTEP raises those two counters too",
		"those count the frames of known VTEPs alone",
		"What is left: a host that sends with the address of a VTEP that the fabric owns, spoofed at the underlay, is that VTEP to the gateway",
		"the operator's source-address validation",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("the row SM-11 of the threat model does not say %q", want)
		}
	}

	// The comment of each counter in NodeEvpn.h says where it is counted: the module before the outer source is checked, from
	// any address, or the gateway, for an unknown VTEP whatever its frame holds and for a known one by what is wrong with it
	header := repoText(t, "src", "Cedar", "NodeEvpn.h")
	for _, c := range []struct{ field, says string }{
		{"UINT64 UnknownVtep;", "dropped, whatever they hold"},
		{"UINT64 UnknownVni;", "from any address: dropped by the module, before the source check"},
		{"UINT64 Malformed;", "from any address (the module, before the source check), and frames of a known VTEP"},
		{"UINT64 NotOurs;", "Frames of a known VTEP"},
		{"UINT64 Strangers;", "Packets of a known VTEP"},
	} {
		line := ""
		for _, l := range strings.Split(header, "\n") {
			if strings.Contains(l, c.field) {
				line = l
			}
		}
		if !strings.Contains(line, c.says) {
			t.Errorf("the comment of %s in NodeEvpn.h does not say %q: %q", c.field, c.says, strings.TrimSpace(line))
		}
	}

	// What the row names in backquotes, and where the code or the test that it names is defined
	evpn := repoText(t, "src", "Cedar", "NodeEvpn.c")
	for _, ref := range []struct{ name, text, def string }{
		{"NodeEvpnReceive", evpn, "static void NodeEvpnReceive("},
		{"NodeEvpnHasVtep", evpn, "bool NodeEvpnHasVtep("},
		{"VxlanInput", repoText(t, "src", "Core", "Vxlan.c"), "void VxlanInput("},
		{"UnknownVtep", header, "UINT64 UnknownVtep;"},
		{"UnknownVni", header, "UINT64 UnknownVni;"},
		{"Malformed", header, "UINT64 Malformed;"},
		{"NotOurs", header, "UINT64 NotOurs;"},
		{"Strangers", header, "UINT64 Strangers;"},
		{"vpntest evpn", repoText(t, "src", "vpntest", "evpntest.c"), `RANZ_TEST("evpn",`},
		{"TestFRREVPN", repoText(t, "ranz-bgp", "internal", "sidecar", "frr_test.go"), "func TestFRREVPN("},
		{"fuzz_evpn", repoText(t, "src", "fuzz", "fuzz_evpn.c"), "NodeEvpnHasVtep("},
	} {
		if !strings.Contains(row, "`"+ref.name+"`") {
			t.Errorf("the row SM-11 of the threat model does not name `%s`", ref.name)
		}
		if !strings.Contains(ref.text, ref.def) {
			t.Errorf("the row SM-11 names `%s`, which the code does not have: no %q", ref.name, ref.def)
		}
	}

	// The boundary of the fabric edge is B9, which names the VTEPs of the routes as what the source address is checked against
	for _, l := range strings.Split(repoText(t, "docs", "threat-model.md"), "\n") {
		if strings.HasPrefix(l, "| B9 |") && !strings.Contains(l, "or against the VTEPs of the routes of the fabric") {
			t.Error("the boundary B9 of the threat model does not name the VTEPs of the routes of the fabric")
		}
	}
}
