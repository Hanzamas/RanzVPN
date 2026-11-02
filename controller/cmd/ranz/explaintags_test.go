package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/explain"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain marks a Network in the tag mode trusted-underlay whose VRF has a link of kind vxlan "tags not
// authenticated" (SDN-87, #386), in the line of the link and in the answer as JSON; the Network of a VRF of kind geneve
// in the tag mode off has no mark. dc-1 and dc-2 share VRF dc, whose Network dc-lan is in trusted-underlay, and VRF lab,
// whose Network lab-lan names no tag mode.
func TestExplainCommandTagsNotAuthenticated(t *testing.T) {
	ctx := context.Background()
	srv, _, admin := startController(t)
	s := explain.Scenario{Name: "tags", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}}
	if err := json.Unmarshal([]byte(`{"resources": [
		{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "vxlan", "vni": 3000}},
		{"kind": "VRF", "name": "lab", "spec": {"id": 40, "ula": "fd00:40::/48", "link": "geneve", "vni": 4000}},
		{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24", "tagMode": "trusted-underlay"}},
		{"kind": "Network", "name": "lab-lan", "spec": {"vrf": "lab", "ipv4Pool": "10.40.0.0/24"}},
		{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["dc", "lab"], "addresses": {"dc-lan": "10.30.0.1", "lab-lan": "10.40.0.1"}, "vtep": {"address": "192.0.2.1"}}},
		{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["dc", "lab"], "addresses": {"dc-lan": "10.30.0.2", "lab-lan": "10.40.0.2"}, "vtep": {"address": "192.0.2.2"}}},
		{"kind": "Policy", "name": "dc-all", "spec": {"vrf": "dc", "action": "allow"}},
		{"kind": "Policy", "name": "lab-all", "spec": {"vrf": "lab", "action": "allow"}}
	]}`), &s.Intent); err != nil {
		t.Fatal(err)
	}
	doc, err := s.Document()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&api.Client{URL: srv.URL, Token: admin, HTTP: srv.Client()}).Apply(ctx, doc); err != nil {
		t.Fatal(err)
	}
	tokenFile := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(tokenFile, []byte(admin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The test server is on a loopback address, so ranz explain pins its certificate (AUD1-DT-13, #461)
	fingerprint := fingerprintOf(srv.Certificate())
	run := func(args ...string) string {
		t.Helper()
		var out, errOut bytes.Buffer
		if code := runExplain(ctx, append([]string{"-server", srv.URL, "-token-file", tokenFile, "-tls-fingerprint", fingerprint, "-protocol", "udp", "-sport", "40000", "-port", "53"}, args...), &out, &errOut); code != 0 {
			t.Fatalf("ranz explain %v: exit code %d: %s", args, code, errOut.String())
		}
		return out.String()
	}

	const dialled = "; dc-2 has no endpoints, so no peer dials it; dc-1 has no endpoints, so no peer dials it\n"
	out := run("-vrf", "dc", "dc-1", "dc-2")
	want := "  dc-1  link    the link of kind vxlan of VRF dc carries the packet on VNI 3000 to the tunnel endpoint of dc-2: unencrypted, plain on a network that the operator trusts" +
		"; tags not authenticated: Network dc-lan is in the tag mode trusted-underlay, so dc-2 takes the source group that the link carries without authenticating it" + dialled
	if !strings.Contains(out, want) || !strings.Contains(out, "verdict: delivered to dc-2 in VRF dc as ") {
		t.Errorf("ranz explain -vrf dc dc-1 dc-2 printed\n%s\nwithout the link %q, or not delivered to dc-2", out, want)
	}
	out = run("-vrf", "lab", "dc-1", "dc-2")
	want = "  dc-1  link    the link of kind geneve of VRF lab carries the packet on VNI 4000 to the tunnel endpoint of dc-2: unencrypted, plain on a network that the operator trusts" + dialled
	if !strings.Contains(out, want) || strings.Contains(out, intent.TagsNotAuthenticated) {
		t.Errorf("ranz explain -vrf lab dc-1 dc-2 printed\n%s\nwithout the link %q, or with a mark", out, want)
	}

	// The answer as JSON carries the tag mode of each plain link and the mark with the Networks that it marks
	for _, c := range []struct {
		vrf, mode, tags string
		networks        []string
	}{
		{"dc", intent.TagModeTrustedUnderlay, intent.TagsNotAuthenticated, []string{"dc-lan"}},
		{"lab", intent.TagModeOff, "", nil},
	} {
		var res explain.Result
		if err := json.Unmarshal([]byte(run("-o", "json", "-vrf", c.vrf, "dc-1", "dc-2")), &res); err != nil {
			t.Fatal(err)
		}
		var links []explain.Link
		for _, st := range res.Steps {
			if st.Kind == explain.StepLink && st.Link != nil {
				links = append(links, *st.Link)
			}
		}
		if len(links) != 1 || links[0].TagMode != c.mode || links[0].Tags != c.tags || !slices.Equal(links[0].Networks, c.networks) {
			t.Errorf("the links of VRF %s in JSON are %+v, want the tag mode %s, the mark %q of %v", c.vrf, links, c.mode, c.tags, c.networks)
		}
	}
}
