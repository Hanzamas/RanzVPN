package explain

import (
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// ranz explain marks the Networks of a VRF whose link is of kind vxlan or geneve and whose tag mode is
// trusted-underlay "tags not authenticated" (SDN-87, #386): the Nodes take the source group that the link carries as
// the operator vouches for the underlay. In the tag mode off the link carries none, and the Noise session of a link of
// kind noise authenticates it, so neither has the mark. The rule written by tag judges the packet the same in each.
func TestTrustedUnderlayTagsNotAuthenticated(t *testing.T) {
	for _, c := range []struct {
		link, mode string // the kind of the link of VRF dc and the tagMode of its Networks, "" for none
		want       string // the tag mode of the link step, "" for none
		marked     bool
	}{
		{"vxlan", "trusted-underlay", intent.TagModeTrustedUnderlay, true},
		{"geneve", "Trusted-Underlay", intent.TagModeTrustedUnderlay, true},
		{"vxlan", "off", intent.TagModeOff, false},
		{"geneve", "", intent.TagModeOff, false},
		{"noise", "trusted-underlay", "", false},
	} {
		t.Run(c.link+"-"+c.mode, func(t *testing.T) {
			vni, vtep1, vtep2, mode := `, "vni": 3000`, `, "vtep": {"address": "192.0.2.1"}`, `, "vtep": {"address": "192.0.2.2"}`, ""
			if c.link == "noise" {
				vni, vtep1, vtep2 = "", "", ""
			}
			if c.mode != "" {
				mode = `, "tagMode": "` + c.mode + `"`
			}
			s := Scenario{Name: "tags", Nodes: map[string]uint8{"dc-1": 1, "dc-2": 33}, Intent: document(t, `{"resources": [
				{"kind": "VRF", "name": "dc", "spec": {"id": 30, "ula": "fd00:30::/48", "link": "`+c.link+`"`+vni+`}},
				{"kind": "Network", "name": "dc-lan", "spec": {"vrf": "dc", "ipv4Pool": "10.30.0.0/24"`+mode+`}},
				{"kind": "Network", "name": "dc-mgmt", "spec": {"vrf": "dc", "ipv4Pool": "10.31.0.0/24"`+mode+`}},
				{"kind": "Node", "name": "dc-1", "spec": {"vrfs": ["dc"], "tags": ["web"], "addresses": {"dc-lan": "10.30.0.1"}`+vtep1+`}},
				{"kind": "Node", "name": "dc-2", "spec": {"vrfs": ["dc"], "tags": ["db"], "addresses": {"dc-lan": "10.30.0.2"}`+vtep2+`}},
				{"kind": "Policy", "name": "web-to-db", "spec": {"vrf": "dc", "action": "allow", "from": {"tags": ["web"]}, "to": {"tags": ["db"]}}}
			]}`)}
			m, _ := model(t, s)
			r, err := m.Explain(Query{From: "dc-1", To: "dc-2", Protocol: "udp", SourcePort: 40000, Port: 53})
			if err != nil {
				t.Fatal(err)
			}
			link := steps(r, StepLink)
			if len(link) != 1 || link[0].Link.Kind != c.link || link[0].Link.TagMode != c.want {
				t.Fatalf("the link steps are %+v, want one of kind %s in the tag mode %q", link, c.link, c.want)
			}
			l := link[0].Link
			if c.marked {
				want := "unencrypted, plain on a network that the operator trusts; tags not authenticated: Networks dc-lan, dc-mgmt are in the tag mode trusted-underlay, so dc-2 takes the source group that the link carries without authenticating it; "
				if l.Tags != intent.TagsNotAuthenticated || !slices.Equal(l.Networks, []string{"dc-lan", "dc-mgmt"}) || !strings.Contains(link[0].Text, want) {
					t.Errorf("the link is %+v and says %q, want the mark %q of dc-lan and dc-mgmt", l, link[0].Text, intent.TagsNotAuthenticated)
				}
			} else if l.Tags != "" || len(l.Networks) != 0 || strings.Contains(link[0].Text, intent.TagsNotAuthenticated) {
				t.Errorf("the link is %+v and says %q, want no mark", l, link[0].Text)
			}
			// The mark is the one that the intent gives each Network
			for _, n := range []string{"dc-lan", "dc-mgmt"} {
				if note := m.in.TagsNote(n); (note == intent.TagsNotAuthenticated) != c.marked {
					t.Errorf("the intent says %q of Network %s", note, n)
				}
			}
			if !r.Verdict.Delivered || r.Verdict.Node != "dc-2" || r.Rules()["dc-2"] != "web-to-db" {
				t.Errorf("the verdict is %+v with the rules %v, want delivered to dc-2 by web-to-db", r.Verdict, r.Rules())
			}
		})
	}
}

// A Network named alone, or a VRF whose Networks the intent does not name, is said as such.
func TestTagsText(t *testing.T) {
	l := &Link{Peer: "dc-2", TagMode: intent.TagModeTrustedUnderlay, Tags: intent.TagsNotAuthenticated, Networks: []string{"dc-lan"}}
	if got, want := tagsText(l), "; tags not authenticated: Network dc-lan is in the tag mode trusted-underlay, so dc-2 takes the source group that the link carries without authenticating it"; got != want {
		t.Errorf("one Network: %q, want %q", got, want)
	}
	l.Networks = nil
	if got := tagsText(l); !strings.HasPrefix(got, "; tags not authenticated: its VRF is in the tag mode trusted-underlay") {
		t.Errorf("no Network: %q", got)
	}
	if got := tagsText(&Link{Peer: "dc-2", TagMode: intent.TagModeOff}); got != "" {
		t.Errorf("the tag mode off: %q, want nothing", got)
	}
}
