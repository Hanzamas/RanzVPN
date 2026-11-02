package forkimport

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// folder is the text of a folder of the Config file with the lines inside it. A space in a name is written $20, as the
// fork writes it.
func folder(name string, lines ...string) string {
	return "declare " + name + "\n{\n" + strings.Join(lines, "\n") + "\n}\n"
}

// configText is the text of a Config file whose Virtual Hubs are the folders hubs.
func configText(hubs ...string) []byte {
	return []byte("declare root\n{\ndeclare ServerConfiguration\n{\n}\ndeclare VirtualHUB\n{\n" + strings.Join(hubs, "") + "}\n}\n")
}

// importOf parses and imports text, and checks that the document applies to an empty intent.
func importOf(t *testing.T, text []byte, opts Options) Result {
	t.Helper()
	root, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Import(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intent.Apply(intent.New(), res.Document, nil); err != nil {
		t.Fatalf("the import does not apply: %v", err)
	}
	return res
}

// resourceNames returns the names of the resources of the kind, in order.
func resourceNames(doc intent.Document, kind string) []string {
	var out []string
	for _, r := range doc.Resources {
		if r.Kind == kind {
			out = append(out, r.Name)
		}
	}
	slices.Sort(out)
	return out
}

// specOf decodes the spec of the resource of the kind and the name into v.
func specOf(t *testing.T, doc intent.Document, kind, name string, v any) {
	t.Helper()
	for _, r := range doc.Resources {
		if r.Kind == kind && r.Name == name {
			if err := json.Unmarshal(r.Spec, v); err != nil {
				t.Fatalf("%s %s: %v", kind, name, err)
			}
			return
		}
	}
	t.Fatalf("the document has no %s %q", kind, name)
}

func policyOf(t *testing.T, doc intent.Document, name string) intent.Policy {
	t.Helper()
	var p intent.Policy
	specOf(t, doc, intent.KindPolicy, name, &p)
	return p
}

func userOf(t *testing.T, doc intent.Document, name string) intent.User {
	t.Helper()
	var u intent.User
	specOf(t, doc, intent.KindUser, name, &u)
	return u
}

// notesOf returns the notes of every Virtual Hub of res as one text.
func notesOf(res Result) string {
	var all []string
	for _, h := range res.Hubs {
		all = append(all, h.Notes...)
	}
	return strings.Join(all, "\n")
}

// namedPolicy is a Policy that a test expects, with its name.
type namedPolicy struct {
	name   string
	policy intent.Policy
}

// checkPolicies checks that the document holds the Policies of want, and no other than want and the ones that let
// through what no entry matches.
func checkPolicies(t *testing.T, doc intent.Document, want []namedPolicy) {
	t.Helper()
	var names []string
	for _, w := range want {
		names = append(names, w.name)
		if got := policyOf(t, doc, w.name); !reflect.DeepEqual(got, w.policy) {
			t.Errorf("Policy %s is %+v, want %+v", w.name, got, w.policy)
		}
	}
	for _, name := range resourceNames(doc, intent.KindPolicy) {
		if !slices.Contains(names, name) && !strings.HasSuffix(name, "-default-allow") {
			t.Errorf("the document has the Policy %s, which the test does not expect", name)
		}
	}
}

// Each Virtual Hub is a VRF with one Network, named after it, in the mode and with the pool that the options give.
func TestEachVirtualHubIsAVRFWithOneNetwork(t *testing.T) {
	text := configText(folder("Lab"), folder("My$20Hub"))
	res := importOf(t, text, Options{})
	if got, want := resourceNames(res.Document, intent.KindVRF), []string{"lab", "my-hub"}; !slices.Equal(got, want) {
		t.Errorf("the VRFs are %v, want %v", got, want)
	}
	if got, want := resourceNames(res.Document, intent.KindNetwork), []string{"lab", "my-hub"}; !slices.Equal(got, want) {
		t.Errorf("the Networks are %v, want %v", got, want)
	}
	if len(res.Hubs) != 2 || res.Hubs[0].Name != "Lab" || res.Hubs[0].VRF != "lab" || res.Hubs[0].Network != "lab" || res.Hubs[1].VRF != "my-hub" {
		t.Errorf("the Virtual Hubs are %+v", res.Hubs)
	}
	if h := res.Hubs[0]; h.Policies != 1 || h.Entries != 0 || h.Groups != 0 || h.Users != 0 {
		t.Errorf("a Virtual Hub with nothing in it is %+v, want the one Policy that lets through what no entry matches", h)
	}
	var n intent.Network
	specOf(t, res.Document, intent.KindNetwork, "lab", &n)
	if want := (intent.Network{VRF: "lab", Mode: intent.ModeL3}); !reflect.DeepEqual(n, want) {
		t.Errorf("the Network is %+v, want %+v", n, want)
	}
	if !strings.Contains(res.Hubs[0].Notes[0], "Network lab has no IPv4 pool") {
		t.Errorf("the notes are %v, want one that says that the Network has no pool", res.Hubs[0].Notes)
	}

	res = importOf(t, text, Options{Mode: "l2", Pools: map[string]string{"LAB": "10.0.0.0/24"}})
	var withOptions intent.Network
	specOf(t, res.Document, intent.KindNetwork, "lab", &withOptions)
	if want := (intent.Network{VRF: "lab", Mode: intent.ModeL2, IPv4Pool: "10.0.0.0/24"}); !reflect.DeepEqual(withOptions, want) {
		t.Errorf("the Network with options is %+v, want %+v", withOptions, want)
	}
	if strings.Contains(notesOf(res), "no IPv4 pool") {
		t.Errorf("the notes of Networks of mode L2 are %q: a pool is no matter of theirs", notesOf(res))
	}

	res = importOf(t, text, Options{Hubs: []string{"MY HUB"}})
	if got := resourceNames(res.Document, intent.KindVRF); !slices.Equal(got, []string{"my-hub"}) || len(res.Hubs) != 1 {
		t.Errorf("the import of one Virtual Hub made the VRFs %v of %d hubs", got, len(res.Hubs))
	}
}

// The entries become Policies in the order of the fork, a pass entry before a discard entry of one priority, each at a
// priority of its own, named after the place that the entry has in that order; and one more Policy lets through what
// no entry matches.
func TestTheAccessListBecomesPoliciesInTheOrderOfTheFork(t *testing.T) {
	acl := folder("AccessList",
		folder("1", "bool Active true", "bool Discard true", "uint Priority 100", "uint Protocol 6", "uint DestPortStart 22", "uint DestPortEnd 22",
			"string DestIpAddress 10.0.0.10", "string DestSubnetMask 255.255.255.255", "string Note no$20ssh"),
		folder("2", "bool Active true", "bool Discard false", "uint Priority 100", "uint Protocol 6", "uint DestPortStart 22", "uint DestPortEnd 22",
			"string SrcUsername alice"),
		folder("3", "bool Active true", "bool Discard false", "uint Priority 200"))
	res := importOf(t, configText(folder("lab", acl)), Options{})
	checkPolicies(t, res.Document, []namedPolicy{
		{"lab-acl-1", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 10, From: intent.PolicyEnd{Tags: []string{"alice"}, Addresses: []string{"0.0.0.0/0"}},
			Protocol: "tcp", Ports: []intent.PolicyValue{"22"}}},
		{"lab-acl-2", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 20, To: intent.PolicyEnd{Addresses: []string{"10.0.0.10"}},
			Protocol: "tcp", Ports: []intent.PolicyValue{"22"}}},
		{"lab-acl-3", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 30}},
		{"lab-default-allow", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: intent.MaxPriority}},
	})
	if h := res.Hubs[0]; h.Entries != 3 || h.Policies != 4 || h.Groups != 1 {
		t.Errorf("the Virtual Hub is %+v, want 3 entries, 4 Policies and the 1 Group that alice made", h)
	}
	if got := resourceNames(res.Document, intent.KindGroup); !slices.Equal(got, []string{"alice"}) {
		t.Errorf("the Groups are %v, want alice, the tag of the entry that names her", got)
	}
}

// An entry whose ports have no protocol is TCP and UDP, an entry that matches by the TCP state is TCP, and a range that
// the fork never matches makes an entry that matches nothing.
func TestAnEntryThatTakesSeveralProtocolsMakesSeveralPolicies(t *testing.T) {
	acl := folder("AccessList",
		folder("1", "bool Active true", "uint Priority 100", "uint DestPortStart 8000", "uint DestPortEnd 8080"),
		folder("2", "bool Active true", "bool Discard true", "uint Priority 200", "bool CheckTcpState true"),
		folder("3", "bool Active true", "bool Discard true", "uint Priority 300", "uint Protocol 6", "uint DestPortStart 70000"))
	res := importOf(t, configText(folder("lab", acl)), Options{})
	every := intent.PolicyEnd{Addresses: []string{"0.0.0.0/0"}}
	checkPolicies(t, res.Document, []namedPolicy{
		{"lab-acl-1-1", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 10, From: every, Protocol: "tcp", Ports: []intent.PolicyValue{"8000-8080"}}},
		{"lab-acl-1-2", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 10, From: every, Protocol: "udp", Ports: []intent.PolicyValue{"8000-8080"}}},
		{"lab-acl-2", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 20, From: every, Protocol: "tcp"}},
	})
	notes := notesOf(res)
	for _, s := range []string{"entry 2 carried without its match by the TCP state", "entry 3 matches no frame in the fork: left out"} {
		if !strings.Contains(notes, s) {
			t.Errorf("the notes are %q, want one that says %q", notes, s)
		}
	}
}

// What a Policy has no match for never lets through a frame that the fork dropped: a deny entry is carried without it,
// an allow entry that has it is left out; a redirect is carried as a deny entry; the entries that match nothing, or that
// are inactive, are left out; and the notes say each.
func TestWhatAPolicyCannotMatchNeverLetsThroughMore(t *testing.T) {
	every := intent.PolicyEnd{Addresses: []string{"0.0.0.0/0"}}
	deny := func(p intent.Policy) intent.Policy {
		p.VRF, p.Action, p.Priority = "lab", intent.PolicyDeny, 10
		return p
	}
	allow := func(p intent.Policy) intent.Policy {
		p.VRF, p.Action, p.Priority = "lab", intent.PolicyAllow, 10
		return p
	}
	cases := []struct {
		name  string
		items []string
		want  map[string]intent.Policy
		note  string
	}{
		{"an allow entry with a source port", []string{"bool Active true", "uint Protocol 17", "uint SrcPortStart 53", "uint SrcPortEnd 53"}, nil,
			"entry 1 left out: it lets through what it matches by source ports"},
		{"a deny entry with a source port", []string{"bool Active true", "bool Discard true", "uint Protocol 17", "uint SrcPortStart 53", "uint SrcPortEnd 53"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{From: every, Protocol: "udp"})}, "entry 1 carried without its match by source ports"},
		{"a deny entry with a mask that is no prefix", []string{"bool Active true", "bool Discard true", "string DestIpAddress 172.16.9.1", "string DestSubnetMask 255.255.0.255"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{To: intent.PolicyEnd{Addresses: []string{"172.16.0.0/16"}}})}, "masks that are no prefix"},
		{"an allow entry with a mask that is no prefix", []string{"bool Active true", "string DestIpAddress 172.16.9.1", "string DestSubnetMask 255.255.0.255"}, nil,
			"entry 1 left out"},
		{"a redirect", []string{"bool Active true", "uint Protocol 6", "uint DestPortStart 80", "uint DestPortEnd 80", "string RedirectUrl http://portal.example/login"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{From: every, Protocol: "tcp", Ports: []intent.PolicyValue{"80"}})}, "has a redirect URL"},
		{"a delay", []string{"bool Active true", "uint Protocol 17", "uint DestPortStart 5060", "uint DestPortEnd 5060", "uint Delay 10"},
			map[string]intent.Policy{"lab-acl-1": allow(intent.Policy{From: every, Protocol: "udp", Ports: []intent.PolicyValue{"5060"}})}, "its delay, jitter and loss are left out"},
		{"an inactive entry", []string{"bool Active false", "bool Discard true"}, nil, "inactive entries left out: 1"},
		{"an entry of IPv6", []string{"bool Active true", "bool Discard true", "bool IsIPv6 true", "string DestIpAddress6 2001:db8:1::", "string DestSubnetMask6 ffff:ffff:ffff::", "uint Protocol 58"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{To: intent.PolicyEnd{Addresses: []string{"2001:db8:1::/48"}}, Protocol: "58"})}, ""},
		{"an entry of IPv6 with the protocol of ICMP", []string{"bool Active true", "bool Discard true", "bool IsIPv6 true", "uint Protocol 1"}, nil,
			"matches no frame in the fork"},
		{"ICMP with ports", []string{"bool Active true", "bool Discard true", "uint Protocol 1", "uint DestPortStart 80", "uint DestPortEnd 80"}, nil,
			"matches no frame in the fork"},
		{"the TCP state of UDP", []string{"bool Active true", "bool Discard true", "uint Protocol 17", "bool CheckTcpState true"}, nil,
			"matches no frame in the fork"},
		{"a source MAC address on an allow entry", []string{"bool Active true", "bool CheckSrcMac true", "string SrcMacAddress 02-00-00-4C-00-03", "string SrcMacMask FF-FF-FF-FF-FF-FF"}, nil,
			"it lets through what it matches by source MAC addresses"},
		{"a source MAC address that the fork cannot read", []string{"bool Active true", "bool CheckSrcMac true", "string SrcMacAddress zz", "string SrcMacMask FF-FF-FF-FF-FF-FF"},
			map[string]intent.Policy{"lab-acl-1": allow(intent.Policy{})}, ""},
		{"a user list file", []string{"bool Active true", "bool Discard true", "string SrcUsername include:blocked.txt"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{})}, "user list files"},
		{"a user of a domain", []string{"bool Active true", "string SrcUsername CORP\\Alice@example.com"},
			map[string]intent.Policy{"lab-acl-1": allow(intent.Policy{From: intent.PolicyEnd{Tags: []string{"alice"}}})}, "an entry names \"Alice\", which is no user or group of the hub"},
		{"an address with host bits under its mask", []string{"bool Active true", "string SrcIpAddress 10.1.2.3", "string SrcSubnetMask 255.255.255.0"},
			map[string]intent.Policy{"lab-acl-1": allow(intent.Policy{From: intent.PolicyEnd{Addresses: []string{"10.1.2.0/24"}}})}, ""},
		{"an address with a mask of no bit", []string{"bool Active true", "string SrcIpAddress 10.1.2.3", "string SrcSubnetMask 0.0.0.0"},
			map[string]intent.Policy{"lab-acl-1": allow(intent.Policy{From: every})}, ""},
		{"the TCP state and a port", []string{"bool Active true", "bool Discard true", "bool CheckTcpState true", "uint DestPortStart 25", "uint DestPortEnd 25"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{From: every, Protocol: "tcp", Ports: []intent.PolicyValue{"25"}})}, "the TCP state"},
		{"a user and an address of the destination", []string{"bool Active true", "bool Discard true", "string DestUsername carol", "string DestIpAddress 10.0.0.0", "string DestSubnetMask 255.0.0.0"},
			map[string]intent.Policy{"lab-acl-1": deny(intent.Policy{To: intent.PolicyEnd{Tags: []string{"carol"}, Addresses: []string{"10.0.0.0/8"}}})}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := importOf(t, configText(folder("lab", folder("AccessList", folder("1", c.items...)))), Options{})
			got := map[string]intent.Policy{}
			for _, name := range resourceNames(res.Document, intent.KindPolicy) {
				if name != "lab-default-allow" {
					got[name] = policyOf(t, res.Document, name)
				}
			}
			if len(got) != len(c.want) {
				t.Errorf("the Policies are %+v, want %+v", got, c.want)
			}
			for name, w := range c.want {
				if !reflect.DeepEqual(got[name], w) {
					t.Errorf("Policy %s is %+v, want %+v", name, got[name], w)
				}
			}
			if notes := notesOf(res); c.note != "" && !strings.Contains(notes, c.note) {
				t.Errorf("the notes are %q, want one that says %q", notes, c.note)
			}
		})
	}
}

// The names of the Virtual Hubs, groups and users are made names of resources, which are DNS labels: the lower case of
// the letters and digits, a hyphen for each run of other characters, a hash for a name that has none or is too long, and
// -2, -3 where two names make one. A user named * has no User.
func TestNamesOfTheFork(t *testing.T) {
	long := strings.Repeat("a", 70)
	groups := folder("GroupList", folder("Staff$20Team", "string RealName Staff"))
	users := folder("UserList",
		folder("John.Doe", "string GroupName staff$20team"),
		folder("john-doe"),
		folder("*"),
		folder("日本語"),
		folder(long))
	res := importOf(t, configText(folder("My$20Hub", folder("SecurityAccountDatabase", groups, users))), Options{})
	if got := resourceNames(res.Document, intent.KindGroup); !slices.Equal(got, []string{"staff-team"}) {
		t.Errorf("the Groups are %v, want staff-team", got)
	}
	want := []string{"john-doe", "john-doe-2", slug("日本語", "user"), slug(long, "user")}
	slices.Sort(want)
	if got := resourceNames(res.Document, intent.KindUser); !slices.Equal(got, want) {
		t.Errorf("the Users are %v, want %v", got, want)
	}
	if got := slug(long, "user"); len(got) != nameLimit || !strings.HasSuffix(got, "-"+shortHash(long)) {
		t.Errorf("the name of a user of 70 letters is %q, want %d characters that end in its hash", got, nameLimit)
	}
	if got := slug("日本語", "user"); got != "user-"+shortHash("日本語") {
		t.Errorf("the name of a user without a letter is %q", got)
	}
	if u := userOf(t, res.Document, "john-doe-2"); !slices.Equal(u.Groups, []string{"staff-team"}) {
		t.Errorf("John.Doe belongs to %v, want the Group of staff team, whatever the case", u.Groups)
	}
	notes := notesOf(res)
	for _, s := range []string{`user "John.Doe" is User "john-doe-2"`, `group "Staff Team" is Group "staff-team"`, `the user "*"`} {
		if !strings.Contains(notes, s) {
			t.Errorf("the notes are %q, want one that says %q", notes, s)
		}
	}
	if strings.Contains(notes, `user "john-doe" is`) {
		t.Errorf("the notes are %q: a name that is only in lower case is no rename", notes)
	}
}

// Two names that make one name get -2, -3 and so on, a name of another Virtual Hub with its group and its users too.
func TestTwoVirtualHubsDoNotShareNames(t *testing.T) {
	hub := func(name string) string {
		groups := folder("GroupList", folder("staff"))
		users := folder("UserList", folder("alice", "string GroupName staff"))
		return folder(name, folder("SecurityAccountDatabase", groups, users),
			folder("AccessList", folder("1", "bool Active true", "uint Priority 100", "string SrcUsername staff")))
	}
	res := importOf(t, configText(hub("A_B"), hub("A$20B"), hub("a-b")), Options{})
	if got := resourceNames(res.Document, intent.KindVRF); !slices.Equal(got, []string{"a-b", "a-b-2", "a-b-3"}) {
		t.Errorf("the VRFs are %v", got)
	}
	if got := resourceNames(res.Document, intent.KindGroup); !slices.Equal(got, []string{"staff", "staff-2", "staff-3"}) {
		t.Errorf("the Groups are %v", got)
	}
	if got := resourceNames(res.Document, intent.KindUser); !slices.Equal(got, []string{"alice", "alice-2", "alice-3"}) {
		t.Errorf("the Users are %v", got)
	}
	// The Virtual Hubs come in the order of their names, so the second is a-b: its rule names the Group of its own staff,
	// which its user belongs to
	if p := policyOf(t, res.Document, "a-b-2-acl-1"); !slices.Equal(p.From.Tags, []string{"staff-2"}) {
		t.Errorf("the rule of the second Virtual Hub is %+v, want the tag staff-2", p)
	}
	if u := userOf(t, res.Document, "alice-2"); !slices.Equal(u.Groups, []string{"staff-2"}) {
		t.Errorf("the user of the second Virtual Hub is %+v, want the Group staff-2", u)
	}
}

// A User has the Group of its group, its expiry in UTC, and the flags FixPassword and NoSavePassword of its own policy,
// else of the policy of its group, as the fork judges a session.
func TestUsersCarryTheirGroupsExpiryAndFlags(t *testing.T) {
	groups := folder("GroupList", folder("staff", "string RealName Staff$20Team", folder("Policy", "bool FixPassword true")))
	users := folder("UserList",
		folder("alice", "string GroupName staff", "uint64 ExpireTime 1893423600000", "string RealName Alice$20A."),
		folder("bob", "string GroupName staff", folder("Policy", "bool NoSavePassword true")),
		folder("carol", "string GroupName nogroup"),
		folder("dave", "uint64 ExpireTime 99999999999999999"))
	res := importOf(t, configText(folder("lab", folder("SecurityAccountDatabase", groups, users))), Options{})
	var g intent.Group
	specOf(t, res.Document, intent.KindGroup, "staff", &g)
	if g.DisplayName != "Staff Team" {
		t.Errorf("the Group staff is %+v, want the display name Staff Team", g)
	}
	alice := userOf(t, res.Document, "alice")
	if want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC); !alice.Expires.Equal(want) {
		t.Errorf("alice expires at %v, want %v: ExpireTime counts the milliseconds since 1970 less 9 hours", alice.Expires, want)
	}
	if !slices.Equal(alice.Groups, []string{"staff"}) || alice.DisplayName != "Alice A." || alice.MayChangePassword == nil || *alice.MayChangePassword || alice.NoSavedPassword {
		t.Errorf("alice is %+v, want the Group staff and the policy of her group, which fixes her password", alice)
	}
	bob := userOf(t, res.Document, "bob")
	if bob.MayChangePassword != nil || !bob.NoSavedPassword || !slices.Equal(bob.Groups, []string{"staff"}) {
		t.Errorf("bob is %+v, want his own policy, which does not fix his password, and no saved password", bob)
	}
	if carol := userOf(t, res.Document, "carol"); len(carol.Groups) != 0 {
		t.Errorf("carol is %+v, want no Group: her group is not one of the hub", carol)
	}
	if dave := userOf(t, res.Document, "dave"); !dave.Expires.IsZero() {
		t.Errorf("dave is %+v, want no expiry: a time past the year 9999 is none", dave)
	}
	if notes := notesOf(res); !strings.Contains(notes, `the user "carol" is in the group "nogroup", which the hub does not have`) {
		t.Errorf("the notes are %q", notes)
	}
}

// A name in an entry is the tag of a Group: the Group of the group of that name, which a user of that name joins, else a
// Group of the user alone. A user does not join the Group of its own name when no entry names it, and a name that the
// hub has no user or group of is a Group with no member.
func TestTheNamesOfEntriesAreTheTagsOfGroups(t *testing.T) {
	groups := folder("GroupList", folder("guests"), folder("ops"))
	users := folder("UserList", folder("alice"), folder("dave", "string GroupName ops"), folder("ops"), folder("erin", "string GroupName guests"), folder("guests"))
	acl := folder("AccessList",
		folder("1", "bool Active true", "uint Priority 100", "string SrcUsername ops"),
		folder("2", "bool Active true", "uint Priority 200", "uint Protocol 6", "uint DestPortStart 22", "uint DestPortEnd 22", "string SrcUsername alice"),
		folder("3", "bool Active true", "bool Discard true", "uint Priority 300", "uint Protocol 1", "string DestUsername carol"))
	res := importOf(t, configText(folder("lab", folder("SecurityAccountDatabase", groups, users), acl)), Options{})
	if got := resourceNames(res.Document, intent.KindGroup); !slices.Equal(got, []string{"alice", "carol", "guests", "ops"}) {
		t.Errorf("the Groups are %v, want the groups of the hub and the ones of alice and carol", got)
	}
	for name, want := range map[string][]string{"alice": {"alice"}, "dave": {"ops"}, "ops": {"ops"}, "erin": {"guests"}, "guests": nil} {
		if got := userOf(t, res.Document, name).Groups; !slices.Equal(got, want) {
			t.Errorf("the user %s belongs to %v, want %v", name, got, want)
		}
	}
	if p := policyOf(t, res.Document, "lab-acl-1"); !slices.Equal(p.From.Tags, []string{"ops"}) || len(p.From.Addresses) != 0 {
		t.Errorf("the first rule is %+v, want the tag ops and no address: a name alone matches the frames of both families", p)
	}
	if p := policyOf(t, res.Document, "lab-acl-3"); !slices.Equal(p.To.Tags, []string{"carol"}) {
		t.Errorf("the last rule is %+v, want the tag carol", p)
	}
	if notes := notesOf(res); !strings.Contains(notes, `an entry names "carol", which is no user or group of the hub`) {
		t.Errorf("the notes are %q", notes)
	}
}

// The options and the file are checked before anything is made.
func TestImportRefusesWhatItCannotTake(t *testing.T) {
	root, err := Parse(configText(folder("lab"), folder("office")))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		opts Options
		want string
	}{
		{"a Virtual Hub that the file has not", Options{Hubs: []string{"nope"}}, `no Virtual Hub "nope"`},
		{"a pool with host bits", Options{Pools: map[string]string{"lab": "10.0.0.5/24"}}, "host bits"},
		{"a pool that is no prefix", Options{Pools: map[string]string{"lab": "ten"}}, "pool"},
		{"a pool of IPv6", Options{Pools: map[string]string{"lab": "fd00::/64"}}, "is not an IPv4 prefix"},
		{"a pool of a Virtual Hub that is not taken", Options{Hubs: []string{"lab"}, Pools: map[string]string{"office": "10.1.0.0/24"}}, "does not take that Virtual Hub"},
		{"a mode that is none", Options{Mode: "l4"}, "the mode of a Network"},
	} {
		if _, err := Import(root, c.opts); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error that says %q", c.name, err, c.want)
		}
	}
	if _, err := Import(&Folder{Name: "root"}, Options{}); !errors.Is(err, ErrNotConfig) {
		t.Errorf("a tree without ServerConfiguration: %v, want ErrNotConfig", err)
	}
	if _, err := Import(nil, Options{}); !errors.Is(err, ErrNotConfig) {
		t.Errorf("no tree: %v, want ErrNotConfig", err)
	}
	empty, err := Parse(configText())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Import(empty, Options{}); err == nil || !strings.Contains(err.Error(), "no Virtual Hub") {
		t.Errorf("a file without a Virtual Hub: %v", err)
	}
}

// A VRF with more rules than a Node's desired state has room for is noted, and one with fewer is not.
func TestMoreRulesThanANodeHasRoomForIsNoted(t *testing.T) {
	hub := func(entries int) Result {
		var acl []string
		for i := 1; i <= entries; i++ {
			acl = append(acl, folder(strconv.Itoa(i), "bool Active true", "uint Priority "+strconv.Itoa(i)))
		}
		return importOf(t, configText(folder("lab", folder("AccessList", acl...))), Options{})
	}
	if res := hub(rulesRoom - 1); strings.Contains(notesOf(res), "64 objects") {
		t.Errorf("%d Policies are noted: %q", rulesRoom, notesOf(res))
	}
	res := hub(rulesRoom)
	if h := res.Hubs[0]; h.Policies != rulesRoom+1 || !strings.Contains(notesOf(res), strconv.Itoa(rulesRoom+1)+" Policies: the desired state of a Node holds 64 objects at most") {
		t.Errorf("%d Policies: the Virtual Hub is %+v, notes %q", rulesRoom+1, h, notesOf(res))
	}
}

// The Policies of a Network whose pool does not hold the prefixes that they match are noted.
func TestAPoolThatDoesNotHoldTheAddressesOfTheRulesIsNoted(t *testing.T) {
	acl := folder("AccessList",
		folder("1", "bool Active true", "bool Discard true", "uint Priority 100", "string DestIpAddress 10.0.0.9", "string DestSubnetMask 255.255.255.255"),
		folder("2", "bool Active true", "bool Discard true", "uint Priority 200", "string DestIpAddress 192.168.7.0", "string DestSubnetMask 255.255.255.0"),
		folder("3", "bool Active true", "bool Discard true", "uint Priority 300", "string SrcIpAddress 192.168.7.0", "string SrcSubnetMask 255.255.255.0"))
	res := importOf(t, configText(folder("lab", acl)), Options{Pools: map[string]string{"lab": "10.0.0.0/24"}})
	want := "the Policies match 192.168.7.0/24, which the pool 10.0.0.0/24 of Network lab does not hold"
	if notes := notesOf(res); !strings.Contains(notes, want) {
		t.Errorf("the notes are %q, want one that says %q", notes, want)
	}
}

// The sample Config file imports as the mapping says, and the document applies to an empty intent and to the intent of a
// first install.
func TestTheSampleConfigImports(t *testing.T) {
	b, err := os.ReadFile("../../../tests/golden/configimport/sample.config")
	if err != nil {
		t.Fatal(err)
	}
	res := importOf(t, b, Options{})
	doc := res.Document
	for _, c := range []struct {
		kind  string
		names []string
	}{
		{intent.KindVRF, []string{"lab", "office"}},
		{intent.KindNetwork, []string{"lab", "office"}},
		{intent.KindGroup, []string{"alice", "carol", "guests", "ops", "staff"}},
		{intent.KindUser, []string{"alice", "bob", "carol", "dave", "erin", "frank", "kim", "lee", "max", "ops", "srv"}},
		{intent.KindPolicy, []string{"lab-acl-1", "lab-acl-2", "lab-acl-3", "lab-acl-4", "lab-acl-6", "lab-acl-7", "lab-acl-8-1", "lab-acl-8-2", "lab-acl-9",
			"lab-acl-11", "lab-acl-12", "lab-acl-13", "lab-acl-14", "lab-acl-15", "lab-default-allow", "office-default-allow"}},
	} {
		slices.Sort(c.names)
		if got := resourceNames(doc, c.kind); !slices.Equal(got, c.names) {
			t.Errorf("the %ss are %v, want %v", c.kind, got, c.names)
		}
	}
	lab, office := res.Hubs[0], res.Hubs[1]
	if lab.Name != "LAB" || lab.Groups != 5 || lab.Users != 8 || lab.Entries != 16 || lab.Policies != 15 {
		t.Errorf("LAB is %+v, want 5 Groups, 8 Users, 16 entries and 15 Policies", lab)
	}
	if office.Name != "OFFICE" || office.Groups != 0 || office.Users != 3 || office.Entries != 0 || office.Policies != 1 {
		t.Errorf("OFFICE is %+v, want 3 Users and the 1 Policy that lets through what no entry matches", office)
	}

	every := intent.PolicyEnd{Addresses: []string{"0.0.0.0/0"}}
	checkPolicies(t, doc, []namedPolicy{
		{"lab-acl-1", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 10, From: intent.PolicyEnd{Tags: []string{"alice"}, Addresses: []string{"0.0.0.0/0"}},
			Protocol: "tcp", Ports: []intent.PolicyValue{"22"}}},
		{"lab-acl-2", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 20, To: intent.PolicyEnd{Addresses: []string{"10.0.0.10"}}, Protocol: "tcp",
			Ports: []intent.PolicyValue{"22"}}},
		{"lab-acl-3", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 30, From: intent.PolicyEnd{Tags: []string{"guests"}},
			To: intent.PolicyEnd{Addresses: []string{"10.0.0.0/24"}}}},
		{"lab-acl-4", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 40, From: intent.PolicyEnd{Tags: []string{"ops"}}}},
		{"lab-acl-6", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 60, To: intent.PolicyEnd{Addresses: []string{"2001:db8:1::/48"}}, Protocol: "58"}},
		{"lab-acl-7", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 70, To: intent.PolicyEnd{Addresses: []string{"172.16.0.0/16"}}}},
		{"lab-acl-8-1", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 80, From: every, Protocol: "tcp", Ports: []intent.PolicyValue{"8000-8080"}}},
		{"lab-acl-8-2", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 80, From: every, Protocol: "udp", Ports: []intent.PolicyValue{"8000-8080"}}},
		{"lab-acl-9", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 90, From: every, Protocol: "udp"}},
		{"lab-acl-11", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 110, From: every, Protocol: "tcp", Ports: []intent.PolicyValue{"80"}}},
		{"lab-acl-12", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: 120, From: every, Protocol: "udp", Ports: []intent.PolicyValue{"5060"}}},
		{"lab-acl-13", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 130, From: every, Protocol: "tcp"}},
		{"lab-acl-14", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 140, From: every, To: intent.PolicyEnd{Tags: []string{"carol"}}, Protocol: "icmp"}},
		{"lab-acl-15", intent.Policy{VRF: "lab", Action: intent.PolicyDeny, Priority: 150, To: intent.PolicyEnd{Addresses: []string{"10.0.5.0/24"}}}},
		{"lab-default-allow", intent.Policy{VRF: "lab", Action: intent.PolicyAllow, Priority: intent.MaxPriority}},
		{"office-default-allow", intent.Policy{VRF: "office", Action: intent.PolicyAllow, Priority: intent.MaxPriority}},
	})
	notes := notesOf(res)
	for _, s := range []string{
		"entry 5 left out: it lets through what it matches by source MAC addresses",
		"entry 7 carried without its match by masks that are no prefix",
		"entry 9 carried without its match by source ports",
		"entry 11 has a redirect URL",
		"entry 12: its delay, jitter and loss are left out",
		"entry 13 carried without its match by the TCP state",
		"entry 15 carried without its match by user list files",
		"entry 16 matches no frame in the fork: left out",
		"inactive entries left out: 1",
		"Network lab has no IPv4 pool",
		"Network office has no IPv4 pool",
	} {
		if !strings.Contains(notes, s) {
			t.Errorf("the notes are\n%s\nwant one that says %q", notes, s)
		}
	}

	again := importOf(t, b, Options{})
	if !reflect.DeepEqual(res, again) {
		t.Error("the import of one file twice made two documents")
	}
	first, err := intent.Apply(intent.New(), intent.FirstInstall(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := intent.Apply(first, doc, nil); err != nil {
		t.Errorf("the document does not apply to the intent of a first install: %v", err)
	}
	if !strings.Contains(res.Report(), `Virtual Hub "LAB": VRF lab and Network lab, 5 Groups, 8 Users, 15 Policies of 16 access list entries`) {
		t.Errorf("the report is\n%s", res.Report())
	}
}
