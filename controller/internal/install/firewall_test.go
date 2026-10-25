package install

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The rules of a Node alone are TCP 443 and UDP 443 for ranz-node.exe; with the Controller, TCP 443
// and 5555 for ranz.exe come too. Nothing else is opened (docs/ports.md).
func TestFirewallRulesAreThePortsOfTheInstalledParts(t *testing.T) {
	dir := filepath.Join("C:", "Program Files", "Ranz VPN")
	node := firewallRules(dir, false)
	both := firewallRules(dir, true)
	if len(node) != 2 || len(both) != 3 {
		t.Fatalf("%d rules for a Node and %d with the Controller, want 2 and 3", len(node), len(both))
	}
	want := []string{
		"TCP 443 for " + filepath.Join(dir, "ranz-node.exe"),
		"UDP 443 for " + filepath.Join(dir, "ranz-node.exe"),
		"TCP 443 and 5555 for " + filepath.Join(dir, "ranz.exe"),
	}
	for i, r := range both {
		if got := r.describe(); got != want[i] {
			t.Errorf("rule %d lets in %s, want %s", i, got, want[i])
		}
		if !r.Inbound || !r.Allow || !r.Enabled || !r.AllProfiles || r.Description == "" || !strings.HasPrefix(r.Name, "Ranz VPN ") {
			t.Errorf("rule %q is not an enabled inbound allow rule of every profile with a description", r.Name)
		}
		if i < len(node) && !r.same(node[i]) {
			t.Errorf("the rule %q of the Node differs with the Controller installed", r.Name)
		}
	}
	names := map[string]bool{}
	for _, r := range both {
		if names[r.Name] {
			t.Errorf("two rules are named %q", r.Name)
		}
		names[r.Name] = true
	}
}

// same ignores the case of the path and the spaces between the ports, and nothing else.
func TestFirewallRuleSame(t *testing.T) {
	r := inbound("Ranz VPN Node (TCP 443)", "d", `C:\Program Files\Ranz VPN\ranz-node.exe`, protocolTCP, "443,5555")
	other := r
	other.Program = `c:\program files\ranz vpn\RANZ-NODE.EXE`
	other.Ports = "443, 5555"
	if !other.same(r) {
		t.Error("a rule whose path differs in case only, or whose ports have spaces, is not the same")
	}
	for name, change := range map[string]func(*firewallRule){
		"name":        func(f *firewallRule) { f.Name += "x" },
		"description": func(f *firewallRule) { f.Description += "x" },
		"program":     func(f *firewallRule) { f.Program += "x" },
		"protocol":    func(f *firewallRule) { f.Protocol = protocolUDP },
		"ports":       func(f *firewallRule) { f.Ports = "443" },
		"direction":   func(f *firewallRule) { f.Inbound = false },
		"action":      func(f *firewallRule) { f.Allow = false },
		"enabled":     func(f *firewallRule) { f.Enabled = false },
		"profiles":    func(f *firewallRule) { f.AllProfiles = false },
	} {
		c := r
		change(&c)
		if c.same(r) {
			t.Errorf("a rule with another %s is the same", name)
		}
	}
}

func names(rules []firewallRule) []string {
	var out []string
	for _, r := range rules {
		out = append(out, r.Name)
	}
	return out
}

// firewallPlan keeps what is as it should be, adds what is missing and removes the rest of the group:
// a second install changes nothing, an install without the Controller service drops its rule, and a
// rule of an older version, a changed one or a doubled one goes.
func TestFirewallPlan(t *testing.T) {
	dir := `C:\Program Files\Ranz VPN`
	both := firewallRules(dir, true)
	node := firewallRules(dir, false)
	changed := both[0]
	changed.Ports = "8443"
	older := inbound("Ranz VPN Node (TCP 8443)", "an older rule", both[0].Program, protocolTCP, "8443")

	for _, c := range []struct {
		name       string
		have, want []firewallRule
		remove     []string
		add        []string
	}{
		{"a first install", nil, both, nil, names(both)},
		{"a second install", both, both, nil, nil},
		{"the Controller is not installed", both, node, []string{both[2].Name}, nil},
		{"the Controller comes", node, both, nil, []string{both[2].Name}},
		{"a changed rule", []firewallRule{changed, both[1]}, node, []string{changed.Name}, []string{changed.Name}},
		{"a rule twice", []firewallRule{both[0], both[0], both[1]}, node, []string{both[0].Name}, []string{both[0].Name}},
		{"a rule of an older version", append([]firewallRule{older}, node...), node, []string{older.Name}, nil},
		{"uninstall", append([]firewallRule{older}, both...), nil, append([]string{older.Name}, names(both)...), nil},
	} {
		remove, add := firewallPlan(c.have, c.want)
		if !slices.Equal(remove, c.remove) || !slices.Equal(names(add), c.add) {
			t.Errorf("%s: removes %q and adds %q, want %q and %q", c.name, remove, names(add), c.remove, c.add)
		}
	}
}

// The rule of the traffic test lets its own port in to the program of the test, in the group, and a
// test on another port has a rule of another name
func TestTestRule(t *testing.T) {
	r := testRule(`C:\ranz-test\ranz\ranz.exe`, 9821)
	if got, want := r.describe(), `TCP 9821 for C:\ranz-test\ranz\ranz.exe`; got != want || r.Name != "Ranz VPN traffic test (TCP 9821)" {
		t.Errorf("the rule %q lets in %s, want %s", r.Name, got, want)
	}
	if !r.Inbound || !r.Allow || !r.Enabled || !r.AllProfiles {
		t.Errorf("the rule %+v is not an enabled inbound allow rule of every profile", r)
	}
	if other := testRule(r.Program, 9822); other.Name == r.Name {
		t.Errorf("the tests on two ports share the rule %q", r.Name)
	}
}

func TestProtocolName(t *testing.T) {
	for protocol, want := range map[int32]string{protocolTCP: "TCP", protocolUDP: "UDP", 1: "protocol 1"} {
		if got := protocolName(protocol); got != want {
			t.Errorf("protocolName(%d) = %q, want %q", protocol, got, want)
		}
	}
}
