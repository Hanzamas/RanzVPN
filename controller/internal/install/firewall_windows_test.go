//go:build windows

package install

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The rules of a group of the test in Windows Firewall, as openPorts and closePorts set the group of
// Ranz VPN: set, read back as they were set, set again without a change, narrowed to the rules of a
// Node, and removed. The rules have names of their own, so that the test touches no rule of an
// install. It needs administrator rights, which the Go job of the CI has.
func TestSetFirewallReadsBackKeepsAndRemoves(t *testing.T) {
	group := fmt.Sprintf("Ranz VPN test %d", time.Now().UnixNano())
	rules := firewallRules(`C:\Program Files\Ranz VPN test`, true)
	for i := range rules {
		rules[i].Name = group + ": " + rules[i].Name
	}
	t.Cleanup(func() { _, _ = setFirewall(group, nil) })

	c, err := setFirewall(group, rules)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("Windows Firewall takes rules from an Administrator only")
	}
	if err != nil {
		t.Fatalf("setFirewall: %v", err)
	}
	if !slices.Equal(names(c.added), names(rules)) || len(c.kept) != 0 || len(c.removed) != 0 {
		t.Fatalf("a first set added %q, kept %q and removed %q, want it to add every rule", names(c.added), names(c.kept), c.removed)
	}
	assertFirewall(t, group, rules)

	// Again: every rule is there as it should be, and stays
	c, err = setFirewall(group, rules)
	if err != nil || !slices.Equal(names(c.kept), names(rules)) || len(c.added) != 0 || len(c.removed) != 0 {
		t.Fatalf("a second set (error %v) kept %q, added %q and removed %q, want it to keep every rule", err, names(c.kept), names(c.added), c.removed)
	}
	assertFirewall(t, group, rules)

	// A rule that differs from the one that should be is replaced, and a rule of the group that no part
	// needs goes
	changed := rules[1]
	changed.Ports = "8443"
	stray := inbound(group+": stray", "a rule of an older version", rules[0].Program, protocolTCP, "9")
	if _, err := setFirewall(group, []firewallRule{rules[0], changed, rules[2], stray}); err != nil {
		t.Fatalf("setting a changed rule: %v", err)
	}
	c, err = setFirewall(group, rules[:2])
	// The removals come in the order in which Windows Firewall lists the rules
	removed := slices.Sorted(slices.Values(c.removed))
	if err != nil || !slices.Equal(removed, slices.Sorted(slices.Values([]string{changed.Name, rules[2].Name, stray.Name}))) || !slices.Equal(names(c.added), []string{changed.Name}) {
		t.Fatalf("the set of the Node's rules (error %v) removed %q and added %q", err, c.removed, names(c.added))
	}
	assertFirewall(t, group, rules[:2])

	// Uninstall: no rule of the group is left
	c, err = setFirewall(group, nil)
	if err != nil || len(c.removed) != 2 {
		t.Fatalf("removing the group (error %v) removed %q", err, c.removed)
	}
	assertFirewall(t, group, nil)
}

// The rule of the traffic test is made for the long path of the running program, even when it was
// started by a path with short names (the TEMP of a runner is C:\Users\RUNNER~1\...), read back in the
// group, and removed again.
func TestAllowTestPortReadsBackAndRemoves(t *testing.T) {
	port := 40000 + int(time.Now().UnixNano()%20000)
	r, undo, err := allowTestPort(port)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Skip("Windows Firewall takes rules from an Administrator only")
	}
	if err != nil {
		t.Fatalf("allowTestPort: %v", err)
	}
	removed := false
	t.Cleanup(func() {
		if !removed {
			undo()
		}
	})
	if strings.Contains(r.Program, "~") {
		t.Errorf("the rule is for %s, a path with short names", r.Program)
	}
	got, err := readFirewall(FirewallGroup)
	if err != nil {
		t.Fatalf("reading the group %s: %v", FirewallGroup, err)
	}
	if i := slices.IndexFunc(got, func(h firewallRule) bool { return h.Name == r.Name }); i < 0 || !got[i].same(r) {
		t.Fatalf("the group %s holds %+v, want the rule %+v", FirewallGroup, got, r)
	}
	undo()
	removed = true
	got, err = readFirewall(FirewallGroup)
	if err != nil {
		t.Fatalf("reading the group %s: %v", FirewallGroup, err)
	}
	if slices.ContainsFunc(got, func(h firewallRule) bool { return h.Name == r.Name }) {
		t.Errorf("the rule %q is still there after the test stopped", r.Name)
	}
}

// assertFirewall checks that the group holds the rules want, as Windows Firewall reads them back.
func assertFirewall(t *testing.T, group string, want []firewallRule) {
	t.Helper()
	got, err := readFirewall(group)
	if err != nil {
		t.Fatalf("reading the group %s: %v", group, err)
	}
	if len(got) != len(want) {
		t.Fatalf("the group %s holds %q, want %q", group, names(got), names(want))
	}
	for _, w := range want {
		i := slices.IndexFunc(got, func(r firewallRule) bool { return r.Name == w.Name })
		if i < 0 || !got[i].same(w) {
			t.Errorf("Windows Firewall holds %+v for the rule %q, want %+v", got, w.Name, w)
		}
	}
}
