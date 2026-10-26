package install

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// The Windows Firewall rules of ranz install (SDN-91, #396): the inbound ports of the parts that it
// installs, and nothing else (docs/ports.md). A Node takes the connections of other Nodes on TCP
// 443, its front door, and UDP 443, QUIC (ADR-0035). A Controller takes the web UI, the API and the
// control streams of the Nodes on TCP 443, and on TCP 5555 when 443 was taken at its first start
// (ADR-0020 decision 6). Each rule lets one protocol in to one program of the Ranz folder, on every
// profile, and every rule belongs to the group FirewallGroup. Install makes the rules of the group
// the ones of the parts that are installed: a rule that is there as it should be stays as it is,
// any other rule of the group goes, and a missing one is added, so a second install and an upgrade
// leave the same rules. Uninstall removes every rule of the group. firewall_windows.go talks to
// Windows Firewall.

// FirewallGroup is the group of the rules of Ranz VPN in Windows Firewall: the Grouping of each
// rule, which Get-NetFirewallRule -Group reads.
const FirewallGroup = "Ranz VPN"

// The IP protocols of a rule, as Windows Firewall numbers them (NET_FW_IP_PROTOCOL of netfw.h)
const (
	protocolTCP = 6
	protocolUDP = 17
)

// firewallRule is one rule of the group: as ranz install makes it, or as Windows Firewall holds it.
type firewallRule struct {
	// Name is the name of the rule, the DisplayName of Get-NetFirewallRule.
	Name string
	// Description says what the ports are for.
	Description string
	// Program is the executable that may take the connections.
	Program string
	// Protocol is protocolTCP or protocolUDP.
	Protocol int32
	// Ports are the local ports, as Windows Firewall writes them: "443" or "443,5555".
	Ports string
	// Inbound, Allow, Enabled and AllProfiles are what every rule of ranz install is: an enabled
	// inbound rule that allows, on the domain, private and public profiles alike.
	Inbound     bool
	Allow       bool
	Enabled     bool
	AllProfiles bool
}

// firewallRules returns the rules of the parts installed in the Ranz folder dir: the Node's
// always, and the Controller's when controller is true.
func firewallRules(dir string, controller bool) []firewallRule {
	node := filepath.Join(dir, payload.NodeExe.Name)
	rules := []firewallRule{
		inbound("Ranz VPN Node (TCP 443)", "The front door of the Ranz VPN Node: the connections of other Nodes (ranz install).", node, protocolTCP, "443"),
		inbound("Ranz VPN Node (UDP 443)", "QUIC of the Ranz VPN Node: the connections of other Nodes (ranz install).", node, protocolUDP, "443"),
	}
	if controller {
		rules = append(rules, inbound("Ranz VPN Controller (TCP 443, 5555)",
			"The Ranz VPN Controller: the web UI, the API and the control streams of the Nodes, on 5555 when 443 was taken (ranz install --controller).",
			filepath.Join(dir, ranzExeName), protocolTCP, "443,5555"))
	}
	return rules
}

// testRule is the rule of the traffic test, ranz test throughput -listen (SDN-53, #246), while it
// serves on the TCP port port: program, the running ranz.exe, may take connections there. It is a
// rule of the group too, so that ranz uninstall removes it when the test was killed before it could.
func testRule(program string, port int) firewallRule {
	return inbound("Ranz VPN traffic test (TCP "+strconv.Itoa(port)+")", "The server of ranz test throughput, while it runs.",
		program, protocolTCP, strconv.Itoa(port))
}

// inbound returns an enabled inbound rule that lets the protocol in on the ports to program, on
// every profile.
func inbound(name, description, program string, protocol int32, ports string) firewallRule {
	return firewallRule{Name: name, Description: description, Program: program, Protocol: protocol, Ports: ports,
		Inbound: true, Allow: true, Enabled: true, AllProfiles: true}
}

// same reports whether the rule r that Windows Firewall holds is the rule want: the case of the
// path of the program and the spaces between the ports do not count.
func (r firewallRule) same(want firewallRule) bool {
	return r.Name == want.Name && r.Description == want.Description && strings.EqualFold(r.Program, want.Program) &&
		r.Protocol == want.Protocol && strings.ReplaceAll(r.Ports, " ", "") == strings.ReplaceAll(want.Ports, " ", "") &&
		r.Inbound == want.Inbound && r.Allow == want.Allow && r.Enabled == want.Enabled && r.AllProfiles == want.AllProfiles
}

// firewallPlan compares the rules of the group that are there, have, with the rules that should be,
// want: the names of the rules to remove, in the order of have, and the rules to add, in the order
// of want. A rule that is there once and as it should be stays. A name that is there twice, or not
// as it should be, or that no rule of want has, goes, all the rules of that name.
func firewallPlan(have, want []firewallRule) (remove []string, add []firewallRule) {
	count := map[string]int{}
	for _, h := range have {
		count[h.Name]++
	}
	wanted := map[string]firewallRule{}
	for _, w := range want {
		wanted[w.Name] = w
	}
	kept := map[string]bool{}
	gone := map[string]bool{}
	for _, h := range have {
		if w, ok := wanted[h.Name]; ok && count[h.Name] == 1 && h.same(w) {
			kept[h.Name] = true
			continue
		}
		if !gone[h.Name] {
			gone[h.Name] = true
			remove = append(remove, h.Name)
		}
	}
	for _, w := range want {
		if !kept[w.Name] {
			add = append(add, w)
		}
	}
	return remove, add
}

// protocolName is the name of the protocol of a rule, for the messages.
func protocolName(protocol int32) string {
	switch protocol {
	case protocolTCP:
		return "TCP"
	case protocolUDP:
		return "UDP"
	}
	return "protocol " + strconv.Itoa(int(protocol))
}

// describe is a rule in the words of the messages: TCP 443 for ranz-node.exe.
func (r firewallRule) describe() string {
	return protocolName(r.Protocol) + " " + strings.ReplaceAll(r.Ports, ",", " and ") + " for " + r.Program
}
