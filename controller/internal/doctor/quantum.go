package doctor

import (
	"fmt"
	"io"
	"strings"
)

// The post-quantum key exchange of the host (CORE-P2-5, #382). The QUIC and TLS-443 paths of a Node are encrypted once, by
// QUIC or by TLS 1.3 on Schannel, and the Noise session over them only authenticates, so a session that is recorded now is
// as safe against a future quantum computer as the key exchange of its outer session. A Node asks for the hybrid
// X25519MLKEM768 where its host has it: CNG has ML-KEM, and the TLS group list in force on the host names x25519_mlkem768
// first. That list is the one of an ECC Curve Order policy where one is set, which wins, else the machine's own, which the
// TLS transport of the Node writes with the hybrid first where no policy decides it, else the default of Windows, which does
// not name the hybrid; msquic takes its TLS from Schannel, so the one list governs both paths (src/Core/TransportGroup.c
// reads it the same way). ranz doctor reports which list holds on the host and whether the host can negotiate the hybrid,
// and where it cannot, what to run to switch it on. A host that cannot falls back to X25519 with every peer, and its Node
// does not report the Capability pqTls; two Nodes that both report it negotiate the hybrid.

// TitleQuantum is the heading of the report of the post-quantum key exchange.
const TitleQuantum = "Post-quantum key exchange (X25519MLKEM768 on QUIC and TLS-443)"

// The registry keys of the two TLS group lists, under HKEY_LOCAL_MACHINE, and their value: the machine's, and the one of an
// ECC Curve Order policy, which wins over it.
const (
	machineListKey = `SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002`
	policyListKey  = `SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`
	listValue      = "EccCurves"
)

// The Schannel names of X25519MLKEM768 and of X25519.
const (
	hybridGroup = "x25519_mlkem768"
	x25519Group = "curve25519"
)

// defaultGroups is the list of Windows 11 24H2 and Windows Server 2025 where the machine has none of its own.
var defaultGroups = []string{"curve25519", "NistP256", "NistP384"}

// The lists in force.
const (
	fromDefault = "the default of Windows"
	fromMachine = "the list of this machine"
	fromPolicy  = "the list of an ECC Curve Order policy"
)

// host is what the report reads of the host.
type host struct {
	// windows says that the host runs Windows, the system of a Node; the other fields are read only there.
	windows bool
	// mlkem says that CNG has ML-KEM.
	mlkem bool
	// policy says that an ECC Curve Order policy sets the list, which wins wherever its value is, and policyList is that
	// list, empty for a value that is no list.
	policy     bool
	policyList []string
	// machine is the machine's own list, nil where it has none.
	machine []string
}

// quantumState is what the report says of a host.
type quantumState struct {
	list []string // the list in force
	from string   // where it comes from: fromDefault, fromMachine or fromPolicy
	asks bool     // the host asks for X25519MLKEM768 first: it can negotiate it
	why  string   // why it cannot, empty when it can
	fix  []string // what to run to switch it on, one line each, empty when it can
}

// decide says of the host h whether it asks for the hybrid and what to run where it does not.
func decide(h host) quantumState {
	s := quantumState{list: defaultGroups, from: fromDefault}
	key := machineListKey
	switch {
	case h.policy:
		s.list, s.from, key = h.policyList, fromPolicy, policyListKey
	case h.machine != nil:
		s.list, s.from = h.machine, fromMachine
	}
	first := len(s.list) > 0 && strings.EqualFold(s.list[0], hybridGroup)
	s.asks = h.mlkem && first
	switch {
	case s.asks:
		return s
	case !h.mlkem:
		s.why = "CNG of this Windows has no ML-KEM, so no TLS of this host can offer X25519MLKEM768"
		s.fix = []string{"Install the latest cumulative update of Windows 11 24H2, Windows Server 2025 or a later release (Settings, Windows Update), which brings ML-KEM to CNG, then run ranz doctor again."}
		return s
	case hasGroup(s.list, hybridGroup):
		s.why = fmt.Sprintf("%s names %s, but not first: Schannel sends the key share of the first group, and a server picks the first of its own list that the client offers", s.from, hybridGroup)
	case h.policy:
		s.why = fmt.Sprintf("%s does not name %s, and a policy wins over the list that the Node sets", s.from, hybridGroup)
	default:
		s.why = fmt.Sprintf("%s does not name %s first; the Node puts it first when its TLS transport starts as an administrator", s.from, hybridGroup)
	}
	s.fix = []string{"Run as an administrator:", "    " + regAdd(key, withHybrid(s.list))}
	if h.policy {
		s.fix = append(s.fix, "or put "+hybridGroup+" first in the ECC Curve Order setting of the Group Policy that sets it (Computer Configuration, Administrative Templates, Network, SSL Configuration Settings).")
	}
	s.fix = append(s.fix, "Then restart the Node service (Restart-Service ranzvpnserver), so that its transports and its next Hello take the list.")
	return s
}

// hasGroup reports whether the list names the group, whose case Schannel ignores.
func hasGroup(list []string, group string) bool {
	for _, g := range list {
		if strings.EqualFold(g, group) {
			return true
		}
	}
	return false
}

// withHybrid returns the list as the TLS transport of a Node writes it: X25519MLKEM768 first, X25519 second, then the other
// groups of list in their order, so that no classical group goes.
func withHybrid(list []string) []string {
	out := []string{hybridGroup, x25519Group}
	for _, g := range list {
		if !strings.EqualFold(g, hybridGroup) && !strings.EqualFold(g, x25519Group) {
			out = append(out, g)
		}
	}
	return out
}

// listText says the groups of a list in the report: their names separated by commas, or none for an empty list or a value
// that is no list.
func listText(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

// regAdd returns the command of reg.exe that writes the list as the value of the list of key, a REG_MULTI_SZ whose groups
// reg.exe takes separated by \0.
func regAdd(key string, list []string) string {
	return fmt.Sprintf(`reg add "HKLM\%s" /v %s /t REG_MULTI_SZ /d "%s" /f`, key, listValue, strings.Join(list, `\0`))
}

// writeQuantum writes the report of the host h to w: its heading, ML-KEM in CNG, the list in force, whether the host can
// negotiate X25519MLKEM768 and, where it cannot, why and what to run to switch it on.
func writeQuantum(w io.Writer, h host) {
	fmt.Fprintf(w, "\n%s\n", TitleQuantum)
	if !h.windows {
		fmt.Fprintln(w, "    This host does not run Windows: a Node runs on Windows only, so there is nothing to check here.")
		return
	}
	s := decide(h)
	yes := "no"
	if h.mlkem {
		yes = "yes"
	}
	fmt.Fprintf(w, "    ML-KEM in CNG: %s\n", yes)
	fmt.Fprintf(w, "    TLS group list in force, %s: %s\n", s.from, listText(s.list))
	if s.asks {
		fmt.Fprintln(w, "    This host can negotiate X25519MLKEM768: its Node asks for it first on QUIC and TLS-443, reports the Capability pqTls, and falls back to X25519 with a peer that does not ask for it.")
		return
	}
	fmt.Fprintf(w, "    This host cannot negotiate X25519MLKEM768: %s. Its sessions use X25519, and its Node does not report the Capability pqTls.\n", s.why)
	fmt.Fprintln(w, "    To switch it on:")
	for _, line := range s.fix {
		fmt.Fprintf(w, "    %s\n", line)
	}
}

// PostQuantum writes to w the report of the post-quantum key exchange of this host: whether it can negotiate the hybrid
// X25519MLKEM768 on the QUIC and TLS-443 paths of its Node, and where it cannot, what to run to switch it on. It changes
// nothing.
func PostQuantum(w io.Writer) {
	writeQuantum(w, thisHost())
}
