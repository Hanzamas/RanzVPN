package doctor

import (
	"bytes"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The commands of reg.exe that ranz doctor prints to switch the hybrid on, for the machine's list and for the one of a
// policy (CORE-P2-5, #382).
const (
	regMachine = `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d `
	regPolicy  = `reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v EccCurves /t REG_MULTI_SZ /d `
)

// ranz doctor tells whether a host can negotiate X25519MLKEM768 and, where it cannot, why and what to run to switch it on
// (CORE-P2-5, #382): the list in force is the policy's where one is set, else the machine's, else the default of Windows,
// and the host asks for the hybrid when CNG has ML-KEM and that list names it first. The command keeps every classical
// group, X25519 second, as the TLS transport of a Node writes the list.
func TestQuantumTellsWhetherTheHostCanNegotiateTheHybrid(t *testing.T) {
	for _, c := range []struct {
		what string
		h    host
		asks bool
		from string
		why  string
		fix  string // a line of what to run, empty when the host can negotiate the hybrid
	}{
		{"the machine's list with the hybrid first", host{windows: true, mlkem: true, machine: []string{"x25519_mlkem768", "curve25519", "NistP256", "NistP384"}},
			true, fromMachine, "", ""},
		{"the name in another case, which Schannel ignores", host{windows: true, mlkem: true, machine: []string{"X25519_MLKEM768", "curve25519"}}, true, fromMachine, "", ""},
		{"a policy with the hybrid first, over a machine's list without it", host{windows: true, mlkem: true, policy: true, policyList: []string{"x25519_mlkem768", "NistP384"},
			machine: []string{"curve25519"}}, true, fromPolicy, "", ""},
		{"the default of Windows", host{windows: true, mlkem: true}, false, fromDefault, "the default of Windows does not name x25519_mlkem768 first",
			regMachine + `"x25519_mlkem768\0curve25519\0NistP256\0NistP384" /f`},
		{"the machine's list without the hybrid", host{windows: true, mlkem: true, machine: []string{"NistP384", "curve25519"}}, false, fromMachine,
			"the list of this machine does not name x25519_mlkem768 first", regMachine + `"x25519_mlkem768\0curve25519\0NistP384" /f`},
		{"the machine's list with the hybrid second", host{windows: true, mlkem: true, machine: []string{"curve25519", "x25519_mlkem768", "NistP256"}}, false, fromMachine,
			"names x25519_mlkem768, but not first", regMachine + `"x25519_mlkem768\0curve25519\0NistP256" /f`},
		{"a policy without the hybrid, which wins over the machine's list with it", host{windows: true, mlkem: true, policy: true,
			policyList: []string{"NistP384", "NistP256"}, machine: []string{"x25519_mlkem768", "curve25519"}}, false, fromPolicy,
			"does not name x25519_mlkem768, and a policy wins over the list that the Node sets", regPolicy + `"x25519_mlkem768\0curve25519\0NistP384\0NistP256" /f`},
		{"a policy whose value is no list", host{windows: true, mlkem: true, policy: true, machine: []string{"x25519_mlkem768"}}, false, fromPolicy,
			"a policy wins", regPolicy + `"x25519_mlkem768\0curve25519" /f`},
		{"no ML-KEM in CNG, whatever the list", host{windows: true, machine: []string{"x25519_mlkem768", "curve25519"}}, false, fromMachine,
			"CNG of this Windows has no ML-KEM", "Windows Update"},
	} {
		t.Run(c.what, func(t *testing.T) {
			s := decide(c.h)
			if s.asks != c.asks || s.from != c.from || !strings.Contains(s.why, c.why) {
				t.Errorf("the host asks %v, from %q, why %q; want %v, %q, %q", s.asks, s.from, s.why, c.asks, c.from, c.why)
			}
			if c.asks != (len(s.fix) == 0) {
				t.Errorf("a host that asks %v has the fix %q", c.asks, s.fix)
			}
			if c.fix != "" && !slices.ContainsFunc(s.fix, func(line string) bool { return strings.Contains(line, c.fix) }) {
				t.Errorf("the fix is %q, without %q", s.fix, c.fix)
			}
			// Schannel takes a change of the machine's list at once, so the Node service restarts for its next Hello; it takes
			// a change of an ECC Curve Order policy when Windows starts
			if !c.asks && c.h.mlkem {
				restart := "Restart-Service ranzvpnserver"
				if c.h.policy {
					restart = "Then restart Windows: Schannel takes a changed ECC Curve Order policy when Windows starts."
				}
				if !slices.ContainsFunc(s.fix, func(line string) bool { return strings.Contains(line, restart) }) {
					t.Errorf("the fix is %q, without %q", s.fix, restart)
				}
			}

			var out bytes.Buffer
			writeQuantum(&out, c.h)
			text := out.String()
			for _, want := range []string{"\n" + TitleQuantum + "\n", "TLS group list in force, " + c.from + ": " + listText(s.list) + "\n"} {
				if !strings.Contains(text, want) {
					t.Errorf("the report has no %q:\n%s", want, text)
				}
			}
			if c.asks != strings.Contains(text, "This host can negotiate X25519MLKEM768") || c.asks == strings.Contains(text, "This host cannot negotiate X25519MLKEM768") ||
				c.asks == strings.Contains(text, "Its sessions use a classical group, which is not quantum-resistant") {
				t.Errorf("the report of a host that asks %v:\n%s", c.asks, text)
			}
			if c.fix != "" && (!strings.Contains(text, "To switch it on:\n") || !strings.Contains(text, c.fix)) {
				t.Errorf("the report has no %q to switch it on:\n%s", c.fix, text)
			}
		})
	}
}

// The command keeps the classical groups of the list, X25519 second, and names the hybrid once.
func TestQuantumCommandKeepsTheClassicalGroups(t *testing.T) {
	got := withHybrid([]string{"NistP521", "curve25519", "x25519_mlkem768", "NistP256"})
	if want := []string{"x25519_mlkem768", "curve25519", "NistP521", "NistP256"}; !slices.Equal(got, want) {
		t.Errorf("the list with the hybrid is %q, want %q", got, want)
	}
	if got := regAdd(machineListKey, []string{"a", "b"}); got != regMachine+`"a\0b" /f` {
		t.Errorf("the command is %q", got)
	}
	if !hasGroup([]string{"NistP256", "X25519_MLKEM768"}, hybridGroup) || hasGroup([]string{"curve25519"}, hybridGroup) || hasGroup(nil, hybridGroup) {
		t.Error("hasGroup does not find the hybrid in any case, or finds it where it is not")
	}
}

// A host that does not run Windows has no Node, so the report says there is nothing to check; the report of this host is
// the one of what it holds.
func TestQuantumOfThisHost(t *testing.T) {
	var out bytes.Buffer
	writeQuantum(&out, host{})
	if text := out.String(); !strings.Contains(text, TitleQuantum) || !strings.Contains(text, "does not run Windows") || strings.Contains(text, "ML-KEM") {
		t.Errorf("the report of a host that does not run Windows is\n%s", text)
	}

	out.Reset()
	PostQuantum(&out)
	text := out.String()
	if runtime.GOOS != "windows" {
		if !strings.Contains(text, "does not run Windows") {
			t.Errorf("the report of this host, which does not run Windows, is\n%s", text)
		}
		return
	}
	h := thisHost()
	if !h.windows || !strings.Contains(text, "ML-KEM in CNG: ") || !strings.Contains(text, "TLS group list in force, "+decide(h).from+": ") {
		t.Errorf("the report of this Windows host (%+v) is\n%s", h, text)
	}
}
