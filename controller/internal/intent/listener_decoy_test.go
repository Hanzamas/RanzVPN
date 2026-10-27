package intent

import (
	"errors"
	"strings"
	"testing"
)

// The decoy of a Listener (AUD1-DT-4 #452): left out it is empty, as before; a loopback address and port is
// kept in its one form and reads back from the resources.
func TestApplyListenerDecoy(t *testing.T) {
	ksp := `"certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}`
	in, err := Apply(listenerBase(t), doc(
		res(KindListener, "edge-a", `{"node": "a", `+ksp+`}`),
		res(KindListener, "edge-b", `{"node": "b", "decoy": "127.0.0.1:8080", `+ksp+`}`),
	), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := in.Listeners["edge-a"].Decoy; d != "" {
		t.Errorf("the decoy of edge-a, which names none, is %q", d)
	}
	if d := in.Listeners["edge-b"].Decoy; d != "127.0.0.1:8080" {
		t.Errorf("the decoy of edge-b is %q, want 127.0.0.1:8080", d)
	}

	// An address of the loopback range and an IPv6 address are accepted, written in their one form
	for spec, want := range map[string]string{
		"127.0.0.1:8080":      "127.0.0.1:8080",
		"127.9.8.7:80":        "127.9.8.7:80",
		"[::1]:8080":          "[::1]:8080",
		"[0:0:0:0:0:0:0:1]:9": "[::1]:9",
	} {
		next, err := Apply(listenerBase(t), doc(res(KindListener, "l", `{"node": "a", "decoy": "`+spec+`", `+ksp+`}`)), nil)
		if err != nil || next.Listeners["l"].Decoy != want {
			t.Errorf("the decoy %s: %v, %q, want %q", spec, err, next.Listeners["l"].Decoy, want)
		}
	}

	// It reads back from the resources, and applies again unchanged
	back, err := FromResources(in.Resources())
	if err != nil || back.Listeners["edge-b"].Decoy != "127.0.0.1:8080" {
		t.Errorf("the Listeners read back: %v, %+v", err, back.Listeners)
	}
}

// The Controller refuses a decoy that is not a loopback address and a port.
func TestApplyListenerDecoyRejects(t *testing.T) {
	ksp := `"certificate": {"ksp": "` + strings.Repeat("ab", 20) + `"}`
	for _, c := range []struct{ decoy, want string }{
		{"192.0.2.10:8080", `is not a loopback address`},
		{"0.0.0.0:8080", `is not a loopback address`},
		{"[::]:8080", `is not a loopback address`},
		{"[2001:db8::1]:8080", `is not a loopback address`},
		{"10.0.0.1:443", `is not a loopback address`},
		{"localhost:8080", `is not an IP address and a port`},
		{"decoy.example.com:8080", `is not an IP address and a port`},
		{"127.0.0.1", `is not an IP address and a port`},
		{"127.0.0.1:http", `is not an IP address and a port`},
		{"127.0.0.1:70000", `is not an IP address and a port`},
		{"127.0.0.1:0", `has port 0`},
		{"http://127.0.0.1:8080", `is not an IP address and a port`},
		{"[fe80::1%eth0]:8080", `is not a loopback address`},
	} {
		_, err := Apply(listenerBase(t), doc(res(KindListener, "l", `{"node": "a", "decoy": "`+c.decoy+`", `+ksp+`}`)), nil)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), `Listener "l": decoy: `) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("the decoy %q: the error is %v, want one with %q", c.decoy, err, c.want)
		}
	}
}
