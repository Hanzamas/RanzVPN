package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
)

// The clients guide (docs/clients.md) is the last criterion of SDN-82 (#377): it has every setup of the ticket,
// the RRAS note, the failover note and the quantum note. Real phones, apps and routers are not run in CI, so
// these tests keep the guide in step with what the product does: its examples are what the controller renders,
// the examples for the routers carry the values of the configuration, and its commands are commands of ranz.

// guideSection is one section of the guide, from a heading of the second level to the next.
type guideSection struct {
	// text is the section as it is written, code blocks included.
	text string
	// fences are its code blocks, each without the lines of its fence.
	fences []string
}

// guide is docs/clients.md by the headings of the second level, in the order that the file has them.
type guide struct {
	sections map[string]*guideSection
	order    []string
}

// readGuide reads docs/clients.md. A checkout on Windows may hold it with CRLF line endings (core.autocrlf), so
// the lines are cut at the line feed after the carriage returns are gone: a heading must not end in one.
func readGuide(t *testing.T) *guide {
	t.Helper()
	b, err := os.ReadFile("../../../docs/clients.md")
	if err != nil {
		t.Fatal(err)
	}
	g := &guide{sections: map[string]*guideSection{}}
	var cur *guideSection
	var fence []string
	inFence := false
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "```"):
			if inFence && cur != nil {
				cur.fences = append(cur.fences, strings.Join(fence, "\n"))
				fence = nil
			}
			inFence = !inFence
		case inFence:
			fence = append(fence, line)
		case strings.HasPrefix(line, "## "):
			name := strings.TrimPrefix(line, "## ")
			cur = &guideSection{}
			g.sections[name] = cur
			g.order = append(g.order, name)
		}
		if cur != nil {
			cur.text += line + "\n"
		}
	}
	return g
}

// section returns the section with the heading, and stops the test when the guide has none.
func (g *guide) section(t *testing.T, heading string) *guideSection {
	t.Helper()
	s, ok := g.sections[heading]
	if !ok {
		t.Fatalf("the guide has no section %q", heading)
	}
	return s
}

// TestClientsGuideHasEverySetup: the guide has a section for each client that the ticket names, with the steps
// of that client, and one for each of the notes.
func TestClientsGuideHasEverySetup(t *testing.T) {
	g := readGuide(t)
	for _, c := range []struct {
		heading string
		says    []string
	}{
		{"Windows", []string{"WireGuard for Windows", "Import tunnel(s) from file", "Activate"}},
		{"Android", []string{"Scan from QR code", "Import from file or archive"}},
		{"iOS", []string{"Create from QR code", "Create from file or archive"}},
		{"macOS", []string{"Mac App Store", "Import tunnel(s) from file"}},
		{"Linux (wg-quick)", []string{"wireguard-tools", "/etc/wireguard/ranz.conf", "wg-quick up ranz"}},
		{"MikroTik RouterOS 7", []string{"/interface wireguard add", "/interface wireguard peers add", "preshared-key="}},
		{"OpenWrt", []string{"proto 'wireguard'", "config wireguard_ranz", "option preshared_key"}},
		{"Windows Server RRAS (IKEv2)", []string{"IKEv2", "not a feature of Ranz"}},
		{"Failover of a gateway", []string{"repoint the DNS name", "wireguard.endpoint", "Endpoint"}},
		{"The PresharedKey and quantum computers", []string{"quantum computer", "Curve25519", "PresharedKey"}},
	} {
		s := g.section(t, c.heading)
		for _, want := range c.says {
			if !strings.Contains(s.text, want) {
				t.Errorf("the section %q does not say %q", c.heading, want)
			}
		}
		if words := len(strings.Fields(s.text)); words < 40 {
			t.Errorf("the section %q has %d words, which is no setup or note", c.heading, words)
		}
	}
}

// guideConfigs returns the two configurations that the guide shows, as the controller renders them for the
// Devices of its example Network: phone, for which the controller made the key pair and the PresharedKey,
// and router, whose public key was given. Their keys are placeholders: every byte of a key is the same.
func guideConfigs(t *testing.T) (phone, router string) {
	t.Helper()
	key := func(b byte) string {
		return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, intent.KeySize))
	}
	spec := func(format string, args ...any) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(format, args...))
	}
	in, err := intent.Apply(intent.New(), intent.Document{Resources: []intent.Resource{
		{Kind: intent.KindVRF, Name: "lab", Spec: spec(`{"id": 7, "ula": "fd07:7:7::/48"}`)},
		{Kind: intent.KindNetwork, Name: "lab-net", Spec: spec(`{"vrf": "lab", "ipv4Pool": "10.70.0.0/24", "ipv6Pool": "fd07:7:7:1::/64"}`)},
		{Kind: intent.KindNode, Name: "gw", Spec: spec(`{"publicKey": %q, "vrfs": ["lab"], "wireguard": {"endpoint": "gw.example.net"}}`, key(0x21))},
		{Kind: intent.KindNode, Name: "host", Spec: spec(`{"publicKey": %q, "vrfs": ["lab"]}`, key(0x22))},
		{Kind: intent.KindDevice, Name: "phone", Spec: spec(`{"network": "lab-net", "gateway": "gw", "publicKey": %q}`, key(0x31))},
		{Kind: intent.KindDevice, Name: "router", Spec: spec(`{"network": "lab-net", "gateway": "gw", "publicKey": %q}`, key(0x32))},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	gateway := bytes.Repeat([]byte{0x11}, intent.KeySize)
	phone, err = in.DeviceConfigWith("phone", gateway, intent.DeviceKeys{
		Private:   bytes.Repeat([]byte{0x01}, intent.KeySize),
		Preshared: bytes.Repeat([]byte{0x03}, intent.KeySize),
	})
	if err != nil {
		t.Fatal(err)
	}
	router, err = in.DeviceConfigWith("router", gateway, intent.DeviceKeys{Preshared: bytes.Repeat([]byte{0x04}, intent.KeySize)})
	if err != nil {
		t.Fatal(err)
	}
	return phone, router
}

// TestClientsGuideShowsWhatTheControllerRenders: the two configurations in the section The configuration are
// the ones that the controller renders, line for line, so a change of the rendering that the guide does not
// follow fails here.
func TestClientsGuideShowsWhatTheControllerRenders(t *testing.T) {
	g := readGuide(t)
	phone, router := guideConfigs(t)
	fences := g.section(t, "The configuration").fences
	for name, want := range map[string]string{"phone": phone, "router": router} {
		if !slices.Contains(fences, strings.TrimRight(want, "\n")) {
			t.Errorf("no code block of the section The configuration is the configuration of Device %s that the controller renders:\n%s", name, want)
		}
	}
}

// configValues returns the values of a configuration that a router has to be given: the addresses, the key
// of the gateway, the PresharedKey, the DNS name and the port of the gateway, and the allowed IPs.
func configValues(t *testing.T, config string) []string {
	t.Helper()
	var values []string
	for _, line := range strings.Split(config, "\n") {
		name, value, ok := strings.Cut(line, " = ")
		if !ok || strings.HasPrefix(name, "#") {
			continue
		}
		switch name {
		case "Address", "AllowedIPs":
			values = append(values, strings.Split(value, ", ")...)
		case "PublicKey", "PresharedKey":
			values = append(values, value)
		case "Endpoint":
			host, port, ok := strings.Cut(value, ":")
			if !ok {
				t.Fatalf("the endpoint %q has no port", value)
			}
			values = append(values, host, port)
		}
	}
	if len(values) < 8 {
		t.Fatalf("the configuration holds %d values to give a router, want 8 or more:\n%s", len(values), config)
	}
	return values
}

// TestClientsGuideRoutersCarryTheConfiguration: the steps for MikroTik RouterOS 7 and for OpenWrt carry every
// value of the configuration of the Device router, so that a router is set up with what the controller shows.
func TestClientsGuideRoutersCarryTheConfiguration(t *testing.T) {
	g := readGuide(t)
	_, router := guideConfigs(t)
	for _, heading := range []string{"MikroTik RouterOS 7", "OpenWrt"} {
		s := g.section(t, heading)
		for _, value := range configValues(t, router) {
			if !strings.Contains(s.text, value) {
				t.Errorf("the section %q has not the value %q of the configuration of Device router", heading, value)
			}
		}
	}
}

// TestClientsGuideCommandsAreCommandsOfRanz: every `ranz` command that a code block of the guide shows is taken
// by ranz as a command, with flags that it has. The controller that these commands reach refuses each of
// them with a 404, so only the parsing is proved: a command that ranz does not know is the usage.
func TestClientsGuideCommandsAreCommandsOfRanz(t *testing.T) {
	g := readGuide(t)
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	cli := &api.Client{URL: srv.URL, Token: "ranz_test", HTTP: srv.Client()}

	seen := map[string]bool{}
	for _, heading := range g.order {
		for _, fence := range g.sections[heading].fences {
			for _, line := range strings.Split(fence, "\n") {
				words := strings.Fields(line)
				if len(words) < 2 || words[0] != "ranz" {
					continue
				}
				if _, sub := subcommands[words[1]]; sub {
					continue
				}
				seen[strings.Join(words[1:min(len(words), 3)], " ")] = true
				if err := do(context.Background(), cli, words[1:], io.Discard); errors.Is(err, errUsage) {
					t.Errorf("the section %q shows `%s`, which ranz takes as a command that it does not have", heading, line)
				}
			}
		}
	}
	for _, want := range []string{"device create", "get devices", "get device-config", "delete Device"} {
		if !seen[want] {
			t.Errorf("no code block of the guide shows `ranz %s`", want)
		}
	}
}
