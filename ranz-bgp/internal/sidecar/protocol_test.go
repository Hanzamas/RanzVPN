package sidecar

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// A message survives the round trip, empty lines are skipped, and the end of the pipe is io.EOF.
func TestReaderWriter(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	sent := Message{
		Type:     TypeStart,
		ASN:      65001,
		RouterID: "192.0.2.1",
		Peers: []Peer{
			{Address: "192.0.2.2", ASN: 65002, Passive: true},
			{Address: "192.0.2.3", ASN: 65001, HoldTime: 9, VRFs: []PeerVRF{{ID: 101, Accept: []string{"10.0.0.3/32"}}, {ID: 102}}},
		},
		Accept: []string{"198.51.100.0/24"},
	}
	if err := w.Write(sent); err != nil {
		t.Fatal(err)
	}
	b.WriteString("\n\r\n")
	if err := w.Write(Message{Type: TypeAnnounce, Prefix: "203.0.113.0/24"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(b.String(), "\n") || strings.Count(b.String(), "\n") != 4 {
		t.Fatalf("not one message per line: %q", b.String())
	}

	r := NewReader(&b)
	got, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != sent.Type || got.ASN != sent.ASN || got.RouterID != sent.RouterID || !reflect.DeepEqual(got.Peers, sent.Peers) || len(got.Accept) != 1 || got.Accept[0] != sent.Accept[0] {
		t.Errorf("start after the round trip: %+v, sent %+v", got, sent)
	}
	got, err = r.Read()
	if err != nil || got.Type != TypeAnnounce || got.Prefix != "203.0.113.0/24" {
		t.Errorf("second message: %+v, %v", got, err)
	}
	if _, err := r.Read(); !errors.Is(err, io.EOF) {
		t.Errorf("after the last message: %v, want io.EOF", err)
	}
}

// What the protocol refuses: no JSON, no type, a line longer than MaxLine.
func TestReaderRefuses(t *testing.T) {
	cases := []struct {
		name, input string
		want        error
	}{
		{"not JSON", "start\n", nil},
		{"no type", `{"asn":65001}` + "\n", nil},
		{"too long", `{"type":"announce","prefix":"` + strings.Repeat("1", MaxLine) + `"}` + "\n", ErrLineTooLong},
	}
	for _, c := range cases {
		_, err := NewReader(strings.NewReader(c.input)).Read()
		if err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: %v, want an error", c.name, err)
			continue
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if err := NewWriter(io.Discard).Write(Message{Type: TypeError, Error: strings.Repeat("x", MaxLine)}); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("writing a message longer than MaxLine: %v, want ErrLineTooLong", err)
	}
}

// The settings of start are checked before BGP starts.
func TestParseStart(t *testing.T) {
	good := func() Message {
		return Message{
			Type:     TypeStart,
			ASN:      65001,
			RouterID: "192.0.2.1",
			Peers:    []Peer{{Address: "192.0.2.2", ASN: 65002}},
			Accept:   []string{"198.51.100.0/24", "2001:db8::/32"},
		}
	}
	cfg, err := parseStart(good())
	if err != nil {
		t.Fatalf("a good start: %v", err)
	}
	if cfg.listenPort != 179 || len(cfg.peers) != 1 || cfg.peers[0].asn != 65002 || len(cfg.accept) != 2 {
		t.Errorf("a good start: %+v", cfg)
	}
	m := good()
	m.ListenPort = -1
	if cfg, err := parseStart(m); err != nil || cfg.listenPort != -1 {
		t.Errorf("listen_port -1: %+v, %v", cfg, err)
	}
	// A node of the peering of the standard mode that is alone in its VRFs starts with no peers
	alone := Message{Type: TypeStart, ASN: 65001, RouterID: "192.0.2.1", Address: "192.0.2.10"}
	if cfg, err := parseStart(alone); err != nil || len(cfg.peers) != 0 || cfg.address != netip.MustParseAddr("192.0.2.10") {
		t.Errorf("a start with an address and no peers: %+v, %v", cfg, err)
	}

	bad := []struct {
		name   string
		change func(m *Message)
	}{
		{"no asn", func(m *Message) { m.ASN = 0 }},
		{"no router id", func(m *Message) { m.RouterID = "" }},
		{"an IPv6 router id", func(m *Message) { m.RouterID = "2001:db8::1" }},
		{"listen port 70000", func(m *Message) { m.ListenPort = 70000 }},
		{"a listen address that is a name", func(m *Message) { m.ListenAddresses = []string{"localhost"} }},
		{"no peers", func(m *Message) { m.Peers = nil }},
		{"a peer without asn", func(m *Message) { m.Peers[0].ASN = 0 }},
		{"a peer twice", func(m *Message) { m.Peers = append(m.Peers, m.Peers[0]) }},
		{"a peer that is a name", func(m *Message) { m.Peers[0].Address = "router.example" }},
		{"host bits in accept", func(m *Message) { m.Accept = []string{"198.51.100.1/24"} }},
		{"an IPv4-mapped accept", func(m *Message) { m.Accept = []string{"::ffff:198.51.100.0/120"} }},
	}
	for _, c := range bad {
		m := good()
		c.change(&m)
		if _, err := parseStart(m); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
