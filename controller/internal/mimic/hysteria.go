package mimic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"

	"github.com/apernet/hysteria/extras/v2/obfs"
)

// The Hysteria mode of the sidecar (ADR-0023 amendment of 2026-10-15; CORE-P2-4, #95): the transport
// for a link that loses many packets, on the library of Hysteria 2 (github.com/apernet/hysteria/core/v2,
// MIT), beside REALITY in the same sidecar. msquic carries the ordinary QUIC transport of the node, with
// BBR; this mode is for the links on which a congestion control that backs off on every loss gets little
// through. It is off unless the settings have its part: the hysteria part of the server settings
// (HysteriaServer), and of each link that dials it (HysteriaLink).
//
//   - The server part listens with QUIC on a UDP address of its own as an HTTP/3 web server (the
//     masquerade). A client that presents one of the secrets of the server gets its streams to the node
//     over the data pipe. Every other request, of a browser, a prober or a client with a wrong secret, is
//     answered by the own decoy site, with its landing page and its certificate, so a prober sees an
//     ordinary HTTP/3 web server, the same site that the REALITY listener splices a prober to.
//   - The client part keeps one QUIC connection to the server of each link, with the QUIC ClientHello
//     of Chrome, which carries every stream of the link.
//   - Brutal, the congestion control of Hysteria, sends at a fixed rate that the link names and does not
//     slow down when packets are lost. A link turns it on with its rates (Brutal); a link without them
//     uses BBR. It is unfair to the other traffic of a link, see Brutal.
//   - Salamander, the optional obfuscation of Hysteria, XORs each UDP packet with the BLAKE2b-256 of a
//     key of the settings and a random salt that leads the packet, so that the packets do not parse as
//     QUIC. Both ends need the same key.
//
// The inner stream is the Noise session of the node, as over REALITY: the data pipe and the line in
// front of each stream are the same (control.go), so the node needs nothing of its own for the mode.
// The library gives no TLS exporter of its QUIC connections, and the QUIC ClientHello of Chrome comes
// from uTLS, whose connection state has none either, so the channel binding of a stream of the mode is
// the SHA-256 of the certificate that the server presented on the connection of the stream (the
// tls-server-end-point binding of RFC 5929, with SHA-256), which both sidecars give their node: a
// connection that a third party terminates presents another certificate, so the Noise handshake of the
// two nodes fails.

// HysteriaServer is the Hysteria mode of the server role: a QUIC listener on UDP beside the REALITY
// listener, with the own decoy as its masquerade. The server role needs the own decoy for it.
type HysteriaServer struct {
	// Listen is the UDP address of the listener. It is required: UDP 443 of a node is the QUIC listener
	// of its Listener resource, msquic, so the mode listens on an address of its own. Port 0 takes a port
	// from the system, which ready reports.
	Listen string `json:"listen"`
	// Secrets are the secrets that a client may present, from 1 to 16, each 16 to 64 bytes as hex digits.
	Secrets []string `json:"secrets"`
	// Salamander is the key of the Salamander obfuscation, 16 to 64 bytes as hex digits: none without
	// one. The links to the server need the same key.
	Salamander string `json:"salamander,omitempty"`
	// MaxMbps is the most that a client may make the server send to it with Brutal, and send to the
	// server, in Mbit/s from 1 to 10000: no limit without it, and the rates of the links decide.
	MaxMbps int `json:"max_mbps,omitempty"`
}

// HysteriaLink is the Hysteria mode of a link: the link dials the Hysteria listener of its server at
// its address, a UDP address, and takes no setting of REALITY (public_key, short_id, fingerprint and
// padding). The address names the link, so a client that reaches one server in both modes gives the
// two links different addresses.
type HysteriaLink struct {
	// Secret is the secret of the client, one of the secrets of the server.
	Secret string `json:"secret"`
	// PinSHA256 is the SHA-256 of the certificate that the server presents, as 64 hex digits: the link
	// takes that certificate and no other. Without it the certificate must chain to the roots of the
	// system for the server name of the link.
	PinSHA256 string `json:"pin_sha256,omitempty"`
	// Salamander is the key of the Salamander obfuscation, as the server has it: none without one.
	Salamander string `json:"salamander,omitempty"`
	// Brutal turns on the Brutal congestion control at the rates of the link; the link uses BBR without it.
	Brutal *Brutal `json:"brutal,omitempty"`
}

// Brutal is the congestion control of Hysteria for a link: a fixed rate in each direction, set for the
// link, at which each end sends whatever it loses. It does not back off when packets are lost and adds
// to its rate what the link loses, so on a link that loses many packets it gets through what a
// congestion control that backs off on every loss does not. It is opt-in for each link because it is
// unfair to every other flow on the link, which backs off where Brutal does not: set the rates to what
// the link carries and never more, and leave it off on a link that is shared with other traffic.
type Brutal struct {
	// UpMbps is the rate at which the client sends, in Mbit/s from 1 to 10000.
	UpMbps int `json:"up_mbps"`
	// DownMbps is the rate at which the server sends to the client, in Mbit/s from 1 to 10000.
	DownMbps int `json:"down_mbps"`
}

// The limits of the settings of the mode.
const (
	minSecret     = 16
	maxSecret     = 64
	maxSecrets    = 16
	minSalamander = 16
	maxSalamander = 64
	maxRateMbps   = 10000
	bytesPerMbit  = 125000
)

// hysteriaServerConfig is the hysteria part of the server settings, checked.
type hysteriaServerConfig struct {
	listen     string
	secrets    []string // as the clients present them: their hex digits in lower case
	salamander []byte   // nil without the obfuscation
	maxRate    uint64   // bytes per second, 0 for no limit
}

// hysteriaLinkConfig is the hysteria part of a link, checked.
type hysteriaLinkConfig struct {
	secret     string // as the client presents it
	pin        []byte // nil to check the chain of the certificate against the roots of the system
	salamander []byte
	up, down   uint64 // the rates of Brutal in bytes per second, 0 for BBR
}

// parseHexBytes reads from least to most bytes from their hex digits.
func parseHexBytes(name, s string, least, most int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) < least || len(b) > most {
		return nil, fmt.Errorf("%s is not %d to %d bytes as pairs of hexadecimal digits", name, least, most)
	}
	return b, nil
}

// parseRate reads a rate in Mbit/s and gives it in bytes per second.
func parseRate(name string, mbps int) (uint64, error) {
	if mbps < 1 || mbps > maxRateMbps {
		return 0, fmt.Errorf("%s %d is not from 1 to %d", name, mbps, maxRateMbps)
	}
	return uint64(mbps) * bytesPerMbit, nil
}

// parseHysteriaServer checks the hysteria part of the server settings: nil without one. The masquerade
// is the own decoy, so the borrow decoy takes no hysteria part.
func parseHysteriaServer(h *HysteriaServer, decoyMode string) (*hysteriaServerConfig, error) {
	if h == nil {
		return nil, nil
	}
	if decoyMode != DecoyOwn {
		return nil, errors.New("start: hysteria answers a prober with the page and the certificate of the own decoy, which the borrow decoy has not")
	}
	cfg := &hysteriaServerConfig{listen: h.Listen}
	if cfg.listen == "" {
		return nil, errors.New("start: hysteria listen is missing: UDP 443 of a node is the QUIC listener of its Listener, so the mode needs an address of its own")
	}
	if _, _, err := splitAddress("start: hysteria listen", cfg.listen, true, true); err != nil {
		return nil, err
	}

	if len(h.Secrets) == 0 || len(h.Secrets) > maxSecrets {
		return nil, fmt.Errorf("start: hysteria secrets has %d entries, from 1 to %d are needed", len(h.Secrets), maxSecrets)
	}
	seen := map[string]bool{}
	for i, s := range h.Secrets {
		b, err := parseHexBytes(fmt.Sprintf("start: hysteria secret %d", i+1), s, minSecret, maxSecret)
		if err != nil {
			return nil, err
		}
		secret := hex.EncodeToString(b)
		if seen[secret] {
			return nil, fmt.Errorf("start: hysteria secret %d twice", i+1)
		}
		seen[secret] = true
		cfg.secrets = append(cfg.secrets, secret)
	}

	if h.Salamander != "" {
		var err error
		if cfg.salamander, err = parseHexBytes("start: hysteria salamander", h.Salamander, minSalamander, maxSalamander); err != nil {
			return nil, err
		}
	}
	if h.MaxMbps != 0 {
		var err error
		if cfg.maxRate, err = parseRate("start: hysteria max_mbps", h.MaxMbps); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// parseHysteriaLink checks the hysteria part of a link, which takes no setting of REALITY.
func parseHysteriaLink(l *Link) (*hysteriaLinkConfig, error) {
	h := l.Hysteria
	if l.PublicKey != "" || l.ShortID != "" || l.Fingerprint != "" || l.Padding.Profile != "" || len(l.Padding.Sizes) != 0 || l.Padding.MinGapMs != 0 || l.Padding.JitterMs != 0 {
		return nil, errors.New("a hysteria link takes no public_key, short_id, fingerprint or padding: those are of REALITY")
	}
	b, err := parseHexBytes("hysteria secret", h.Secret, minSecret, maxSecret)
	if err != nil {
		return nil, err
	}
	cfg := &hysteriaLinkConfig{secret: hex.EncodeToString(b)}
	if h.PinSHA256 != "" {
		if cfg.pin, err = parseHexBytes("hysteria pin_sha256", h.PinSHA256, sha256.Size, sha256.Size); err != nil {
			return nil, err
		}
	}
	if h.Salamander != "" {
		if cfg.salamander, err = parseHexBytes("hysteria salamander", h.Salamander, minSalamander, maxSalamander); err != nil {
			return nil, err
		}
	}
	if h.Brutal != nil {
		if cfg.up, err = parseRate("hysteria brutal up_mbps", h.Brutal.UpMbps); err != nil {
			return nil, err
		}
		if cfg.down, err = parseRate("hysteria brutal down_mbps", h.Brutal.DownMbps); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

// certBinding is the channel binding of a stream of the mode: the SHA-256 of the certificate that the
// server presented on its connection, as the text of the first line of the stream.
func certBinding(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// listenUDP opens the UDP socket of a listener or of a connection of the mode at address, with
// Salamander when key is set: what goes out is obfuscated, and what comes in and does not deobfuscate
// is dropped.
func listenUDP(address string, key []byte) (net.PacketConn, error) {
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return pc, nil
	}
	conn, err := obfs.WrapPacketConnSalamander(pc, key)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return conn, nil
}
