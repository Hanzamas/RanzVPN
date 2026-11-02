package explain

import (
	"fmt"
	"strings"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

// The key exchange of a link (CORE-P2-5, #382). A link of kind noise is a Noise session over QUIC or TLS-443, which encrypt
// its records once: the Noise session only authenticates, bound to its outer session (ADR-0023). So a session that is
// recorded now is safe against a future quantum computer when the key exchange of its outer session is, which is the case
// for the hybrid X25519MLKEM768. A Node asks for it where its host has it (src/Core/TransportGroup.c) and reports that as
// the Capability pqTls. Each end offers the groups of its host: the client offers its list in its order, with the key
// shares of the first groups, and the server picks one of the groups that the client offers. So the session of two Nodes
// that both report pqTls negotiates X25519MLKEM768, and every other session falls back to a classical group without
// failing: the client offers X25519 first, as the list that a Node writes puts it, and the server picks one of the
// classical groups, not always X25519 (the Schannel server of Windows Server 2025 picked secp384r1 of the three that its
// client offered, X25519 first). Explain says at each link of kind noise which of the two it negotiates and whether it is
// quantum-resistant, from the Capabilities that the two Nodes reported last; a Node that reported none counts as one
// without pqTls. A link of kind vxlan or geneve encrypts nothing, so it has no key exchange.

// The key exchange of the outer session of a link of kind noise: the hybrid by its name in the TLS registry of IANA, or a
// classical group, one without ML-KEM, which the server of the session picks.
const (
	KeyExchangeHybrid    = "X25519MLKEM768"
	KeyExchangeClassical = "classical"
)

// WithCapabilities gives the model the Capabilities that the Nodes reported last, by Node name, which the key exchange of
// each link follows; a Node that caps does not hold reported none. It returns m.
func (m *Model) WithCapabilities(caps map[string]*controlpb.Capabilities) *Model {
	m.caps = caps
	return m
}

// keyExchange gives the link l of kind noise from the Node s to the Node peer the key exchange of its outer session: the
// hybrid when both report pqTls, else a classical group, with the Nodes that do not report it.
func (w *walk) keyExchange(s *node, peer string, l *Link) {
	if l.Kind != linkNoise {
		return
	}
	for _, n := range []string{s.name, peer} {
		if !w.m.caps[n].GetPqTls() {
			l.WithoutPQTLS = append(l.WithoutPQTLS, n)
		}
	}
	l.QuantumResistant = len(l.WithoutPQTLS) == 0
	l.KeyExchange = KeyExchangeClassical
	if l.QuantumResistant {
		l.KeyExchange = KeyExchangeHybrid
	}
}

// keyExchangeText says the key exchange of the link l of kind noise from the Node s to the Node peer after what it says of
// the encryption: "; its QUIC or TLS-443 session negotiates X25519MLKEM768, quantum-resistant, as dc-1 and dc-2 both report
// pqTls", or "...a classical group, not quantum-resistant, as dc-2 does not report pqTls".
func keyExchangeText(s, peer string, l *Link) string {
	if l.KeyExchange == "" {
		return ""
	}
	if l.QuantumResistant {
		return fmt.Sprintf("; its QUIC or TLS-443 session negotiates %s, quantum-resistant, as %s and %s both report pqTls", l.KeyExchange, s, peer)
	}
	verb := "does"
	if len(l.WithoutPQTLS) > 1 {
		verb = "do"
	}
	return fmt.Sprintf("; its QUIC or TLS-443 session negotiates a classical group, not quantum-resistant, as %s %s not report pqTls", strings.Join(l.WithoutPQTLS, " and "), verb)
}
