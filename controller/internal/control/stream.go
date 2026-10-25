// Package control is the Noise control stream between a node and the controller (#176
// "Control protocol"). TLS 1.3 carries it, with the ALPN protocol ALPN; a Noise_IK handshake on
// it authenticates both ends by their static keys and is bound to that TLS session through a TLS
// exporter, so the data is encrypted once, by TLS (ADR-0022, ADR-0023 single encryption). After
// the handshake every frame is a 4-byte big-endian length and one ControlMessage of
// proto/ranz/control/v1/control.proto.
//
// The node opens the stream (the Noise initiator, which knows the controller's static key in
// advance); the controller learns the node's static key from the handshake and looks the node up
// by it.
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/keys"
)

const (
	// ALPN is the TLS application protocol of the control stream: on the controller's port it
	// tells a control stream from the HTTP of the API and the web UI.
	ALPN = "ranz-control/1"
	// MaxFrame is the largest frame either end accepts.
	MaxFrame = 16 << 20

	// exporterLabel names the TLS exporter (RFC 8446 section 7.5) whose output goes into the
	// Noise prologue.
	exporterLabel = "EXPORTER-ranz-control-noise"
	prologue      = "ranz control stream 1"
	// maxHandshakeFrame bounds a Noise handshake message (the Noise maximum).
	maxHandshakeFrame = 65535
	// handshakeTimeout bounds the TLS and Noise handshakes together.
	handshakeTimeout = 10 * time.Second
)

// staticMarker stands in for the private half of the local static key in the Noise handshake
// state. The private half may stay in a key storage provider, so staticDH hands every
// Diffie-Hellman with this marker to the key; it is not 32 bytes long, so no ephemeral key is
// ever taken for it.
var staticMarker = []byte("the static key of keys.Static")

// staticDH is X25519 for flynn/noise, the DH of Noise_IK_25519_AESGCM_SHA256 (ADR-0022): the
// Diffie-Hellman with the local static key goes to that key, every other one (the ephemeral
// keys) is done here.
type staticDH struct {
	key keys.Static
}

func (d staticDH) GenerateKeypair(random io.Reader) (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(random)
}

func (d staticDH) DH(priv, pub []byte) ([]byte, error) {
	if bytes.Equal(priv, staticMarker) {
		return d.key.DH(pub)
	}
	return noise.DH25519.DH(priv, pub)
}

func (d staticDH) DHLen() int {
	return 32
}

func (d staticDH) DHName() string {
	return "25519"
}

// Conn is one control stream after the handshake.
type Conn struct {
	tc   *tls.Conn
	peer []byte
	rmu  sync.Mutex
	wmu  sync.Mutex
}

// PeerKey returns the static key of the other end.
func (c *Conn) PeerKey() []byte {
	return c.peer
}

// RemoteAddr returns the network address of the other end.
func (c *Conn) RemoteAddr() net.Addr {
	return c.tc.RemoteAddr()
}

// Read reads the next frame and returns its message and its bytes as they came.
func (c *Conn) Read() (*controlpb.ControlMessage, []byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	b, err := readFrame(c.tc, MaxFrame)
	if err != nil {
		return nil, nil, err
	}
	m := &controlpb.ControlMessage{}
	if err := proto.Unmarshal(b, m); err != nil {
		return nil, b, fmt.Errorf("control: malformed frame: %w", err)
	}
	return m, b, nil
}

// Write sends m as one frame and returns the bytes it sent.
func (c *Conn) Write(m *controlpb.ControlMessage) ([]byte, error) {
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFrame {
		return nil, fmt.Errorf("control: a frame of %d bytes is larger than %d", len(b), MaxFrame)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return b, writeFrame(c.tc, b)
}

// SetReadDeadline sets the deadline of the next Read.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.tc.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline of the next Write.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tc.SetWriteDeadline(t)
}

// Close closes the stream.
func (c *Conn) Close() error {
	return c.tc.Close()
}

// Dial opens a control stream to the controller at addr as the node with the static key key.
// The handshake fails unless the controller holds the private half of controllerKey.
func Dial(ctx context.Context, addr string, key keys.Static, controllerKey []byte) (*Conn, error) {
	return dial(ctx, addr, key, controllerKey, nil)
}

// dial is Dial, with verify, when it is not nil, as the VerifyConnection of the TLS session
// (DialPinned).
func dial(ctx context.Context, addr string, key keys.Static, controllerKey []byte, verify func(tls.ConnectionState) error) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	// The certificate is not checked: the Noise handshake authenticates the controller by its
	// static key, and the exporter binds that handshake to this TLS session, so a TLS session
	// that anyone else terminates fails the handshake (ADR-0023).
	tc := tls.Client(raw, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{ALPN},
		InsecureSkipVerify: true,
		VerifyConnection:   verify,
	})
	c, err := handshake(ctx, tc, key, true, controllerKey)
	if err != nil {
		tc.Close()
		return nil, err
	}
	return c, nil
}

// Accept runs the controller side of the handshake on tc, a TLS connection whose client asked
// for ALPN, as the controller with the static key key. The node's static key is PeerKey of the
// result. On an error tc is closed.
func Accept(ctx context.Context, tc *tls.Conn, key keys.Static) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	c, err := handshake(ctx, tc, key, false, nil)
	if err != nil {
		tc.Close()
		return nil, err
	}
	return c, nil
}

// handshake runs the TLS handshake on tc if it has not run yet, then the two Noise_IK messages
// with the TLS exporter in the prologue. The Noise cipher states are dropped: TLS encrypts the
// stream (ADR-0023).
func handshake(ctx context.Context, tc *tls.Conn, key keys.Static, initiator bool, peer []byte) (*Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := tc.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("control: %w", err)
		}
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("control: TLS handshake: %w", err)
	}
	st := tc.ConnectionState()
	if st.NegotiatedProtocol != ALPN {
		return nil, fmt.Errorf("control: the TLS session negotiated the protocol %q, not %q", st.NegotiatedProtocol, ALPN)
	}
	ekm, err := st.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("control: TLS exporter: %w", err)
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(staticDH{key: key}, noise.CipherAESGCM, noise.HashSHA256),
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		Prologue:      append([]byte(prologue), ekm...),
		StaticKeypair: noise.DHKey{Private: staticMarker, Public: key.Public()},
		PeerStatic:    peer,
	})
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if initiator {
		msg, _, _, err := hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
		if err := writeFrame(tc, msg); err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
		msg, err = readFrame(tc, maxHandshakeFrame)
		if err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
		if _, _, _, err := hs.ReadMessage(nil, msg); err != nil {
			return nil, fmt.Errorf("control: Noise handshake: the controller does not hold the expected static key, or the TLS session is not end to end: %w", err)
		}
	} else {
		msg, err := readFrame(tc, maxHandshakeFrame)
		if err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
		if _, _, _, err := hs.ReadMessage(nil, msg); err != nil {
			return nil, fmt.Errorf("control: Noise handshake: the node does not know this controller's static key, or the TLS session is not end to end: %w", err)
		}
		msg, _, _, err = hs.WriteMessage(nil, nil)
		if err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
		if err := writeFrame(tc, msg); err != nil {
			return nil, fmt.Errorf("control: Noise handshake: %w", err)
		}
	}
	if err := tc.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return &Conn{tc: tc, peer: hs.PeerStatic()}, nil
}

func writeFrame(w io.Writer, b []byte) error {
	frame := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	_, err := w.Write(append(frame, b...))
	return err
}

func readFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > uint32(limit) {
		return nil, fmt.Errorf("control: a frame of %d bytes is larger than %d", n, limit)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
