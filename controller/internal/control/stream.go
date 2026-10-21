// Package control is the Noise control stream between a node and the controller (#176
// "Control protocol"). TLS 1.3 carries it; a Noise_IK handshake on it authenticates both ends by
// their static keys and is bound to that TLS session through a TLS exporter, so the data is
// encrypted once, by TLS (ADR-0022, ADR-0023 single encryption). After the handshake every frame
// is a 4-byte big-endian length and one ControlMessage of proto/ranz/control/v1/control.proto.
//
// The node opens the stream (the Noise initiator, which knows the controller's static key in
// advance); the controller learns the node's static key from the handshake and looks the node up
// by it.
package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
)

const (
	// ALPN is the TLS application protocol of the control stream.
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

// suite is Noise_IK_25519_AESGCM_SHA256: X25519, AES-GCM and SHA-256 (ADR-0022).
var suite = noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

// GenerateKey returns a new static key pair.
func GenerateKey() (noise.DHKey, error) {
	return noise.DH25519.GenerateKeypair(rand.Reader)
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

// Dial opens a control stream to the controller at addr as the node with static key key. The
// handshake fails unless the controller holds the private key of controllerKey.
func Dial(ctx context.Context, addr string, key noise.DHKey, controllerKey []byte) (*Conn, error) {
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
	})
	c, err := handshake(ctx, tc, noise.Config{
		CipherSuite:   suite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		StaticKeypair: key,
		PeerStatic:    controllerKey,
	})
	if err != nil {
		tc.Close()
		return nil, err
	}
	return c, nil
}

// Listener accepts control streams.
type Listener struct {
	ln  net.Listener
	key noise.DHKey
	cfg *tls.Config
}

// Listen listens for control streams on the TCP address addr, as the controller with static key
// key.
func Listen(addr string, key noise.DHKey) (*Listener, error) {
	cert, err := selfSigned()
	if err != nil {
		return nil, fmt.Errorf("control: certificate: %w", err)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	return &Listener{ln: ln, key: key, cfg: &tls.Config{
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
		Certificates: []tls.Certificate{cert},
	}}, nil
}

// Addr returns the address the listener listens on.
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// Accept waits for the next connection. Pass it to Handshake, which may block for a while, on
// its own goroutine.
func (l *Listener) Accept() (net.Conn, error) {
	return l.ln.Accept()
}

// Close stops the listener.
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Handshake runs the TLS and Noise handshakes on a connection that Accept returned. The node's
// static key is PeerKey of the result.
func (l *Listener) Handshake(ctx context.Context, raw net.Conn) (*Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	tc := tls.Server(raw, l.cfg)
	c, err := handshake(ctx, tc, noise.Config{
		CipherSuite:   suite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		StaticKeypair: l.key,
	})
	if err != nil {
		tc.Close()
		return nil, err
	}
	return c, nil
}

// handshake runs the TLS handshake on tc, then the two Noise_IK messages with the TLS exporter
// in the prologue. The Noise cipher states are dropped: TLS encrypts the stream (ADR-0023).
func handshake(ctx context.Context, tc *tls.Conn, cfg noise.Config) (*Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		if err := tc.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("control: %w", err)
		}
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("control: TLS handshake: %w", err)
	}
	st := tc.ConnectionState()
	ekm, err := st.ExportKeyingMaterial(exporterLabel, nil, 32)
	if err != nil {
		return nil, fmt.Errorf("control: TLS exporter: %w", err)
	}
	cfg.Prologue = append([]byte(prologue), ekm...)
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, fmt.Errorf("control: %w", err)
	}
	if cfg.Initiator {
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

// selfSigned returns a new self-signed ECDSA P-256 certificate for the TLS side of the stream.
// Nobody checks it (see Dial), so a new one per process is enough.
func selfSigned() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ranz-controller"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
