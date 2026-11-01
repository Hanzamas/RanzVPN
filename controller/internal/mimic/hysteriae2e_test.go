package mimic

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	hyclient "github.com/apernet/hysteria/core/v2/client"
	hyerrors "github.com/apernet/hysteria/core/v2/errors"
	hyserver "github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

// The Hysteria mode end to end, as the core uses it (hysteria.go): a test is the node at both ends of
// the two sidecars, with their QUIC connection on the loopback of the runner, and a prober that is an
// ordinary HTTP/3 client.

// testPage is the landing page of the own decoy of the tests of the mode.
const testPage = "<html><body>the decoy of the Hysteria tests</body></html>"

// hysteriaSettings is a server of the mode with the secret testSecret, whose own decoy has its
// certificate in files that the test made, so that its links can pin it. It returns the pin: the
// SHA-256 of the certificate as hex digits.
func hysteriaSettings(t *testing.T, private string) (*ServerSettings, string) {
	t.Helper()
	pair, err := selfSignedCert(testName)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writePair(t, dir, pair, "cert.pem", "key.pem")
	s := ownSettings(private)
	s.Decoy.SelfSigned = false
	s.Decoy.CertFile = filepath.Join(dir, "cert.pem")
	s.Decoy.KeyFile = filepath.Join(dir, "key.pem")
	s.Decoy.Page = testPage
	s.Hysteria = &HysteriaServer{Listen: "127.0.0.1:0", Secrets: []string{testSecret}}
	return s, certBinding(pair.Certificate[0])
}

// A link of the mode carries the inner stream of its node: the stream reaches the node of the server over
// the data pipe, both sidecars give their node the same binding, the SHA-256 of the certificate of the
// server, and the Noise session of the two nodes runs over the stream. The streams of a link share its
// connection: one client for the server, one stream for each dial.
func TestHysteriaCarriesTheNoiseSessionOfTheNodes(t *testing.T) {
	private, _ := keyPair(t)
	s, pin := hysteriaSettings(t, private)
	srv, data := runServer(t, s, Options{skipDetect: true})
	if !strings.HasPrefix(srv.ready.Hysteria, "127.0.0.1:") {
		t.Fatalf("ready tells the Hysteria listener %q", srv.ready.Hysteria)
	}
	cl, pipe := runClient(t, Options{}, hysteriaLinkTo(srv.ready.Hysteria, pin))

	conn, binding, err := dialLink(pipe, srv.ready.Hysteria)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	if binding != pin || st.binding != pin {
		t.Fatalf("the sidecars gave their nodes the bindings %q and %q, want the SHA-256 of the certificate %q", binding, st.binding, pin)
	}
	noiseOver(t, conn, st.conn, binding)
	exchange(t, conn, st.conn, 1<<20)
	exchange(t, st.conn, conn, 1<<20)

	conn2, binding2, err := dialLink(pipe, srv.ready.Hysteria)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	st2 := data.next(t)
	defer st2.conn.Close()
	if binding2 != pin || st2.binding != pin {
		t.Errorf("the second stream has the bindings %q and %q, want %q", binding2, st2.binding, pin)
	}
	exchange(t, conn2, st2.conn, 4096)
	exchange(t, st2.conn, conn2, 4096)

	if m := srv.event(TypeAccepted); !strings.HasPrefix(m.Peer, "127.0.0.1:") {
		t.Errorf("the accepted event names the peer %q", m.Peer)
	}
	if c := srv.counters(); c.Accepted != 1 || c.Streams != 2 || c.Probes != 0 {
		t.Errorf("the server counted %d clients, %d streams and %d probes, want 1, 2 and 0", c.Accepted, c.Streams, c.Probes)
	}
	if c := cl.counters(); c.Streams != 2 {
		t.Errorf("the client counted %d streams, want 2", c.Streams)
	}
}

// The mode is off by default: a server without the hysteria part has no Hysteria listener.
func TestAServerWithoutTheModeHasNoHysteriaListener(t *testing.T) {
	private, _ := keyPair(t)
	srv, _ := runServer(t, ownSettings(private), Options{skipDetect: true})
	if srv.ready.Hysteria != "" {
		t.Errorf("a server without the hysteria part tells the Hysteria listener %q", srv.ready.Hysteria)
	}
}

// brutalRate is the rate at which an end of a connection of the mode sends (the onBrutal option).
type brutalRate struct {
	role string
	bps  uint64
}

// Brutal runs at the rates that a link names and at no other: the client sends at the rate up of its
// link and the server at the rate down, each within the limit of the server, and a link without rates
// uses BBR at both ends, whatever limit the server has.
func TestBrutalRunsAtTheRatesOfTheLinkOnly(t *testing.T) {
	cases := []struct {
		name           string
		brutal         *Brutal
		maxMbps        int
		client, server uint64
	}{
		{"a link without Brutal uses BBR", nil, 0, 0, 0},
		{"a link with Brutal", &Brutal{UpMbps: 40, DownMbps: 30}, 0, 40 * bytesPerMbit, 30 * bytesPerMbit},
		{"a server with a limit", &Brutal{UpMbps: 40, DownMbps: 30}, 20, 20 * bytesPerMbit, 20 * bytesPerMbit},
		{"a server with a limit and a link without Brutal", nil, 20, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rates := make(chan brutalRate, 4)
			onBrutal := func(role string, bps uint64) { rates <- brutalRate{role, bps} }
			private, _ := keyPair(t)
			s, pin := hysteriaSettings(t, private)
			s.Hysteria.MaxMbps = c.maxMbps
			srv, data := runServer(t, s, Options{skipDetect: true, onBrutal: onBrutal})
			link := hysteriaLinkTo(srv.ready.Hysteria, pin)
			link.Hysteria.Brutal = c.brutal
			_, pipe := runClient(t, Options{onBrutal: onBrutal}, link)

			conn, _, err := dialLink(pipe, srv.ready.Hysteria)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			st := data.next(t)
			defer st.conn.Close()

			got := map[string]uint64{}
			for range 2 {
				select {
				case r := <-rates:
					got[r.role] = r.bps
				case <-time.After(testTimeout):
					t.Fatalf("the ends told the rates %v only", got)
				}
			}
			if got[RoleClient] != c.client || got[RoleServer] != c.server {
				t.Errorf("the client sends at %d and the server at %d bytes/s, want %d and %d (0 for BBR)", got[RoleClient], got[RoleServer], c.client, c.server)
			}
		})
	}
}

// h3Do sends a request of an ordinary HTTP/3 client and reads its answer.
func h3Do(t *testing.T, c *http.Client, method, url string, header http.Header) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// h3Client is an ordinary HTTP/3 client whose every request goes to addr, whatever host its URL names,
// with the server name of the decoy. It takes any certificate, as a prober takes the decoy's.
func h3Client(t *testing.T, addr string, handshake time.Duration) *http.Client {
	t.Helper()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: testName, InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: handshake},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
		},
	}
	t.Cleanup(func() { tr.Close() })
	return &http.Client{Transport: tr, Timeout: testTimeout}
}

// A prober that is an ordinary HTTP/3 client, which knows no secret, gets the own decoy from an HTTP/3
// web server: the landing page, a 404 for another path and the certificate of the decoy, over the ALPN
// h3. A client of the protocol with a wrong secret gets the decoy too, never the answer of the protocol.
// The server counts each request as a probe and tells the node of each.
func TestAnHTTP3ProberGetsTheDecoySite(t *testing.T) {
	private, _ := keyPair(t)
	s, pin := hysteriaSettings(t, private)
	srv, _ := runServer(t, s, Options{skipDetect: true})
	client := h3Client(t, srv.ready.Hysteria, 10*time.Second)

	resp, body := h3Do(t, client, http.MethodGet, "https://"+testName+"/", nil)
	if resp.StatusCode != http.StatusOK || body != testPage {
		t.Errorf("the landing page: %s %q", resp.Status, body)
	}
	if resp.ProtoMajor != 3 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h3" {
		t.Fatalf("the answer came over %s, want HTTP/3 with the ALPN h3", resp.Proto)
	}
	if len(resp.TLS.PeerCertificates) == 0 || certBinding(resp.TLS.PeerCertificates[0].Raw) != pin {
		t.Error("the prober did not see the certificate of the own decoy")
	}
	if resp, _ := h3Do(t, client, http.MethodGet, "https://"+testName+"/admin", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another path: %s, want 404", resp.Status)
	}
	auth := http.Header{"Hysteria-Auth": {"not a secret of the server"}, "Hysteria-Cc-Rx": {"0"}}
	if resp, _ := h3Do(t, client, http.MethodPost, "https://hysteria/auth", auth); resp.StatusCode == 233 {
		t.Error("a wrong secret got the answer of the protocol")
	}

	if c := srv.counters(); c.Probes != 3 || c.Accepted != 0 || c.Streams != 0 {
		t.Errorf("the server counted %d probes, %d clients and %d streams, want 3, 0 and 0", c.Probes, c.Accepted, c.Streams)
	}
	for range 3 {
		if m := srv.event(TypeProbe); !strings.HasPrefix(m.Peer, "127.0.0.1:") || m.Reason == "" {
			t.Errorf("a probe event with the peer %q and the reason %q", m.Peer, m.Reason)
		}
	}
}

// udpTap is a UDP relay in front of a server that keeps what its clients send, as a censor on the path
// sees it.
type udpTap struct {
	conn   *net.UDPConn
	server *net.UDPAddr
	mu     sync.Mutex
	sent   [][]byte
}

func startUDPTap(t *testing.T, server string) *udpTap {
	t.Helper()
	to, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := &udpTap{conn: conn, server: to}
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.run()
	}()
	t.Cleanup(func() {
		conn.Close()
		<-done
	})
	return u
}

func (u *udpTap) addr() string {
	return u.conn.LocalAddr().String()
}

func (u *udpTap) datagrams() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([][]byte(nil), u.sent...)
}

// run takes the datagrams of the clients and sends each to the server from a socket of that client, which
// carries the answers of the server back, until the tap closes.
func (u *udpTap) run() {
	ups := map[string]*net.UDPConn{}
	defer func() {
		for _, up := range ups {
			up.Close()
		}
	}()
	buf := make([]byte, 65536)
	for {
		n, from, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		u.mu.Lock()
		u.sent = append(u.sent, append([]byte(nil), buf[:n]...))
		u.mu.Unlock()
		up := ups[from.String()]
		if up == nil {
			if up, err = net.DialUDP("udp", nil, u.server); err != nil {
				continue
			}
			ups[from.String()] = up
			go func() {
				back := make([]byte, 65536)
				for {
					m, err := up.Read(back)
					if err != nil {
						return
					}
					u.conn.WriteToUDP(back[:m], from)
				}
			}()
		}
		up.Write(buf[:n])
	}
}

// quicLongHeader reports whether b starts as a QUIC packet with a long header of version 1 (RFC 9000)
// or 2 (RFC 9369): the header form and the fixed bit set, and the version.
func quicLongHeader(b []byte) bool {
	if len(b) < 5 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	return v == 1 || v == 0x6b3343cf
}

// quicInitial reports whether b parses as an Initial packet of a QUIC client (RFC 9000 section 17.2.2),
// as a censor parses it to read its server name: in a datagram of at least 1200 bytes, the long header
// with the type Initial of its version, two connection ids of at most 20 bytes, the token and the
// length of the packet, which the datagram holds.
func quicInitial(b []byte) bool {
	if len(b) < 1200 || !quicLongHeader(b) {
		return false
	}
	typ := (b[0] >> 4) & 3
	if v := binary.BigEndian.Uint32(b[1:5]); (v == 1 && typ != 0) || (v != 1 && typ != 1) {
		return false
	}
	p := b[5:]
	for range 2 {
		if len(p) < 1 || p[0] > 20 || len(p) < 1+int(p[0]) {
			return false
		}
		p = p[1+int(p[0]):]
	}
	token, n, err := quicvarint.Parse(p)
	if err != nil || token > uint64(len(p)-n) {
		return false
	}
	p = p[n+int(token):]
	length, n, err := quicvarint.Parse(p)
	return err == nil && length >= 20 && length <= uint64(len(p)-n)
}

// With Salamander on, no packet on the wire parses as QUIC: a censor that reads the Initial packets of
// QUIC for their server name finds none, a plain QUIC client gets no answer from the server, and a link
// with another key gets no stream, where the link with the key of the server gets its stream. Without
// Salamander the same check finds the Initial packets of the client, so the check knows QUIC when it
// sees it.
func TestSalamanderHidesTheQUICPackets(t *testing.T) {
	for _, salamander := range []bool{false, true} {
		t.Run(fmt.Sprintf("salamander %v", salamander), func(t *testing.T) {
			private, _ := keyPair(t)
			s, pin := hysteriaSettings(t, private)
			if salamander {
				s.Hysteria.Salamander = testSalamander
			}
			srv, data := runServer(t, s, Options{skipDetect: true})
			tap := startUDPTap(t, srv.ready.Hysteria)
			link := hysteriaLinkTo(tap.addr(), pin)
			if salamander {
				link.Hysteria.Salamander = testSalamander
			}
			_, pipe := runClient(t, Options{}, link)
			conn, _, err := dialLink(pipe, tap.addr())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			st := data.next(t)
			defer st.conn.Close()
			exchange(t, conn, st.conn, 64<<10)
			exchange(t, st.conn, conn, 64<<10)

			sent := tap.datagrams()
			initials, long := 0, 0
			for _, d := range sent {
				if quicInitial(d) {
					initials++
				}
				if quicLongHeader(d) {
					long++
				}
			}
			if !salamander {
				if initials == 0 {
					t.Fatalf("none of the %d datagrams of a client without Salamander parses as an Initial packet of QUIC: the check does not know QUIC", len(sent))
				}
				return
			}
			if initials != 0 || long != 0 {
				t.Errorf("with Salamander, %d of the %d datagrams of the client parse as Initial packets of QUIC and %d have a long header of QUIC", initials, len(sent), long)
			}

			// A plain QUIC client gets no answer: the server drops what does not deobfuscate
			before := len(tap.datagrams())
			if resp, err := h3Client(t, tap.addr(), 2*time.Second).Get("https://" + testName + "/"); err == nil {
				resp.Body.Close()
				t.Fatal("a plain QUIC client got an answer from a server with Salamander")
			}
			plain := 0
			for _, d := range tap.datagrams()[before:] {
				if quicInitial(d) {
					plain++
				}
			}
			if plain == 0 {
				t.Error("the plain QUIC client sent no Initial packet that the tap saw")
			}

			// A link with another key gets no stream
			wrong := hysteriaLinkTo(tap.addr(), pin)
			wrong.Hysteria.Salamander = strings.Repeat("3c", 16)
			_, wrongPipe := runClient(t, Options{}, wrong)
			if c, _, err := dialLink(wrongPipe, tap.addr()); err == nil {
				c.Close()
				t.Error("a link with another key of Salamander got a stream")
			}
		})
	}
}

// A link takes its server only with the pinned certificate and the secret: another certificate than the
// pin is refused before the secret goes out, a link without a pin takes only a certificate that chains
// to the roots of the system, and a wrong secret gets the decoy, which the server counts as a probe.
func TestAHysteriaLinkNeedsThePinAndTheSecret(t *testing.T) {
	private, _ := keyPair(t)
	s, pin := hysteriaSettings(t, private)
	srv, _ := runServer(t, s, Options{skipDetect: true})

	_, pipe := runClient(t, Options{}, hysteriaLinkTo(srv.ready.Hysteria, strings.Repeat("00", 32)))
	if _, _, err := dialLink(pipe, srv.ready.Hysteria); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a link with another pin: %v", err)
	}
	_, pipe = runClient(t, Options{}, hysteriaLinkTo(srv.ready.Hysteria, ""))
	if _, _, err := dialLink(pipe, srv.ready.Hysteria); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Errorf("a link without a pin to a self-signed certificate: %v", err)
	}
	if c := srv.counters(); c.Probes != 0 || c.Accepted != 0 {
		t.Errorf("a handshake that the client refused reached the server: %d probes, %d clients", c.Probes, c.Accepted)
	}

	wrong := hysteriaLinkTo(srv.ready.Hysteria, pin)
	wrong.Hysteria.Secret = strings.Repeat("a5", 32)
	_, pipe = runClient(t, Options{}, wrong)
	if _, _, err := dialLink(pipe, srv.ready.Hysteria); err == nil || !strings.Contains(err.Error(), "authentication error") {
		t.Errorf("a link with a wrong secret: %v", err)
	}
	if c := srv.counters(); c.Probes != 1 || c.Accepted != 0 {
		t.Errorf("a wrong secret: %d probes and %d clients, want 1 and 0", c.Probes, c.Accepted)
	}
}

// A Hysteria listener whose address is taken refuses the start, as the REALITY listener does.
func TestAHysteriaListenerThatIsTakenRefusesTheStart(t *testing.T) {
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	s := withHysteria(HysteriaServer{Listen: taken.LocalAddr().String(), Secrets: []string{testSecret}})
	m, err := startOver(t, Message{Type: TypeStart, Role: RoleServer, Pipe: "p", Server: s})
	if m.Type != TypeError || !strings.Contains(m.Error, "the Hysteria listener cannot listen on") || err == nil {
		t.Errorf("the sidecar answered %+v and Run returned %v, want a refusal of the listener", m, err)
	}
}

// fakeClient is a client of the library that a test drives: TCP gives the errors of errs in turn, and
// streams after them.
type fakeClient struct {
	mu     sync.Mutex
	errs   []error
	closed bool
}

func (f *fakeClient) TCP(string) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.errs) != 0 {
		err := f.errs[0]
		f.errs = f.errs[1:]
		return nil, err
	}
	a, b := net.Pipe()
	b.Close()
	return a, nil
}

func (f *fakeClient) UDP() (hyclient.HyUDPConn, error) {
	return nil, errNoUDP
}

func (f *fakeClient) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeClient) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// A link keeps its connection for its streams and makes it again once it ended: a stream that finds the
// connection gone takes a new one, and an error that is no end of the connection is the dial's.
func TestAHysteriaLinkMakesItsConnectionAgain(t *testing.T) {
	cfg := mustLink(t, hysteriaLinkTo("127.0.0.1:9", strings.Repeat("ab", 32)))
	var made []*fakeClient
	next := []error{hyerrors.ClosedError{}} // what the first connection does with its first stream
	l := &hyLink{cfg: cfg, log: slog.New(slog.DiscardHandler), newClient: func(*hyclient.Config) (hyclient.Client, *hyclient.HandshakeInfo, error) {
		f := &fakeClient{errs: next}
		next = nil
		made = append(made, f)
		return f, &hyclient.HandshakeInfo{}, nil
	}}

	stream, _, err := l.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if len(made) != 2 || !made[0].isClosed() || made[1].isClosed() {
		t.Fatalf("after a connection that ended, %d connections, want 2 with the first one closed", len(made))
	}

	if stream, _, err = l.dial(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	if len(made) != 2 {
		t.Errorf("a second stream made a connection of its own: %d connections", len(made))
	}

	made[1].errs = []error{hyerrors.DialError{Message: "refused"}}
	var dialErr hyerrors.DialError
	if _, _, err = l.dial(context.Background()); !errors.As(err, &dialErr) || len(made) != 2 {
		t.Errorf("a refused stream: %v, %d connections", err, len(made))
	}

	// A connection that ends, and the next one at once: the second end is the dial's
	made[1].errs = []error{hyerrors.ClosedError{}}
	next = []error{hyerrors.ClosedError{}}
	var closed hyerrors.ClosedError
	if _, _, err = l.dial(context.Background()); !errors.As(err, &closed) || len(made) != 3 {
		t.Errorf("two connections that ended: %v, %d connections", err, len(made))
	}

	l.close()
	if !made[2].isClosed() {
		t.Error("close left the connection of the link open")
	}
	l.close()
}

// A dial that ends while the connection is made closes the socket of the connection, and the link
// keeps no connection.
func TestAHysteriaLinkGivesUpWhenItsDialEnds(t *testing.T) {
	cfg := mustLink(t, hysteriaLinkTo("127.0.0.1:9", strings.Repeat("ab", 32)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var made *fakeClient
	l := &hyLink{cfg: cfg, log: slog.New(slog.DiscardHandler), newClient: func(c *hyclient.Config) (hyclient.Client, *hyclient.HandshakeInfo, error) {
		pc, err := c.ConnFactory.New(c.ServerAddr)
		if err != nil {
			return nil, nil, err
		}
		cancel()
		// The end of the dial closes the socket: the read ends
		pc.SetReadDeadline(time.Now().Add(testTimeout))
		if _, _, err := pc.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("the socket of the connection was read: %v, want it closed", err)
		}
		made = &fakeClient{}
		return made, &hyclient.HandshakeInfo{}, nil
	}}
	if _, _, err := l.dial(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("a dial whose context ended: %v", err)
	}
	if made == nil || !made.isClosed() || l.conn != nil {
		t.Error("the connection that the dial made is kept")
	}
}

// The hooks of the server part on their own: a client that authenticates gets the binding that the
// handshake at its address remembered, and a client whose handshake the memory does not hold gets the
// binding of the latest handshake, so strangers that fill the memory take no client its binding; the
// memory of the handshakes stays in its bound; a stream whose node is gone gets nothing of the node; UDP
// is refused.
func TestTheHooksOfTheHysteriaServer(t *testing.T) {
	var events []Message
	h := &hyServer{ctx: context.Background(), cfg: &hysteriaServerConfig{secrets: []string{testSecret}}, pipe: pipeName(t, "gone"),
		log: slog.New(slog.DiscardHandler), emit: func(m Message) { events = append(events, m) }, count: &counters{},
		handshakes: map[string]handshake{}, requests: map[string]string{}, pipes: map[*hyPipe]struct{}{}}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 4433}

	if ok, _ := h.Authenticate(addr, "not the secret", 0); ok {
		t.Error("a wrong secret authenticates")
	}
	if ok, id := h.Authenticate(addr, testSecret, 0); !ok || id != noBinding {
		t.Errorf("a client before the first handshake: %v with the id %q, want no binding", ok, id)
	}
	h.remember(addr.String(), "aa")
	if ok, id := h.Authenticate(addr, testSecret, 0); !ok || id != "aa" {
		t.Errorf("the client at the address of the handshake: %v with the id %q, want the binding aa", ok, id)
	}
	if len(h.handshakes) != 0 {
		t.Errorf("the memory keeps %d handshakes after their client authenticated", len(h.handshakes))
	}
	// The client authenticates again, or from another address than that of its handshake
	moved := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 4433}
	if ok, id := h.Authenticate(moved, testSecret, 0); !ok || id != "aa" {
		t.Errorf("a client whose handshake the memory does not hold: %v with the id %q, want the binding of the latest handshake aa", ok, id)
	}

	old := time.Now().Add(-2 * handshakeAge)
	for i := range maxHandshakes {
		h.handshakes[fmt.Sprint(i)] = handshake{binding: "old", at: old}
	}
	h.remember("new", "bb")
	if len(h.handshakes) != 1 || h.handshakes["new"].binding != "bb" {
		t.Errorf("a full memory of old handshakes keeps %d of them", len(h.handshakes))
	}
	for i := range maxHandshakes {
		h.handshakes[fmt.Sprint(i)] = handshake{binding: "young", at: time.Now()}
	}
	late := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 3), Port: 4433}
	h.remember(late.String(), "cc")
	if _, found := h.handshakes[late.String()]; found {
		t.Error("a handshake beyond the bound was remembered")
	}
	// Strangers that fill the memory with handshakes that never authenticate take no client its binding
	if ok, id := h.Authenticate(late, testSecret, 0); !ok || id != "cc" {
		t.Errorf("a client whose handshake found the memory full: %v with the id %q, want the binding of the latest handshake cc", ok, id)
	}

	h.TCPRequest(addr, "dd", "stream")
	if _, err := h.TCP("stream"); !errors.Is(err, errNodeAway) || len(h.requests) != 0 {
		t.Errorf("a stream whose node is gone: %v, %d requests kept", err, len(h.requests))
	}
	if len(events) != 1 || events[0].Type != TypeError || !strings.Contains(events[0].Error, "the data pipe of the node") {
		t.Errorf("the node was told %+v", events)
	}
	if _, err := h.UDP("192.0.2.2:53"); !errors.Is(err, errNoUDP) {
		t.Errorf("UDP: %v", err)
	}
	if err := h.CheckUDP("192.0.2.2:53"); !errors.Is(err, errNoUDP) {
		t.Errorf("CheckUDP: %v", err)
	}
	h.Disconnect(addr, "aa", nil)
	h.TCPError(addr, "aa", "stream", io.EOF)
	h.UDPRequest(addr, "aa", 1, "192.0.2.2:53")
	h.UDPError(addr, "aa", 1, io.EOF)
}

// The Hysteria part never turns on the sniff of Hysteria and carries no UDP of a client, whatever its
// settings: the configuration that it gives the server of the library has no RequestHook, the hook
// through which the sniff (extras/v2/sniff) reads what a client sends, and DisableUDP, and a client with
// the secret hears that the server carries no UDP and has its UDP refused. GO-2026-5288, an OOM of the
// sniff on a QUIC packet that a client sends over UDP, needs both (.github/quality/govulncheck-accepted.txt).
func TestTheHysteriaListenerNeverTurnsOnTheSniff(t *testing.T) {
	cases := []struct {
		name       string
		salamander string
		maxMbps    int
	}{
		{"the smallest part", "", 0},
		{"every setting", testSalamander, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			private, _ := keyPair(t)
			s, _ := hysteriaSettings(t, private)
			s.Hysteria.Secrets = append(s.Hysteria.Secrets, strings.Repeat("01", 16))
			s.Hysteria.Salamander = c.salamander
			s.Hysteria.MaxMbps = c.maxMbps
			configs := make(chan *hyserver.Config, 1)
			srv, _ := runServer(t, s, Options{skipDetect: true, onHysteria: func(config *hyserver.Config) { configs <- config }})
			select {
			case config := <-configs:
				if config.RequestHook != nil || !config.DisableUDP {
					t.Errorf("the library got the RequestHook %T and DisableUDP %v, want none and true", config.RequestHook, config.DisableUDP)
				}
			case <-time.After(testTimeout):
				t.Fatal("the Hysteria part gave the library no configuration")
			}

			addr, err := net.ResolveUDPAddr("udp", srv.ready.Hysteria)
			if err != nil {
				t.Fatal(err)
			}
			var key []byte
			if c.salamander != "" {
				if key, err = hex.DecodeString(c.salamander); err != nil {
					t.Fatal(err)
				}
			}
			client, info, err := hyclient.NewClient(&hyclient.Config{
				ConnFactory: connFactory(func(net.Addr) (net.PacketConn, error) { return listenUDP("127.0.0.1:0", key) }),
				ServerAddr:  addr,
				Auth:        testSecret,
				TLSConfig:   hyclient.TLSConfig{ServerName: testName, InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if info.UDPEnabled {
				t.Error("the server told a client with the secret that it carries UDP")
			}
			if _, err := client.UDP(); err == nil {
				t.Error("a client with the secret got UDP")
			}
		})
	}
}

// The documentation tells the port of the listener of the mode, that the mode is off by default, and that
// Brutal takes an explicit rate for each link and is unfair to the other traffic of the link (CORE-P2-4,
// #95).
func TestTheDocsTellTheModeAndThatBrutalIsUnfair(t *testing.T) {
	b, err := os.ReadFile("../../../docs/ports.md")
	if err != nil {
		t.Fatal(err)
	}
	// The page is written for a person: its white space is folded into one space, as the docs test of the mimic section does
	ports := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{"`hysteria` part of the `MimicServer` setting", "Off by default", "an explicit rate for each link", "unfair to the other traffic of the link"} {
		if !strings.Contains(ports, want) {
			t.Errorf("docs/ports.md does not say %q", want)
		}
	}
}
