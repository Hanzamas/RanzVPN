package mimic

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/flynn/noise"
	utls "github.com/refraction-networking/utls"
)

// The sidecars end to end, as the core uses them: a test is the node at both ends. The client
// sidecar listens on a pipe and the node dials a link through it; the server sidecar dials the pipe
// of its node, once for each client that proved the key of the server. Between them is the TCP
// connection that a censor sees, whose first bytes a tap on the client records.

// runServer starts a server sidecar with the data pipe of its node.
func runServer(t *testing.T, s *ServerSettings, opts Options) (*sidecarNode, *dataServer) {
	t.Helper()
	data := listenData(t)
	return startSidecar(t, Message{Type: TypeStart, Role: RoleServer, Pipe: data.name, Server: s}, opts), data
}

// runClient starts a client sidecar with the links, and returns it with the name of its data pipe.
func runClient(t *testing.T, opts Options, links ...Link) (*sidecarNode, string) {
	t.Helper()
	pipe := pipeName(t, "client")
	n := startSidecar(t, Message{Type: TypeStart, Role: RoleClient, Pipe: pipe, Client: &ClientSettings{Links: links}}, opts)
	return n, pipe
}

// linkTo is the link to the server at address that holds the private key of public.
func linkTo(address, public string) Link {
	return Link{Address: address, ServerName: testName, PublicKey: public, ShortID: testShortID}
}

func writeNoise(t *testing.T, c net.Conn, msg []byte) {
	t.Helper()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(msg)))
	if _, err := c.Write(append(frame, msg...)); err != nil {
		t.Fatal(err)
	}
}

func readNoise(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		t.Fatal(err)
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

// noiseOver runs a Noise_IK handshake between the node at the end of one stream (the initiator) and the
// node at the end of the other (the responder), with the channel binding of the stream in the
// prologue as the core puts it, and then sends a message each way under the keys: the stream that
// the sidecars carry is the Noise session of the nodes, which they never look into.
func noiseOver(t *testing.T, initiator, responder net.Conn, binding string) {
	t.Helper()
	initiator.SetDeadline(time.Now().Add(testTimeout))
	responder.SetDeadline(time.Now().Add(testTimeout))
	defer initiator.SetDeadline(time.Time{})
	defer responder.SetDeadline(time.Time{})

	suite := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)
	iKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rKey, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prologue := append([]byte("ranz mimic test "), binding...)
	hi, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Random: rand.Reader, Pattern: noise.HandshakeIK, Initiator: true,
		Prologue: prologue, StaticKeypair: iKey, PeerStatic: rKey.Public,
	})
	if err != nil {
		t.Fatal(err)
	}
	hr, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: suite, Random: rand.Reader, Pattern: noise.HandshakeIK,
		Prologue: prologue, StaticKeypair: rKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	msg, _, _, err := hi.WriteMessage(nil, []byte("hello from the initiator"))
	if err != nil {
		t.Fatal(err)
	}
	writeNoise(t, initiator, msg)
	payload, _, _, err := hr.ReadMessage(nil, readNoise(t, responder))
	if err != nil || string(payload) != "hello from the initiator" {
		t.Fatalf("the responder read %q from the first message: %v", payload, err)
	}
	if !bytes.Equal(hr.PeerStatic(), iKey.Public) {
		t.Error("the responder does not know the static key of the initiator")
	}
	msg, rc1, rc2, err := hr.WriteMessage(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeNoise(t, responder, msg)
	_, ic1, ic2, err := hi.ReadMessage(nil, readNoise(t, initiator))
	if err != nil {
		t.Fatalf("the initiator cannot read the second message: %v", err)
	}

	// c1 carries what the initiator sends and c2 what the responder sends
	ct, err := ic1.Encrypt(nil, nil, []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	writeNoise(t, initiator, ct)
	pt, err := rc1.Decrypt(nil, nil, readNoise(t, responder))
	if err != nil || string(pt) != "ping" {
		t.Fatalf("the responder read %q: %v", pt, err)
	}
	ct, err = rc2.Encrypt(nil, nil, []byte("pong"))
	if err != nil {
		t.Fatal(err)
	}
	writeNoise(t, responder, ct)
	pt, err = ic2.Decrypt(nil, nil, readNoise(t, initiator))
	if err != nil || string(pt) != "pong" {
		t.Fatalf("the initiator read %q: %v", pt, err)
	}
}

// get sends a request for path to the site behind conn and reads the answer.
func get(t *testing.T, conn net.Conn, host, path string) (*http.Response, string) {
	t.Helper()
	conn.SetDeadline(time.Now().Add(testTimeout))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to the request for %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("the body of the answer to %s: %v", path, err)
	}
	return resp, string(body)
}

// proberDial is a TLS connection of a prober to addr that asks for the site name.
func proberDial(addr, name string, roots *x509.CertPool) (*tls.Conn, error) {
	cfg := &tls.Config{ServerName: name, RootCAs: roots, InsecureSkipVerify: roots == nil}
	return tls.DialWithDialer(&net.Dialer{Timeout: testTimeout}, "tcp", addr, cfg)
}

// The inner stream reaches the node: a client that proves the key of the server gets a stream to the
// node over the data pipe, with the ClientHello of a browser on the wire, and the Noise session of
// the two nodes runs over it, bound to the TLS session by the exporter that both sidecars hand their node.
func TestNoiseStreamThroughTheBorrowDecoy(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})
	taps := make(chan *tap, 4)
	cl, pipe := runClient(t, Options{dialOuter: tapDialer(taps)}, linkTo(srv.ready.Listen, public))

	conn, binding, err := dialLink(pipe, srv.ready.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()

	if _, err := hex.DecodeString(binding); err != nil || len(binding) != 2*BindingSize {
		t.Fatalf("the binding %q is not %d bytes as hex digits", binding, BindingSize)
	}
	if binding != st.binding {
		t.Fatalf("the sidecars gave their nodes the bindings %q and %q: the nodes would not agree", binding, st.binding)
	}

	noiseOver(t, conn, st.conn, binding)
	exchange(t, conn, st.conn, 1<<20)
	exchange(t, st.conn, conn, 1<<20)

	// What the network saw first is the ClientHello of the browser that the link names, Edge by default
	tp := <-taps
	first := tp.all()[0].data
	if len(first) < 6 || first[0] != 0x16 {
		t.Fatalf("the first bytes that the network saw are not a handshake record: %x", first[:min(len(first), 8)])
	}
	h, err := parseClientHello(first[5:])
	if err != nil {
		t.Fatal(err)
	}
	spec, err := utls.UTLSIdToSpec(chromiumParrot)
	if err != nil {
		t.Fatal(err)
	}
	checkHelloAgainstSpec(t, h, spec)
	if got := h.serverName(); got != testName {
		t.Errorf("the SNI on the wire is %q, want %q", got, testName)
	}

	if m := srv.event(TypeAccepted); m.Peer == "" {
		t.Errorf("accepted without a peer: %+v", m)
	}
	if s := srv.counters(); s.Accepted != 1 || s.Streams != 1 || s.Probes != 0 {
		t.Errorf("the server counted %+v, want one stream and no probe", s)
	}
	if s := cl.counters(); s.Streams != 1 {
		t.Errorf("the client counted %+v, want one stream", s)
	}
}

// Every stream has a TLS session of its own: the bindings differ, and what goes into one stream comes
// out of its other end only.
func TestStreamsAreIndependent(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})
	_, pipe := runClient(t, Options{}, linkTo(srv.ready.Listen, public))

	const streams = 4
	byBinding := map[string]net.Conn{}
	for range streams {
		conn, binding, err := dialLink(pipe, srv.ready.Listen)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if byBinding[binding] != nil {
			t.Errorf("two streams have the binding %s", binding)
		}
		byBinding[binding] = conn
	}
	for range streams {
		st := data.next(t)
		defer st.conn.Close()
		conn := byBinding[st.binding]
		if conn == nil {
			t.Fatalf("a stream of the server has the binding %s, which no client stream has", st.binding)
		}
		delete(byBinding, st.binding)
		exchange(t, conn, st.conn, 64<<10)
		exchange(t, st.conn, conn, 64<<10)
	}
	if s := srv.counters(); s.Accepted != streams || s.Streams != streams {
		t.Errorf("the server counted %+v, want %d streams", s, streams)
	}
}

// A prober that fails the handshake is spliced to the real site: it sees the real certificate of the
// site and its pages, and the sidecar, which holds no key of the site, could not have made them.
func TestProbersAreSplicedToTheRealSite(t *testing.T) {
	site := startSite(t, testName, "the body of the real site")
	private, _ := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})
	addr := srv.ready.Listen

	siteCert, err := x509.ParseCertificate(site.der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(siteCert)

	// A browser, or a prober that asks for the site by its name, completes a TLS handshake that only the
	// site can sign: the certificate checks out against the certificate of the site, and the page is the site's
	conn, err := proberDial(addr, testName, roots)
	if err != nil {
		t.Fatalf("the prober cannot verify the certificate of the real site through the sidecar: %v", err)
	}
	if got := conn.ConnectionState().PeerCertificates[0].Raw; !bytes.Equal(got, site.der) {
		t.Error("the certificate that the prober sees is not the one of the real site")
	}
	resp, body := get(t, conn, testName, "/")
	if resp.StatusCode != http.StatusOK || body != site.body {
		t.Errorf("the page is %d %q, want the page of the real site %q", resp.StatusCode, body, site.body)
	}
	conn.Close()
	probe := srv.event(TypeProbe)
	if probe.Peer == "" || probe.Reason == "" {
		t.Errorf("the probe event is %+v", probe)
	}

	// A prober that asks for another name sees the same site and the same certificate
	conn, err = proberDial(addr, "other.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().PeerCertificates[0].Raw; !bytes.Equal(got, site.der) {
		t.Error("the certificate that a prober with another name sees is not the one of the real site")
	}
	conn.Close()
	if probe = srv.event(TypeProbe); !strings.Contains(probe.Reason, "server name mismatch") {
		t.Errorf("the probe event is %+v, want a server name mismatch", probe)
	}

	// A prober that speaks no TLS gets what the site answers to that: its own refusal
	raw, err := net.DialTimeout("tcp", addr, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(testTimeout))
	io.WriteString(raw, "GET / HTTP/1.0\r\n\r\n")
	reply, _ := io.ReadAll(raw)
	raw.Close()
	if !strings.HasPrefix(string(reply), "HTTP/1.0 400") {
		t.Errorf("the site answered a plain HTTP request with %q", reply)
	}
	if probe = srv.event(TypeProbe); probe.Reason == "" {
		t.Errorf("the probe event is %+v", probe)
	}

	if len(data.streams) != 0 {
		t.Error("a prober got a stream to the node")
	}
	if s := srv.counters(); s.Probes != 3 || s.Accepted != 0 {
		t.Errorf("the server counted %+v, want 3 probes and no stream", s)
	}
}

// A client that has the wrong key, the wrong short id or a clock that is far off is no Ranz client to
// the server: it is spliced to the site, sees the certificate of the site, and its link fails.
func TestAClientThatIsNoRanzClientIsSpliced(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})
	addr := srv.ready.Listen

	behind := func() time.Time { return time.Now().Add(-10 * time.Minute) }
	ahead := func() time.Time { return time.Now().Add(10 * time.Minute) }
	cases := []struct {
		name string
		link func() Link
		opts Options
	}{
		{"a short id that the server does not know", func() Link { l := linkTo(addr, public); l.ShortID = "ffff"; return l }, Options{}},
		{"no short id", func() Link { l := linkTo(addr, public); l.ShortID = ""; return l }, Options{}},
		{"a key that is not the server's", func() Link { _, other := keyPair(t); return linkTo(addr, other) }, Options{}},
		{"a clock ten minutes behind", func() Link { return linkTo(addr, public) }, Options{now: behind}},
		{"a clock ten minutes ahead", func() Link { return linkTo(addr, public) }, Options{now: ahead}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, pipe := runClient(t, c.opts, c.link())
			conn, _, err := dialLink(pipe, addr)
			if err == nil {
				conn.Close()
				t.Fatal("the link connected")
			}
			if !strings.Contains(err.Error(), "did not prove its key") {
				t.Errorf("the link failed with %q, want the server that did not prove its key", err)
			}
			if probe := srv.event(TypeProbe); probe.Reason == "" {
				t.Errorf("the probe event is %+v", probe)
			}
		})
	}
	if len(data.streams) != 0 {
		t.Error("a client that is no Ranz client got a stream to the node")
	}

	// The clock may be a minute off, which is within the two that the server allows
	_, pipe := runClient(t, Options{now: func() time.Time { return time.Now().Add(time.Minute) }}, linkTo(addr, public))
	conn, _, err := dialLink(pipe, addr)
	if err != nil {
		t.Fatalf("a clock one minute ahead: %v", err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	exchange(t, conn, st.conn, 4096)
}

// The browser of a link is the one that the ClientHello on the wire is: Chrome and Firefox are as
// selectable as Edge, and a REALITY server takes each of them.
func TestChromeAndFirefoxLinksReachTheNode(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})

	for _, name := range []string{FingerprintChrome, FingerprintFirefox} {
		t.Run(name, func(t *testing.T) {
			taps := make(chan *tap, 4)
			link := linkTo(srv.ready.Listen, public)
			link.Fingerprint = name
			_, pipe := runClient(t, Options{dialOuter: tapDialer(taps)}, link)
			conn, binding, err := dialLink(pipe, srv.ready.Listen)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			st := data.next(t)
			defer st.conn.Close()
			if binding != st.binding {
				t.Errorf("the bindings are %q and %q", binding, st.binding)
			}
			exchange(t, conn, st.conn, 10000)
			exchange(t, st.conn, conn, 10000)

			h, err := parseClientHello((<-taps).all()[0].data[5:])
			if err != nil {
				t.Fatal(err)
			}
			var spec utls.ClientHelloSpec
			if name == FingerprintFirefox {
				spec, err = firefoxSpec()
			} else {
				spec, err = utls.UTLSIdToSpec(chromiumParrot)
			}
			if err != nil {
				t.Fatal(err)
			}
			checkHelloAgainstSpec(t, h, spec)
		})
	}
}

// A client that gets through while the node does not read its data pipe has nothing to talk to: the
// server tells the node, and closes the connection.
func TestTheServerNeedsTheDataPipeOfTheNode(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	// A data pipe that no node made
	start := Message{Type: TypeStart, Role: RoleServer, Pipe: pipeName(t, "nowhere"), Server: borrowSettings(private, site.addr)}
	srv := startSidecar(t, start, Options{skipDetect: true})
	_, pipe := runClient(t, Options{}, linkTo(srv.ready.Listen, public))

	conn, _, err := dialLink(pipe, srv.ready.Listen)
	if err == nil {
		// The client side is through, and then its stream ends
		conn.SetReadDeadline(time.Now().Add(testTimeout))
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Error("the stream carries data that no node reads")
		}
		conn.Close()
	}
	if m := srv.event(TypeError); !strings.Contains(m.Error, "data pipe") || m.Peer == "" {
		t.Errorf("the error event is %+v, want one about the data pipe with the peer", m)
	}
}

// Both sidecars answer the node's stats: what they counted since they started.
func TestStatsAndUnknownMessages(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})
	if m := srv.counters(); m.Accepted != 0 || m.Probes != 0 || m.Streams != 0 || m.Dropped != 0 {
		t.Errorf("the counters of a new sidecar are %+v", m)
	}
	if srv.ready.Protocol != ProtocolVersion || !strings.HasPrefix(srv.ready.Version, "ranz mimic") || srv.ready.Decoy != "" {
		t.Errorf("ready is %+v", srv.ready)
	}
	if _, _, err := net.SplitHostPort(srv.ready.Listen); err != nil {
		t.Errorf("ready names the listener %q: %v", srv.ready.Listen, err)
	}

	// The settings come once, and a type that nothing knows is an error that the sidecar survives
	srv.w.Write(Message{Type: TypeStart, Role: RoleServer, Pipe: data.name})
	if m := srv.event(TypeError); !strings.Contains(m.Error, "once") {
		t.Errorf("a second start was answered with %+v", m)
	}
	srv.w.Write(Message{Type: "reboot"})
	if m := srv.event(TypeError); !strings.Contains(m.Error, "unknown message type") {
		t.Errorf("an unknown type was answered with %+v", m)
	}

	_, pipe := runClient(t, Options{}, linkTo(srv.ready.Listen, public))
	conn, _, err := dialLink(pipe, srv.ready.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	// The node has the stream, and the sidecar counts it just after it wrote the binding, so the node asks until the
	// stream is counted. The check is as it was: one stream, and a count that does not come fails it
	m := srv.countersUntil(func(c Message) bool { return c.Accepted >= 1 && c.Streams >= 1 })
	if m.Accepted != 1 || m.Streams != 1 {
		t.Errorf("the counters after one stream are %+v", m)
	}
}

// The client role answers a node that asks for what it has no link for, or that asks badly, with an
// error and a closed pipe, and one link that is down does not stop the others.
func TestClientRefusesWhatItCannotDial(t *testing.T) {
	site := startSite(t, testName, "the real site")
	private, public := keyPair(t)
	srv, data := runServer(t, borrowSettings(private, site.addr), Options{skipDetect: true})

	// The address of a server that is down: a port that was free a moment ago
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := closed.Addr().String()
	closed.Close()

	_, pipe := runClient(t, Options{}, linkTo(down, public), linkTo(srv.ready.Listen, public))

	if _, _, err := dialLink(pipe, "192.0.2.77:443"); err == nil || !strings.Contains(err.Error(), "not a link") {
		t.Errorf("a link that is not in the settings: %v", err)
	}
	if _, _, err := dialLink(pipe, down); err == nil || !strings.HasPrefix(err.Error(), "error ") {
		t.Errorf("a server that is down: %v", err)
	}

	// A request that is no request: the pipe is closed on the node
	raw, err := dialPipe(t.Context(), pipe)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(raw, "GET / HTTP/1.1\r\n")
	raw.SetReadDeadline(time.Now().Add(testTimeout))
	reply, _ := readLine(raw, 1000)
	if !strings.HasPrefix(reply, "error ") {
		t.Errorf("a request that is no dial was answered with %q", reply)
	}
	raw.Close()

	// A line that never ends
	raw, err = dialPipe(t.Context(), pipe)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(raw, strings.Repeat("x", 2*maxRequest))
	raw.SetReadDeadline(time.Now().Add(testTimeout))
	// The sidecar closes its end: the read ends at once, with the end of the stream or with an error
	// of a connection that was reset, and never with the deadline
	start := time.Now()
	io.ReadAll(raw)
	if time.Since(start) > testTimeout/2 {
		t.Error("the sidecar did not close a pipe whose request is too long")
	}
	raw.Close()

	// The other link still works
	conn, _, err := dialLink(pipe, srv.ready.Listen)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	st := data.next(t)
	defer st.conn.Close()
	exchange(t, conn, st.conn, 1000)
}
