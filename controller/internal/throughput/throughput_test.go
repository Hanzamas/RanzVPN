package throughput

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The harness nodes of these tests are two ends of the in-process loopback transport, as the nodes
// of the vpntest harness are (src/Core/TransportLoopback.c): a listener takes any address as its
// name, which here is the overlay address of its node, and a dial finds the listener by that name.
// The node simulator of the controller tests speaks the control protocol only and has no data plane
// to carry a test, so the harness here is the transport of the C harness written once more for Go.

// loopback is the network of the harness nodes.
type loopback struct {
	mu        sync.Mutex
	listeners map[string]*loopbackListener
}

func newLoopback() *loopback {
	return &loopback{listeners: make(map[string]*loopbackListener)}
}

// loopbackAddr is the address of a listener of the loopback network.
type loopbackAddr string

func (a loopbackAddr) Network() string { return "loopback" }
func (a loopbackAddr) String() string  { return string(a) }

// loopbackListener is a listener of the loopback network.
type loopbackListener struct {
	network *loopback
	addr    string
	conns   chan net.Conn
	closed  chan struct{}
	once    sync.Once
}

// listen listens on addr.
func (n *loopback) listen(addr string) (net.Listener, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, taken := n.listeners[addr]; taken {
		return nil, fmt.Errorf("loopback: %s is taken", addr)
	}
	l := &loopbackListener{network: n, addr: addr, conns: make(chan net.Conn, 64), closed: make(chan struct{})}
	n.listeners[addr] = l
	return l, nil
}

// dial connects to the listener of addr: the client end of a pipe, whose server end the listener
// accepts.
func (n *loopback) dial(ctx context.Context, _, addr string) (net.Conn, error) {
	n.mu.Lock()
	l := n.listeners[addr]
	n.mu.Unlock()
	if l == nil {
		return nil, fmt.Errorf("loopback: nothing listens on %s", addr)
	}
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
	case <-ctx.Done():
	}
	client.Close()
	server.Close()
	return nil, fmt.Errorf("loopback: %s did not take the connection", addr)
}

func (l *loopbackListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *loopbackListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		l.network.mu.Lock()
		delete(l.network.listeners, l.addr)
		l.network.mu.Unlock()
	})
	return nil
}

func (l *loopbackListener) Addr() net.Addr {
	return loopbackAddr(l.addr)
}

// harnessNode is a node of the harness: it serves tests on its overlay address and runs tests to
// the others over the loopback network.
type harnessNode struct {
	name    string
	address string
	network *loopback
}

// startNode starts the test server of a node on address, which stops when the test ends.
func startNode(t *testing.T, network *loopback, name, address string) *harnessNode {
	t.Helper()
	ln, err := network.listen(address)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, t.Logf) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("%s: Serve: %v", name, err)
		}
	})
	return &harnessNode{name: name, address: address, network: network}
}

// test runs a test from the node to another node over the loopback network.
func (n *harnessNode) test(t *testing.T, to *harnessNode, opts Options) Result {
	t.Helper()
	opts.Dial = n.network.dial
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := Run(ctx, to.address, opts)
	if err != nil {
		t.Fatalf("%s to %s: %v", n.name, to.name, err)
	}
	return res
}

// checkStream checks that a direction of a test moved data at a rate.
func checkStream(t *testing.T, what string, s Stream, connections int) {
	t.Helper()
	if s.Connections != connections {
		t.Errorf("%s: %d connections, want %d", what, s.Connections, connections)
	}
	if s.Bytes == 0 || s.Bps == 0 || s.WindowSeconds <= 0.05 || s.WindowSeconds > 10 {
		t.Errorf("%s: %d bytes over %.3f s at %d bps", what, s.Bytes, s.WindowSeconds, s.Bps)
	}
}

// ranz test throughput reports a rate between two harness nodes (the criterion of SDN-53, #246):
// each way, over the overlay addresses of the nodes, with the data on the connections that the
// test opened, in both directions of a full test.
func TestTwoHarnessNodesReportARate(t *testing.T) {
	network := newLoopback()
	a := startNode(t, network, "node-a", "100.64.0.1:9821")
	b := startNode(t, network, "node-b", "100.64.0.2:9821")
	for _, c := range []struct{ from, to *harnessNode }{{a, b}, {b, a}} {
		res := c.from.test(t, c.to, Options{Connections: 4, Span: 300 * time.Millisecond})
		what := c.from.name + " to " + c.to.name
		if res.Address != c.to.address {
			t.Errorf("%s: the address is %s", what, res.Address)
		}
		checkStream(t, what+", download", res.Download, 2)
		checkStream(t, what+", upload", res.Upload, 2)
		if res.TotalBytes != res.Download.Bytes+res.Upload.Bytes || res.TotalBps != res.Download.Bps+res.Upload.Bps {
			t.Errorf("%s: the total is %d bytes at %d bps, not the sum of %+v and %+v", what, res.TotalBytes, res.TotalBps, res.Download, res.Upload)
		}
		if res.SpanSeconds < 0.29 || res.SpanSeconds > 0.31 {
			t.Errorf("%s: the span is %v s", what, res.SpanSeconds)
		}
		text := res.String()
		for _, want := range []string{"Throughput test to " + c.to.address, "Download", "Upload", "Total", " bytes ", "bps"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the report has no %q:\n%s", what, want, text)
			}
		}
	}
}

// A test in one direction moves data in that direction only, over any number of connections.
func TestOneWayTests(t *testing.T) {
	network := newLoopback()
	a := startNode(t, network, "node-a", "100.64.0.1:9821")
	b := startNode(t, network, "node-b", "100.64.0.2:9821")
	down := a.test(t, b, Options{Direction: Download, Connections: 3, Span: 200 * time.Millisecond})
	checkStream(t, "download", down.Download, 3)
	if down.Upload.Connections != 0 || down.Upload.Bytes != 0 || down.Upload.Bps != 0 {
		t.Errorf("a download test uploaded: %+v", down.Upload)
	}
	up := a.test(t, b, Options{Direction: Upload, Connections: 1, Span: 200 * time.Millisecond})
	checkStream(t, "upload", up.Upload, 1)
	if up.Download.Connections != 0 || up.Download.Bytes != 0 || up.Download.Bps != 0 {
		t.Errorf("an upload test downloaded: %+v", up.Download)
	}
}

// The test runs over TCP as well, between a server and a client of one process.
func TestOverTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, t.Logf) }()
	res, err := Run(ctx, ln.Addr().String(), Options{Connections: 4, Span: 300 * time.Millisecond, Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	checkStream(t, "download", res.Download, 2)
	checkStream(t, "upload", res.Upload, 2)
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

// A test that ends with its context stops at once, and says so.
func TestRunStopsWithItsContext(t *testing.T) {
	network := newLoopback()
	a := startNode(t, network, "node-a", "100.64.0.1:9821")
	b := startNode(t, network, "node-b", "100.64.0.2:9821")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	begin := time.Now()
	_, err := Run(ctx, b.address, Options{Connections: 2, Span: time.Minute, Dial: a.network.dial})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run ended with %v, want that its context was canceled", err)
	}
	if took := time.Since(begin); took > 20*time.Second {
		t.Errorf("Run took %v to stop", took)
	}
}

// A test does not run with options that cannot give a rate.
func TestRunRefusals(t *testing.T) {
	for _, c := range []struct {
		what string
		opts Options
	}{
		{"too many connections", Options{Connections: MaxConnections + 1}},
		{"a negative number of connections", Options{Connections: -1}},
		{"an odd number of connections both ways", Options{Connections: 3}},
		{"one connection both ways", Options{Connections: 1}},
		{"a direction that is none", Options{Direction: 7, Connections: 2}},
		{"a span that is negative", Options{Span: -time.Second}},
		{"a span below a millisecond", Options{Span: time.Microsecond}},
		{"a span beyond the longest", Options{Span: MaxSpan + time.Second}},
	} {
		if _, err := Run(context.Background(), "100.64.0.2:9821", c.opts); err == nil {
			t.Errorf("a test with %s ran", c.what)
		}
	}
	// A test of the defaults of vpncmd is a test: its options complete
	o, err := Options{}.complete()
	if err != nil || o.Connections != DefaultConnections || o.Span != DefaultSpan || o.Direction != Full || o.Dial == nil {
		t.Errorf("the default options are %+v (%v)", o, err)
	}
}

// A client that connects to something that is no test server is told so, and a server that gets
// something that is no request closes the connection and serves the next test as before.
func TestWhatIsNoTestServerOrNoClient(t *testing.T) {
	network := newLoopback()
	a := startNode(t, network, "node-a", "100.64.0.1:9821")
	b := startNode(t, network, "node-b", "100.64.0.2:9821")

	// Another service: it answers a request with a page
	web, err := network.listen("100.64.0.9:80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { web.Close() })
	go func() {
		for {
			c, err := web.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := Run(ctx, "100.64.0.9:80", Options{Connections: 2, Span: time.Second, Dial: a.network.dial}); err == nil || !strings.Contains(err.Error(), "another service") {
		t.Errorf("a test against a web server: %v, want that the address is of another service", err)
	}
	if _, err := Run(ctx, "100.64.0.99:9821", Options{Connections: 2, Span: time.Second, Dial: a.network.dial}); err == nil {
		t.Error("a test against an address that nothing listens on ran")
	}

	// A client that says nothing sensible
	for _, request := range [][]byte{{'X', 0, 0, 0, 0, 0, 0, 1}, {'D', 1, 0, 0, 0, 0, 0, 1}, {'U', 0, 0, 0, 0, 0, 0, 0}, {'D', 0}} {
		conn, err := a.network.dial(ctx, "tcp", b.address)
		if err != nil {
			t.Fatal(err)
		}
		greeting := make([]byte, len(Greeting))
		if _, err := io.ReadFull(conn, greeting); err != nil || string(greeting) != Greeting {
			t.Fatalf("the greeting is %q (%v)", greeting, err)
		}
		conn.Write(request)
		conn.Close()
	}
	res := a.test(t, b, Options{Connections: 2, Span: 200 * time.Millisecond})
	checkStream(t, "download", res.Download, 1)
	checkStream(t, "upload", res.Upload, 1)
}

// failingListener is a listener whose Accept fails.
type failingListener struct{}

func (failingListener) Accept() (net.Conn, error) { return nil, errors.New("accept failed") }
func (failingListener) Close() error              { return nil }
func (failingListener) Addr() net.Addr            { return loopbackAddr("none") }

// Serve returns the error of a listener that fails, and nil for the end of its context.
func TestServe(t *testing.T) {
	if err := Serve(context.Background(), failingListener{}, nil); err == nil || err.Error() != "accept failed" {
		t.Errorf("Serve of a listener that fails: %v", err)
	}
	ln, err := newLoopback().listen("100.64.0.1:9821")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Serve(ctx, ln, nil); err != nil {
		t.Errorf("Serve with a context that ended: %v", err)
	}
}

// countingConn counts the bytes that are written to a connection.
type countingConn struct {
	net.Conn
	written atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(int64(n))
	return n, err
}

// The client counts a download exactly as the server sent it: the payload of every frame, none of
// the headers, and the end frame ends it.
func TestDownloadIsCountedAsSent(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	counter := &countingConn{Conn: server}
	errc := make(chan error, 1)
	go func() {
		errc <- send(counter, 100*time.Millisecond)
		server.Close()
	}()
	st, err := receive(client, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	written := counter.written.Load()
	frames := (written - frameHeader) / (frameHeader + MaxPayload)
	if frames == 0 || written != frames*(frameHeader+MaxPayload)+frameHeader {
		t.Fatalf("the server wrote %d bytes, not whole frames and an end frame", written)
	}
	if st.bytes != uint64(frames)*MaxPayload {
		t.Errorf("the client counted %d bytes of %d frames of %d", st.bytes, frames, MaxPayload)
	}
	if st.elapsed() <= 0 || st.first.IsZero() {
		t.Errorf("the client counted no time: %v", st.elapsed())
	}
}

// The server counts an upload as the client sent it, and the report that it answers holds that
// count and a time.
func TestUploadIsReportedAsSent(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	errc := make(chan error, 1)
	go func() {
		errc <- answerUpload(server, time.Second)
		server.Close()
	}()
	const frames = 20
	for range frames {
		if _, err := client.Write(dataFrame()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := client.Write(endFrame[:]); err != nil {
		t.Fatal(err)
	}
	rep, err := ReadReport(client)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if rep.Bytes != frames*MaxPayload || rep.Elapsed < 0 {
		t.Errorf("the report is %+v, want %d bytes", rep, frames*MaxPayload)
	}

	// A stream that ends without its end frame is an error of the server, and gets no report
	client2, server2 := net.Pipe()
	defer client2.Close()
	go func() {
		client2.Write(dataFrame())
		client2.Close()
	}()
	if err := answerUpload(server2, time.Second); err == nil {
		t.Error("an upload that ended without its end frame was answered")
	}
	server2.Close()
}

// stream returns a stream of frames with the payload sizes, and its end frame.
func stream(sizes ...int) []byte {
	var b bytes.Buffer
	for _, n := range sizes {
		var h [frameHeader]byte
		binary.BigEndian.PutUint32(h[:], uint32(n))
		b.Write(h[:])
		b.Write(make([]byte, n))
	}
	b.Write(endFrame[:])
	return b.Bytes()
}

// A receiver counts the payload of a stream in whatever pieces it arrives, and tells the end.
func TestReceiverCountsWhateverThePieces(t *testing.T) {
	data := stream(100, MaxPayload, 1, 5000)
	const want = 100 + MaxPayload + 1 + 5000
	rng := rand.New(rand.NewSource(1))
	for _, piece := range []int{1, 2, 3, 4, 5, 7, 4096, len(data), 0} {
		var r Receiver
		rest := data
		done := false
		for len(rest) > 0 {
			n := piece
			if n == 0 {
				n = 1 + rng.Intn(10000)
			}
			n = min(n, len(rest))
			var err error
			if done, err = r.Input(rest[:n]); err != nil {
				t.Fatalf("pieces of %d bytes: %v", piece, err)
			}
			rest = rest[n:]
			if done != (len(rest) == 0) {
				t.Fatalf("pieces of %d bytes: done is %v with %d bytes left", piece, done, len(rest))
			}
		}
		if r.Bytes() != want {
			t.Errorf("pieces of %d bytes: %d bytes counted, want %d", piece, r.Bytes(), want)
		}
	}
}

// A receiver refuses data after the end of the stream and a frame that is larger than a frame can
// be, and counts an empty piece as nothing.
func TestReceiverRefusals(t *testing.T) {
	var r Receiver
	if done, err := r.Input(nil); done || err != nil {
		t.Errorf("an empty piece: %v, %v", done, err)
	}
	if done, err := r.Input(endFrame[:]); !done || err != nil {
		t.Errorf("the end frame: %v, %v", done, err)
	}
	if done, err := r.Input(nil); !done || err != nil {
		t.Errorf("an empty piece after the end: %v, %v", done, err)
	}
	if _, err := r.Input([]byte{1}); err == nil {
		t.Error("data after the end of the stream was taken")
	}

	var big Receiver
	var h [frameHeader]byte
	binary.BigEndian.PutUint32(h[:], MaxPayload+1)
	if _, err := big.Input(h[:]); err == nil {
		t.Error("a frame larger than MaxPayload was taken")
	}
	var edge Receiver
	binary.BigEndian.PutUint32(h[:], MaxPayload)
	if _, err := edge.Input(h[:]); err != nil {
		t.Errorf("a frame of MaxPayload bytes: %v", err)
	}
}

// A request is read as it was written, and what is not a request is refused.
func TestRequest(t *testing.T) {
	for _, req := range []Request{{Download, time.Second}, {Upload, 15 * time.Second}, {Download, time.Millisecond}, {Upload, MaxSpan}} {
		var b bytes.Buffer
		if err := req.Write(&b); err != nil {
			t.Fatal(err)
		}
		if b.Len() != requestSize {
			t.Errorf("%+v is %d bytes", req, b.Len())
		}
		got, err := ReadRequest(&b)
		if err != nil || got != req {
			t.Errorf("%+v was read as %+v (%v)", req, got, err)
		}
	}
	for _, req := range []Request{{Full, time.Second}, {Direction(9), time.Second}, {Download, 0}, {Upload, -time.Second}, {Download, MaxSpan + time.Second}} {
		if err := req.Write(io.Discard); err == nil {
			t.Errorf("%+v was written", req)
		}
	}
	tooLong := make([]byte, requestSize)
	copy(tooLong, []byte{'D', 0, 0, 0})
	binary.BigEndian.PutUint32(tooLong[4:], uint32(MaxSpan/time.Millisecond)+1)
	for what, b := range map[string][]byte{
		"a direction that is none":       {'X', 0, 0, 0, 0, 0, 0, 1},
		"reserved bytes that are not 0":  {'D', 0, 1, 0, 0, 0, 0, 1},
		"a span of 0":                    {'U', 0, 0, 0, 0, 0, 0, 0},
		"a span beyond the longest":      tooLong,
		"a request that is cut short":    {'D', 0, 0},
		"a request that is not even one": {},
	} {
		if _, err := ReadRequest(bytes.NewReader(b)); err == nil {
			t.Errorf("%s was read as a request", what)
		}
	}
}

// A report is read as it was written, and a negative time is written as none.
func TestReport(t *testing.T) {
	var b bytes.Buffer
	want := Report{Bytes: 1 << 40, Elapsed: 1500 * time.Millisecond}
	if err := want.Write(&b); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadReport(&b); err != nil || got != want {
		t.Errorf("%+v was read as %+v (%v)", want, got, err)
	}
	b.Reset()
	if err := (Report{Bytes: 5, Elapsed: -time.Second}).Write(&b); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadReport(&b); err != nil || got.Elapsed != 0 || got.Bytes != 5 {
		t.Errorf("a negative time was read as %+v (%v)", got, err)
	}
	huge := make([]byte, reportSize)
	binary.BigEndian.PutUint64(huge[8:], 1<<63)
	if _, err := ReadReport(bytes.NewReader(huge)); err == nil {
		t.Error("a time beyond the range of a duration was read")
	}
	if _, err := ReadReport(bytes.NewReader(huge[:5])); err == nil {
		t.Error("a report that is cut short was read")
	}
}

// The figures of a stream: the bytes as Ethernet frames unless the test is raw, the rate over the
// window, and the doubling of the rate.
func TestFinish(t *testing.T) {
	// 1,000 full payloads of 1,460 bytes are 1,000 frames of 1,514
	s := Stream{Bytes: 1460 * 1000}
	s.finish(time.Second, false, false)
	if s.Bytes != 1514*1000 || s.Bps != 1514*1000*8 || s.WindowSeconds != 1 {
		t.Errorf("framed: %+v", s)
	}
	s = Stream{Bytes: 1460 * 1000}
	s.finish(2*time.Second, true, false)
	if s.Bytes != 1460*1000 || s.Bps != 1460*1000*8/2 {
		t.Errorf("raw over two seconds: %+v", s)
	}
	s = Stream{Bytes: 1000}
	s.finish(time.Second, true, true)
	if s.Bps != 2*1000*8 || s.Bytes != 1000 {
		t.Errorf("doubled: %+v", s)
	}
	s = Stream{Bytes: 1000}
	s.finish(0, true, true)
	if s.Bps != 0 {
		t.Errorf("a rate over no time: %+v", s)
	}
}

// The numbers of the report.
func TestNumberFormats(t *testing.T) {
	for n, want := range map[uint64]string{0: "0", 7: "7", 999: "999", 1000: "1,000", 1234567: "1,234,567", 1234567890: "1,234,567,890"} {
		if got := grouped(n); got != want {
			t.Errorf("grouped(%d) = %s, want %s", n, got, want)
		}
	}
	for n, want := range map[uint64]string{0: "0.00 bps", 999: "999.00 bps", 1000: "1.00 Kbps", 1_500_000: "1.50 Mbps", 9_876_000_000: "9.88 Gbps", 12_340_000_000_000: "12.34 Tbps"} {
		if got := rate(n); got != want {
			t.Errorf("rate(%d) = %s, want %s", n, got, want)
		}
	}
}

// The text of a result and its JSON.
func TestResultFormats(t *testing.T) {
	res := Result{
		Address:     "100.64.0.2:9821",
		SpanSeconds: 15,
		Download:    Stream{Connections: 16, Bytes: 1234567890, WindowSeconds: 15.01, Bps: 1_000_000_000},
		Upload:      Stream{Connections: 16, Bytes: 987654321, WindowSeconds: 15.02, Bps: 500_000_000},
		TotalBytes:  2222222211,
		TotalBps:    1_500_000_000,
	}
	text := res.String()
	for _, want := range []string{"Throughput test to 100.64.0.2:9821", "15s", "Ethernet headers counted yes", "Rates doubled            no",
		"1,234,567,890 bytes", "1.00 Gbps", "987,654,321 bytes", "500.00 Mbps", "2,222,222,211 bytes", "1.50 Gbps"} {
		if !strings.Contains(text, want) {
			t.Errorf("the text has no %q:\n%s", want, text)
		}
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"address":"100.64.0.2:9821"`, `"spanSeconds":15`, `"download":{"connections":16,"bytes":1234567890,"windowSeconds":15.01,"bps":1000000000}`, `"totalBps":1500000000`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("the JSON has no %s:\n%s", want, b)
		}
	}
	if got := Direction(5).String(); got != "Direction(5)" {
		t.Errorf("an unknown direction is %s", got)
	}
}
