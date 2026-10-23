package throughput

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// dialTimeout bounds the opening of one connection.
const dialTimeout = 10 * time.Second

// Options are the choices of a test. The zero value is the test of vpncmd's defaults: 32
// connections, both ways, for 15 seconds, over TCP.
type Options struct {
	// Connections is the number of TCP connections, DefaultConnections when it is 0. A test in
	// both ways needs an even number of them, at least 2.
	Connections int
	// Direction is the way the data flows: Full, which is the zero value, Download or Upload.
	Direction Direction
	// Span is how long the senders send, DefaultSpan when it is 0.
	Span time.Duration
	// Raw leaves the TCP/IP and Ethernet headers out of the count. Without it, the bytes of each
	// direction are counted as the Ethernet frames that carry them (a payload of 1,460 bytes in a
	// frame of 1,514), as vpncmd counted them, so that the rate compares with the line rate of
	// the link.
	Raw bool
	// Double doubles the rate of each direction: for a link whose device both receives and sends
	// what the test sends, so that the rate that the device handles is the one that shows.
	Double bool
	// Dial opens a connection to an address. A nil Dial opens a TCP connection; the harness gives
	// the in-process transport of its nodes.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
}

// complete returns the options with their defaults filled in, or says what is wrong with them.
func (o Options) complete() (Options, error) {
	if o.Connections == 0 {
		o.Connections = DefaultConnections
	}
	if o.Connections < 0 || o.Connections > MaxConnections {
		return o, fmt.Errorf("throughput: %d connections is not between 1 and %d", o.Connections, MaxConnections)
	}
	switch o.Direction {
	case Full:
		if o.Connections < 2 || o.Connections%2 != 0 {
			return o, fmt.Errorf("throughput: a test in both ways needs an even number of connections, at least 2, not %d", o.Connections)
		}
	case Download, Upload:
	default:
		return o, fmt.Errorf("throughput: %v is no direction", o.Direction)
	}
	if o.Span == 0 {
		o.Span = DefaultSpan
	}
	if o.Span < time.Millisecond || o.Span > MaxSpan {
		return o, fmt.Errorf("throughput: a span of %v is not between 1 ms and %v", o.Span, MaxSpan)
	}
	if o.Dial == nil {
		o.Dial = (&net.Dialer{}).DialContext
	}
	return o, nil
}

// directionOf returns the direction of connection i of a test in direction d: the connections of
// a Full test alternate, the first one downloads.
func directionOf(d Direction, i int) Direction {
	if d == Full {
		if i%2 == 0 {
			return Download
		}
		return Upload
	}
	return d
}

// outcome is how one connection of a test went.
type outcome struct {
	dir Direction
	// bytes are the bytes of payload that the receiver counted. first and last are when its first
	// and its last data arrived at the client, for a download; elapsed is the time that the server
	// counted from its first data to its last, for an upload.
	bytes       uint64
	first, last time.Time
	elapsed     time.Duration
	err         error
}

// Run runs the test of opts against the server at address, a host and a port, and returns what it
// measured. It opens every connection first and starts the data on all of them at once. It stops
// at once when ctx ends, and a connection that fails ends the test with its error.
func Run(ctx context.Context, address string, opts Options) (Result, error) {
	opts, err := opts.complete()
	if err != nil {
		return Result{}, err
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	n := opts.Connections
	outs := make([]outcome, n)
	ready := make(chan error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i] = runStream(ctx, address, opts, i, ready, start)
		}()
	}
	for range n {
		if err := <-ready; err != nil {
			cancel()
			wg.Wait()
			if parent.Err() != nil {
				return Result{}, parent.Err()
			}
			return Result{}, err
		}
	}
	close(start)
	wg.Wait()
	if parent.Err() != nil {
		return Result{}, parent.Err()
	}
	for _, o := range outs {
		if o.err != nil {
			return Result{}, o.err
		}
	}
	return summarize(address, opts, outs), nil
}

// runStream runs connection i of a test: it opens it and reads the greeting of the server, tells
// ready how that went, waits for start, and then runs the stream. A failure before ready is the
// error that ready gets, a failure after it the error of the outcome.
func runStream(ctx context.Context, address string, opts Options, i int, ready chan<- error, start <-chan struct{}) outcome {
	dir := directionOf(opts.Direction, i)
	out := outcome{dir: dir}
	fail := func(err error) outcome {
		out.err = fmt.Errorf("connection %d: %w", i+1, err)
		return out
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := opts.Dial(dctx, "tcp", address)
	cancel()
	if err != nil {
		out = fail(err)
		ready <- out.err
		return out
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := greet(conn); err != nil {
		out = fail(err)
		ready <- out.err
		return out
	}
	ready <- nil
	select {
	case <-start:
	case <-ctx.Done():
		return fail(ctx.Err())
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fail(err)
	}
	if err := (Request{Direction: dir, Span: opts.Span}).Write(conn); err != nil {
		return fail(err)
	}
	if dir == Download {
		st, err := receive(conn, opts.Span+grace)
		if err != nil {
			return fail(err)
		}
		out.bytes, out.first, out.last = st.bytes, st.first, st.last
		return out
	}
	if err := send(conn, opts.Span); err != nil {
		return fail(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(grace)); err != nil {
		return fail(err)
	}
	rep, err := ReadReport(conn)
	if err != nil {
		return fail(fmt.Errorf("the report of the server: %w", err))
	}
	out.bytes, out.elapsed = rep.Bytes, rep.Elapsed
	return out
}

// greet reads the greeting of the server on conn.
func greet(conn net.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(setupTimeout)); err != nil {
		return err
	}
	got := make([]byte, len(Greeting))
	if _, err := io.ReadFull(conn, got); err != nil {
		return fmt.Errorf("the server did not greet: %w", err)
	}
	if string(got) != Greeting {
		return errors.New("the server's greeting is not that of a throughput test server: the address is of another service")
	}
	return nil
}
