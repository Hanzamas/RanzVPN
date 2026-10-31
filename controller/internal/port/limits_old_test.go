package port

import (
	"crypto/tls"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/control"
)

// TEMPORARY (CI-FLAKE-2, #562): the test as it was before the fix, which a step of ranz.yml runs for a comparison with
// the new one. It is removed in the last commit of the branch.
func TestOldThousandNodesBehindOneAddressConnectWithTheDefaults(t *testing.T) {
	if os.Getenv("RANZ_FLAKE_562") == "" {
		t.Skip("run by the temporary step of CI-FLAKE-2 (#562) only")
	}
	const nodes = 1000
	var connected atomic.Int64
	s := &Server{TLS: &tls.Config{Certificates: []tls.Certificate{certificate(t)}}, Control: echo(&connected)}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ln) }()
	defer func() {
		ln.Close()
		<-done
		s.Close()
	}()

	var wg sync.WaitGroup
	var failed atomic.Int64
	start := make(chan struct{})
	// The loopback of Windows resets connections when more than a few hundred are opened in one instant, which is
	// the host's backlog and no limit of the port: the Nodes connect 200 at a time, within the same second
	room := make(chan struct{}, 200)
	for i := 0; i < nodes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			room <- struct{}{}
			defer func() { <-room }()
			d := net.Dialer{Timeout: 60 * time.Second}
			raw, err := d.Dial("tcp", ln.Addr().String())
			if err != nil {
				failed.Add(1)
				return
			}
			defer raw.Close()
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{control.ALPN}})
			_ = tc.SetDeadline(time.Now().Add(60 * time.Second))
			if err := tc.Handshake(); err != nil {
				failed.Add(1)
				return
			}
			// The stream is the node's: it holds until the test is over
			if _, err := tc.Write([]byte{1}); err != nil {
				failed.Add(1)
				return
			}
			b := make([]byte, 1)
			if _, err := io.ReadFull(tc, b); err != nil {
				failed.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if failed.Load() != 0 || connected.Load() != nodes {
		t.Errorf("%d of %d Nodes behind one address did not connect, and Control took %d streams", failed.Load(), nodes, connected.Load())
	}
	r := s.Refusals()
	if r.Admitted != nodes || r.Full+r.Source+r.Rate+r.Handshake != 0 {
		t.Errorf("the refusals are %+v, want %d admitted and none refused", r, nodes)
	}
}
