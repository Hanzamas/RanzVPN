package rqlitetest

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// portOf returns the port of an address that Addrs gave.
func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// The addresses are all different, and their ports are below the ones that the system hands out as the source port of a
// connection and to a listener on port 0.
func TestAddrsAreDifferentAndBelowTheSourcePorts(t *testing.T) {
	seen := map[string]bool{}
	for _, addr := range Addrs(t, 40) {
		if seen[addr] {
			t.Errorf("%s was given twice", addr)
		}
		seen[addr] = true
		if port := portOf(t, addr); port < runPorts.low || port >= runPorts.high || port >= firstSourcePort() {
			t.Errorf("%s is no port from %d to %d below the source ports, which start at %d", addr, runPorts.low, runPorts.high, firstSourcePort())
		}
	}
}

// The cure of CI-FLAKE-4 (#581): the connections that the clients of a run open take their source ports from the range that
// the system hands out, and none of them takes one of the addresses that Addrs gave between the hand-out and the bind of the
// caller, so the bind finds each address free while 200 connections of other clients are open.
func TestConnectionsDoNotTakeTheAddresses(t *testing.T) {
	addrs := Addrs(t, 8)
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var accepted []net.Conn
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	var clients []net.Conn
	t.Cleanup(func() {
		for _, c := range clients {
			c.Close()
		}
		srv.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range accepted {
			c.Close()
		}
	})
	for range 200 {
		c, err := net.Dial("tcp", srv.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		if port := c.LocalAddr().(*net.TCPAddr).Port; port >= runPorts.low && port < runPorts.high {
			t.Errorf("a connection took the source port %d, which is one of the ports from %d to %d of the addresses", port, runPorts.low, runPorts.high)
		}
	}
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			t.Errorf("the bind of %s failed with 200 connections of other clients open: %v", addr, err)
			continue
		}
		ln.Close()
	}
}

// The race that the addresses are handed out against (CI-FLAKE-4, #581): the port of a listener that was closed is a number
// that a client can have as the source port of its connection, and a bind of that number then fails. This is how a helper
// that gave back the address of a listener that it had closed met the clients of its run (TestRunServesTheCertificateOfItsSetting
// on the port 39469, which is in the range of the source ports of Linux). A system that lets a listener share a port with a
// connection does not show it: the test says so and passes.
func TestTheRaceOfTheAddressOfAClosedListener(t *testing.T) {
	srv, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	old, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := old.Addr().(*net.TCPAddr)
	old.Close()
	c, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: addr.IP, Port: addr.Port}}).Dial("tcp", srv.Addr().String())
	if err != nil {
		t.Skipf("the number was taken before the client could have it: %v", err)
	}
	defer c.Close()
	ln, err := net.Listen("tcp", addr.String())
	if err == nil {
		ln.Close()
		t.Skip("this system lets a listener bind a port that a connection has as its source port")
	}
	t.Logf("the bind of %s, the address of a listener that was closed, failed once a client had the number as its source port: %v", addr, err)
}

// Callers that ask at the same time, in this process or in another one of the run, which share the directory of the locks,
// never get the same address, also where the ports to choose from are few: 100 addresses from 400 ports, asked by ten callers
// at once. A pool that chose at random and held no lock would give some number twice.
func TestCallersThatAskAtTheSameTimeNeverGetTheSameAddress(t *testing.T) {
	p := &portPool{dir: t.TempDir(), low: 10000, high: 10400}
	const callers, each = 10, 10
	got := make(chan []string, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, release, err := p.reserve(each)
			if err != nil {
				t.Error(err)
				return
			}
			t.Cleanup(release)
			got <- addrs
		}()
	}
	wg.Wait()
	close(got)
	seen := map[string]bool{}
	for addrs := range got {
		for _, addr := range addrs {
			if seen[addr] {
				t.Errorf("%s was given to two callers", addr)
			}
			seen[addr] = true
		}
	}
	if len(seen) != callers*each {
		t.Errorf("%d addresses were given, want %d", len(seen), callers*each)
	}
	if n := p.held(); n != callers*each {
		t.Errorf("%d ports are locked, want %d", n, callers*each)
	}
}

// The ports of a test go back when it ends, so that the next test can have them.
func TestThePortsOfATestGoBackWhenItEnds(t *testing.T) {
	p := &portPool{dir: t.TempDir(), low: 10000, high: 10400}
	t.Run("a test", func(t *testing.T) {
		addrs, release, err := p.reserve(5)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
		if n := p.held(); n != len(addrs) {
			t.Errorf("%d ports are locked while the test runs, want %d", n, len(addrs))
		}
	})
	if n := p.held(); n != 0 {
		t.Errorf("%d ports are still locked after the test ended", n)
	}
}

// A pool that has fewer ports than the caller asks for says so, and gives back the locks that it took.
func TestAPoolThatRunsOutSaysSo(t *testing.T) {
	p := &portPool{dir: t.TempDir(), low: 10000, high: 10003}
	_, _, err := p.reserve(4)
	if err == nil || !strings.Contains(err.Error(), "no port from 10000 to 10003") {
		t.Fatalf("4 addresses from 3 ports: %v, want an error that names the range", err)
	}
	if n := p.held(); n != 0 {
		t.Errorf("%d ports are still locked after the failure", n)
	}
}

// The lock of a test process that was killed stays in the directory, and is taken over once it is older than a test can be.
func TestTheLockOfAKilledTestIsTakenOver(t *testing.T) {
	p := &portPool{dir: t.TempDir(), low: 10000, high: 10020}
	old := time.Now().Add(-2 * staleAfter)
	for port := p.low; port < p.high; port++ {
		lock := filepath.Join(p.dir, strconv.Itoa(port))
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(lock, old, old); err != nil {
			t.Fatal(err)
		}
	}
	_, release, err := p.reserve(1)
	if err != nil {
		t.Fatalf("a pool whose locks are all older than %v gave no address: %v", staleAfter, err)
	}
	t.Cleanup(release)
}
