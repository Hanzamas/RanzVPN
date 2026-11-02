package rqlitetest

import (
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The addresses that the tests give to code that binds them later (CI-FLAKE-4, #581, and CI-FLAKE-5, #592). A test cannot
// keep a listener on an address that it hands to rqlited, or to a Controller that starts again on it. A helper that listened
// on port 0, noted the address and closed the listener gave back a number that the system hands out again: as the source
// port of a connection that a client of the run opens, or to a listener on port 0 that another test process asks for. Then
// the bind of the code under test failed with "address already in use", or two processes of the run bound the same number,
// and the one whose bind failed took the answers of the other for its own.
//
// So the addresses come from ports below the ones that the system hands out, which no connection and no listener on port
// 0 takes, and the tests of the run take them one at a time: a port is the test's until it ends, under a lock that is a file
// in a directory of the temp directory, which every test process of the run shares. A port that something else holds is
// skipped. Only a program that binds one of these ports by its number, without asking here, can still take it.

// Addrs returns n TCP addresses on 127.0.0.1 for the test t to give to code that binds them later: an rqlited, or a
// Controller that starts again on the same addresses. They are all different, no other test of the run has them until t
// ends, and the system hands none out as the source port of a connection, so the bind of the code under test finds them
// free.
func Addrs(t testing.TB, n int) []string {
	t.Helper()
	addrs, release, err := runPorts.reserve(n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	return addrs
}

// portTries is how many ports reserve looks at for one address before it gives up: the ones that are locked, or that
// something holds, are skipped.
const portTries = 1000

// staleAfter is the age from which the lock of a port is taken for the leftover of a test process that was killed: a test
// holds its ports for less than the 20 minutes of the -timeout of the CI jobs.
const staleAfter = time.Hour

// portPool hands out the ports from low up to, and not including, high, each under a lock that is a file of dir.
type portPool struct {
	dir       string
	low, high int
}

// runPorts is the pool of the tests of a run. Its directory is the same for every test process of the run, which go test
// starts one for each package, so that they never take the same port.
var runPorts = newPortPool()

func newPortPool() *portPool {
	p := &portPool{dir: filepath.Join(os.TempDir(), "ranz-test-ports-"+strconv.Itoa(os.Getuid())), low: 20000, high: 32000}
	if first := firstSourcePort(); first < p.high && first-p.low >= 1000 {
		p.high = first
	}
	return p
}

// firstSourcePort returns the lowest port that the system hands out as the source port of a connection and to a listener
// on port 0: on Linux the one that ip_local_port_range says (32768 by default), on Windows and macOS 49152.
func firstSourcePort() int {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	if err != nil {
		return 49152
	}
	var first, last int
	if n, _ := fmt.Sscan(string(b), &first, &last); n != 2 {
		return 49152
	}
	return first
}

// reserve returns n addresses on 127.0.0.1 with ports of p, all different, and the function that gives them back. The
// caller calls it once the processes that bound the addresses ended.
func (p *portPool) reserve(n int) ([]string, func(), error) {
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("rqlitetest: %w", err)
	}
	var addrs, locks []string
	release := func() {
		for _, lock := range locks {
			os.Remove(lock)
		}
	}
	for len(addrs) < n {
		port, lock, err := p.one()
		if err != nil {
			release()
			return nil, nil, err
		}
		addrs = append(addrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		locks = append(locks, lock)
	}
	return addrs, release, nil
}

// one locks a port of p that nothing holds, and returns it with the file of its lock. The lock is a file made with
// O_EXCL, which only one of the processes that ask at the same time wins. The port is then bound and let go once, which
// finds the ports that something else holds: a process that outlived its run, or a range that the system keeps for itself,
// as Windows does for some.
func (p *portPool) one() (int, string, error) {
	for range portTries {
		port := p.low + rand.IntN(p.high-p.low)
		lock := filepath.Join(p.dir, strconv.Itoa(port))
		f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, fs.ErrExist) {
			if fi, err := os.Stat(lock); err == nil && time.Since(fi.ModTime()) > staleAfter {
				os.Remove(lock)
			}
			continue
		}
		if err != nil {
			return 0, "", fmt.Errorf("rqlitetest: locking a port: %w", err)
		}
		f.Close()
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			os.Remove(lock)
			continue
		}
		l.Close()
		return port, lock, nil
	}
	return 0, "", fmt.Errorf("rqlitetest: no port from %d to %d that nothing holds, in %d tries; %d are locked by the tests of this run", p.low, p.high, portTries, p.held())
}

// held returns how many ports of p are locked now, by the tests of this process and of the others of the run.
func (p *portPool) held() int {
	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return 0
	}
	return len(entries)
}
