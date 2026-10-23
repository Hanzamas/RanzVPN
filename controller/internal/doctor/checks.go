package doctor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/Hanzamas/RanzVPN/controller/internal/certgen"
)

// clock is the time that the kernel check reads and waits on, which a test replaces.
type clock struct {
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// realClock is the clock of the host.
var realClock = clock{
	now: time.Now,
	sleep: func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-t.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	},
}

func checkKernel(ctx context.Context) error {
	return kernel(ctx, realClock)
}

// kernel checks the clock as the kernel check of vpncmd checked its tick counter: it never goes
// backwards over ten pauses of 100 ms, and the ten pauses take between half a second and two.
func kernel(ctx context.Context, c clock) error {
	const (
		rounds = 10
		pause  = 100 * time.Millisecond
	)
	start := c.now()
	prev := start
	for range rounds {
		t := c.now()
		if t.Before(prev) {
			return fmt.Errorf("the clock went backwards by %v", prev.Sub(t))
		}
		prev = t
		if err := c.sleep(ctx, pause); err != nil {
			return err
		}
	}
	elapsed := c.now().Sub(start)
	if elapsed <= 5*pause || elapsed >= 20*pause {
		return fmt.Errorf("%d pauses of %v took %v, not between %v and %v", rounds, pause, elapsed, 5*pause, 20*pause)
	}
	return nil
}

// checkMemory allocates 2,000 buffers of 1,000 bytes, fills them with a pattern, grows each to
// three times its size and checks that the whole pattern is still there, as the memory check of
// vpncmd did with its allocator.
func checkMemory(context.Context) error {
	const (
		count = 2000
		size  = 1000
	)
	bufs := make([][]byte, count)
	for i := range bufs {
		b := make([]byte, size)
		for j := range b {
			b[j] = byte(j % 256)
		}
		bufs[i] = b
	}
	for i, b := range bufs {
		grown := make([]byte, 3*size)
		copy(grown, b)
		for j := size; j < len(grown); j++ {
			grown[j] = byte(j % 256)
		}
		bufs[i] = grown
	}
	for i, b := range bufs {
		for j, v := range b {
			if v != byte(j%256) {
				return fmt.Errorf("buffer %d holds %d at offset %d, not %d", i, v, j, byte(j%256))
			}
		}
	}
	return nil
}

// checkStrings splits and converts text as the string check of vpncmd did: 64 numbers in a
// comma-separated list, a number as ANSI and as Unicode text, and text outside ASCII across
// UTF-16.
func checkStrings(context.Context) error {
	var list []string
	want := 0
	for i := range 64 {
		list = append(list, strconv.Itoa(i))
		want += i
	}
	sum := 0
	for _, s := range strings.Split(strings.Join(list, ","), ",") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("converting %q of a split list: %w", s, err)
		}
		sum += n
	}
	if sum != want {
		return fmt.Errorf("the numbers of a split list add up to %d, not %d", sum, want)
	}
	const number = "123456789"
	if n, err := strconv.Atoi(number); err != nil || n != 123456789 {
		return fmt.Errorf("the ANSI text %s converts to %d (%v)", number, n, err)
	}
	wide := string(utf16.Decode(utf16.Encode([]rune(number))))
	if n, err := strconv.Atoi(wide); err != nil || n != 123456789 {
		return fmt.Errorf("the Unicode text %s converts to %d (%v)", number, n, err)
	}
	const text = "Ranz é世界 \U0001F310"
	if back := string(utf16.Decode(utf16.Encode([]rune(text)))); back != text {
		return fmt.Errorf("the text %q comes back from UTF-16 as %q", text, back)
	}
	return nil
}

func checkFileSystem(context.Context) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("the path of the executable: %w", err)
	}
	return fileSystem(exe, os.TempDir())
}

// fileSystem checks that the folder of the executable exe lists it, as the file system check of
// vpncmd checked its own, and that a file of 1,234,567 bytes written in the folder tmp reads back
// as it was written, and goes again.
func fileSystem(exe, tmp string) error {
	dir, base := filepath.Dir(exe), filepath.Base(exe)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("listing %s: %w", dir, err)
	}
	listed := false
	for _, e := range entries {
		if strings.EqualFold(e.Name(), base) {
			listed = true
			break
		}
	}
	if !listed {
		return fmt.Errorf("the folder %s does not list %s", dir, base)
	}

	const size = 1234567
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	f, err := os.CreateTemp(tmp, "ranz-doctor-*")
	if err != nil {
		return fmt.Errorf("creating a file in %s: %w", tmp, err)
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", name, err)
	}
	info, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("the size of %s: %w", name, err)
	}
	if info.Size() != size {
		return fmt.Errorf("%s is %d bytes, not %d", name, info.Size(), size)
	}
	back, err := os.ReadFile(name)
	if err != nil {
		return fmt.Errorf("reading %s: %w", name, err)
	}
	if !bytes.Equal(back, data) {
		return fmt.Errorf("%s reads back other than it was written", name)
	}
	return nil
}

// checkThreads runs the thread check of vpncmd: 32 threads that each add to a counter 32 times
// under a lock, which must come to 1,024, and a thread that starts the next one and waits for it,
// 32 deep.
func checkThreads(context.Context) error {
	const (
		workers = 32
		steps   = 32
	)
	var (
		mu    sync.Mutex
		total int
		wg    sync.WaitGroup
	)
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range steps {
				mu.Lock()
				total++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if total != workers*steps {
		return fmt.Errorf("%d threads that add %d times each made %d, not %d", workers, steps, total, workers*steps)
	}

	depth := 0
	var nest func(n int)
	nest = func(n int) {
		if n == 0 {
			return
		}
		depth++
		done := make(chan struct{})
		go func() {
			defer close(done)
			nest(n - 1)
		}()
		<-done
	}
	nest(workers)
	if depth != workers {
		return fmt.Errorf("threads that start one another reached a depth of %d, not %d", depth, workers)
	}
	return nil
}

// networkTimeout bounds each connection of the network check.
const networkTimeout = 10 * time.Second

func checkNetwork(ctx context.Context) error {
	return network(ctx, "127.0.0.1:0", 8, 128)
}

// network checks the network as the network check of vpncmd did: it serves TLS on the address
// address with a certificate that it makes, and opens clients connections to it at once; each
// reads count numbers that the server sends, 1, 2, 3 and on, and they must arrive in order. The
// clients check the certificate of the server against the one that was made.
func network(ctx context.Context, address string, clients, count int) error {
	key, err := certgen.NewKey(0)
	if err != nil {
		return fmt.Errorf("a key for the test server: %w", err)
	}
	der, err := certgen.Make(certgen.Request{Name: certgen.Name{CommonName: "localhost"}, Days: 1}, key, nil)
	if err != nil {
		return fmt.Errorf("a certificate for the test server: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("the certificate of the test server: %w", err)
	}
	ln, err := tls.Listen("tcp", address, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		return fmt.Errorf("listening on %s: %w", address, err)
	}
	defer ln.Close()
	go serveNumbers(ln, 2*count)

	trust := x509.NewCertPool()
	trust.AddCert(cert)
	cfg := &tls.Config{RootCAs: trust, ServerName: "localhost"}
	results := make(chan error, clients)
	for range clients {
		go func() { results <- readNumbers(ctx, ln.Addr().String(), cfg, count) }()
	}
	var failed []error
	for range clients {
		if err := <-results; err != nil {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

// serveNumbers accepts the connections of ln and sends each the numbers 1 to count, four bytes
// each, big-endian.
func serveNumbers(ln net.Listener, count int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(networkTimeout))
			var b [4]byte
			for i := 1; i <= count; i++ {
				binary.BigEndian.PutUint32(b[:], uint32(i))
				if _, err := conn.Write(b[:]); err != nil {
					return
				}
			}
		}()
	}
}

// readNumbers connects to addr over TLS with cfg and reads the numbers 1 to count in order.
func readNumbers(ctx context.Context, addr string, cfg *tls.Config, count int) error {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: networkTimeout}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(networkTimeout))
	var b [4]byte
	for want := 1; want <= count; want++ {
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return fmt.Errorf("reading the number %d from %s: %w", want, addr, err)
		}
		if got := binary.BigEndian.Uint32(b[:]); got != uint32(want) {
			return fmt.Errorf("received %d from %s, not %d", got, addr, want)
		}
	}
	return nil
}
