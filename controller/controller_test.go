package controllercmd

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
)

// A taken TLS port falls back, the fallback sticks once the port is free again (ADR-0020), and
// an explicit -listen goes back to the port and drops the record.
func TestListenTLSFallback(t *testing.T) {
	dir := t.TempDir()
	hold, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := hold.Addr().String()

	ln, fell, err := listenTLS(addr, "0", false, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fell || ln.Addr().String() == addr {
		t.Errorf("with %s taken the port is %s (fell back: %v), want a fallback", addr, ln.Addr(), fell)
	}
	ln.Close()
	if _, err := os.Stat(filepath.Join(dir, fallbackFile)); err != nil {
		t.Errorf("the fallback is not recorded: %v", err)
	}

	hold.Close()
	ln, fell, err = listenTLS(addr, "0", false, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fell {
		t.Errorf("with %s free again the controller left the recorded fallback for %s", addr, ln.Addr())
	}
	ln.Close()

	ln, fell, err = listenTLS(addr, "0", true, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fell || ln.Addr().String() != addr {
		t.Errorf("an explicit -listen %s gave %s (fell back: %v)", addr, ln.Addr(), fell)
	}
	ln.Close()
	if _, err := os.Stat(filepath.Join(dir, fallbackFile)); !os.IsNotExist(err) {
		t.Errorf("an explicit -listen kept the fallback record (%v)", err)
	}

	ln, fell, err = listenTLS(addr, "0", false, dir)
	if err != nil {
		t.Fatal(err)
	}
	if fell || ln.Addr().String() != addr {
		t.Errorf("with no record and %s free the port is %s (fell back: %v)", addr, ln.Addr(), fell)
	}
	ln.Close()
}

func TestParseFlagsListenSet(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil || cfg.listen != ":443" || cfg.listenSet {
		t.Errorf("no flags: listen %q, set %v, %v", cfg.listen, cfg.listenSet, err)
	}
	cfg, err = parseFlags([]string{"-listen", ":443"})
	if err != nil || !cfg.listenSet {
		t.Errorf("-listen :443: set %v, %v", cfg.listenSet, err)
	}
}

// The service log keeps within 30 days and 256 MB unless the flags say otherwise (SDN-54), 0 is no
// limit, and a limit that makes no sense is refused.
func TestParseFlagsLogLimits(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil || cfg.logLimits() != logfile.DefaultLimits() {
		t.Errorf("no flags: the log limits are %+v, %v", cfg.logLimits(), err)
	}
	cfg, err = parseFlags([]string{"-log-days", "7", "-log-mb", "64"})
	if err != nil || cfg.logLimits() != logfile.LimitsOf(7, 64) {
		t.Errorf("-log-days 7 -log-mb 64: the log limits are %+v, %v", cfg.logLimits(), err)
	}
	cfg, err = parseFlags([]string{"-log-days", "0", "-log-mb", "0"})
	if err != nil || cfg.logLimits() != (logfile.Limits{}) {
		t.Errorf("-log-days 0 -log-mb 0: the log limits are %+v, %v", cfg.logLimits(), err)
	}
	for _, args := range [][]string{{"-log-days", "-1"}, {"-log-mb", "-5"}, {"-log-days", "36501"}, {"-log-mb", "1048577"}} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}
