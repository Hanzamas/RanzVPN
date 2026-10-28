package controllercmd

import (
	"testing"

	"github.com/Hanzamas/RanzVPN/controller/internal/port"
)

// The limits for a source of the TLS port are settings (AUD1-DT-3, #451): without a flag each is 0, which the port reads
// as its default, a flag sets it, and a value below 0 makes no sense.
func TestParseFlagsLimitsForASource(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil || cfg.limits != (port.Limits{}) {
		t.Errorf("no flags: the limits are %+v, %v, want the defaults (all 0)", cfg.limits, err)
	}
	cfg, err = parseFlags([]string{"-max-pending", "100", "-max-pending-per-source", "10", "-connect-rate", "5.5", "-connect-burst", "20", "-handshake-rate", "2", "-handshake-burst", "4"})
	want := port.Limits{MaxPending: 100, MaxPendingPerSource: 10, ConnectRate: 5.5, ConnectBurst: 20, HandshakeRate: 2, HandshakeBurst: 4}
	if err != nil || cfg.limits != want {
		t.Errorf("the six flags: the limits are %+v, %v, want %+v", cfg.limits, err, want)
	}
	for _, args := range [][]string{{"-max-pending", "-1"}, {"-max-pending-per-source", "-1"}, {"-connect-rate", "-0.5"}, {"-connect-burst", "-1"}, {"-handshake-rate", "-1"}, {"-handshake-burst", "-1"}} {
		if _, err := parseFlags(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
}
