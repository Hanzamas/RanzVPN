package controller

import (
	"crypto/tls"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/telemetry"
)

// The cap on the control streams that wait for a Hello (CS-4, AUD1-DT-2 #450, control.Waiting). A
// stream waits from the moment that ServeStream takes its TLS connection until its Hello is read.
// When too many wait in all (control.MaxWaiting) or for its source address (control.MaxWaitingPerSource)
// the stream is closed at once, before its Noise handshake, and counted in ranz_control_refused_total.

// refuseWaiting closes tc, a TLS connection that the cap on the streams that wait for a Hello refused
// for the reason err. It logs the refusal once in a while for each reason, with the count of the
// ones it did not log, so that a flood does not fill the log.
func (c *Controller) refuseWaiting(tc *tls.Conn, err error) {
	if skipped, ok := c.waitingLog.Take(err.Error(), time.Now()); ok {
		c.log.Warn("control stream closed: too many wait for a Hello", "remote", tc.RemoteAddr().String(), "err", err, "skipped", skipped)
	}
	tc.Close()
}

// waitingSamples gives the series of the metric control_refused: how many control streams the cap on
// the ones that wait for a Hello closed, for the cap in all and for the cap of one source.
func (c *Controller) waitingSamples() []telemetry.Sample {
	full, source := c.waiting.Refused()
	return []telemetry.Sample{
		{Metric: "control_refused", Labels: []string{"all"}, Value: full},
		{Metric: "control_refused", Labels: []string{"source"}, Value: source},
	}
}
