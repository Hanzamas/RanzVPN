// Package sidecar runs rqlited, the rqlite server, as a child process of the controller (#176
// "Controller store": rqlite as a sidecar of each controller). This skeleton runs one member;
// the 3 and 5 member clusters use the same process with join flags.
package sidecar

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"
)

// Rqlited is one rqlited process.
type Rqlited struct {
	Path     string    // the rqlited executable
	DataDir  string    // its data directory
	HTTPAddr string    // host:port of its HTTP API
	RaftAddr string    // host:port of its Raft transport
	NodeID   string    // its Raft node id, "1" when empty
	Output   io.Writer // its standard output and error, discarded when nil

	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// URL returns the URL of the HTTP API.
func (r *Rqlited) URL() string {
	return "http://" + r.HTTPAddr
}

// Start starts rqlited and waits until it serves (its /readyz answers 200), it exits, or ctx
// ends.
func (r *Rqlited) Start(ctx context.Context) error {
	if err := os.MkdirAll(r.DataDir, 0o700); err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	id := r.NodeID
	if id == "" {
		id = "1"
	}
	cmd := exec.Command(r.Path, "-node-id", id, "-http-addr", r.HTTPAddr, "-raft-addr", r.RaftAddr, r.DataDir)
	if r.Output != nil {
		cmd.Stdout = r.Output
		cmd.Stderr = r.Output
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sidecar: starting %s: %w", r.Path, err)
	}
	done := make(chan struct{})
	r.cmd, r.done = cmd, done
	go func() {
		r.err = cmd.Wait()
		close(done)
	}()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready(ctx, r.URL()+"/readyz") {
			return nil
		}
		select {
		case <-done:
			r.cmd = nil
			return fmt.Errorf("sidecar: rqlited exited before it was ready: %v", r.err)
		case <-ctx.Done():
			r.Stop()
			return fmt.Errorf("sidecar: rqlited is not ready: %w", ctx.Err())
		case <-tick.C:
		}
	}
}

// Stop stops rqlited and waits for it to exit: an interrupt first where the platform has one,
// so rqlited closes its store itself, and a kill on Windows or after 10 s. rqlite writes a
// change to its Raft log on disk before it acknowledges it, so a kill loses no acknowledged
// write.
func (r *Rqlited) Stop() {
	if r.cmd == nil {
		return
	}
	if err := r.cmd.Process.Signal(os.Interrupt); err != nil {
		_ = r.cmd.Process.Kill()
	}
	select {
	case <-r.done:
	case <-time.After(10 * time.Second):
		_ = r.cmd.Process.Kill()
		<-r.done
	}
	r.cmd = nil
}

// Done is closed when rqlited exits.
func (r *Rqlited) Done() <-chan struct{} {
	return r.done
}

func ready(ctx context.Context, url string) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
