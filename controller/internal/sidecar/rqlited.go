// Package sidecar runs rqlited, the rqlite server, as a child process of the controller (#176
// "Controller store": rqlite as a sidecar of each controller). One code path serves one member
// and the 3 or 5 members of a cluster: a member of a cluster is the same process with the Raft
// addresses of the members to join (rqlite's automatic clustering with -join and
// -bootstrap-expect, https://rqlite.io/docs/clustering/automatic-clustering/).
//
// rqlited ends with the controller, also when the controller is killed: on Linux the kernel sends
// it SIGKILL when the controller exits (Pdeathsig), on Windows it runs in a job object that ends
// it when the controller's handle to the job closes, as every handle does when a process exits.
// So a restarted controller finds the ports of its member free.
package sidecar

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Rqlited is one rqlited process.
type Rqlited struct {
	Path     string    // the rqlited executable
	DataDir  string    // its data directory
	HTTPAddr string    // host:port of its HTTP API
	RaftAddr string    // host:port of its Raft transport
	RaftAdv  string    // host:port of its Raft transport as the other members reach it, RaftAddr when empty
	NodeID   string    // its Raft node id, "1" when empty
	Join     []string  // the Raft addresses of the members of the cluster; none for one member
	Expect   int       // the number of members that form a new cluster (rqlited -bootstrap-expect), 0 to join one
	Output   io.Writer // its standard output and error, discarded when nil

	// AuthFile is the credential file of rqlited (-auth, see credential.go): every request of its
	// HTTP API then needs the credential, and a member of a cluster joins with it (-join-as). Empty
	// for no credential.
	AuthFile string
	// NodeCACert, NodeCert and NodeKey are the PEM files of the mutual TLS between the members
	// (-node-cert with -node-verify-client): the Raft transport and the node API of the cluster are encrypted, and a
	// member that does not present a certificate of NodeCACert is refused. All three, or none.
	NodeCACert string
	NodeCert   string
	NodeKey    string

	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// args returns the command line of rqlited.
func (r *Rqlited) args() []string {
	id := r.NodeID
	if id == "" {
		id = "1"
	}
	args := []string{"-node-id", id, "-http-addr", r.HTTPAddr, "-raft-addr", r.RaftAddr}
	if r.RaftAdv != "" {
		args = append(args, "-raft-adv-addr", r.RaftAdv)
	}
	if r.AuthFile != "" {
		args = append(args, "-auth", r.AuthFile)
		if len(r.Join) > 0 {
			args = append(args, "-join-as", CredentialUser)
		}
	}
	if r.NodeCert != "" {
		args = append(args, "-node-cert", r.NodeCert, "-node-key", r.NodeKey, "-node-ca-cert", r.NodeCACert, "-node-verify-client")
	}
	if len(r.Join) > 0 {
		args = append(args, "-join", strings.Join(r.Join, ","))
	}
	if r.Expect > 0 {
		args = append(args, "-bootstrap-expect", strconv.Itoa(r.Expect))
	}
	return append(args, r.DataDir)
}

// URL returns the URL of the HTTP API.
func (r *Rqlited) URL() string {
	return "http://" + r.HTTPAddr
}

// Start starts rqlited and waits until it serves (its /readyz answers 200, which needs a Raft
// leader, so a new cluster serves once its members found each other), it exits, or ctx ends.
func (r *Rqlited) Start(ctx context.Context) error {
	if err := os.MkdirAll(r.DataDir, 0o700); err != nil {
		return fmt.Errorf("sidecar: %w", err)
	}
	cmd := exec.Command(r.Path, r.args()...)
	if r.Output != nil {
		cmd.Stdout = r.Output
		cmd.Stderr = r.Output
	}
	prepare(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("sidecar: starting %s: %w", r.Path, err)
	}
	release, err := bind(cmd.Process)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("sidecar: tying rqlited to the controller: %w", err)
	}
	done := make(chan struct{})
	r.cmd, r.done = cmd, done
	go func() {
		r.err = cmd.Wait()
		release()
		close(done)
	}()
	var user, password string
	if r.AuthFile != "" {
		if user, password, err = ReadCredential(r.AuthFile); err != nil {
			r.Stop()
			return fmt.Errorf("sidecar: %w", err)
		}
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready(ctx, r.URL()+"/readyz", user, password) {
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

// ReadyTimeout is how long one request of the poll for readiness waits for its answer. The /readyz of rqlited asks the
// leader for its metadata through the Raft port, on a connection of its own, and runs a query, before it answers. On a
// host that is busy, with other programs that take every core and other test processes that open connections, that takes
// more than a second, and a poll that cut each request at a second sent it again, and cut it again, for as long as the host
// stayed busy, while the node was a leader that was ready: a request that the poll sends before the node listens is refused
// at once, so a long wait for the answer costs a start on an idle host nothing.
const ReadyTimeout = 10 * time.Second

func ready(ctx context.Context, url, user, password string) bool {
	ctx, cancel := context.WithTimeout(ctx, ReadyTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	if user != "" {
		req.SetBasicAuth(user, password)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
