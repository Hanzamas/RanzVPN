package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/Hanzamas/RanzVPN/controller/internal/audit"
	"github.com/Hanzamas/RanzVPN/controller/internal/controlpb"
	"github.com/Hanzamas/RanzVPN/controller/internal/intent"
	"github.com/Hanzamas/RanzVPN/controller/internal/store"
)

// The live operations of operators (SDN-50 #243, ADR-0031 amendment of 2026-10-27): what an operator
// asks of the controller at the moment he asks it, and what the intent never holds. They are the
// sessions (sessions.go), the bans of users (bans.go) and the tables of the L2 Networks (tables.go).
// Each is a call of the API under /api/v1/operations that needs the role operator, and each makes an
// audit record of its own, kind operation (auditOperation).
//
// An operation on the tables of a Network is a request to a node. The controller sends the node an
// Operation on its control stream, with an id of its own, and the node answers with an OperationResult
// of the same id: operate queues the Operation for the writer of the stream (writeLoop), and the
// reader of the stream (readLoop) hands the answer to the call that waits for it
// (takeOperationResult). Only a node that reports the Capability operations is sent one, since a node
// that does not know the frame ends its stream.

const (
	// DefaultOperationTimeout is how long the controller waits for the answer of a node to an
	// Operation, when Config.OperationTimeout is 0.
	DefaultOperationTimeout = 10 * time.Second
	// maxQueuedOperations bounds the Operations that wait for the writer of one stream, so that a
	// node that does not read cannot make the controller hold what operators ask of it without end.
	maxQueuedOperations = 64
)

var (
	// ErrOperationTimeout marks an Operation that its node did not answer within the timeout.
	ErrOperationTimeout = errors.New("the node did not answer in time")
	// errNoStream marks an Operation for a node whose control stream ended, or that has none.
	errNoStream = errors.New("the node has no control stream")
	// errBusy marks an Operation for a node that has too many waiting.
	errBusy = errors.New("the node has too many operations waiting")
)

// badRequest is the error of a live operation that its caller asked for wrongly: its text says what is
// wrong, and to the API it is an intent.ErrInvalid, which it answers with 400 Bad Request.
type badRequest string

func (e badRequest) Error() string { return string(e) }

// Is makes a badRequest an intent.ErrInvalid.
func (e badRequest) Is(target error) bool { return target == intent.ErrInvalid }

// badRequestf returns the badRequest that format and args make.
func badRequestf(format string, args ...any) error {
	return badRequest(fmt.Sprintf(format, args...))
}

// liveState is what the controller keeps for the live operations: the banned users (bans.go) and the
// Operations that wait for the answer of a node.
type liveState struct {
	// bans are the banned users by name, guarded by Controller.mu. New loads them from the store.
	bans map[string]store.Ban
	// timeout is how long an Operation waits for its answer. New sets it, and nothing changes it.
	timeout time.Duration

	mu      sync.Mutex // guards seq and pending
	seq     uint64     // the id of the last Operation
	pending map[uint64]*pendingOperation
}

// liveStream is what a control stream holds for the live operations: the session that it is
// (sessions.go) and the Operations that wait for its writer. Controller.mu guards it.
type liveStream struct {
	id     string    // the id of the session, which an operator names to end it
	since  time.Time // when the node's stream was accepted
	source string    // the address that the stream came from, without its port
	ops    []*controlpb.Operation
}

// pendingOperation is an Operation that was sent, or queued to be sent, to the node of s and that
// waits for its answer.
type pendingOperation struct {
	s    *stream
	done chan *controlpb.OperationResult // holds the answer: one at most
}

// newLiveStream returns the session of a control stream that came from remote: a new random id, and
// the time now.
func newLiveStream(remote net.Addr) liveStream {
	var id [8]byte
	_, _ = rand.Read(id[:])
	return liveStream{id: hex.EncodeToString(id[:]), since: time.Now().UTC().Truncate(time.Millisecond), source: audit.Host(remote.String())}
}

// startLiveOperations sets the timeout of the Operations from cfg and loads the bans of users from
// the store. New calls it before it compiles the first desired states, which leave out the Nodes of
// the banned users.
func (c *Controller) startLiveOperations(ctx context.Context, cfg Config) error {
	c.live.timeout = cfg.OperationTimeout
	if c.live.timeout <= 0 {
		c.live.timeout = DefaultOperationTimeout
	}
	bans, err := c.store.Bans(ctx)
	if err != nil {
		return err
	}
	c.live.bans = make(map[string]store.Ban, len(bans))
	for _, b := range bans {
		c.live.bans[b.User] = b
	}
	return nil
}

// auditOperation records a live operation in the audit log: the kind operation, with the action and
// the subject, and the origin of the call in ctx as its actor and its source. An operation that
// failed is recorded with the outcome failure and the error as its message; one that worked, with
// message. A record that cannot be stored is logged by the audit log: the operation is done and stays.
func (c *Controller) auditOperation(ctx context.Context, action, subject string, err error, message string) {
	r := audit.Record{Kind: audit.Operation, Action: action, Subject: subject, Outcome: audit.Success, Message: message}
	if err != nil {
		r.Outcome, r.Message = audit.Failure, err.Error()
	}
	_ = c.RecordAudit(ctx, r)
}

// operate sends the Operation op to the node of s and waits for its answer, which is the
// OperationResult of the same id. The id is the controller's: operate gives op the next one. It
// returns ErrOperationTimeout when the node does not answer within the timeout, errNoStream when the
// stream ends or is not the one of its node any more, and the error of ctx when ctx ends first.
func (c *Controller) operate(ctx context.Context, s *stream, op *controlpb.Operation) (*controlpb.OperationResult, error) {
	p := &pendingOperation{s: s, done: make(chan *controlpb.OperationResult, 1)}
	c.live.mu.Lock()
	c.live.seq++
	op.Id = c.live.seq
	if c.live.pending == nil {
		c.live.pending = map[uint64]*pendingOperation{}
	}
	c.live.pending[op.Id] = p
	c.live.mu.Unlock()
	defer c.forgetOperation(op.Id)

	c.mu.Lock()
	n := c.nodes[s.name]
	switch {
	case n == nil || n.stream != s:
		c.mu.Unlock()
		return nil, errNoStream
	case len(s.live.ops) >= maxQueuedOperations:
		c.mu.Unlock()
		return nil, errBusy
	}
	s.live.ops = append(s.live.ops, op)
	c.mu.Unlock()
	// What the writer has not taken when this call ends is no longer wanted
	defer c.dequeueOperation(s, op)
	s.poke()

	timer := time.NewTimer(c.live.timeout)
	defer timer.Stop()
	select {
	case res := <-p.done:
		return res, nil
	case <-timer.C:
		return nil, ErrOperationTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.done:
		return nil, errNoStream
	}
}

// forgetOperation drops the Operation id, which is answered, or is no longer waited for.
func (c *Controller) forgetOperation(id uint64) {
	c.live.mu.Lock()
	defer c.live.mu.Unlock()
	delete(c.live.pending, id)
}

// dequeueOperation takes op out of the Operations that wait for the writer of s, if it is still
// there.
func (c *Controller) dequeueOperation(s *stream, op *controlpb.Operation) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if i := slices.Index(s.live.ops, op); i >= 0 {
		s.live.ops = slices.Delete(s.live.ops, i, i+1)
	}
}

// takeOperationResult hands the OperationResult r, which the node of s sent, to the call that waits
// for it. An answer that no Operation of this node waits for, because it came too late or because
// the node sent an id that it was never given, is dropped: a node can answer only what it was asked.
func (c *Controller) takeOperationResult(s *stream, r *controlpb.OperationResult) {
	c.live.mu.Lock()
	p := c.live.pending[r.GetId()]
	if p != nil && p.s == s {
		delete(c.live.pending, r.GetId())
	} else {
		p = nil
	}
	c.live.mu.Unlock()
	if p == nil {
		c.log.Debug("an operation result dropped: no operation of the node waits for it", "node", s.name, "id", r.GetId())
		return
	}
	// The channel holds one answer, and the Operation was taken out of pending, so this never waits
	p.done <- r
}

// sendOperations writes the Operations ops, which the writer of s took from its queue, to the stream.
// It reports false after it closed the stream because a write failed.
func (c *Controller) sendOperations(s *stream, ops []*controlpb.Operation) bool {
	for _, op := range ops {
		if _, err := s.conn.Write(&controlpb.ControlMessage{Body: &controlpb.ControlMessage_Operation{Operation: op}}); err != nil {
			c.log.Warn("sending an operation", "node", s.name, "id", op.GetId(), "err", err)
			s.shut()
			return false
		}
		c.log.Info("operation sent", "node", s.name, "id", op.GetId(), "kind", op.GetKind().String(), "network", op.GetNetwork())
	}
	return true
}
