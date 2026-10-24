//go:build windows

package mimic

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// pipeSDDL is the strict DACL of the pipes that the sidecar creates (ADR-0039 decision 3), the one
// that the node gives its own: the owner alone, the account of the node, which the sidecar runs as.
// A pipe is for local clients only (go-winio rejects remote clients).
const pipeSDDL = "D:P(A;;GA;;;OW)"

// pipeBuffer is the size of the buffers of a pipe, in each direction.
const pipeBuffer = 64 * 1024

// listenPipe creates the named pipe name, which the node connects to: overlapped I/O through
// go-winio, so that a stream reads and writes the pipe at the same time.
func listenPipe(name string) (net.Listener, error) {
	return winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL, InputBufferSize: pipeBuffer, OutputBufferSize: pipeBuffer})
}

// dialPipe connects to the named pipe name that the node created, until ctx ends when all its
// instances are busy.
func dialPipe(ctx context.Context, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, name)
}
