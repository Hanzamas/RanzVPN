//go:build windows

package main

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

// dialNode connects to the named pipe of the node: overlapped I/O through go-winio, so that the
// session reads and writes the pipe at the same time.
func dialNode(ctx context.Context, name string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, name)
}
