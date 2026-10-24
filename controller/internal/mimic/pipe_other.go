//go:build !windows

package mimic

import (
	"context"
	"net"
)

// The node runs on Windows only, and its pipes are named pipes. Elsewhere a pipe is a Unix socket
// at the path that names it, so that the rest of the sidecar builds and is tested on Linux as well.

func listenPipe(name string) (net.Listener, error) {
	return net.Listen("unix", name)
}

func dialPipe(ctx context.Context, name string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", name)
}
