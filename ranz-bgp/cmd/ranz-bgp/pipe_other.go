//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
)

// dialNode fails: the node runs on Windows only, so its named pipe exists there only. The rest of
// ranz-bgp builds and is tested on Linux as well.
func dialNode(ctx context.Context, name string) (net.Conn, error) {
	return nil, errors.New("the named pipe of the node exists on Windows only")
}
