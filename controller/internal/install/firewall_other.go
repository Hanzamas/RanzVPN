//go:build !windows

package install

import "io"

// AllowTestPort does nothing: this OS has no Windows Firewall, and the port is the business of its
// own firewall.
func AllowTestPort(io.Writer, int) func() { return func() {} }
