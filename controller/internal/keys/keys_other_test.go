//go:build !windows

package keys

import "testing"

// cleanupKeys does nothing: the keys of a data directory are files in it.
func cleanupKeys(*testing.T, string) {}
