//go:build !windows

package install

import (
	"errors"
	"testing"
)

// On an OS without Windows services, RestartNode refuses as Install does.
func TestRestartNodeRefuses(t *testing.T) {
	if err := RestartNode(); !errors.Is(err, errNotWindows) {
		t.Errorf("RestartNode: %v, want the error of an OS without Windows services", err)
	}
}
