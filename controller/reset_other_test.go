//go:build !windows

package controllercmd

import (
	"errors"
	"os"
	"testing"
)

// Outside Windows only root holds the rights of reset-admin. CI runs the tests as another user.
func TestAdminRightsNeedRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the tests run as root")
	}
	if err := adminRights(); !errors.Is(err, errNoAdminRights) {
		t.Errorf("adminRights of uid %d gave %v, want %v", os.Geteuid(), err, errNoAdminRights)
	}
}
