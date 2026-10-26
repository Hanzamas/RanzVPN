//go:build !windows

package port

import "testing"

// Without Windows there is no front door to take sockets from: the controller listens itself.
func TestNoFrontDoor(t *testing.T) {
	if DefaultFrontDoorPipe != "" {
		t.Errorf("the default handoff pipe is %q here", DefaultFrontDoorPipe)
	}
	fd, err := ListenFrontDoor(`\\.\pipe\ranz-port-test`, &Server{})
	if err == nil || fd != nil {
		t.Fatal("a handoff pipe was made without Windows")
	}
	var none *FrontDoor
	if none.Addr() != "" || none.Close() != nil {
		t.Error("the FrontDoor of no Windows has an address or a Close that fails")
	}
}
