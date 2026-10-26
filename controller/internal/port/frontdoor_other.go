//go:build !windows

package port

import "errors"

// DefaultFrontDoorPipe is empty where no node hands over sockets: the front door of ADR-0035 is a
// Windows one.
const DefaultFrontDoorPipe = ""

// FrontDoor is the handoff pipe of a controller, which only Windows has.
type FrontDoor struct{}

// ListenFrontDoor fails: the controller takes no sockets from a front door here.
func ListenFrontDoor(name string, s *Server) (*FrontDoor, error) {
	return nil, errors.New("port: the handoff pipe of the front door needs Windows")
}

// Addr is the name of the pipe.
func (f *FrontDoor) Addr() string {
	return ""
}

// Close does nothing.
func (f *FrontDoor) Close() error {
	return nil
}
