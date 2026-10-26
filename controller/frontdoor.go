package controllercmd

import (
	"log/slog"

	"github.com/Hanzamas/RanzVPN/controller/internal/port"
)

// serveFrontDoor opens the handoff pipe of -front-door-pipe, through which the front door of a node
// on the same host hands over the connections of the TLS port (SDN-73, #352; ADR-0035), and serves
// them on the TLS port tlsPort. It returns nil without the pipe: none was asked for, or it cannot be
// made, for example because another controller on the host holds the name. The controller then
// takes the connections of its own listener alone, as it does without a front door.
func serveFrontDoor(pipe string, tlsPort *port.Server, log *slog.Logger) *port.FrontDoor {
	if pipe == "" {
		return nil
	}
	fd, err := port.ListenFrontDoor(pipe, tlsPort)
	if err != nil {
		log.Warn("the handoff pipe of the front door is not open: the controller takes the connections of its own listener only", "pipe", pipe, "err", err)
		return nil
	}
	log.Info("handoff pipe of the front door", "pipe", fd.Addr())
	return fd
}
