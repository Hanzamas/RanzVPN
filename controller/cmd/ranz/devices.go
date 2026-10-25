package main

import (
	"context"
	"io"

	"github.com/Hanzamas/RanzVPN/controller/internal/api"
)

// The verbs of the WireGuard Devices (SDN-80 #375):
//
//	ranz get devices             print every Device with the last handshake and the traffic that its
//	                             gateway reported
//	ranz get device-config NAME  print the WireGuard configuration of the Device NAME, the text of the
//	                             .conf file that a stock WireGuard client imports
//
// args are the arguments after get.
func getDevices(ctx context.Context, c *api.Client, args []string, out io.Writer) error {
	switch {
	case len(args) == 1 && args[0] == "devices":
		devices, err := c.Devices(ctx)
		if err != nil {
			return err
		}
		return show(out, api.DeviceList{Devices: devices})
	case len(args) == 2 && args[0] == "device-config":
		config, err := c.DeviceConfig(ctx, args[1])
		if err != nil {
			return err
		}
		_, err = io.WriteString(out, config)
		return err
	}
	return errUsage
}
