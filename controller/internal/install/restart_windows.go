//go:build windows

package install

import (
	"fmt"

	"golang.org/x/sys/windows/svc/mgr"
)

// NodeServiceName is the name of the Node service, ranzvpnserver, for the verbs of `ranz node`.
const NodeServiceName = nodeServiceName

// RestartNode stops the Node service and starts it again, and waits until it runs: the Node takes
// its Controller settings at start (`ranz node controller`, SDN-90). It needs administrator rights.
func RestartNode() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("the service manager (does ranz run as an Administrator?): %w", err)
	}
	defer m.Disconnect()
	if err := stopService(m, nodeServiceName); err != nil {
		return err
	}
	s, err := m.OpenService(nodeServiceName)
	if err != nil {
		return fmt.Errorf("the %s service: %w", nodeServiceName, err)
	}
	defer s.Close()
	return startService(s, nodeServiceName)
}
