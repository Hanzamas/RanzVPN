//go:build !windows

package install

// NodeServiceName is the name of the Node service, ranzvpnserver, for the verbs of `ranz node`.
const NodeServiceName = nodeServiceName

// RestartNode refuses: there is no Windows service on this OS.
func RestartNode() error { return errNotWindows }
