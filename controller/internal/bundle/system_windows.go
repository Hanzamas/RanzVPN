//go:build windows

package bundle

import (
	"fmt"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceNames are the Windows services of Ranz: the Node's (ADR-0020 decision 4) and the
// Controller's.
var serviceNames = []string{"ranzvpnserver", "ranz-controller"}

// osVersion returns the version of Windows, as RtlGetVersion tells it, which the manifest of the
// program does not change.
func osVersion() string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}

// Services returns what the service control manager holds of the services of Ranz. It connects to
// the manager and opens each service with the right to read only, so that a service account that is
// no administrator can too: mgr.Connect asks for every right, which only an administrator has.
func Services() ([]Service, error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, fmt.Errorf("the service control manager: %w", err)
	}
	m := &mgr.Mgr{Handle: h}
	defer m.Disconnect()
	out := []Service{}
	for _, name := range serviceNames {
		out = append(out, queryService(m, name))
	}
	return out, nil
}

// queryService returns the state and the configuration of the service name; a service that cannot
// be opened is not installed.
func queryService(m *mgr.Mgr, name string) Service {
	sv := Service{Name: name}
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return sv
	}
	h, err := windows.OpenService(m.Handle, p, windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return sv
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()
	sv.Installed = true
	if st, err := s.Query(); err == nil {
		sv.State = stateName(st.State)
		sv.ProcessID = st.ProcessId
		sv.ExitCode = st.Win32ExitCode
	}
	if cfg, err := s.Config(); err == nil {
		sv.Account = cfg.ServiceStartName
		sv.Command = cfg.BinaryPathName
		sv.StartType = startTypeName(cfg.StartType)
	}
	return sv
}

// stateName returns the name of a state of a service.
func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "start pending"
	case svc.StopPending:
		return "stop pending"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continue pending"
	case svc.PausePending:
		return "pause pending"
	case svc.Paused:
		return "paused"
	}
	return fmt.Sprintf("state %d", uint32(s))
}

// startTypeName returns the name of the start type of a service.
func startTypeName(t uint32) string {
	switch t {
	case mgr.StartAutomatic:
		return "automatic"
	case mgr.StartManual:
		return "manual"
	case mgr.StartDisabled:
		return "disabled"
	}
	return fmt.Sprintf("start type %d", t)
}
