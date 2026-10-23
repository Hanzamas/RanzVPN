//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// serviceName is the Node's Windows service (ADR-0020 decision 4); serviceAccount is its virtual
// account (ADR-0039 decision 3), the same way controller/service_windows.go names its own
// service's account.
const (
	serviceName    = "ranzvpnserver"
	serviceAccount = `NT SERVICE\` + serviceName
)

// controllerServiceName is the Controller's Windows service (controller/service_windows.go's own
// serviceName): install and uninstall start and stop it by name, and controllercmd.Install and
// controllercmd.Uninstall do the rest.
const controllerServiceName = "ranz-controller"

// dirSDDL is the access list of the Ranz VPN folder under Program Files: full control for SYSTEM
// and the Administrators, protected so it inherits nothing from Program Files and grants nothing
// to Users (the ticket's acceptance criterion).
const dirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// serviceWait bounds how long Install and Uninstall wait for a service to reach the state they
// asked it for.
const serviceWait = 30 * time.Second

// installDir is the fixed Ranz VPN folder under Program Files that Install writes the payload
// files into (ADR-0011 and ADR-0020 amendments): the folder the spike MSI of ADR-0020 already used
// for the current server.
func installDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Ranz VPN")
}

func nodeExePath() string {
	return filepath.Join(installDir(), payload.NodeExe.Name)
}

// protectDir creates dir if it does not exist and sets its DACL to sddl, protected so it inherits
// nothing from its parent.
func protectDir(dir, sddl string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("the folder %s: %w", dir, err)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	return nil
}

func serviceExists(m *mgr.Mgr, name string) bool {
	s, err := m.OpenService(name)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// waitState polls s until it reaches want, for up to serviceWait.
func waitState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(serviceWait)
	for {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("did not reach state %d within %s (it is %d)", want, serviceWait, status.State)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ensureRunning starts the service name if it is not already running.
func ensureRunning(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	if status.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("starting the %s service: %w", name, err)
	}
	if err := waitState(s, svc.Running); err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	return nil
}

// stopService stops the service name if it is running, and waits for it to reach the Stopped
// state.
func stopService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("the %s service is not installed: %w", name, err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	if status.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stopping the %s service: %w", name, err)
		}
		if err := waitState(s, svc.Stopped); err != nil {
			return fmt.Errorf("the %s service: %w", name, err)
		}
	}
	return nil
}

// stopAndDelete stops the service name (stopService) and removes it.
func stopAndDelete(m *mgr.Mgr, name string) error {
	if err := stopService(m, name); err != nil {
		return err
	}
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return fmt.Errorf("removing the %s service: %w", name, err)
	}
	return nil
}

// removeDir removes dir, retrying for a few seconds: a service that just stopped can hold its exe
// file open for a short moment after the SCM reports it Stopped.
func removeDir(dir string) error {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	deadline := time.Now().Add(10 * time.Second)
	var err error
	for {
		if err = os.RemoveAll(dir); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("removing %s: %w", dir, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Install writes the Node payload into the Ranz VPN folder under Program Files, registers the
// Node service ranzvpnserver under its virtual account and starts it, and, with controller, also
// registers and starts the Controller service. See the package doc for what a second call does.
func Install(controller bool) error {
	dir := installDir()
	if err := protectDir(dir, dirSDDL); err != nil {
		return fmt.Errorf("install: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer m.Disconnect()

	if serviceExists(m, serviceName) {
		if err := ensureRunning(m, serviceName); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	} else {
		if err := payload.Install(dir, payload.NodeExe); err != nil {
			return fmt.Errorf("install: the Node payload: %w", err)
		}
		s, err := m.CreateService(serviceName, nodeExePath(), mgr.Config{
			DisplayName:      "Ranz VPN Node",
			Description:      "Runs the Ranz VPN data plane (ranz-node).",
			StartType:        mgr.StartAutomatic,
			ServiceStartName: serviceAccount,
			SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
		}, "/service")
		if err != nil {
			return fmt.Errorf("install: registering the %s service: %w", serviceName, err)
		}
		defer s.Close()
		if err := s.Start(); err != nil {
			return fmt.Errorf("install: starting the %s service: %w", serviceName, err)
		}
		if err := waitState(s, svc.Running); err != nil {
			return fmt.Errorf("install: the %s service: %w", serviceName, err)
		}
	}

	if !controller {
		return nil
	}
	if serviceExists(m, controllerServiceName) {
		if err := ensureRunning(m, controllerServiceName); err != nil {
			return fmt.Errorf("install: %w", err)
		}
		return nil
	}
	if err := controllercmd.Install(); err != nil {
		return fmt.Errorf("install: the Controller service: %w", err)
	}
	cs, err := m.OpenService(controllerServiceName)
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	defer cs.Close()
	if err := cs.Start(); err != nil {
		return fmt.Errorf("install: starting the %s service: %w", controllerServiceName, err)
	}
	if err := waitState(cs, svc.Running); err != nil {
		return fmt.Errorf("install: the %s service: %w", controllerServiceName, err)
	}
	return nil
}

// Uninstall stops and removes the Node service and, if it was registered, the Controller service,
// deletes the Ranz VPN folder under Program Files, and leaves the Node's data directory alone.
func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	defer m.Disconnect()

	var errs []error
	if serviceExists(m, controllerServiceName) {
		if err := stopService(m, controllerServiceName); err != nil {
			errs = append(errs, fmt.Errorf("the %s service: %w", controllerServiceName, err))
		} else if err := controllercmd.Uninstall(); err != nil {
			errs = append(errs, fmt.Errorf("the %s service: %w", controllerServiceName, err))
		}
	}
	if err := stopAndDelete(m, serviceName); err != nil {
		errs = append(errs, fmt.Errorf("the %s service: %w", serviceName, err))
	}
	if err := removeDir(installDir()); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("uninstall: %w", errors.Join(errs...))
	}
	return nil
}
