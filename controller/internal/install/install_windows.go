//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	controllercmd "github.com/Hanzamas/RanzVPN/controller"
	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// nodeAccount is the virtual account of the Node service (ADR-0039 decision 3), named the way
// controller/service_windows.go names the account of the Controller service.
const nodeAccount = `NT SERVICE\` + nodeServiceName

// nodeDescription is the description of the Node service. The service sets the same text itself
// when it starts (SVC_RANZVPNSERVER_DESCRIPT of the string table), so the two agree.
const nodeDescription = "This runs the node of Ranz VPN: the server, client, bridge and relay roles that its configuration selects. When this service is stopped, the node on this computer stops."

// serviceWait is how long Install and Uninstall wait for a service to reach the state they asked
// for. The Controller takes the longest: it opens its keys and its store before it reports running.
const serviceWait = 60 * time.Second

// installDir is the Ranz folder: the fixed folder under Program Files that holds ranz-node.exe and
// ranz.exe. The system names Program Files; an environment variable of the caller does not.
func installDir() (string, error) {
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("the Program Files folder: %w", err)
	}
	return filepath.Join(base, folderName), nil
}

// protectDir makes the folder dir if it is not there and sets its access list to folderSDDL. It
// reports whether it made the folder, so that a caller whose checks fail can remove it again.
func protectDir(dir string) (bool, error) {
	_, statErr := os.Stat(dir)
	created := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false, fmt.Errorf("the folder %s: %w", dir, err)
	}
	if err := setAccessList(dir); err != nil {
		if created {
			_ = os.Remove(dir)
		}
		return false, err
	}
	return created, nil
}

// setAccessList replaces the access list of dir with folderSDDL, protected, so that nothing is
// inherited from the folder above it.
func setAccessList(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(folderSDDL())
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("the access list of %s: %w", dir, err)
	}
	return nil
}

// serviceExists reports whether the service name is registered.
func serviceExists(m *mgr.Mgr, name string) (bool, error) {
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("the %s service: %w", name, err)
	}
	s.Close()
	return true, nil
}

// waitState polls s until it is in the state want, for up to serviceWait. A service that stops
// while it is expected to run has failed, and the wait ends at once with its exit code.
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
		if status.State == svc.Stopped && want != svc.Stopped {
			return fmt.Errorf("it stopped with exit code %d (service-specific %d)", status.Win32ExitCode, status.ServiceSpecificExitCode)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("it did not reach state %d within %s (it is in state %d)", want, serviceWait, status.State)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// startService starts s and waits until it runs.
func startService(s *mgr.Service, name string) error {
	err := s.Start()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("starting the %s service: %w", name, err)
	}
	if err := waitState(s, svc.Running); err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	return nil
}

// ensureRunning makes sure that the service name, which exists, runs: it starts it when it is
// stopped and waits when it is starting.
func ensureRunning(w io.Writer, m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	switch status.State {
	case svc.Running:
	case svc.Stopped:
		if err := startService(s, name); err != nil {
			return err
		}
	default:
		if err := waitState(s, svc.Running); err != nil {
			return fmt.Errorf("the %s service: %w", name, err)
		}
	}
	fmt.Fprintf(w, "install: the %s service is running\n", name)
	return nil
}

// stopService stops the service name if it runs and waits until it has stopped. A service that is
// not registered is no error: there is nothing to stop.
func stopService(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	if status.State == svc.Stopped {
		return nil
	}
	_, err = s.Control(svc.Stop)
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) && !errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
		return fmt.Errorf("stopping the %s service: %w", name, err)
	}
	if err := waitState(s, svc.Stopped); err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	return nil
}

// removeService stops the service name and deletes it. It reports whether the service was
// registered; one that was not is no error, so that ranz uninstall can run twice.
func removeService(m *mgr.Mgr, name string) (bool, error) {
	if err := stopService(m, name); err != nil {
		return false, err
	}
	s, err := m.OpenService(name)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	err = s.Delete()
	if err != nil && !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
		return true, fmt.Errorf("removing the %s service: %w", name, err)
	}
	return true, nil
}

// Install makes the Ranz folder with its access list, writes ranz-node.exe, wintun.dll, the NOTICE,
// wireguard.dll and a copy of the running ranz.exe into it, puts the SeLow driver and the XDP runtime on the
// machine where this build carries them (drivers.go), registers the Node service under its virtual
// account and starts it, and, with opts.Controller, does the same for the Controller service. It
// reports each step to w. See the package documentation for what a second call does.
func Install(w io.Writer, opts Options) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("install: the path of ranz.exe: %w", err)
	}
	dir, err := installDir()
	if err != nil {
		return fmt.Errorf("install: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("install: the service control manager (does ranz install run as an Administrator?): %w", err)
	}
	defer m.Disconnect()

	if err := installNode(w, m, dir, self, opts); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if opts.Controller {
		if err := installController(w, m, dir); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}
	// The ports of the parts that are installed now (firewall.go; SDN-91, #396)
	openPorts(w, m, dir)
	return nil
}

// installNode makes the Ranz folder, fills it, puts the drivers on the machine and registers and
// starts the Node service. A call whose payload does not pass its check removes the folder again,
// when it made it, and registers nothing. The drivers come before the service starts, so that the
// Node finds them at its start and reports them as its Capabilities.
func installNode(w io.Writer, m *mgr.Mgr, dir, self string, opts Options) error {
	exists, err := serviceExists(m, nodeServiceName)
	if err != nil {
		return err
	}
	created, err := protectDir(dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "install: the folder %s is for SYSTEM and the Administrators, and the two service accounts may read and run what is in it\n", dir)
	if err := writeFiles(w, dir, self, exists, opts); err != nil {
		if created {
			_ = os.RemoveAll(dir)
		}
		return err
	}
	installed := installDrivers(w, m, dir, opts)
	if exists {
		// A Node that runs has read what the machine holds at its start, so a driver that this call put there
		// reaches the controller as a Capability only after the Node starts again
		if installed > 0 {
			fmt.Fprintf(w, "install: the %s service restarts, so that the Node reports the drivers that were just installed as its Capabilities\n", nodeServiceName)
			if err := stopService(m, nodeServiceName); err != nil {
				return err
			}
		}
		return ensureRunning(w, m, nodeServiceName)
	}
	return createNode(w, m, dir)
}

// writeFiles writes the files of the Ranz folder, each through payload.Install, which refuses a
// file whose hash or Authenticode signature does not check: ranz-node.exe, wintun.dll and the
// NOTICE beside it, wireguard.dll unless opts.NoWireGuard, and the copy of ranz.exe. With
// onlyMissing a file that is there stays as it is: a service that exists may be running it.
func writeFiles(w io.Writer, dir, self string, onlyMissing bool, opts Options) error {
	node := payload.NodeExe
	nodePath := filepath.Join(dir, node.Name)
	if !onlyMissing || !fileExists(nodePath) {
		if err := payload.Install(dir, node); err != nil {
			return fmt.Errorf("the Node payload: %w", err)
		}
		fmt.Fprintf(w, "install: %s written (SHA-256 %x), after its hash and its Authenticode signature checked\n", nodePath, node.SHA256)
	}
	if err := writeWintun(w, dir, onlyMissing, opts.Notice); err != nil {
		return err
	}
	if err := writeWireGuard(w, dir, onlyMissing, opts.NoWireGuard); err != nil {
		return err
	}
	return writeSelf(w, dir, self, onlyMissing)
}

// writeWireGuard writes wireguard.dll, the DLL of WireGuardNT that a gateway of WireGuard Devices
// loads from the folder of its executable (SDN-80, #375), byte for byte as WireGuard LLC signed it;
// the NOTICE that writeWintun writes holds its licence too. The DLL installs the WireGuardNT driver
// itself when the Node creates its WireGuard interface, so there is nothing more to do for it here.
// With noWireGuard it writes nothing.
func writeWireGuard(w io.Writer, dir string, onlyMissing, noWireGuard bool) error {
	dll := payload.WireGuardDll
	dllPath := filepath.Join(dir, dll.Name)
	if noWireGuard {
		fmt.Fprintf(w, "install: %s is left out (--no-wireguard): the Node is the gateway of no WireGuard Device and reports no Capability wireguard\n", dll.Name)
		return nil
	}
	if onlyMissing && fileExists(dllPath) {
		return nil
	}
	if err := payload.Install(dir, dll); err != nil {
		return fmt.Errorf("the WireGuardNT payload: %w", err)
	}
	fmt.Fprintf(w, "install: %s written (SHA-256 %x), after its hash and its Authenticode signature checked\n", dllPath, dll.SHA256)
	return nil
}

// writeWintun writes wintun.dll, the DLL that the client role of the Node loads from the folder of
// its executable, byte for byte as WireGuard LLC signed it, and the NOTICE beside it, whose text
// holds the licence of the DLL (the licence asks for it to go with the DLL). The DLL installs
// its driver itself when the Node creates an adapter, so there is nothing more to do for it here.
func writeWintun(w io.Writer, dir string, onlyMissing bool, notice string) error {
	dll := payload.WintunDll
	dllPath := filepath.Join(dir, dll.Name)
	if !onlyMissing || !fileExists(dllPath) {
		if err := payload.Install(dir, dll); err != nil {
			return fmt.Errorf("the Wintun payload: %w", err)
		}
		fmt.Fprintf(w, "install: %s written (SHA-256 %x), after its hash and its Authenticode signature checked\n", dllPath, dll.SHA256)
	}
	if notice == "" {
		return nil
	}
	text := payload.NewUnsigned(noticeFileName, []byte(notice))
	textPath := filepath.Join(dir, text.Name)
	if !onlyMissing || !fileExists(textPath) {
		if err := payload.Install(dir, text); err != nil {
			return fmt.Errorf("the NOTICE: %w", err)
		}
		fmt.Fprintf(w, "install: %s written (SHA-256 %x), after its hash checked\n", textPath, text.SHA256)
	}
	return nil
}

// writeSelf writes a copy of the running ranz.exe, self, into the Ranz folder, through
// payload.Install like the Node payload. It writes nothing when self is the copy in the folder, or
// with onlyMissing when there is one.
func writeSelf(w io.Writer, dir, self string, onlyMissing bool) error {
	dest := filepath.Join(dir, ranzExeName)
	if sameFile(self, dest) || (onlyMissing && fileExists(dest)) {
		return nil
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return fmt.Errorf("reading %s: %w", self, err)
	}
	p := payload.New(ranzExeName, data)
	if err := payload.Install(dir, p); err != nil {
		return fmt.Errorf("the copy of ranz.exe: %w", err)
	}
	fmt.Fprintf(w, "install: %s written (SHA-256 %x), after its hash and its Authenticode signature checked\n", dest, p.SHA256)
	return nil
}

// createNode registers the Node service under its virtual account, with an unrestricted service
// SID, and starts it. It runs ranz-node.exe in the Ranz folder with /service, as the service
// program of src/Mayaqua/Microsoft.c expects.
func createNode(w io.Writer, m *mgr.Mgr, dir string) error {
	exe := filepath.Join(dir, payload.NodeExe.Name)
	s, err := m.CreateService(nodeServiceName, exe, mgr.Config{
		DisplayName:      "Ranz VPN Node",
		Description:      nodeDescription,
		StartType:        mgr.StartAutomatic,
		ErrorControl:     mgr.ErrorNormal,
		ServiceStartName: nodeAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, "/service")
	if err != nil {
		return fmt.Errorf("registering the %s service: %w", nodeServiceName, err)
	}
	defer s.Close()
	if err := setRecovery(s); err != nil {
		_ = s.Delete()
		return fmt.Errorf("registering the %s service: %w", nodeServiceName, err)
	}
	fmt.Fprintf(w, "install: the %s service is registered, to run as %s\n", nodeServiceName, nodeAccount)
	if err := startService(s, nodeServiceName); err != nil {
		return err
	}
	fmt.Fprintf(w, "install: the %s service is running\n", nodeServiceName)
	return nil
}

// recoveryResetSeconds is how long a service runs without a failure before its failure count starts
// from zero again: a day, as the service program of src/Mayaqua/MicrosoftService.c sets it.
const recoveryResetSeconds = 24 * 60 * 60

// setRecovery has the Service Control Manager restart the service 10 seconds after each of its
// first three failures, as MsSetServiceRecovery of src/Mayaqua/MicrosoftService.c does for a service
// that it installs itself.
func setRecovery(s *mgr.Service) error {
	restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 10 * time.Second}
	err := s.SetRecoveryActions([]mgr.RecoveryAction{restart, restart, restart}, recoveryResetSeconds)
	if err != nil {
		return fmt.Errorf("its recovery actions: %w", err)
	}
	return nil
}

// installController registers the Controller service, to run the ranz.exe of the Ranz folder as
// `ranz.exe controller`, and starts it. A service that exists is only started.
func installController(w io.Writer, m *mgr.Mgr, dir string) error {
	exists, err := serviceExists(m, controllerServiceName)
	if err != nil {
		return err
	}
	if !exists {
		if err := controllercmd.Install(filepath.Join(dir, ranzExeName)); err != nil {
			return fmt.Errorf("registering the %s service: %w", controllerServiceName, err)
		}
		fmt.Fprintf(w, "install: the %s service is registered\n", controllerServiceName)
	}
	return ensureRunning(w, m, controllerServiceName)
}

// Uninstall stops and removes the Controller service, if it is registered, and the Node service,
// takes out the drivers that ranz install put on the machine (and no other: the install record
// names them), removes the Ranz folder, and leaves the data directories alone. It reports each
// step to w. When it runs from the ranz.exe in the Ranz folder, that file cannot be deleted while
// it runs: it and the folder are removed at the next restart. With opts.KeepRanz it leaves that
// file and the folder to its caller instead, and schedules nothing for the restart.
func Uninstall(w io.Writer, opts UninstallOptions) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("uninstall: the path of ranz.exe: %w", err)
	}
	dir, err := installDir()
	if err != nil {
		return fmt.Errorf("uninstall: %w", err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("uninstall: the service control manager (does ranz uninstall run as an Administrator?): %w", err)
	}
	defer m.Disconnect()

	var errs []error
	if err := removeController(w, m); err != nil {
		errs = append(errs, err)
	}
	removed, err := removeService(m, nodeServiceName)
	if err != nil {
		errs = append(errs, err)
	} else if removed {
		fmt.Fprintf(w, "uninstall: the %s service is removed\n", nodeServiceName)
	}
	// The drivers go before the folder: the manifest of the XDP counters is in it
	if err := removeDrivers(w, m, dir); err != nil {
		errs = append(errs, err)
	}
	if err := removeDir(w, dir, self, opts.KeepRanz); err != nil {
		errs = append(errs, err)
	}
	// The rules of the group in Windows Firewall (firewall.go; SDN-91, #396)
	closePorts(w)
	if len(errs) > 0 {
		return fmt.Errorf("uninstall: %w", errors.Join(errs...))
	}
	return nil
}

// removeController stops the Controller service, if it is registered, and removes it with
// controllercmd.Uninstall, which also removes its event source and its URL reservations.
func removeController(w io.Writer, m *mgr.Mgr) error {
	exists, err := serviceExists(m, controllerServiceName)
	if err != nil || !exists {
		return err
	}
	if err := stopService(m, controllerServiceName); err != nil {
		return err
	}
	if err := controllercmd.Uninstall(); err != nil {
		return fmt.Errorf("the %s service: %w", controllerServiceName, err)
	}
	fmt.Fprintf(w, "uninstall: the %s service is removed\n", controllerServiceName)
	return nil
}

// removeDir removes the Ranz folder, trying again for a few seconds: a service that has just
// stopped, or a scanner, can hold a file for a moment. self is the running ranz.exe. When it is the
// copy in the folder it cannot be deleted while it runs, so the rest of the folder goes at once and
// that file and the folder at the next restart. With keepRanz the rest of the folder goes the same
// way and ranz.exe and the folder stay, whichever ranz.exe runs, for the caller to remove: nothing
// is scheduled for the restart, and it returns once no other process holds ranz.exe (waitUnheld).
func removeDir(w io.Writer, dir, self string, keepRanz bool) error {
	if !fileExists(dir) {
		return nil
	}
	keep := ""
	if keepRanz || sameFile(self, filepath.Join(dir, ranzExeName)) {
		keep = ranzExeName
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := removeExcept(dir, keep)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("removing %s: %w", dir, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if keep == "" {
		fmt.Fprintf(w, "uninstall: the folder %s is removed\n", dir)
		return nil
	}
	if keepRanz {
		waitUnheld(w, filepath.Join(dir, keep), 10*time.Second)
		fmt.Fprintf(w, "uninstall: %s and the folder %s stay, for the caller to remove\n", keep, dir)
		return nil
	}
	if err := removeAtRestart(filepath.Join(dir, keep), dir); err != nil {
		return err
	}
	fmt.Fprintf(w, "uninstall: %s is running, so it and the folder %s are removed at the next restart\n", keep, dir)
	return nil
}

// removeAtRestart has Windows remove the files and folders paths at the next restart, in this
// order, so a folder follows the file in it.
func removeAtRestart(paths ...string) error {
	for _, path := range paths {
		p, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return fmt.Errorf("removing %s at the next restart: %w", path, err)
		}
		if err := windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
			return fmt.Errorf("removing %s at the next restart: %w", path, err)
		}
	}
	return nil
}
