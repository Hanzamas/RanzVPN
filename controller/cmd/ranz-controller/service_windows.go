//go:build windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceName is the name of the Windows service and the source of its Application log entries.
const serviceName = "ranz-controller"

// The event IDs of the service's entries in the Application log.
const (
	eventStarted = 1
	eventStopped = 2
	eventFailed  = 3
)

// logFile is the name of the service's log in the data directory.
const logFile = "controller.log"

// dataDirSDDL is the ACL of a data directory the controller creates: full control for SYSTEM,
// the Administrators and the directory's owner, inherited, and nothing for anyone else. A
// directory created under ProgramData would otherwise let every user read the controller key.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Ranz", "controller")
}

func protectDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString(dataDirSDDL)
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("data directory ACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("data directory ACL of %s: %w", dir, err)
	}
	return nil
}

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runService runs the controller under the service control manager.
func runService(cfg config) error {
	elog, err := eventlog.Open(serviceName)
	if err != nil {
		return err
	}
	defer elog.Close()
	return svc.Run(serviceName, &service{cfg: cfg, elog: elog})
}

type service struct {
	cfg  config
	elog *eventlog.Log
}

// Execute starts the controller, reports it running once it serves, and stops it on a stop or
// shutdown request. The service log is controller.log in the data directory; the start, the
// stop and a failure also go to the Application log.
func (s *service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}
	f, err := s.openLog()
	if err != nil {
		_ = s.elog.Error(eventFailed, fmt.Sprintf("%s: %v", serviceName, err))
		return true, 1
	}
	defer f.Close()
	log := slog.New(slog.NewTextHandler(f, nil))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, s.cfg, log, f, func() {
			status <- svc.Status{State: svc.Running, Accepts: accepts}
			_ = s.elog.Info(eventStarted, fmt.Sprintf("%s started", serviceName))
		})
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				log.Error("controller failed", "err", err)
				_ = s.elog.Error(eventFailed, fmt.Sprintf("%s failed: %v", serviceName, err))
				return true, 1
			}
			_ = s.elog.Info(eventStopped, fmt.Sprintf("%s stopped", serviceName))
			return false, 0
		case r := <-req:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
			}
		}
	}
}

func (s *service) openLog() (*os.File, error) {
	if err := makeDataDir(s.cfg.dataDir); err != nil {
		return nil, err
	}
	return os.OpenFile(filepath.Join(s.cfg.dataDir, logFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// install registers the Windows service, started automatically as LocalSystem and running this
// executable with args, and the event source of its Application log entries.
func install(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("the service %s already exists", serviceName)
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: "Ranz controller",
		Description: "Keeps the Ranz intent and pushes the desired state of each node over the control stream.",
		StartType:   mgr.StartAutomatic,
	}, args...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		_ = s.Delete()
		return fmt.Errorf("registering the event source: %w", err)
	}
	return nil
}

// uninstall removes the service and its event source. The service must be stopped first.
func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the service %s is not installed: %w", serviceName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		return err
	}
	if err := eventlog.Remove(serviceName); err != nil {
		return fmt.Errorf("removing the event source: %w", err)
	}
	return nil
}
