//go:build windows

package controllercmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Hanzamas/RanzVPN/controller/internal/logfile"
	"github.com/Hanzamas/RanzVPN/controller/internal/port"
)

// serviceName is the name of the Windows service and the source of its Application log entries.
const serviceName = "ranz-controller"

// serviceAccount is the account the service runs as, its virtual account, not LocalSystem (ADR-0039
// decision 3), and serviceSID its SID, the one Windows derives from the service name (the SHA-1 of
// its upper-case UTF-16 form, as sc showsid prints it), so that the ACLs can name it before the
// service exists.
const (
	serviceAccount = `NT SERVICE\` + serviceName
	serviceSID     = "S-1-5-80-3572785604-795126647-2475823641-2319294638-1653438898"
)

// The event IDs of the service's entries in the Application log.
const (
	eventStarted = 1
	eventStopped = 2
	eventFailed  = 3
	eventWarning = 4 // the TLS port fell back to 5555
	eventReset   = 5 // reset-admin created an admin token
)

// reservationSDDL lets the service's account register the URL prefixes of the plain-HTTP port
// (the right `netsh http add urlacl user="NT SERVICE\ranz-controller"` gives).
const reservationSDDL = "D:(A;;GX;;;" + serviceSID + ")"

// The registry value, under the service's key, that lists the URL reservations install made, so
// that uninstall removes those and no reservation that existed before.
const (
	parametersKey   = `SYSTEM\CurrentControlSet\Services\` + serviceName + `\Parameters`
	reservationsVal = "UrlReservations"
)

// logFile is the name of the service's log in the data directory.
const logFile = "controller.log"

// dataDirSDDL is the ACL of a data directory the controller creates: full control for SYSTEM,
// the Administrators, the directory's owner and the service's account, inherited, and nothing for
// anyone else. A directory created under ProgramData would otherwise let every user read the
// controller key. The owner is in the list, so the owner must be SYSTEM, the Administrators or an
// account of the controller's own (checkDataDirOwner), or the list would give a user that made the
// directory first a right in it. A new directory gets the list in the call that makes it (makeProtectedDir),
// so that it has no other list at any moment.
const dataDirSDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)(A;OICI;FA;;;" + serviceSID + ")"

func defaultDataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Ranz", "controller")
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
// shutdown request. The service log is controller.log in the data directory, within the age and
// disk limits of -log-days and -log-mb; the start, the stop, a failure and a fallback of the TLS
// port also go to the Application log.
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
		done <- run(ctx, s.cfg, log, f, hooks{
			ready: func() {
				status <- svc.Status{State: svc.Running, Accepts: accepts}
				_ = s.elog.Info(eventStarted, fmt.Sprintf("%s started", serviceName))
			},
			warn: func(msg string) {
				_ = s.elog.Warning(eventWarning, fmt.Sprintf("%s: %s", serviceName, msg))
			},
			logFile: f.Path(),
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

// openLog opens the service log in the data directory, which keeps its files within the limits of
// the configuration (internal/logfile). It applies them at once, so limits that are lower than the
// ones of the last run take effect at the start.
func (s *service) openLog() (*logfile.Writer, error) {
	if err := makeDataDir(s.cfg.dataDir); err != nil {
		return nil, err
	}
	return logfile.New(filepath.Join(s.cfg.dataDir, logFile), s.cfg.logLimits())
}

// install registers the Windows service, started automatically as its virtual account and running
// this executable as `ranz controller` with args, the event source of its Application log
// entries, and, with -http-listen, the HTTP.sys URL reservations of the plain-HTTP port. It
// makes the data directory with the Administrators as its owner, or takes over the one that exists
// (takeOverDataDir), so that the service's account, which is not an administrator, has it and no
// other account does.
func install(args []string, cfg config) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return installService(exe, args, cfg)
}

// installService is install for the executable exe, which the service runs as `exe controller`
// with args: `ranz install` (internal/install, ONE-2 #311) names the ranz.exe that it copied into
// the Ranz folder, so that the service does not run from wherever the download was left.
func installService(exe string, args []string, cfg config) error {
	if err := takeOverDataDir(cfg.dataDir); err != nil {
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
		DisplayName:      "Ranz controller",
		Description:      "Keeps the Ranz intent and pushes the desired state of each node over the control stream.",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: serviceAccount,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, append([]string{"controller"}, args...)...)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info); err != nil {
		_ = s.Delete()
		return fmt.Errorf("registering the event source: %w", err)
	}
	if cfg.httpListen != "" {
		if err := reserve(cfg.httpListen); err != nil {
			_ = s.Delete()
			_ = eventlog.Remove(serviceName)
			return err
		}
	}
	return nil
}

// reserve makes the HTTP.sys URL reservations of the plain-HTTP port for the service's account and
// records the ones it made under the service's key. A reservation that exists already stays as it
// is.
func reserve(httpListen string) error {
	prefixes, err := port.PlainPrefixes(httpListen)
	if err != nil {
		return err
	}
	var made []string
	for _, p := range prefixes {
		created, err := port.Reserve(p, reservationSDDL)
		if err != nil {
			for _, m := range made {
				_ = port.Unreserve(m)
			}
			return err
		}
		if created {
			made = append(made, p)
		}
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, parametersKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("recording the URL reservations: %w", err)
	}
	defer k.Close()
	if err := k.SetStringsValue(reservationsVal, made); err != nil {
		return fmt.Errorf("recording the URL reservations: %w", err)
	}
	return nil
}

// uninstall removes the service, its event source and the URL reservations that install made.
// The service must be stopped first.
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
	var made []string
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, parametersKey, registry.QUERY_VALUE); err == nil {
		made, _, _ = k.GetStringsValue(reservationsVal)
		k.Close()
	}
	if err := s.Delete(); err != nil {
		return err
	}
	var errs []error
	for _, p := range made {
		if err := port.Unreserve(p); err != nil {
			errs = append(errs, err)
		}
	}
	if err := eventlog.Remove(serviceName); err != nil {
		errs = append(errs, fmt.Errorf("removing the event source: %w", err))
	}
	return errors.Join(errs...)
}

// Install registers the Windows service so that it runs the executable exe as `exe controller`,
// with its default data directory and no plain HTTP reservation (installService reads only
// cfg.dataDir and cfg.httpListen; the service picks up every other default, such as its TLS port,
// from its own flags the next time it runs). It does not start the service, as install does not
// either; `ranz install -controller` (internal/install, ONE-2 #311) starts it itself, alongside
// the Node service.
func Install(exe string) error {
	return installService(exe, nil, config{dataDir: defaultDataDir()})
}

// InstallAdminFrom is Install with the flag -admin-from of the service set to adminFrom, the admin
// source allowlist that the first start applies (AUD1-DT-6, #454): prefixes separated by commas, or
// "any".
func InstallAdminFrom(exe, adminFrom string) error {
	return installService(exe, adminFromArgs(adminFrom), config{dataDir: defaultDataDir()})
}

// Uninstall removes the Windows service. The service must be stopped first, as uninstall needs;
// `ranz uninstall` (internal/install, ONE-2 #311) stops it itself before calling this.
func Uninstall() error {
	return uninstall()
}
