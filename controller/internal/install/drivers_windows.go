//go:build windows

package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// toolWait is how long a tool of Windows may run. netcfg waits for the lock of the network
// configuration, and the adapters rebind under it, which takes a while on a busy machine.
const toolWait = 3 * time.Minute

// installRecordKey is the registry key of the install record (HKEY_LOCAL_MACHINE): one string
// value for each driver that ranz install put on the machine, which holds the name that Windows
// published its INF under (oemNN.inf). ranz uninstall removes the drivers that the record names and
// no other, so a driver that was there before ranz install stays.
const installRecordKey = `SOFTWARE\Hanzcodes\Ranz VPN\Drivers`

// The setupapi.dll functions that publish a driver package into the driver store and remove it
// again. They are what netcfg and the INetCfg installer of src/Cedar/Win32Com.c call too.
var (
	setupapi                  = windows.NewLazySystemDLL("setupapi.dll")
	procSetupCopyOEMInfW      = setupapi.NewProc("SetupCopyOEMInfW")
	procSetupUninstallOEMInfW = setupapi.NewProc("SetupUninstallOEMInfW")
)

const (
	spostPath       = 1 // SPOST_PATH of setupapi.h: the media location is a path
	suoiForceDelete = 1 // SUOI_FORCEDELETE: delete the INF although a device uses it
)

// systemFolder returns the System32 folder, which the system names: the tools that ranz runs
// come from it, never from the search path.
func systemFolder() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_System, windows.KF_FLAG_DEFAULT)
	if err != nil {
		return "", fmt.Errorf("the System32 folder: %w", err)
	}
	return dir, nil
}

// shortened returns text with at most limit bytes, for an error message.
func shortened(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}

// runTool runs the tool name of the System32 folder with args, waits for it, and returns what it
// printed. A tool that fails or does not finish within toolWait is an error that holds its output.
func runTool(name string, args ...string) (string, error) {
	sys, err := systemFolder()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), toolWait)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(sys, name), args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if ctx.Err() != nil {
		return text, fmt.Errorf("%s did not finish within %s", name, toolWait)
	}
	if err != nil {
		return text, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, shortened(text, 400))
	}
	return text, nil
}

// publishINF puts the driver package whose INF is at path into the driver store, which checks the
// signature of its catalog and that the catalog covers the INF and the files, and returns the name
// that Windows published the INF under (oemNN.inf). A package that is in the store already, with
// the same INF, gives its own name again.
func publishINF(path string) (string, error) {
	inf, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("the INF %s: %w", path, err)
	}
	media, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("the INF %s: %w", path, err)
	}
	var published [windows.MAX_PATH]uint16
	var needed uint32
	r, _, callErr := procSetupCopyOEMInfW.Call(
		uintptr(unsafe.Pointer(inf)),
		uintptr(unsafe.Pointer(media)),
		spostPath,
		0,
		uintptr(unsafe.Pointer(&published[0])),
		uintptr(len(published)),
		uintptr(unsafe.Pointer(&needed)),
		0)
	if r == 0 {
		return "", fmt.Errorf("publishing the INF %s to the driver store (SetupCopyOEMInf): %w", path, callErr)
	}
	return filepath.Base(windows.UTF16ToString(published[:])), nil
}

// unpublishINF removes the INF that Windows published under name (oemNN.inf) from the driver store.
// An INF that is gone already is no error.
func unpublishINF(name string) error {
	inf, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("the INF %s: %w", name, err)
	}
	r, _, callErr := procSetupUninstallOEMInfW.Call(uintptr(unsafe.Pointer(inf)), suoiForceDelete, 0)
	if r == 0 && !errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND) {
		return fmt.Errorf("removing the INF %s from the driver store (SetupUninstallOEMInf): %w", name, callErr)
	}
	return nil
}

// recordDriver notes in the install record that ranz install put the driver record on the machine,
// published as the INF published.
func recordDriver(record, published string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, installRecordKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("the install record HKLM\\%s: %w", installRecordKey, err)
	}
	defer k.Close()
	if err := k.SetStringValue(record, published); err != nil {
		return fmt.Errorf("the install record HKLM\\%s: %w", installRecordKey, err)
	}
	return nil
}

// recordedDriver returns the INF that the install record names for the driver record, and whether
// the record names it at all.
func recordedDriver(record string) (string, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, installRecordKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	published, _, err := k.GetStringValue(record)
	if err != nil || published == "" {
		return "", false
	}
	return published, true
}

// forgetDriver takes the driver record out of the install record, and the key itself once it holds
// no value.
func forgetDriver(record string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, installRecordKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return
	}
	_ = k.DeleteValue(record)
	names, err := k.ReadValueNames(-1)
	k.Close()
	if err == nil && len(names) == 0 {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, installRecordKey)
	}
}

// installDrivers puts the drivers that this build carries on the machine, one after the other, and
// reports each step to w. The Node does not need a driver to run: one that fails to install is taken
// out again and reported as a warning, and the Node then reports its Capability as missing and falls
// back to the next L2 backend (ADR-0002 amendment of 2026-10-21). A machine that has a driver
// already keeps it, and ranz uninstall leaves it.
func installDrivers(w io.Writer, m *mgr.Mgr, dir string, opts Options) {
	if len(payload.SeLowPackage) == 0 && len(payload.XdpPackage) == 0 {
		fmt.Fprintln(w, "install: this build carries Wintun only (arm64 has no SeLow driver and no XDP runtime): the Node reports neither of them, and an L2 Network is refused for it (ADR-0022)")
		return
	}
	if opts.NoXDP {
		fmt.Fprintln(w, "install: the XDP runtime is left out (--no-xdp): the Node falls back to SeLow")
	}
	for _, d := range selectDrivers(payload.SeLowPackage, payload.XdpPackage, opts.NoXDP) {
		if err := installDriver(w, m, dir, d); err != nil {
			fmt.Fprintf(w, "install: warning: %s was not installed: %v\n", d.label, err)
		}
	}
}

// installDriver puts the driver d on the machine: its package is written under the Ranz folder,
// published to the driver store, its network component is installed, its driver started, and the
// install recorded. A step that fails takes out what the steps before it did.
func installDriver(w io.Writer, m *mgr.Mgr, dir string, d driver) error {
	exists, err := serviceExists(m, d.service)
	if err != nil {
		return err
	}
	if exists {
		fmt.Fprintf(w, "install: %s is on this machine already (the %s service): ranz leaves it as it is, and uninstall leaves it too\n", d.label, d.service)
		return nil
	}

	pkg := filepath.Join(dir, driversFolder, d.record)
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		return fmt.Errorf("the folder %s: %w", pkg, err)
	}
	for _, p := range d.files {
		if err := payload.Install(pkg, p); err != nil {
			_ = os.RemoveAll(pkg)
			return err
		}
	}
	fmt.Fprintf(w, "install: the files of %s are written to %s, each after its hash checked, and its Authenticode signature where it carries one\n", d.label, pkg)

	published, err := publishINF(filepath.Join(pkg, d.inf))
	if err != nil {
		_ = os.RemoveAll(pkg)
		return err
	}
	if err := installComponent(m, pkg, d, published); err != nil {
		if undoErr := removeDriver(w, m, dir, d, published, "install"); undoErr != nil {
			fmt.Fprintf(w, "install: taking %s out again: %v\n", d.label, undoErr)
		}
		return err
	}
	fmt.Fprintf(w, "install: %s is installed and runs (the INF is published as %s, the service is %s)\n", d.label, published, d.service)
	return nil
}

// installComponent installs the network component of d from the package that is published, as
// Microsoft's xdp-setup.ps1 installs the XDP runtime: netcfg installs the component, lodctr
// registers the performance counters of a driver that has a manifest, and the driver starts. It
// records the install last.
func installComponent(m *mgr.Mgr, pkg string, d driver, published string) error {
	if _, err := runTool("netcfg.exe", "-v", "-l", filepath.Join(pkg, d.inf), "-c", d.class, "-i", d.component); err != nil {
		return err
	}
	if d.manifest != "" {
		sys, err := systemFolder()
		if err != nil {
			return err
		}
		if _, err := runTool("lodctr.exe", "/m:"+filepath.Join(pkg, d.manifest), filepath.Join(sys, "drivers")+`\`); err != nil {
			return err
		}
	}
	if err := startDriver(m, d.service); err != nil {
		return err
	}
	return recordDriver(d.record, published)
}

// startDriver starts the driver of the service name and waits until it runs. A driver that has
// just been installed may refuse its first start, so it tries a few times, as Microsoft's
// xdp-setup.ps1 does.
func startDriver(m *mgr.Mgr, name string) error {
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("the %s service: %w", name, err)
	}
	defer s.Close()
	var last error
	for i := 0; i < 5; i++ {
		if last = startService(s, name); last == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return last
}

// removeDriver takes the driver d off the machine, as Microsoft's xdp-setup.ps1 does for the XDP
// runtime: its performance counters, its network component, its service, the INF that Windows
// published for it (published, "" for none) and the files that the INF copied into System32. A
// step that fails is reported as a note and the others still run; the driver is gone when its
// service is. Only then is it taken out of the install record. verb is the command that reports.
func removeDriver(w io.Writer, m *mgr.Mgr, dir string, d driver, published, verb string) error {
	pkg := filepath.Join(dir, driversFolder, d.record)
	note := func(err error) {
		fmt.Fprintf(w, "%s: note: %v\n", verb, err)
	}

	if d.manifest != "" && fileExists(filepath.Join(pkg, d.manifest)) {
		if _, err := runTool("unlodctr.exe", "/m:"+filepath.Join(pkg, d.manifest)); err != nil {
			note(err)
		}
	}
	if _, err := runTool("netcfg.exe", "-u", d.component); err != nil {
		note(err)
	}
	if _, err := removeService(m, d.service); err != nil {
		note(err)
	}
	if published != "" {
		if err := unpublishINF(published); err != nil {
			note(err)
		}
	}
	sys, err := systemFolder()
	if err != nil {
		note(err)
	} else {
		for _, name := range d.leftovers {
			if err := removeLeftover(w, filepath.Join(sys, name), verb); err != nil {
				note(err)
			}
		}
	}

	exists, err := serviceExists(m, d.service)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("the %s service is still registered", d.service)
	}
	forgetDriver(d.record)
	return nil
}

// removeLeftover deletes the file path that the INF of a driver copied into System32. A file that
// a loaded driver or a program still holds goes at the next restart.
func removeLeftover(w io.Writer, path, verb string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if delayed := removeAtRestart(path); delayed != nil {
		return err
	}
	fmt.Fprintf(w, "%s: %s is in use, so it is removed at the next restart\n", verb, path)
	return nil
}

// removeDrivers takes the drivers that the install record names off the machine, and no other.
// A driver that is on the machine and not in the record was there before ranz install, or ranz
// install did not put it there: it stays.
func removeDrivers(w io.Writer, m *mgr.Mgr, dir string) error {
	var errs []error
	for _, d := range everyDriver() {
		published, recorded := recordedDriver(d.record)
		if !recorded {
			if exists, err := serviceExists(m, d.service); err == nil && exists {
				fmt.Fprintf(w, "uninstall: %s was on this machine before ranz install (the %s service): it stays\n", d.label, d.service)
			}
			continue
		}
		if err := removeDriver(w, m, dir, d, published, "uninstall"); err != nil {
			errs = append(errs, fmt.Errorf("removing %s: %w", d.label, err))
			continue
		}
		fmt.Fprintf(w, "uninstall: %s is removed\n", d.label)
	}
	return errors.Join(errs...)
}
