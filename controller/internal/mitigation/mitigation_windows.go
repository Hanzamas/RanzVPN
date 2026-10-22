//go:build windows

package mitigation

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                       = windows.NewLazySystemDLL("kernel32.dll")
	procSetProcessMitigationPolicy = kernel32.NewProc("SetProcessMitigationPolicy")
	procGetProcessMitigationPolicy = kernel32.NewProc("GetProcessMitigationPolicy")
)

// Apply keeps the DLL search of the process to System32 and sets each policy of Policies that is
// not off. main calls it first, before the process starts anything. The error is that of the DLL
// search.
func Apply() ([]Result, error) {
	var dllErr error
	if err := windows.SetDefaultDllDirectories(windows.LOAD_LIBRARY_SEARCH_SYSTEM32); err != nil {
		dllErr = fmt.Errorf("SetDefaultDllDirectories: %w", err)
	}
	results := make([]Result, 0, len(Policies))
	for _, p := range Policies {
		r := Result{Policy: p}
		if p.Off == "" {
			flags := p.Flags
			ok, _, err := procSetProcessMitigationPolicy.Call(uintptr(p.Policy), uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
			if ok == 0 {
				r.Err = fmt.Errorf("SetProcessMitigationPolicy %s: %w", p.Name, err)
			}
		}
		results = append(results, r)
	}
	return results, dllErr
}

// Get returns the flags of the policy p of the process h, a handle with
// PROCESS_QUERY_INFORMATION.
func Get(h windows.Handle, p Policy) (uint32, error) {
	var flags uint32
	ok, _, err := procGetProcessMitigationPolicy.Call(uintptr(h), uintptr(p.Policy), uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags))
	if ok == 0 {
		return 0, fmt.Errorf("GetProcessMitigationPolicy %s: %w", p.Name, err)
	}
	return flags, nil
}

// Check reads the process h from outside, as the tests do, and returns what it lacks: a policy of
// Policies that is not off and not set, or a module other than its executable that is not in
// System32. h needs PROCESS_QUERY_INFORMATION and PROCESS_VM_READ.
func Check(h windows.Handle) ([]string, error) {
	var lacks []string
	for _, p := range Policies {
		if p.Off != "" {
			continue
		}
		flags, err := Get(h, p)
		if err != nil {
			return nil, err
		}
		if flags&p.Flags != p.Flags {
			lacks = append(lacks, fmt.Sprintf("mitigation %s: flags %#x, %#x not set", p.Name, flags, p.Flags&^flags))
		}
	}

	sys32, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	sys32 = strings.ToLower(sys32) + `\`
	var exe [windows.MAX_PATH]uint16
	if err := windows.GetModuleFileNameEx(h, 0, &exe[0], uint32(len(exe))); err != nil {
		return nil, fmt.Errorf("GetModuleFileNameEx: %w", err)
	}
	mods := make([]windows.Handle, 1024)
	var size uint32
	err = windows.EnumProcessModulesEx(h, &mods[0], uint32(len(mods))*uint32(unsafe.Sizeof(mods[0])), &size, windows.LIST_MODULES_ALL)
	if err != nil {
		return nil, fmt.Errorf("EnumProcessModulesEx: %w", err)
	}
	mods = mods[:min(len(mods), int(size/uint32(unsafe.Sizeof(mods[0]))))]
	for _, m := range mods {
		var name [windows.MAX_PATH]uint16
		if err := windows.GetModuleFileNameEx(h, m, &name[0], uint32(len(name))); err != nil {
			lacks = append(lacks, fmt.Sprintf("module %#x: no name (%v)", m, err))
			continue
		}
		path := windows.UTF16ToString(name[:])
		if strings.EqualFold(path, windows.UTF16ToString(exe[:])) || strings.HasPrefix(strings.ToLower(path), sys32) {
			continue
		}
		lacks = append(lacks, "a DLL outside System32: "+path)
	}
	return lacks, nil
}
