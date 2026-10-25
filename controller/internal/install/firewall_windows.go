//go:build windows

package install

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Windows Firewall through its COM interface INetFwPolicy2 (netfw.h), the native API that
// MsAddFirewallRule of src/Mayaqua/MicrosoftFirewall.c uses for the slim fork (REL-2, #47). Go has no
// COM of its own, so this file calls the methods of the interfaces through their tables of methods,
// with ole32 and oleaut32 of System32 for the objects, the strings and the enumerator.

var (
	ole32                = windows.NewLazySystemDLL("ole32.dll")
	oleaut32             = windows.NewLazySystemDLL("oleaut32.dll")
	procCoCreateInstance = ole32.NewProc("CoCreateInstance")
	procSysAllocString   = oleaut32.NewProc("SysAllocString")
	procSysFreeString    = oleaut32.NewProc("SysFreeString")
	procVariantClear     = oleaut32.NewProc("VariantClear")
)

// The classes and interfaces of the firewall policy, as src/Mayaqua/MicrosoftFirewall.c defines
// them, and the enumerator of a collection (oaidl.h)
var (
	clsidNetFwPolicy2 = windows.GUID{Data1: 0xE2B3C97F, Data2: 0x6AE1, Data3: 0x41AC, Data4: [8]byte{0x81, 0x7A, 0xF6, 0xF9, 0x21, 0x66, 0xD7, 0xDD}}
	iidNetFwPolicy2   = windows.GUID{Data1: 0x98325047, Data2: 0xC671, Data3: 0x4174, Data4: [8]byte{0x8D, 0x81, 0xDE, 0xFC, 0xD3, 0xF0, 0x31, 0x86}}
	clsidNetFwRule    = windows.GUID{Data1: 0x2C5BC43E, Data2: 0x3369, Data3: 0x4C33, Data4: [8]byte{0xAB, 0x0C, 0xBE, 0x94, 0x69, 0x67, 0x7A, 0xF4}}
	iidNetFwRule      = windows.GUID{Data1: 0xAF230D27, Data2: 0xBABA, Data3: 0x4E42, Data4: [8]byte{0xAC, 0xED, 0xF5, 0x24, 0xF2, 0x2C, 0xFC, 0xE2}}
	iidEnumVariant    = windows.GUID{Data1: 0x00020404, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}
)

// The places of the methods that this file calls in the tables of methods of the interfaces, in the
// order of netfw.h and oaidl.h: the three of IUnknown, then the four of IDispatch for the firewall
// interfaces, then the methods of the interface. A property of INetFwRule is a get and a put, in
// this order.
const (
	methodQueryInterface = 0
	methodRelease        = 2

	policyGetRules = 18 // INetFwPolicy2::get_Rules

	rulesAdd     = 8  // INetFwRules::Add
	rulesRemove  = 9  // INetFwRules::Remove
	rulesItem    = 10 // INetFwRules::Item
	rulesNewEnum = 11 // INetFwRules::get__NewEnum

	ruleGetName            = 7
	rulePutName            = 8
	ruleGetDescription     = 9
	rulePutDescription     = 10
	ruleGetApplicationName = 11
	rulePutApplicationName = 12
	ruleGetProtocol        = 15
	rulePutProtocol        = 16
	ruleGetLocalPorts      = 17
	rulePutLocalPorts      = 18
	ruleGetDirection       = 27
	rulePutDirection       = 28
	ruleGetEnabled         = 33
	rulePutEnabled         = 34
	ruleGetGrouping        = 35
	rulePutGrouping        = 36
	ruleGetProfiles        = 37
	rulePutProfiles        = 38
	ruleGetAction          = 41
	rulePutAction          = 42

	enumNext = 3 // IEnumVARIANT::Next
)

// The values of netfw.h, wtypes.h and winerror.h that this file uses
const (
	clsctxInprocServer = 1          // CLSCTX_INPROC_SERVER
	fwDirectionIn      = 1          // NET_FW_RULE_DIR_IN
	fwActionAllow      = 1          // NET_FW_ACTION_ALLOW
	fwProfilesAll      = 0x7FFFFFFF // NET_FW_PROFILE2_ALL
	variantTrue        = 0xFFFF     // VARIANT_TRUE, the VARIANT_BOOL -1
	vtDispatch         = 9          // VT_DISPATCH
	rpcEChangedMode    = 0x80010106 // RPC_E_CHANGED_MODE: COM runs on this thread in the other apartment
	removeMax          = 1000       // Rules of one name that a removal takes at most, so that a store that keeps one cannot hold it
)

// comObject is a COM interface as Windows hands it out: its first word points to the table of its
// methods, and each method takes the interface as its first argument.
type comObject struct {
	methods *[64]uintptr
}

// call calls the method at index of the table of o with args, and returns its HRESULT as an error.
// An argument may be the address of a variable of the caller, which the method writes to.
//
//go:uintptrescapes
func (o *comObject) call(index int, args ...uintptr) error {
	r, _, _ := syscall.SyscallN(o.methods[index], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return hresult(r)
}

func (o *comObject) release() {
	syscall.SyscallN(o.methods[methodRelease], uintptr(unsafe.Pointer(o)))
}

// query returns the interface iid of o, which the caller releases.
func (o *comObject) query(iid *windows.GUID) (*comObject, error) {
	var out *comObject
	if err := o.call(methodQueryInterface, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out))); err != nil {
		return nil, err
	}
	return out, nil
}

// getString reads the string property of o at the method index.
func (o *comObject) getString(index int) (string, error) {
	var b *uint16
	if err := o.call(index, uintptr(unsafe.Pointer(&b))); err != nil {
		return "", err
	}
	defer procSysFreeString.Call(uintptr(unsafe.Pointer(b)))
	return windows.UTF16PtrToString(b), nil
}

// getInt reads the property of o at the method index whose value is a LONG or an enum of netfw.h.
func (o *comObject) getInt(index int) (int32, error) {
	var v int32
	err := o.call(index, uintptr(unsafe.Pointer(&v)))
	return v, err
}

// putString writes the string property of o at the method index, as a BSTR.
func (o *comObject) putString(index int, s string) error {
	u, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return err
	}
	b, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(u)))
	if b == 0 {
		return errors.New("SysAllocString: out of memory")
	}
	defer procSysFreeString.Call(b)
	return o.call(index, b)
}

// hresult is the error of the HRESULT of a COM method, nil when it succeeded. A Win32 error that it
// carries (FACILITY_WIN32) is that error, so that errors.Is finds windows.ERROR_ACCESS_DENIED.
func hresult(r uintptr) error {
	hr := uint32(r)
	if int32(hr) >= 0 {
		return nil
	}
	if hr>>16 == 0x8007 {
		return windows.Errno(hr & 0xFFFF)
	}
	return fmt.Errorf("HRESULT 0x%08X", hr)
}

// variant is a VARIANT of oaidl.h as the enumerator of the rules fills it: its type, and for
// VT_DISPATCH the interface of one rule.
type variant struct {
	vt       uint16
	_        [3]uint16
	dispatch *comObject
	_        uintptr
}

// withRules runs f with the rule collection of the firewall policy, on a thread of its own with COM
// initialized for it, as MsFirewallOpen does: S_OK and S_FALSE take a reference that it returns,
// and RPC_E_CHANGED_MODE leaves the apartment of the thread as it is.
func withRules(f func(rules *comObject) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED)
	switch {
	case err == nil || errors.Is(err, windows.Errno(1)): // S_OK, S_FALSE
		defer windows.CoUninitialize()
	case errors.Is(err, windows.Errno(rpcEChangedMode)):
	default:
		return fmt.Errorf("COM: %w", err)
	}

	var policy *comObject
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNetFwPolicy2)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidNetFwPolicy2)), uintptr(unsafe.Pointer(&policy)))
	if err := hresult(r); err != nil {
		return fmt.Errorf("the firewall policy (INetFwPolicy2): %w", err)
	}
	defer policy.release()
	var rules *comObject
	if err := policy.call(policyGetRules, uintptr(unsafe.Pointer(&rules))); err != nil {
		return fmt.Errorf("the rules of the firewall policy: %w", err)
	}
	defer rules.release()
	return f(rules)
}

// readRule reads the rule r when it is a rule of the group group: false for a rule of another group,
// of which it reads no more than the group.
func readRule(r *comObject, group string) (firewallRule, bool, error) {
	var fr firewallRule
	in, err := r.getString(ruleGetGrouping)
	if err != nil || in != group {
		return fr, false, err
	}
	for _, p := range []struct {
		index int
		to    *string
	}{{ruleGetName, &fr.Name}, {ruleGetDescription, &fr.Description}, {ruleGetApplicationName, &fr.Program}, {ruleGetLocalPorts, &fr.Ports}} {
		if *p.to, err = r.getString(p.index); err != nil {
			return fr, false, err
		}
	}
	var values [4]int32
	for i, index := range []int{ruleGetProtocol, ruleGetDirection, ruleGetProfiles, ruleGetAction} {
		if values[i], err = r.getInt(index); err != nil {
			return fr, false, err
		}
	}
	var enabled int16
	if err := r.call(ruleGetEnabled, uintptr(unsafe.Pointer(&enabled))); err != nil {
		return fr, false, err
	}
	fr.Protocol = values[0]
	fr.Inbound = values[1] == fwDirectionIn
	fr.AllProfiles = values[2] == fwProfilesAll
	fr.Allow = values[3] == fwActionAllow
	fr.Enabled = enabled != 0
	return fr, true, nil
}

// groupRules returns the rules of the collection whose group is group, in the order of the
// collection.
func groupRules(rules *comObject, group string) ([]firewallRule, error) {
	var unknown *comObject
	if err := rules.call(rulesNewEnum, uintptr(unsafe.Pointer(&unknown))); err != nil {
		return nil, fmt.Errorf("the enumerator of the rules: %w", err)
	}
	defer unknown.release()
	enum, err := unknown.query(&iidEnumVariant)
	if err != nil {
		return nil, fmt.Errorf("the enumerator of the rules: %w", err)
	}
	defer enum.release()

	var out []firewallRule
	for {
		var v variant
		var fetched uint32
		if err := enum.call(enumNext, 1, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&fetched))); err != nil {
			return nil, fmt.Errorf("the next rule: %w", err)
		}
		if fetched == 0 {
			return out, nil
		}
		var fr firewallRule
		var in bool
		if v.vt == vtDispatch && v.dispatch != nil {
			if rule, err := v.dispatch.query(&iidNetFwRule); err == nil {
				fr, in, err = readRule(rule, group)
				rule.release()
				if err != nil {
					procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
					return nil, fmt.Errorf("a rule: %w", err)
				}
			}
		}
		procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
		if in {
			out = append(out, fr)
		}
	}
}

// removeRules removes every rule named name: INetFwRules::Remove removes one rule of the name at a
// time and succeeds when there is none, so the loop ends when Item finds none any more.
func removeRules(rules *comObject, name string) error {
	u, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	b, _, _ := procSysAllocString.Call(uintptr(unsafe.Pointer(u)))
	if b == 0 {
		return errors.New("SysAllocString: out of memory")
	}
	defer procSysFreeString.Call(b)
	for range removeMax {
		var rule *comObject
		if err := rules.call(rulesItem, b, uintptr(unsafe.Pointer(&rule))); err != nil || rule == nil {
			return nil
		}
		rule.release()
		if err := rules.call(rulesRemove, b); err != nil {
			return fmt.Errorf("removing the rule %q: %w", name, err)
		}
	}
	return fmt.Errorf("removing the rule %q: Windows Firewall still holds one after %d removals", name, removeMax)
}

// addRule adds fr to the collection, in the group group.
func addRule(rules *comObject, fr firewallRule, group string) error {
	var rule *comObject
	r, _, _ := procCoCreateInstance.Call(uintptr(unsafe.Pointer(&clsidNetFwRule)), 0, clsctxInprocServer,
		uintptr(unsafe.Pointer(&iidNetFwRule)), uintptr(unsafe.Pointer(&rule)))
	if err := hresult(r); err != nil {
		return fmt.Errorf("a new rule (NetFwRule): %w", err)
	}
	defer rule.release()
	// The protocol comes before the ports: Windows Firewall takes ports only for TCP and UDP
	steps := []func() error{
		func() error { return rule.putString(rulePutName, fr.Name) },
		func() error { return rule.putString(rulePutDescription, fr.Description) },
		func() error { return rule.putString(rulePutApplicationName, fr.Program) },
		func() error { return rule.call(rulePutProtocol, uintptr(fr.Protocol)) },
		func() error { return rule.putString(rulePutLocalPorts, fr.Ports) },
		func() error { return rule.call(rulePutDirection, fwDirectionIn) },
		func() error { return rule.call(rulePutProfiles, fwProfilesAll) },
		func() error { return rule.call(rulePutAction, fwActionAllow) },
		func() error { return rule.call(rulePutEnabled, variantTrue) },
		func() error { return rule.putString(rulePutGrouping, group) },
		func() error { return rules.call(rulesAdd, uintptr(unsafe.Pointer(rule))) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return fmt.Errorf("adding the rule %q: %w", fr.Name, err)
		}
	}
	return nil
}

// firewallChange is what setFirewall did: the rules that it kept as they were, the names whose rules
// it removed, and the rules that it added.
type firewallChange struct {
	kept    []firewallRule
	removed []string
	added   []firewallRule
}

// setFirewall makes the rules of the group group the rules want: it keeps a rule that is there as
// it should be, removes the others of the group and adds the missing ones (firewallPlan). With want
// empty it removes every rule of the group.
func setFirewall(group string, want []firewallRule) (firewallChange, error) {
	var c firewallChange
	err := withRules(func(rules *comObject) error {
		have, err := groupRules(rules, group)
		if err != nil {
			return err
		}
		remove, add := firewallPlan(have, want)
		for _, w := range want {
			if !slices.ContainsFunc(add, func(r firewallRule) bool { return r.Name == w.Name }) {
				c.kept = append(c.kept, w)
			}
		}
		for _, name := range remove {
			if err := removeRules(rules, name); err != nil {
				return err
			}
			c.removed = append(c.removed, name)
		}
		for _, r := range add {
			if err := addRule(rules, r, group); err != nil {
				return err
			}
			c.added = append(c.added, r)
		}
		return nil
	})
	return c, err
}

// readFirewall returns the rules of the group group, as Windows Firewall holds them.
func readFirewall(group string) ([]firewallRule, error) {
	var out []firewallRule
	err := withRules(func(rules *comObject) error {
		var err error
		out, err = groupRules(rules, group)
		return err
	})
	return out, err
}

// openPorts makes the rules of the group FirewallGroup the ones of the parts that are installed in
// the Ranz folder dir: the Node's, and the Controller's when its service is registered. It reports
// each rule to w. Windows Firewall that cannot be changed (its service is off, or another firewall
// owns the policy) is a warning: the Node and the Controller run all the same, and the ports are
// opened by hand.
func openPorts(w io.Writer, m *mgr.Mgr, dir string) {
	controller, err := serviceExists(m, controllerServiceName)
	if err != nil {
		fmt.Fprintf(w, "install: warning: Windows Firewall was not changed: %v\n", err)
		return
	}
	c, err := setFirewall(FirewallGroup, firewallRules(dir, controller))
	for _, name := range c.removed {
		fmt.Fprintf(w, "install: Windows Firewall: the rule %q of the group %s is removed, no part needs it as it was\n", name, FirewallGroup)
	}
	for _, r := range c.kept {
		fmt.Fprintf(w, "install: Windows Firewall lets in %s, the rule %q of the group %s, which is there already\n", r.describe(), r.Name, FirewallGroup)
	}
	for _, r := range c.added {
		fmt.Fprintf(w, "install: Windows Firewall lets in %s, the rule %q of the group %s\n", r.describe(), r.Name, FirewallGroup)
	}
	if err != nil {
		fmt.Fprintf(w, "install: warning: Windows Firewall was not set as it should be, so open the ports of docs/ports.md by hand: %v\n", err)
	}
}

// AllowTestPort lets the connections of the traffic test in to the running ranz.exe on the TCP port
// port while ranz test throughput -listen serves there (testRule), and reports it to w. The func that
// it returns removes the rule again. A rule that cannot be made is reported, and the test serves all
// the same: an Administrator then opens the port by hand.
func AllowTestPort(w io.Writer, port int) func() {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(w, "Windows Firewall: the path of this program: %v\n", err)
		return func() {}
	}
	r := testRule(self, port)
	err = withRules(func(rules *comObject) error {
		if err := removeRules(rules, r.Name); err != nil {
			return err
		}
		return addRule(rules, r, FirewallGroup)
	})
	if err != nil {
		fmt.Fprintf(w, "Windows Firewall does not let in %s (%v): open the port by hand if the client cannot connect\n", r.describe(), err)
		return func() {}
	}
	fmt.Fprintf(w, "Windows Firewall lets in %s while the test runs, the rule %q of the group %s\n", r.describe(), r.Name, FirewallGroup)
	return func() {
		_ = withRules(func(rules *comObject) error { return removeRules(rules, r.Name) })
	}
}

// closePorts removes every rule of the group FirewallGroup, whichever install or version made it,
// and reports it to w. A Windows Firewall that cannot be changed is a warning, as for openPorts, so
// that it never holds up an uninstall, which the MSI runs too.
func closePorts(w io.Writer) {
	c, err := setFirewall(FirewallGroup, nil)
	for _, name := range c.removed {
		fmt.Fprintf(w, "uninstall: Windows Firewall: the rule %q of the group %s is removed\n", name, FirewallGroup)
	}
	if err != nil {
		fmt.Fprintf(w, "uninstall: warning: the rules of the group %s were not all removed from Windows Firewall: %v\n", FirewallGroup, err)
	}
}
