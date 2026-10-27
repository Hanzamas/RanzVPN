package install

import (
	"errors"

	"github.com/Hanzamas/RanzVPN/controller/internal/payload"
)

// ErrRebootRequired is what Uninstall returns, wrapped, when Windows did not let go of the network
// component of a driver within unbindWait: unbinding ms_xdp can hang after heavy load (#72, risk
// R2), so ranz uninstall stops waiting, leaves the driver in the install record for the next
// uninstall, and reports that a restart finishes it (exit code 3010) instead of hanging.
var ErrRebootRequired = errors.New("a restart of Windows is needed to finish: a network component did not unbind in time")

// Options is what the operator asked ranz install for.
type Options struct {
	// Controller also registers and starts the Controller service (ranz install --controller).
	Controller bool
	// AdminFrom is --admin-from: the prefixes that the API and the web UI of the Controller accept
	// connections from, or AdminFromAny; none for the default (adminfrom.go). Only a Controller that
	// is registered by this call takes it.
	AdminFrom []string
	// NoXDP leaves the XDP runtime out (ranz install --no-xdp), on a server that does not want it.
	NoXDP bool
	// NoWireGuard leaves wireguard.dll of WireGuardNT out (ranz install --no-wireguard), on a Node
	// that is the gateway of no WireGuard Device (SDN-80, #375): the Node reports no Capability
	// wireguard, and the controller refuses a Device whose gateway it is.
	NoWireGuard bool
	// Notice is the NOTICE of ranz.exe (ranz notice). Install writes it beside the files whose
	// licences it holds, as NOTICE.txt, because the licences of Wintun and WireGuardNT ask for their
	// text to go with the DLL wherever the DLL is written to disk. Empty writes no file.
	Notice string
}

// The folder of the Ranz folder that holds the files of the driver packages, one folder for each
// driver, and the name of the NOTICE that goes beside them.
const (
	driversFolder  = "drivers"
	noticeFileName = "NOTICE.txt"
)

// driver is one driver package that ranz install puts on the machine besides the Node (ONE-3,
// #312): SeLow, a protocol driver for x64 only, and the XDP runtime, a filter driver and its API
// library, also for x64 only. The Wintun driver is not one of them: wintun.dll installs it itself
// when the Node creates an adapter, so ranz install only writes the DLL.
type driver struct {
	// label is what the messages call the driver.
	label string
	// record is the name of the driver in the install record, and of its folder under drivers.
	record string
	// service is the service that the driver registers. A service of that name that is there
	// before ranz install runs is a driver that ranz leaves as it is, now and at uninstall.
	service string
	// component is the id of the network component, for netcfg.
	component string
	// class is the class of the component in the words of netcfg: p for a protocol, s for a service.
	class string
	// inf is the INF of the package, which names the other files.
	inf string
	// manifest is the manifest of the performance counters of the driver, "" for none.
	manifest string
	// leftovers are the files of System32 that the INF copies there and that stay when the
	// component is removed: ranz uninstall deletes them. Paths are relative to System32.
	leftovers []string
	// settings are written to the Parameters key of the service (settingsKey) once the component
	// is installed, and by every later install that finds the driver of an earlier ranz install.
	// They go with the key of the service when the driver is removed.
	settings []setting
	// files are the files of the package, which install writes into its folder; none on an
	// architecture that has no package.
	files []payload.Payload
}

// setting is a DWORD value of the Parameters key of the service of a driver, which the driver reads
// as its tuning.
type setting struct {
	name  string
	value uint32
}

// settingsKey returns the key that the settings of d go to (HKEY_LOCAL_MACHINE): the Parameters
// key of its service. The XDP runtime reads its tuning there and nowhere else (XDP_PARAMETERS_KEY
// of microsoft/xdp-for-windows: the key of the service of xdp.sys and \Parameters, which its INF
// creates), and watches that key, so a setting written there reaches a running driver.
func settingsKey(d driver) string {
	return `SYSTEM\CurrentControlSet\Services\` + d.service + `\Parameters`
}

// xdpRxRingSize is the XdpRxRingSize that install sets for the XDP runtime: the frames of the
// receive ring that XDP gives a queue when a program attaches to it, a power of two from 8 to 8192.
// XDP inspects what the host sends (TX inspect) through that ring, and with the default of 32 a
// send() of UDP segmentation offload of 44 segments left its sender blocked for good on a KM-TEST
// adapter, while a send() of 16 segments went through (#72, risk R1). A value on the key of the
// service itself, beside Parameters, never reached XDP, which kept the default.
const xdpRxRingSize = 1024

// seLowDriver is the SeLow NDIS protocol driver of SoftEther, which captures and injects the frames
// of a Local Bridge. Its INF is of the class NetTrans and installs the component SeLow (SL_PROTOCOL_NAME
// of src/SeLow/SeLowCommon.h, as src/Cedar/Win32Com.c installs it).
var seLowDriver = driver{
	label:     "the SeLow driver",
	record:    "SeLow",
	service:   "SeLow",
	component: "SeLow",
	class:     "p",
	inf:       "SeLow_x64.inf",
	leftovers: []string{`drivers\SeLow_x64.sys`},
}

// xdpDriver is the XDP for Windows runtime: the filter driver xdp.sys, installed as the network
// component ms_xdp, and the xdpapi.dll that the Node loads. It installs as Microsoft's xdp-setup.ps1
// does it: netcfg for the component and lodctr for the performance counters, then its receive ring
// is set up (xdpRxRingSize).
var xdpDriver = driver{
	label:     "the XDP runtime",
	record:    "xdp",
	service:   "xdp",
	component: "ms_xdp",
	class:     "s",
	inf:       "xdp.inf",
	manifest:  "xdppcw.man",
	leftovers: []string{`drivers\xdp.sys`, "xdpapi.dll"},
	settings:  []setting{{"XdpRxRingSize", xdpRxRingSize}},
}

// selectDrivers returns the drivers that Install puts on the machine, in the order it installs
// them: SeLow, then the XDP runtime unless noXDP. A driver whose package holds no file is left out:
// the architecture has none (arm64 has Wintun only).
func selectDrivers(selow, xdp []payload.Payload, noXDP bool) []driver {
	var out []driver
	if len(selow) > 0 {
		d := seLowDriver
		d.files = selow
		out = append(out, d)
	}
	if len(xdp) > 0 && !noXDP {
		d := xdpDriver
		d.files = xdp
		out = append(out, d)
	}
	return out
}

// everyDriver returns the drivers that an earlier install may have put on the machine, whatever
// this build carries: ranz uninstall removes the ones that its install record names.
func everyDriver() []driver {
	return []driver{seLowDriver, xdpDriver}
}
