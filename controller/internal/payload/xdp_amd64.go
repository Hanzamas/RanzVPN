//go:build windows && amd64

package payload

import _ "embed"

// The files of xdp/ are placeholders in the committed tree: empty, which Install refuses, since a
// payload with no data is never written. The sign_and_integrity job of windows.yml
// (.github/scripts/self-integrity.ps1, ONE-3 #312) writes the files of runtime/native of the pinned
// Microsoft.XDP-for-Windows.Runtime.x64 package (.github/scripts/fetch-xdp.ps1) over them, in its own
// checkout, before it builds the ranz.exe that it signs. They keep the production signature of
// Microsoft (ADR-0018 amendment of 2026-10-22).
//
//go:embed xdp/xdp.sys
var xdpSysBytes []byte

//go:embed xdp/xdpapi.dll
var xdpApiBytes []byte

//go:embed xdp/xdp.cat
var xdpCatBytes []byte

//go:embed xdp/xdp.inf
var xdpInfBytes []byte

//go:embed xdp/xdppcw.man
var xdpManBytes []byte

// XdpPackage is the XDP runtime (ADR-0018 amendment of 2026-10-22, ONE-3 #312): the driver, its API
// library and its catalog carry the signature of Microsoft, and the INF and the manifest of the
// performance counters have none of their own. The INF puts the driver in System32\drivers and
// the API library in System32 when Windows installs the package, as Microsoft's xdp-setup.ps1 does.
// It is x64 only, since Microsoft ships no production-signed runtime for arm64 (ADR-0022).
var XdpPackage = []Payload{
	New("xdp.sys", xdpSysBytes),
	New("xdpapi.dll", xdpApiBytes),
	New("xdp.cat", xdpCatBytes),
	NewUnsigned("xdp.inf", xdpInfBytes),
	NewUnsigned("xdppcw.man", xdpManBytes),
}
