//go:build windows && amd64

package payload

import _ "embed"

// The files of the SeLow driver package of SoftEther, which Microsoft signed for Windows 10 and
// later: a copy of the folder src/bin/hamcore/DriverPackages/SeLow_Win10/x64, byte for byte, in
// selow/, because go:embed reads files below its own package only. selow_test.go compares each file
// with the one in hamcore, so the two cannot drift apart.
//
//go:embed selow/SeLow_x64.sys
var selowSysBytes []byte

//go:embed selow/SeLow_Win10_x64.cat
var selowCatBytes []byte

//go:embed selow/SeLow_x64.inf
var selowInfBytes []byte

// SeLowPackage is the SeLow driver package (ADR-0011 amendment of 2026-10-22, ONE-3 #312): the
// driver and its catalog, which carry the signature of Microsoft, and the INF, which has none of
// its own and which Windows checks against the catalog when it publishes the package. It is
// x64 only: SeLow cannot be built for arm64 without a driver signing pipeline of our own (ADR-0013).
var SeLowPackage = []Payload{
	New("SeLow_x64.sys", selowSysBytes),
	New("SeLow_Win10_x64.cat", selowCatBytes),
	NewUnsigned("SeLow_x64.inf", selowInfBytes),
}
