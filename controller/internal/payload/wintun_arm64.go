//go:build windows && arm64

package payload

import _ "embed"

// wintun_arm64.dll is a placeholder in the committed tree: empty, which Install refuses, since a
// payload with no data is never written. The sign_and_integrity job of windows.yml
// (.github/scripts/self-integrity.ps1, ONE-3 #312) writes the wintun.dll of the pinned Wintun
// release (.github/scripts/fetch-wintun.ps1) over it, in its own checkout, before it builds the
// ranz.exe that it signs. The DLL is embedded as WireGuard LLC signed it and is never changed or
// signed again: its licence lets it be redistributed unmodified only (THIRD_PARTY.TXT, NOTICE).
//
//go:embed wintun_arm64.dll
var wintunArm64Bytes []byte

// WintunDll is the Wintun payload of this architecture: the wintun.dll that the client role of the
// Node loads from the folder of its executable, and which installs its driver itself (ADR-0011
// amendment of 2026-10-22, ONE-3 #312). On arm64 it is the only driver that ranz install carries.
var WintunDll = New("wintun.dll", wintunArm64Bytes)
