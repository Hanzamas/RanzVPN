//go:build windows && amd64

package payload

import _ "embed"

// wireguard_amd64.dll is a placeholder in the committed tree: empty, which Install refuses, since a
// payload with no data is never written. The sign_and_integrity job of windows.yml
// (.github/scripts/self-integrity.ps1, SDN-80 #375) writes the wireguard.dll of the pinned
// WireGuardNT SDK (.github/scripts/fetch-wireguard.ps1) over it, in its own checkout, before it
// builds the ranz.exe that it signs. The DLL is embedded as WireGuard LLC signed it and is never
// changed or signed again: its licence lets it be redistributed unmodified only (THIRD_PARTY.TXT,
// NOTICE).
//
//go:embed wireguard_amd64.dll
var wireguardAmd64Bytes []byte

// WireGuardDll is the WireGuardNT payload of this architecture: the wireguard.dll that a gateway of
// WireGuard Devices loads from the folder of its executable, and which installs the WireGuardNT
// driver itself (SDN-80 #375). ranz install --no-wireguard leaves it out.
var WireGuardDll = New("wireguard.dll", wireguardAmd64Bytes)
