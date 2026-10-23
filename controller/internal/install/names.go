package install

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// The names that install and uninstall share with the services and the files they make. The Node
// service is ranzvpnserver (ADR-0020 decision 4), the Controller service is the one of
// controller/service_windows.go, and ranz.exe is the name that the Node looks for next to its own
// executable (NODE_BGP_EXE_NAME of src/Cedar/Node.h).
const (
	nodeServiceName       = "ranzvpnserver"
	controllerServiceName = "ranz-controller"
	ranzExeName           = "ranz.exe"
	folderName            = "Ranz VPN"
)

// serviceSID returns the SID that Windows gives the virtual account NT SERVICE\name of the service
// name, the one that sc showsid prints: S-1-5-80 and the five 32-bit words of the SHA-1 of the name
// in upper case, as UTF-16 with the low byte first. The access list of the Ranz folder names the
// accounts by it, so it can be set before the services exist.
func serviceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(raw[2*i:], u)
	}
	sum := sha1.Sum(raw)
	sid := "S-1-5-80"
	for i := 0; i < len(sum); i += 4 {
		sid += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(sum[i:]))
	}
	return sid
}

// folderSDDL is the access list of the Ranz folder under Program Files, in SDDL. SYSTEM and the
// Administrators get full control. The virtual accounts of the Node and Controller services get read
// and execute: a service starts its executable as that account, which is in neither group and
// would otherwise have no right to it. Nobody else gets anything, Users included. The list is
// protected, so it inherits nothing from Program Files, which lets Users read.
func folderSDDL() string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" +
		"(A;OICI;FRFX;;;" + serviceSID(nodeServiceName) + ")" +
		"(A;OICI;FRFX;;;" + serviceSID(controllerServiceName) + ")"
}
