package payload

import "testing"

// The WireGuardNT payload (SDN-80 #375) is wireguard.dll, the name that a gateway Node loads, and a
// signed file whose signature Install checks.
func TestWireGuardDllName(t *testing.T) {
	if WireGuardDll.Name != "wireguard.dll" {
		t.Errorf("the WireGuardNT payload is named %q, not wireguard.dll", WireGuardDll.Name)
	}
	if WireGuardDll.Unsigned || WireGuardDll.Catalog != "" {
		t.Error("the WireGuardNT payload is not checked by its own signature: WireGuard LLC signs the DLL and Install must check it")
	}
}
