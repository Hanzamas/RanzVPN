//go:build !windows || (!amd64 && !arm64)

package payload

// WireGuardDll is empty outside Windows on x64 and arm64 (SDN-80, #375): ranz install, the only
// caller, exists only on Windows (internal/install), so there is nothing to embed for another OS or
// architecture.
var WireGuardDll = Payload{Name: "wireguard.dll"}
