//go:build !windows || (!amd64 && !arm64)

package payload

// WintunDll is empty outside Windows on x64 and arm64 (ONE-3, #312): ranz install, the only
// caller, exists only on Windows (internal/install), so there is nothing to embed for another OS or
// architecture.
var WintunDll = Payload{Name: "wintun.dll"}
