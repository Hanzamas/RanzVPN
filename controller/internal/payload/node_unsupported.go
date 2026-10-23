//go:build !windows || (!amd64 && !arm64)

package payload

// NodeExe is empty outside Windows/amd64 and Windows/arm64: ranz install, the only caller, exists
// only on Windows (internal/install), so there is nothing to embed for another OS or architecture.
var NodeExe = Payload{Name: "ranz-node.exe"}
