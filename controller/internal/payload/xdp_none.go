//go:build !windows || !amd64

package payload

// XdpPackage is empty outside Windows on x64 (ONE-3, #312): Microsoft ships no production-signed XDP
// runtime for arm64 (ADR-0022), and ranz install exists only on Windows.
var XdpPackage []Payload
