//go:build !windows || !amd64

package payload

// SeLowPackage is empty outside Windows on x64 (ONE-3, #312): there is no SeLow driver package for
// arm64 (ADR-0013, ADR-0022 amendment of 2026-10-21), and ranz install exists only on Windows.
var SeLowPackage []Payload
