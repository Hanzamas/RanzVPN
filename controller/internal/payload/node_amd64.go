//go:build windows && amd64

package payload

import _ "embed"

// node_amd64.exe is a placeholder in the committed tree (empty: Install refuses it, since a
// payload with no data is never written). The install job of windows.yml (ONE-2, #311) replaces
// it with the Authenticode-signed ranz-node.exe that the x64 job of windows.yml builds, before
// building ranz.exe, so the real payload is embedded only in that build.
//
//go:embed node_amd64.exe
var nodeAmd64Bytes []byte

// NodeExe is the ranz-node payload of this architecture (ADR-0011 amendment of 2026-10-22).
var NodeExe = New("ranz-node.exe", nodeAmd64Bytes)
