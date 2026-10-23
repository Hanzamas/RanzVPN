//go:build windows && amd64

package payload

import _ "embed"

// node_amd64.exe is a placeholder in the committed tree: empty, which Install refuses, since a
// payload with no data is never written. The sign_and_integrity job of windows.yml
// (.github/scripts/self-integrity.ps1, ONE-2 #311) writes the Authenticode-signed ranz-node.exe
// that the x64 job of windows.yml builds over it, in its own checkout, before it builds the
// ranz.exe that it signs, so only that build carries the real payload.
//
//go:embed node_amd64.exe
var nodeAmd64Bytes []byte

// NodeExe is the ranz-node payload of this architecture (ADR-0011 amendment of 2026-10-22).
var NodeExe = New("ranz-node.exe", nodeAmd64Bytes)
