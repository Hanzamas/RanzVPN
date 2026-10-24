//go:build windows && arm64

package payload

import _ "embed"

// rqlited_arm64.exe is a placeholder in the committed tree (empty: Ensure and Install refuse it,
// since a payload with no data is never written). The Windows arm64 job of ranz.yml (ONE-4, #313)
// replaces it with the rqlited.exe of the pinned rqlite release, signed with a certificate of CI
// that the runner trusts, before it builds ranz.exe, so the real member is embedded only in that
// build. rqlite publishes no Windows build for arm64 and cannot be built without cgo, so this is
// the x64 rqlited.exe of the release, which Windows 11 on ARM runs under emulation; Windows 10 on
// ARM has no emulation of x64, and a Controller there runs the rqlited that -rqlited names.
//
//go:embed rqlited_arm64.exe
var rqlitedArm64Bytes []byte

// Rqlited is the rqlite member of a Controller: the rqlited.exe of the pinned rqlite release
// (ADR-0026 amendment of 2026-10-23). ranz controller writes it under its data directory with
// Ensure and runs it as its sidecar.
var Rqlited = New("rqlited.exe", rqlitedArm64Bytes)
