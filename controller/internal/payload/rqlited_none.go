//go:build !windows || !amd64

package payload

// Rqlited is empty outside Windows on x64 (ONE-4, #313): rqlite publishes a Windows build for x64
// only, and the Authenticode check that Ensure and Install make exists only on Windows, so there is
// no rqlite member to carry for another OS or architecture. ranz controller runs the rqlited that
// -rqlited names there, or uses the rqlite at -rqlite.
var Rqlited = Payload{Name: "rqlited.exe"}
