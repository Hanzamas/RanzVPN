// Package install is `ranz install` and `ranz uninstall` (ONE-2, #311; ADR-0011 and ADR-0020
// amendments of 2026-10-22).
//
// Install makes the Ranz folder under Program Files and sets its access list: full control for
// SYSTEM and the Administrators, read and execute for the virtual accounts of the two services,
// nothing for Users. It writes two files into it, each after its hash and its Authenticode
// signature check (internal/payload): ranz-node.exe, the Node payload, and ranz.exe, a copy of the
// running ranz.exe. The copy is what the Controller service runs as `ranz.exe controller` and what
// the Node starts as `ranz.exe bgp`, next to ranz-node.exe, so neither runs from wherever the
// download was left. Then it registers the Node service ranzvpnserver under its virtual account
// (ADR-0039 decision 3) and starts it. With the Controller asked for it registers and starts the
// Controller service as well, under its own virtual account; without it no Controller service is
// made. A payload that fails its check is never written and never started: the call fails, no
// service is registered, and a Ranz folder that this call made is removed again.
//
// Uninstall stops and removes both services and the Ranz folder, and leaves the data directories
// alone (the Node's under ProgramData, which NewNode of src/Cedar/Node.c owns, and the
// Controller's), as ADR-0020 decision 3 asks. A later Install resumes with the same Configuration
// store and so the same Node identity key, which the key storage provider keeps for the virtual
// account of the service.
//
// Running Install again is safe. A service that exists is not made again, and a file that is
// there is not written again, because the running service holds it open: the call only writes a
// file that is missing and starts a service that does not run. Uninstall can run twice too.
//
// The Windows part is install_windows.go; every other OS refuses (install_other.go).
package install
