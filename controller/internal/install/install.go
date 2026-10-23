// Package install is `ranz install` and `ranz uninstall` (ONE-2, #311; ADR-0011 and ADR-0020
// amendments of 2026-10-22): the Node payload (ranz-node.exe, internal/payload) is written into
// the fixed Ranz VPN folder under Program Files, with an access list for SYSTEM and the
// Administrators only, after its hash and its Authenticode signature check; the Node service
// ranzvpnserver is registered under its virtual account (ADR-0039 decision 3) and started; and,
// when the caller asks for the Controller too, the Controller service (controllercmd) is
// registered and started beside it, under its own virtual account. A payload that fails its check
// is never written and never started, and no service is registered for it.
//
// Uninstall stops and removes both services and the folder, and leaves the Node's data directory
// (ProgramData, which NewNode of src/Cedar/Node.c owns) alone, as ADR-0020 decision 3 asks: a
// later Install resumes with the same Configuration store and so the same Node identity key.
//
// Running Install again when the Node service already exists does not touch the payload file
// again (the running service holds it open) or recreate the service; it only makes sure the
// service runs, so a second `ranz install` is a safe no-op.
//
// Windows only: see install_other.go for every other OS.
package install
