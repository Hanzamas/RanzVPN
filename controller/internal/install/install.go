// Package install is `ranz install` and `ranz uninstall` (ONE-2, #311; ONE-3, #312; ADR-0011 and
// ADR-0020 amendments of 2026-10-22).
//
// Install makes the Ranz folder under Program Files and sets its access list: full control for
// SYSTEM and the Administrators, read and execute for the virtual accounts of the two services,
// nothing for Users. It writes four files into it, each after its hash and its Authenticode
// signature check (internal/payload): ranz-node.exe, the Node payload, wintun.dll, the Wintun
// driver of WireGuard LLC, which the Node loads from its own folder and which installs its driver
// itself, the NOTICE beside it (NOTICE.txt, which holds the licence of Wintun, hash checked only),
// and ranz.exe, a copy of the running ranz.exe. The copy is what the Controller service runs as
// `ranz.exe controller` and what the Node starts as `ranz.exe bgp`, next to ranz-node.exe, so
// neither runs from wherever the download was left.
//
// Then it puts the drivers of the machine's architecture on it (drivers.go): on x64 the SeLow
// driver and the XDP runtime, each written under drivers\ in the Ranz folder, published to the
// driver store, installed as its network component with netcfg, started, and noted in the install
// record (HKLM\SOFTWARE\Hanzcodes\Ranz VPN\Drivers); on arm64 there are none, so Wintun is the
// only driver, and the Node reports no SeLow and no XDP. A driver that is on the machine already
// stays as it is and is not noted. ranz install --no-xdp leaves the XDP runtime out. A driver that
// fails to install is taken out again and reported as a warning, and the install goes on: the Node
// runs without it, reports its Capability as missing and falls back to the next L2 backend. Then it
// registers the Node service ranzvpnserver under its virtual account (ADR-0039 decision 3) and
// starts it. With the Controller asked for it registers and starts the Controller service as well,
// under its own virtual account; without it no Controller service is made. A payload of the Ranz
// folder that fails its check is never written and never started: the call fails, no service is
// registered, and a Ranz folder that this call made is removed again.
//
// Uninstall stops and removes both services, takes out the drivers that the install record names
// (and leaves the ones that were on the machine before), and removes the Ranz folder. It leaves
// the data directories alone (the Node's under ProgramData, which NewNode of src/Cedar/Node.c
// owns, and the Controller's), as ADR-0020 decision 3 asks. A later Install resumes with the same
// Configuration store and so the same Node identity key, which the key storage provider keeps for
// the virtual account of the service.
//
// Running Install again is safe. A service that exists is not made again, and a file that is
// there is not written again, because the running service holds it open: the call only writes a
// file that is missing and starts a service that does not run. A driver that is there is not
// installed again; one that this call does install (after ranz install --no-xdp, say) makes a Node
// that runs start again, because the Node reads what the machine holds at its start and reports it
// as its Capabilities (src/Cedar/NodeCaps.c). Uninstall can run twice too.
//
// The Windows part is install_windows.go and drivers_windows.go; every other OS refuses
// (install_other.go).
package install
