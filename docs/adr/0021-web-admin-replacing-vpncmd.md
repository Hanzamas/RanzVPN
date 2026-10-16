# ADR-0021: Web admin console and HTTP API, replacing vpncmd

**Status:** Accepted (2026-10-13, from the grilling). Built on the slim fork now, with an API contract designed to survive the new-core swap.

## Context

After ticket #4 removed the upstream JSON-RPC API and HTML5 console, vpncmd is the only admin surface the slim fork has. The code for the old surface still exists on `main-oracle` (`src/Cedar/Admin.c`, the `JsonRpc*` functions): JSON-RPC 2.0 at `/api/` on every TLS listener, Basic or header auth, a generic `PackToJson`/`JsonToPack` walker, and an HTML5 console at `/admin` served from hamcore `wwwroot`. Today admin traffic is native RPC (Pack over TLS) on the 443 and 5555 listeners; `AdminDispatch` holds the Cedar super lock per call, rights checks (server admin or hub admin) sit inside the handlers, and the `adminip.txt` source-IP allow list still exists.

Ticket #28 adds runtime field tables for the admin RPCs (about 108 RPCs over 63 wire types), so a structure's JSON shape can be generated from a table instead of per-RPC code. ADR-0008 puts the admin UI on http.sys with a Schannel binding in the new core; ADR-0011 makes the admin surface an API for a web UI and does not carry vpncmd into the new core; ADR-0020 ships vpncmd in the MSI until a replacement exists. The question was what the replacement is, and how much of it to build now on the slim fork rather than waiting for the new core.

## Decision

1. **Build it now on the slim fork**, with an API contract made to survive the core swap (ADR-0022). vpncmd is the only admin surface today; building the API once against a stable contract means the new core keeps the same UI.

2. **Surface.** Served on the server's existing admin TLS listener(s): `/admin` for the UI, `POST /api/v1/<RpcName>` for the API. No new certificate plumbing and no `netsh http add sslcert` step; the listener's certificate is reused (self-signed by default, set with `ServerCertSet`). Never plain HTTP.

3. **API shape: RPC-style.** `POST /api/v1/<RpcName>` with the request structure as JSON in the body; the reply is the structure as JSON, or `{"error":{"code","name","message"}}`. The JSON is generated from the #28 admin-RPC field tables (no per-RPC marshalling code); hand-written structures get hand-written JSON next to their Pack code, and an RPC area appears in the API only after its #28 slice lands. REST resources per object can be layered on later. Pack keys are the contract, without the upstream `_str`/`_u32` suffixes: numbers stay numbers, bools are `true`/`false`, IP addresses and binary are strings (binary base64), times ISO-8601 UTC.

4. **UI: a vanilla HTML/CSS/JS single-page app**, no framework and no build runtime on the server, embedded in `hamcore.se2` and served at `/admin/`. The MSI already ships hamcore, so the UI, the API and the server version travel together, and there is no CORS. Schema-driven forms come from a `GET /api/v1/schema` endpoint built from the #28 tables; the hand-made pages are server status, hubs, users, sessions, cascades, Local Bridge, listeners, certificates and logs. Scripting is covered by documented PowerShell `Invoke-RestMethod` and curl examples, not a new CLI.

5. **Authentication.** The existing credentials: the server-admin password and the per-hub admin passwords. The browser gets a session cookie (`HttpOnly; Secure; SameSite=Strict`) plus a per-session CSRF token required on every mutating request; an Origin/Host check and no CORS. TOTP is a later addition. In the new core (ADR-0022) this becomes **named admin accounts with roles** (owner, hub-admin, read-only) stored in SQLite.

6. **Access control.** The admin surface answers only **localhost and private (LAN) IPs by default**, with a configurable allowlist (the successor of `adminip.txt`, applied to the web path too). A request to `/admin` from a non-allowlisted IP is served the **decoy landing page, not a 403**: the server must not reveal that it is a VPN admin to an unlisted client. The decoy is the same page the active-probing path serves (ADR-0023).

7. **Brute-force protection.** After **5 failed logins, a 15-minute per-IP lockout**, and every failure is logged. The #28 NumItem overflow fix (option b: reject a count whose byte size overflows, before the rights checks) lands before any HTTP exposure, because a web API widens who can reach that code.

8. **Audit and metrics.** Every mutating admin action is audited at the `AdminDispatch` choke point (so native RPC and web are both covered): time, source IP, transport, principal (server, `hub:X` or a token id), RPC name, hub and result code, secrets redacted; of the reads, only logins. The audit trail goes to the server **log file and the Windows Event Log**. A **`/metrics` endpoint in Prometheus format** is served on the admin listener, and service lifecycle events go to the Windows Event Log. This needs a read/write flag per RPC, i.e. the #28 runtime RPC-table question is answered yes.

9. **Backup and restore** of configuration run through the web admin (`ConfigGet`/`ConfigSet`).

10. **When vpncmd dies.** vpncmd is frozen now (no new commands) and deleted only when the UI covers hubs, users, sessions, cascades, Local Bridge, listeners, certificates and logs; the generic API already covers every RPC; and the harness goldens have moved from vpncmd output to API/Pack goldens (`vpncmd /TOOLS Check` moves into vpntest). The #28 vpncmd command table and its driver are then dropped. In practice this lands with the new core (ADR-0011).

## Consequences

- vpncmd ships in the MSI (ADR-0020) and stays the scripting path and the harness test seam until the UI reaches parity; deleting it earlier would blind CI.
- The API depends on the #28 RPC tables and on the runtime RPC table (the read/write flag drives both the audit and the schema endpoint).
- The new core moves the same API to http.sys with a Schannel binding (ADR-0008) and swaps the credential model for named accounts and roles in SQLite (ADR-0022); the UI is built once against the unchanged contract.
- Keeping 443 presentable to unlisted clients (the decoy page rather than a 403) ties the admin surface to the anti-censorship design (ADR-0023); 443 never reveals an admin API.
- The parser restored for the JSON body (the oracle's Parson-derived parser) and the HTTP request path get fuzz targets in the existing fuzz-asan job; negative cases (401 without auth, 403 without CSRF, native-vs-web rights parity, 413 on an oversized body) are added to the harness.
