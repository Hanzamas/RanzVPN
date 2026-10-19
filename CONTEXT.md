# Ranz VPN

Slimmed fork of SoftEther VPN (C, CMake): native SE-VPN protocol only, Windows 10 / Server 2016 and later on x64 and arm64, headless `vpnserver` and `vpncmd`, no GUI. Almost all code lives in two static libraries: `mayaqua` (runtime) and `cedar` (VPN logic, links `mayaqua`). Scope decisions are in `docs/adr/` (start with ADR-0001, ADR-0012, ADR-0013).

## Module map

A module is one `X.c` / `X.h` pair under `src/Cedar` or `src/Mayaqua`. Edges below combine `#include` and the identifiers each `.c` file uses from another module's header (counts are approximate). Two things to know before reading the tables:

- The low-level Mayaqua modules (OS, Win32, Memory, Object, Kernel, Str, Internat, FileIO, Tracking, Tick64, Mayaqua) call each other in cycles. They are one layer, not a chain. `InitMayaqua` brings them up in this order: OS, FIFO, kernel status, Tracking, threading, string library, crypto, Tick64, Network, exe name and command line, OS info, Microsoft (`MsInit`), hamcore, string table.
- The Cedar core (Hub, Session, Connection, Protocol, Server, Admin, Account, Logging) is also one cycle. Only the leaves listed as "none in Cedar" below are independent.

Executables: `vpnserver` uses Cedar/Server (`StInit`, `StStartServer`) and `MsService`; `vpncmd` uses Cedar/Command (`CommandMain`); `vpntest` uses Account, Admin, Command, Connection, Listener, MsChapV2, Server, Session, WaterMark and many Mayaqua modules; `fuzz` uses Mayaqua only (Cfg, Encrypt, HTTP, Pack, TcpIp).

### Mayaqua (`src/Mayaqua`)

| Module | Responsibility | Main types | Uses | Used by |
|---|---|---|---|---|
| MayaType.h | Header only: base typedefs and forward declarations of every Mayaqua struct; includes `Crypto/Types.h` | `UINT`, `bool`, `typedef struct X X` | none | every module |
| OS | `OSxxx` facade (memory, lock, event, thread, file, time) forwarding through one table, set at `OSInit` | `OS_DISPATCH_TABLE` | Win32, Kernel, FileIO, Object | all Mayaqua, 12 Cedar modules |
| Win32 | The only OS back end: Win32 API implementation of the dispatch table | none | OS, Microsoft, Internat, Kernel, FileIO | OS, Microsoft, Kernel, Tick64, Internat, FileIO |
| Memory | Allocator aliases (no custom allocator) and containers | `BUF`, `LIST`, `QUEUE`, `FIFO`, `HASH_LIST`, `SK` | Mayaqua, OS, Object, FileIO, Encoding | all |
| Object | Synchronisation and lifetime primitives | `LOCK`, `EVENT`, `COUNTER`, `REF`, `DEADCHECK` | Mayaqua, OS, Kernel, Tick64 | Memory, Kernel, Encrypt, Network, DNS, Cfg, Str, Win32, most Cedar |
| Kernel | Threads and thread pool, single-instance guard, system and local time, locale strings | `THREAD`, `INSTANCE`, `LOCALE`, `MEMINFO` | OS, Object, Internat, Table | Memory, Object, OS, Network, Encrypt, Microsoft, 13 Cedar modules |
| Tick64 | Monotonic 64-bit millisecond clock | `TICK64`, `ADJUST_TIME` | OS, Kernel, Microsoft, Object | Object, Memory, FileIO, Network, DNS, Stun, Table, 12 Cedar modules |
| Tracking | Debug-only memory and call-stack tracking | `TRACKING_OBJECT`, `CALLSTACK_DATA` | OS, Str, Kernel | Mayaqua, Memory, OS |
| Str | ANSI/UTF-8 string helpers and tokenising | `TOKEN_LIST` | Memory, Internat, OS | all |
| Internat | Wide-string (`Uni*`) helpers and charset conversion | `UNI_TOKEN_LIST` | Memory, Str, Mayaqua, Win32 | all |
| Encoding | Base64 only | none | none | Memory |
| FileIO | Files, directories, dump read/write, hamcore reader (`\|name` paths, PE resources) | `IO`, `DIRENT`, `DIRLIST`, `HC` | Internat, OS, Mayaqua, Win32 | Cfg, Microsoft, Network, Table, 10 Cedar modules |
| Encrypt | Crypto wrappers: certificates, keys, RSA, DH, SHA-256 and `CIPHER` on OpenSSL; MD4, MD5, SHA-1, RC4, DES and random on CNG; SHA-0 own code | `X`, `K`, `NAME`, `CIPHER`, `CRYPT`, `DH_CTX` | Internat, Object, OS, Kernel | Cfg, Table, Network, Pack, Stun, Memory, Kernel, 16 Cedar modules |
| Cfg | Text configuration tree and reader/writer | `FOLDER`, `ITEM`, `CFG_RW` | FileIO, Internat, Encrypt, Network | Table, Cedar/Server (the config file), Account, Admin, SeLowUser |
| Table | String table, language list, `_SS`/`_UU`/`_II`/`_E` lookup, `$lang.config` | `TABLE`, `LANGLIST` | Internat, Encrypt, FileIO, Cfg, Mayaqua | Kernel, Microsoft, Command, Console, Admin, Hub and others |
| Mayaqua | Library init and free, command line, minimal mode, OS info, kernel status counters | none | all base modules | every executable, Cedar |
| Network | Sockets (TCP, UDP, SSL), listen/accept/connect, IP types, cancel objects, socket sets | `SOCK`, `SOCKSET`, `CANCEL`, `IP`, `IPV6_ADDR`, `SSL_ACCEPT_SETTINGS` | Object, Encrypt, OS, FileIO, Microsoft, DNS, Pack | DNS, HTTP, Proxy, Stun, TcpIp, Pack, Cfg, Table, 15 Cedar modules |
| DNS | Resolver with forward and reverse caches | `DNS_CACHE`, `DNS_RESOLVER` | Network, Object, Kernel, Tick64 | Network, Stun, Table, Logging, Protocol, Server |
| TcpIp | Wire-format headers and parse/build for Ethernet, ARP, IPv4/IPv6, ICMP, UDP, TCP, DHCP | `PKT`, `MAC_HEADER`, `IPV4_HEADER`, `DHCPV4_DATA` | Memory, Network, Encrypt | Hub (frame inspection), Logging, Bridge, Command, Connection, Server, UdpAccel |
| HTTP | HTTP header parse and send | `HTTP_HEADER`, `HTTP_VALUE` | Pack, Network, Kernel | Proxy, Cedar/Protocol, Wpc, Admin, Command, Cedar |
| Proxy | Outbound HTTP CONNECT, SOCKS4 and SOCKS5 connectors | `PROXY_PARAM_IN`, `PROXY_PARAM_OUT` | Network, HTTP | Protocol, Wpc |
| Stun | STUN binding request/response (mapped address discovery) | none | Network, DNS, Tick64, Encrypt | Cedar/UdpAccel, vpntest |
| Pack | PACK serialisation | `PACK`, `ELEMENT`, `VALUE` | Memory, Encrypt, Network, Internat | HTTP, Network, Protocol, Admin, Account, Command, Remote, Server |
| Microsoft | Windows services, registry, privileges, process list, adapter info, `MsService` | `MS`, `MS_ADAPTER`, `MS_TCP`, `MS_PROCESS` | Internat, Table, FileIO, Kernel, Win32 | Win32, Mayaqua, Network, Table, Tick64, Admin, Bridge, BridgeWin32, Cedar, Command, Console, Logging, SeLowUser, Server, `vpnserver` |

`Crypto/Key.c`, `Crypto/Key.h` and `Crypto/Types.h` hold no code (7, 6 and 4 lines); `MayaType.h` includes `Types.h`.

### Cedar (`src/Cedar`)

| Module | Responsibility | Main types | Uses (in Cedar) | Used by (in Cedar) |
|---|---|---|---|---|
| CedarType.h | Header only: forward declarations of every Cedar struct | `CEDAR`, `HUB`, `SESSION`, ... | none | every module |
| Cedar | Root `CEDAR` object (listeners, hubs, connections, CA list, server certificate, Local Bridge list, traffic counters), `InitCedar`/`FreeCedar`, protocol constants (`CONNECTION_TYPE_*`, `TCP_*`) | `CEDAR`, `TRAFFIC`, `NETSVC`, `NON_SSL`, `TINY_LOG` | Hub, Connection, Listener, Bridge, Logging, WaterMark | all except MsChapV2, UdpAccel, WaterMark, Win32Com, BridgeWin32, SeLowUser |
| Server | Process-level `SERVER`: config load/save (`$ranz_server.config`), hub creation from config, autosave thread, syslog, capability list, `StInit`/`StStartServer`/`StStopServer` | `SERVER`, `SERVER_LISTENER`, `CAPS`, `SYSLOG_SETTING` | Account, Logging, Hub, Listener, Sam, Bridge, BridgeWin32, Link | Admin, Command, Hub, Logging, Protocol, Sam, Session |
| Listener | TCP and UDP listeners, accept threads, DoS protection, UDP entry table | `LISTENER`, `DOS`, `UDP_ENTRY` | Logging, Connection, Session | Cedar, Connection, Server |
| Connection | Transport state: sockets, TCP half-connections, send/receive block queues, client options | `CONNECTION`, `TCP`, `TCPSOCK`, `UDP`, `BLOCK`, `CLIENT_OPTION`, `CLIENT_AUTH` | UdpAccel, BridgeWin32, Logging, Session, Listener | Admin, Bridge, Cedar, Hub, Link, Listener, Protocol, Session, UdpAccel |
| Protocol | SE-VPN handshake (signature, hello, login PACKs), `ServerAccept`, `ClientConnect`, additional connections, certificate checks | `CHECK_CERT_THREAD_PROC` | Hub, Logging, UdpAccel, Session, Account, Server, Sam, Admin, Wpc, MsChapV2 | Account, Admin, Hub, Session |
| Session | Session state machine (`SessionMain`, `NewClientSession`, `NewServerSession`), packet adapters, keep-alive | `SESSION`, `PACKET_ADAPTER`, `NODE_INFO` | Connection, Protocol, Server, Account, Hub, Logging | Admin, Bridge, Connection, Hub, Link, Listener, Protocol |
| Hub | Virtual switch: MAC and IP tables, frame forwarding and filtering, traffic limits, user database, CA and CRL lists, hub log, watchdog | `HUB`, `HUBDB`, `HUB_OPTION`, `ACCESS`, `MAC_TABLE_ENTRY`, `IP_TABLE_ENTRY`, `HUB_PA` | Logging, Session, Account, Server, Connection, Link, Protocol, Bridge | Admin, Bridge, Cedar, Command, Protocol, Sam, Server, Session |
| Account | Users, groups, policies, authentication method records | `USER`, `USERGROUP`, `POLICY`, `AUTHPASSWORD`, `AUTHUSERCERT`, `AUTHROOTCERT`, `AUTHNT` | Protocol, Hub, Session, Connection (mostly header level) | Admin, Bridge, Command, Hub, Protocol, Sam, Server, Session |
| Sam | Hub-level user authentication (password, anonymous, certificate, plain, MS-CHAPv2) | none of its own | Account, MsChapV2, Server, Hub, Logging | Admin, Command, Protocol, Server |
| MsChapV2 | Standalone MS-CHAPv2 helpers (NT hash, challenge, responses) | `IPC_MSCHAP_V2_AUTHINFO` | none in Cedar | Protocol, Sam |
| Link | Cascade: a Hub-owned client Session paired with a server Session on the same Hub | `LINK` | Session, Connection, Logging | Admin, Hub, Server |
| Bridge | Local Bridge: bridge-mode Session on a Hub joined to a physical adapter; per-Cedar Local Bridge list | `BRIDGE`, `LOCALBRIDGE` | Session, Account, Hub, Connection, Logging, BridgeWin32 | Admin, Cedar, Connection, Hub, Server |
| BridgeWin32 | Windows NIC access for bridging: open adapter through SeLow, get/put frames, MTU, device enumeration (`Win32Eth*`) | `ETH`, `WP_ADAPTER` | SeLowUser (and Microsoft) | Admin, Bridge, Connection, Server |
| SeLowUser + Win32Com | User-mode side of the SeLow NDIS driver: adapter list, packet get/put, driver install (`Win32Com.cpp` installs the protocol driver through `INetCfg`) | `SU`, `SU_ADAPTER`, `SU_ADAPTER_LIST` | Microsoft, FileIO, Cfg | BridgeWin32 only |
| UdpAccel | UDP acceleration: key and cookie exchange, encrypted UDP send and receive, optional STUN discovery | `UDP_ACCEL` | Connection | Connection, Protocol |
| Remote | RPC transport over a socket: request/response PACKs | `RPC`, `RPC_DISPATCHER` | none in Cedar (Pack, Network) | Admin |
| Admin | Admin RPC: `AdminAccept`, `AdminDispatch` table of `St*` handlers, `Sc*` client calls, `InRpc*`/`OutRpc*` converters | `ADMIN`, about 70 `RPC_*` structs | Hub, Server, Account, Logging, Sam, Link, Session, Bridge, Remote | Command, Protocol |
| Command | `vpncmd`: `CommandMain`, server-admin commands (`Ps*`), tools (`Pt*`), traffic test (`Tt*`), table output (`CT`) | `PS`, `PT`, `CT`, `TTC`, `TTS`, `TT_RESULT` | Console, Admin, Account, Server, Hub, Sam, Database | `vpncmd`, `vpntest` |
| Console | Console abstraction, command-line parameter parser, command tables, prompts | `CONSOLE`, `PARAM`, `CMD`, `LOCAL_CONSOLE_PARAM` | none in Cedar | Command |
| Logging | Threaded rotating file logger, packet and hub logs, log eraser, syslog | `LOG`, `PACKET_LOG`, `HUB_LOG`, `ERASER`, `SLOG` | Server | Admin, Bridge, Cedar, Connection, Hub, Link, Listener, Protocol, Sam, Server, Session |
| Wpc | HTTP(S) fetch helper with optional proxy | `URL_DATA`, `INTERNET_SETTING`, `WPC_CONNECT` | none in Cedar | Protocol |
| WaterMark | GIF "digital watermark" blob (from hamcore `watermark.bin`) the client uploads in the signature step and the server checks | none | none | Cedar (init), Protocol |
| Database | Vestigial: one function, `LiGetLicenseStatusStr` | none | none | Command |

## Language

**Hub**:
A virtual Ethernet switch (`HUB`). Sessions attached to it exchange Ethernet frames; it owns users, groups, the access list, logs and Cascades. Servers host many Hubs.
_Avoid_: virtual switch, network, room

**Session**:
One authenticated attachment of a peer to a Hub (`SESSION`), with a policy and traffic counters. It is a client Session, a Cascade Session (`LinkModeClient` or `LinkModeServer`) or a Bridge Session (`BridgeMode`).
_Avoid_: tunnel, user connection

**Connection**:
One transport link (`CONNECTION`) that runs the handshake and carries data blocks over TCP/SSL sockets (several `TCPSOCK` half-connections, each with a direction) or UDP. A Session owns one Connection. The `CONNECTION_TYPE_*` value tells what a Connection is for: login, additional socket, admin RPC, hub enumeration or password change.
_Avoid_: using it as a synonym for Session; socket

**Cascade**:
A Hub dialling another Hub as a client (`LINK`): a client Session out to the remote Hub joined to a server Session on the local Hub, so the two Hubs form one L2 segment. It is the only client the slim fork keeps (ADR-0012). vpncmd uses `Cascade*` commands; the code and RPC use `Link`.
_Avoid_: client connection, tunnel, VPN link

**Local Bridge**:
An L2 bridge between a Hub and a physical Ethernet adapter. `LOCALBRIDGE` is the configured pair (Hub name, device name, with `Monitor`, `TapMode`, `LimitBroadcast` flags). `BRIDGE` is the running instance, which holds a bridge-mode Session and an `ETH`. On Windows 10 it runs on SeLow (ADR-0013).
_Avoid_: network bridge, bare "Bridge" (also the `Cedar->Bridge` product-flavour flag)

**SeLow**:
SoftEther's signed NDIS lightweight filter driver that captures and injects frames for a Local Bridge. Driver sources live in `src/SeLow`; the user-mode side is `SeLowUser`.

**PACK**:
SE-VPN's key/value message: a `PACK` holds named `ELEMENT`s, each with one or more typed `VALUE`s (int, int64, string, wide string, data). It carries the handshake (hello, login, welcome) and every admin RPC request and response.
_Avoid_: packet (an Ethernet frame is a `PKT`; a queued data unit is a `BLOCK`)

**Admin RPC**:
The management protocol. A Connection whose login PACK has `method` = `admin` (`CONNECTION_TYPE_ADMIN_RPC`) is authenticated by `AdminAccept` as server admin or Hub admin (`ADMIN`) and then loops: a request PACK with `function_name` goes through `AdminDispatch` to an `St*` handler, and the reply PACK carries `error_code`. Callers use the `Sc*` wrappers; `vpncmd` is the main caller.
_Avoid_: JSON-RPC (removed from the fork), management API

**hamcore**:
The files of `src/bin/hamcore/`, compiled into `vpnserver`, `vpncmd` and `vpntest` as PE resources of type `HAMCORE` by `cmake/RanzResources.cmake` (one resource per file, and an `INDEX` resource that names them) and read by `ReadHamcore` through `FindResource`/`LoadResource`. Files are named with a `|` prefix in IO paths (for example `|strtable_en.stb`, `|root_certs.dat`, `|watermark.bin`). A loose `hamcore/` folder next to the executable wins over the built-in files. An executable without them is fatal at start-up (`InitHamcore`). There is no `hamcore.se2` archive any more.
_Avoid_: resource file, data pack

**String table**:
The `strtable_<lang>.stb` file in hamcore (`en`, `id`), loaded by `InitTable` into `TABLE` entries. Code looks entries up by key: `_SS` (ANSI), `_UU` (wide), `_II` (integer), `_E` (error code to text). The language comes from `$lang.config` and `languages.txt`. `vpncmd` output is built from `_UU` strings, so the harness goldens depend on it.
_Avoid_: resource strings, locale file

**UDP Acceleration**:
An optional encrypted UDP data path set up inside a Session (`UDP_ACCEL`), with an optional STUN lookup of the mapped address.

**Config file**:
The server's text configuration tree (`$ranz_server.config`, `FOLDER`/`ITEM`), loaded and autosaved by `Server.c` through `CFG_RW`. Its format is frozen.

**Machine identity**:
The 20 bytes that `GenerateMachineUniqueHash` returns for a server: a hash of the Windows MachineGuid and the `MachineIdSalt` of the Config file, kept in the `CEDAR`. It sets the MAC address and the 172.31.x.x address of every Hub and the `unique_id` of a Cascade login. It stays the same across restarts, renames and IP changes; servers cloned from one image differ only when each has its own config file, and so its own salt (FIX-5, `docs/upgrade-notes.md`).
_Avoid_: machine ID (Windows' name for the MachineGuid), `UniqueId` (a random value per `CEDAR`, copied into `NODE_INFO`)

## Flagged ambiguities

- "Cedar" names both the library and the root `CEDAR` object. "Mayaqua" is only the library.
- "Bridge" is the Local Bridge feature, the `BRIDGE` object, the `Bridge.c` module and the `Cedar->Bridge` flag. Say Local Bridge for the feature.
- "Link" in code is "Cascade" in vpncmd and in prose. Use Cascade, and `LINK` only for the struct.
