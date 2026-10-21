# Ranz VPN

Slimmed fork of SoftEther VPN (C, CMake): native SE-VPN protocol only, Windows 10 / Server 2016 and later on x64 and arm64, headless `vpnserver` and `vpncmd`, no GUI. Almost all code lives in two static libraries: `mayaqua` (runtime) and `cedar` (VPN logic, links `mayaqua`). Scope decisions are in `docs/adr/` (start with ADR-0001, ADR-0012, ADR-0013).

## Module map

A module is one `X.c` / `X.h` pair under `src/Mayaqua`, `src/Cedar` or `src/Core` (the new core). The files split out of a god file (#29) belong to that file's module and use its header as their API header. Declarations that only those files need are in the module-internal header `XInternal.h`, which only the module's own files include. Encrypt is named differently: its API header is `Encrypt.h`, its code is `src/Mayaqua/Crypto/*.c` and its internal header is `Crypto/Cng.h`. The tree has 53 modules (23 in Mayaqua, 29 in Cedar, 1 in Core) and four headers without code: MayaType.h, Platform.h, CedarType.h, and `src/GlobalConst.h` (the product name strings, included by Cedar.h, FileIO, Mayaqua and Microsoft).

The Uses and Used by columns are generated from the tree, not written by hand:

- Module A uses module B when a file of A names a function or global that a source file of B defines, or a macro, type, enum constant or inline function that a header of B declares. "Types and macros only" marks a dependency with no call.
- An `#include` that supplies nothing is not counted. MayaType.h and CedarType.h are left out, because every module uses them.
- The Uses column is each module's list of allowed dependencies. A change that calls into a module outside that list adds an edge, and the edge must show up as a change to this map.
- The facts describe the tree at the commit that last rewrote this map. A script over the `#include` lines and identifiers of `src/` computed them, and CodeGraph cross-checked them.

Executables:

- `vpnserver` uses, in Cedar: Cedar, Server; in Mayaqua: Mayaqua, Microsoft.
- `vpncmd` uses, in Cedar: Cedar, Command; in Mayaqua: Internat, Kernel, Mayaqua, Memory, Microsoft.
- `ranz-node` uses, in Cedar: Cedar, Node; in Mayaqua: Mayaqua, Microsoft.
- `vpntest` uses, in Cedar: all except Bridge, Link, RpcField, Win32Com (Sam for its types and macros only); in Mayaqua: all except Tracking.
- `fuzz` uses, in Cedar: Protocol; in Mayaqua: Cfg, Encrypt, HTTP, IpAddr, Mayaqua, Memory, Network, Pack, Stun, TcpIp.
- `coretest` uses, in Core: Crypto; nothing of Cedar or Mayaqua.

### Mayaqua (`src/Mayaqua`)

| Module | Contract | Main types | Uses | Used by |
|---|---|---|---|---|
| MayaType.h | Base typedefs, the Windows SDK includes, the endian helpers and the forward declaration of every Mayaqua struct | `UINT`, `bool`, `typedef struct X X` | none | every module |
| Platform.h | The declarations of the Win32 and FileIO functions that Cedar may call: memory information and priority, the OS version, folder compression | none | none (declares functions that Win32 and FileIO define) | included by Admin, Cedar, Eraser, LogWriter, Server, Win32 |
| Win32: `Win32.c`, `Console.c`, `Diag.c`, `OsInfo.c`, `Proc.c` | The Win32 back end of the runtime: process start-up, heap allocation, thread names and priority, the single-instance mutex, console input and output, process launch, call stacks, and the Windows version and CPU count | `OS_INFO` (in MayaType.h) | FileIO, Internat, Kernel, Memory, Microsoft, Str; types and macros only: Mayaqua, Tracking | In Mayaqua: Encrypt, FileIO, Internat, Kernel, Mayaqua, Memory, Microsoft, Object, Tracking. In Cedar: Admin, Cedar, Server. Programs: `vpntest` |
| Memory: `Memory.c`, `MemoryAlloc.c`, `MemoryInternal.h` | Allocation (`Malloc`, `Free`, memory tags and the canary) and the containers every module shares, with zlib compression and byte helpers | `BUF`, `LIST`, `QUEUE`, `FIFO`, `SK`, `HASH_LIST` | Encrypt, FileIO, Internat, Kernel, Mayaqua, Object, Str, Tracking, Win32 | In Mayaqua: all. In Cedar: all. Programs: `vpncmd`, `vpntest`, `fuzz` |
| Object: `Object.c`, `Native.h` | Synchronisation and lifetime primitives (locks, events, reference and plain counters, the dead-lock check); `Native.h` holds their inline Win32 fast paths | `LOCK`, `EVENT`, `REF`, `COUNTER`, `DEADCHECK` | Kernel, Mayaqua, Memory, Str, Tick64, Win32 | In Mayaqua: Cfg, DNS, Kernel, Mayaqua, Memory, Network, Tracking. In Cedar: all except HubLog, RpcField, SeLowUser, Tunables, WaterMark, Win32Com. Programs: `vpntest` |
| Kernel | Threads, the single-instance guard, system and local time with their date strings, the locale and `AbortExit` | `THREAD`, `INSTANCE`, `LOCALE`, `MEMINFO` | Encrypt, Internat, Mayaqua, Memory, Microsoft, Object, Str, Win32 | In Mayaqua: Cfg, DNS, Encrypt, FileIO, HTTP, Mayaqua, Memory, Microsoft, Network, Object, Table, Tick64, Tracking, Win32. In Cedar: Account, Admin, Bridge, Cedar, Command, ConfigStore, Connection, Eraser, Hub, Link, Listener, LogWriter, PacketLog, Protocol, SeLowUser, Server, Session. Programs: `vpncmd`, `vpntest` |
| Tick64 | The monotonic 64-bit millisecond clock and its wall-clock adjustment history | `TICK64`, `ADJUST_TIME` | Kernel, Memory, Str | In Mayaqua: DNS, Mayaqua, Microsoft, Network, Object, Stun. In Cedar: Account, Admin, Bridge, Cedar, Command, Connection, Hub, Listener, LogWriter, Protocol, SeLowUser, Session, Syslog, UdpAccel. Programs: `vpntest` |
| Tracking | Debug-only object and call-stack tracking for the memory check | `TRACKING_OBJECT`, `CALLSTACK_DATA`, `MEMORY_STATUS` | Kernel, Mayaqua, Memory, Object, Str, Win32 | In Mayaqua: Mayaqua, Memory; types and macros only: Win32 |
| Trace | `Debug()` output to the "Ranz.VPN" ETW TraceLogging provider | none | Memory, Str | In Mayaqua: Encrypt, Mayaqua, Str. Programs: `vpntest` |
| Str | ANSI and UTF-8 string helpers, formatting, tokenising and `Debug()` | `TOKEN_LIST` | Internat, Mayaqua, Memory, Trace | In Mayaqua: all. In Cedar: all except Tunables. Programs: `vpntest` |
| Internat | Wide-string (`Uni*`) helpers and conversion between UTF-16, UTF-8 and the ANSI code page | `UNI_TOKEN_LIST` | Mayaqua, Memory, Str, Win32 | In Mayaqua: Cfg, Encrypt, FileIO, HTTP, Kernel, Memory, Microsoft, Pack, Str, Table, Win32. In Cedar: Account, Admin, BridgeWin32, Cedar, Command, ConfigStore, Console, Eraser, Hub, HubLog, Link, LogWriter, Node, PacketLog, Protocol, Sam, SeLowUser, Server, Syslog. Programs: `vpncmd`, `vpntest` |
| FileIO | Files, directories and paths, the executable name, and hamcore (`|name` files from PE resources or a loose folder); it also defines the `Win32*` file functions of Win32.h and Platform.h | `IO`, `DIRENT`, `DIRLIST`, `HC` | Internat, Kernel, Mayaqua, Memory, Str, Win32 | In Mayaqua: Cfg, Mayaqua, Memory, Microsoft, Network, Win32. In Cedar: Admin, Cedar, Command, ConfigStore, Console, Eraser, Hub, HubLog, LogWriter, Node, Protocol, SeLowUser, Server, Win32Com. Programs: `vpntest` |
| Encrypt: `Encrypt.h`, `Crypto/*.c` (9 files), `Crypto/Cng.h` | Cryptography: hashes, random numbers and RC4 on CNG; AEAD, RSA, DH, X.509 and PEM on OpenSSL; SHA-0 own code; the start-up of both libraries | `X`, `K`, `NAME`, `X_SERIAL`, `CIPHER`, `CRYPT`, `DH_CTX` | Internat, Kernel, Memory, Str, Trace, Win32; types and macros only: Mayaqua | In Mayaqua: Cfg, Kernel, Mayaqua, Memory, Microsoft, Network, Pack, Stun. In Cedar: Account, Admin, BridgeWin32, Cedar, Command, ConfigStore, Connection, Hub, Link, Protocol, Sam, SeLowUser, Server, Session, UdpAccel, WaterMark; types and macros only: Remote. Programs: `vpntest`, `fuzz` |
| Mayaqua | Library start-up and shut-down in a fixed order, the fatal exit, minimal mode, OS information and the kernel status counters (`KS_*`) | none | Encrypt, FileIO, Kernel, Memory, Microsoft, Network, Object, Str, Table, Tick64, Trace, Tracking, Win32 | In Mayaqua: FileIO, Internat, Kernel, Memory, Microsoft, Object, Str, Table, Tracking; types and macros only: Encrypt, Win32. In Cedar: Admin, Cedar, Command, Protocol, Server, WaterMark; types and macros only: Eraser, HubLog. Programs: `vpnserver`, `vpncmd`, `ranz-node`, `vpntest`, `fuzz` |
| Cfg | The text configuration tree and its reader and writer, with the staged save and the set-aside of a bad file | `FOLDER`, `ITEM`, `CFG_RW` | Encrypt, FileIO, Internat, IpAddr, Kernel, Memory, Object, Str | In Mayaqua: Network, Table, TcpIp. In Cedar: Account, Admin, Cedar, ConfigStore, Console, Hub, SeLowUser, Server, Tunables. Programs: `vpntest`, `fuzz` |
| Table | The string table (`_SS`, `_UU`, `_II`, `_E`), the language list and `$lang.config` | `TABLE`, `LANGLIST` | Cfg, Internat, Kernel, Mayaqua, Memory, Microsoft, Str | In Mayaqua: Mayaqua; types and macros only: Microsoft. In Cedar: Admin, Command, Connection, Protocol, Session; types and macros only: Account, Cedar, Console, Hub, HubLog, LogWriter, Server. Programs: `vpntest` |
| Microsoft: `Microsoft.c`, `MicrosoftAdapter.c`, `MicrosoftProcess.c`, `MicrosoftReg.c`, `MicrosoftService.c`, `MicrosoftSystem.c`, `MicrosoftInternal.h` | Windows services and the event log, the registry, processes and tokens, network adapters and firewall registration, and system information (`Ms*`) | `MS`, `MS_ADAPTER`, `MS_ADAPTER_LIST`, `MS_SVC_ARG` | Encrypt, FileIO, Internat, Kernel, Mayaqua, Memory, Str, Tick64, Win32; types and macros only: Table | In Mayaqua: Kernel, Mayaqua, Network, Table, Win32. In Cedar: BridgeWin32, Cedar, Command, Console, LogWriter, Protocol, Sam, SeLowUser, Server. Programs: `vpnserver`, `vpncmd`, `ranz-node`, `vpntest` |
| IpAddr | IP address values: parse, print, compare and mask IPv4 and IPv6 addresses | `IP`, `IPV6_ADDR` | Memory, Str | In Mayaqua: Cfg, DNS, HTTP, Network, Pack, Proxy, Stun; types and macros only: TcpIp. In Cedar: Admin, Command, Connection, Hub, Listener, PacketLog, Protocol, Syslog, UdpAccel; types and macros only: Cedar, RpcField, Server, Session. Programs: `vpntest`, `fuzz` |
| Network: `Network.c`, `NetworkDns.c`, `NetworkSocket.c`, `NetworkTls.c`, `NetworkInternal.h` | Sockets: TCP and UDP, listen, accept and connect, cancel objects and socket sets, TLS contexts and records, the NIC and IP client lists, the private IP file, and host-name lookups over DNS | `SOCK`, `SOCKSET`, `CANCEL`, `SOCK_EVENT`, `SSL_ACCEPT_SETTINGS`, `NIC_ENTRY` | Cfg, DNS, Encrypt, FileIO, IpAddr, Kernel, Memory, Microsoft, Object, Str, Tick64 | In Mayaqua: DNS, HTTP, Mayaqua, Proxy, Stun, TcpIp. In Cedar: Account, Admin, Bridge, BridgeWin32, Cedar, Command, Connection, Hub, Link, Listener, Protocol, Remote, Server, Session, Syslog, UdpAccel. Programs: `vpntest`, `fuzz` |
| DNS | The resolver with forward and reverse caches, and the wait-thread list | `DNS_CACHE`, `DNS_RESOLVER` | IpAddr, Kernel, Memory, Network, Object, Str, Tick64 | In Mayaqua: Network, Stun; types and macros only: Proxy. In Cedar: Protocol, Server, Syslog. Programs: `vpntest` |
| TcpIp: `TcpIp.c`, `Dhcp.c`, `Pkt.c`, `PktChecksum.c`, `PktIpv6.c`, `PktSniff.c`, `TcpIpInternal.h` | Frame parsing into `PKT` (Ethernet to TCP and UDP, VLAN, IPv6, ICMPv6), checksums, the TCP MSS clamp, DHCP options, and the HTTP and SNI sniffing of the packet log | `PKT`, `MAC_HEADER`, `IPV4_HEADER`, `TCP_HEADER`, `DHCP_OPTION` | Cfg, Memory, Network, Str; types and macros only: IpAddr | In Cedar: Bridge, Hub, PacketLog, Session; types and macros only: Command, UdpAccel. Programs: `vpntest`, `fuzz` |
| HTTP: `HTTP.c`, `PackHttp.c`, `HTTPInternal.h` | HTTP header parse and send, PACK over HTTP (`HttpClientSend`, `HttpServerRecv`) and the decoy page | `HTTP_HEADER`, `HTTP_VALUE` | Internat, IpAddr, Kernel, Memory, Network, Pack, Str | In Mayaqua: Proxy. In Cedar: Admin, Command, Protocol; types and macros only: Cedar, Connection. Programs: `vpntest`, `fuzz` |
| Proxy | Outbound HTTP CONNECT, SOCKS4 and SOCKS5 connect (`ProxyConnect`) | `PROXY_PARAM_IN`, `PROXY_PARAM_OUT` | HTTP, IpAddr, Memory, Network, Str; types and macros only: DNS | In Cedar: Protocol; types and macros only: Command, Connection. Programs: `vpntest` |
| Stun | STUN binding request and response (mapped address discovery only) | none | DNS, Encrypt, IpAddr, Memory, Network, Str, Tick64 | In Cedar: UdpAccel. Programs: `vpntest`, `fuzz` |
| Pack | PACK serialisation: elements, typed values and the binary form | `PACK`, `ELEMENT`, `VALUE` | Encrypt, Internat, IpAddr, Memory, Str | In Mayaqua: HTTP. In Cedar: Account, Admin, Command, Protocol, Remote, RpcField, Server; types and macros only: WaterMark. Programs: `vpntest`, `fuzz` |

### Cedar (`src/Cedar`)

| Module | Contract | Main types | Uses in Cedar | Uses in Mayaqua | Used by |
|---|---|---|---|---|---|
| CedarType.h | The forward declaration of every Cedar struct | `CEDAR`, `HUB`, `SESSION`, ... | none | none | every Cedar module |
| Cedar | The root `CEDAR` object (listener, hub and connection lists, server certificate and cipher list, no-SSL list, queue budgets, traffic counters), `InitCedar`/`FreeCedar` and the protocol constants that several modules share | `CEDAR`, `TRAFFIC`, `NON_SSL`, `NETSVC`, `TINY_LOG` | Bridge, Connection, Hub, HubLog, Listener, Protocol, Tunables, WaterMark; types and macros only: Admin, Server | Cfg, Encrypt, FileIO, Internat, Kernel, Mayaqua, Memory, Microsoft, Network, Object, Str, Tick64, Win32; types and macros only: HTTP, IpAddr, Table | Account, Admin, Command, Connection, Hub, Link, Listener, Node, PacketLog, Protocol, Server, Session, UdpAccel; types and macros only: Bridge, ConfigStore, Console, HubLog, Remote, Sam, SeLowUser. Programs: `vpnserver`, `vpncmd`, `ranz-node`, `vpntest` |
| Tunables | The global tunables (`GP_*`): ids, config keys and defaults in one table, with their load and save | none | none | Cfg, Memory | Cedar, Server. Programs: `vpntest` |
| Server: `Server.c`, `ServerCaps.c`, `ServerListener.c`, `ServerInternal.h` | The process-level `SERVER`: Config file load and save, autosave, hubs from the config, syslog settings, capabilities, the listener list and `StInit`/`StStartServer`/`StStopServer` | `SERVER`, `SERVER_LISTENER`, `CAPS`, `SYSLOG_SETTING` | Account, Bridge, BridgeWin32, Cedar, Eraser, Hub, HubLog, Link, Listener, LogWriter, Protocol, RpcField, Syslog, Tunables; types and macros only: Admin, Connection, Session | Cfg, DNS, Encrypt, FileIO, Internat, Kernel, Mayaqua, Memory, Microsoft, Network, Object, Pack, Str, Win32; types and macros only: IpAddr, Table | Admin, Command, Connection, HubLog, Node, PacketLog, Protocol, Session; types and macros only: Cedar. Programs: `vpnserver`, `vpntest` |
| Listener | TCP listeners, their accept threads and DoS protection | `LISTENER`, `DOS` | Cedar, Connection, HubLog | IpAddr, Kernel, Memory, Network, Object, Str, Tick64 | Admin, Cedar, Server. Programs: `vpntest` |
| Connection | The transport state of a Connection: sockets, TCP half-connections, block queues, the send and receive loop, keep-alive and the client options | `CONNECTION`, `TCP`, `TCPSOCK`, `BLOCK`, `CLIENT_OPTION`, `CLIENT_AUTH` | Bridge, Cedar, HubLog, Protocol, Server, Session, UdpAccel; types and macros only: Hub, Link | Encrypt, IpAddr, Kernel, Memory, Network, Object, Str, Table, Tick64; types and macros only: HTTP, Proxy | Admin, Bridge, Cedar, Hub, Link, Listener, Protocol, Session, UdpAccel; types and macros only: Account, Command, Remote, Server. Programs: `vpntest` |
| Protocol: `Protocol.c`, `ProtocolClient.c`, `ProtocolServer.c`, `ProtocolInternal.h` | The SE-VPN handshake: `ServerAccept` and the login admission on the server side, `ClientConnect` and additional connections on the client side, certificate chain download and the Machine identity hash | `LOGIN_REQ`, `SERVER_LOGIN`, `HUB_LOGIN` | Account, Admin, Cedar, Connection, Hub, HubLog, Sam, Server, Session, UdpAccel, WaterMark | DNS, Encrypt, FileIO, HTTP, Internat, IpAddr, Kernel, Mayaqua, Memory, Microsoft, Network, Object, Pack, Proxy, Str, Table, Tick64 | Account, Admin, Cedar, Connection, Hub, Server, Session. Programs: `vpntest`, `fuzz` |
| Session | The Session state machine (`SessionMain`, `NewClientSession`, `NewServerSession`), its packet adapter, traffic accounting, QoS priority, delayed packets and the cancel list | `SESSION`, `PACKET_ADAPTER`, `NODE_INFO` | Account, Bridge, Cedar, Connection, Hub, HubLog, Protocol, Server, UdpAccel; types and macros only: Link | Encrypt, Kernel, Memory, Network, Object, Str, Table, TcpIp, Tick64; types and macros only: IpAddr | Admin, Bridge, Connection, Hub, Link, PacketLog, Protocol; types and macros only: Account, Command, Server. Programs: `vpntest` |
| Hub: `Hub.c`, `HubOption.c`, `HubPacket.c`, `HubTable.c`, `HubInternal.h` | The Virtual Hub: frame forwarding (`StorePacket`), MAC and IP tables, the access list, IP access control, CA and CRL lists, the user list cache, hub options and messages, the traffic limiter and the watchdog | `HUB`, `HUBDB`, `HUB_OPTION`, `ACCESS`, `MAC_TABLE_ENTRY`, `IP_TABLE_ENTRY`, `HUB_PA` | Account, Bridge, Cedar, Connection, HubLog, Link, LogWriter, PacketLog, Protocol, Sam, Session; types and macros only: Admin | Cfg, Encrypt, FileIO, Internat, IpAddr, Kernel, Memory, Network, Object, Str, TcpIp, Tick64; types and macros only: Table | Admin, Bridge, Cedar, Command, Node, PacketLog, Protocol, Sam, Server, Session; types and macros only: Account, Connection, HubLog, Link, UdpAccel. Programs: `vpntest` |
| Account | Users, groups, policies and authentication data records of a Hub | `USER`, `USERGROUP`, `POLICY`, `AUTHPASSWORD`, `AUTHUSERCERT`, `AUTHROOTCERT`, `AUTHNT` | Cedar, Protocol, RpcField; types and macros only: Connection, Hub, Session | Cfg, Encrypt, Internat, Kernel, Memory, Network, Object, Pack, Str, Tick64; types and macros only: Table | Admin, Bridge, Command, ConfigStore, Hub, Link, Protocol, Sam, Server, Session. Programs: `vpntest` |
| Sam | The credential gate of a login (`SamAuthenticate`): password, anonymous, certificate and plain authentication | `AUTH_REQUEST`, `AUTH_RESULT` | Account, Hub, LogWriter; types and macros only: Cedar | Encrypt, Internat, Memory, Microsoft, Object, Str | Hub, Node, Protocol. Programs: `vpntest` (types and macros only) |
| Link | Cascade: a Hub-owned client Session paired with a server Session on the same Hub | `LINK` | Account, Cedar, Connection, HubLog, Session; types and macros only: Hub | Encrypt, Internat, Kernel, Memory, Network, Object, Str | Admin, Hub, Server; types and macros only: Connection, Session |
| Bridge | Local Bridge: a bridge-mode Session on a Hub joined to a physical adapter, and the per-Cedar Local Bridge list | `BRIDGE`, `LOCALBRIDGE` | Account, BridgeWin32, Connection, Hub, HubLog, Session; types and macros only: Cedar | Kernel, Memory, Network, Object, Str, TcpIp, Tick64 | Admin, Cedar, Connection, Hub, Server, Session |
| BridgeWin32 | Windows adapter access for the Local Bridge through SeLow: open, get and put frames, MTU and enumeration (`Win32Eth*`) | `ETH`, `WP_ADAPTER` | Admin, SeLowUser | Encrypt, Internat, Memory, Microsoft, Network, Object, Str | Admin, Bridge, Server. Programs: `vpntest` |
| SeLowUser | The user-mode side of the SeLow driver: adapter list, packet get and put, driver install | `SU`, `SU_ADAPTER`, `SU_ADAPTER_LIST` | Win32Com; types and macros only: Cedar | Cfg, Encrypt, FileIO, Internat, Kernel, Memory, Microsoft, Str, Tick64 | BridgeWin32; types and macros only: Win32Com. Programs: `vpntest` |
| Win32Com | The SeLow protocol driver install through the `INetCfg` COM interfaces | none | types and macros only: SeLowUser | FileIO, Memory, Str | SeLowUser |
| UdpAccel | UDP Acceleration: key and cookie exchange, encrypted UDP send and receive, optional STUN discovery | `UDP_ACCEL` | Cedar, Connection, HubLog; types and macros only: Hub | Encrypt, IpAddr, Memory, Network, Object, Str, Stun, Tick64; types and macros only: TcpIp | Connection, Protocol, Session. Programs: `vpntest` |
| WaterMark | The watermark blob (hamcore `watermark.bin`) that the client uploads in the signature step and the server checks | none | none | Encrypt, Mayaqua, Memory, Str; types and macros only: Pack | Cedar, Protocol. Programs: `vpntest` |
| Remote | The RPC transport over a socket: request and response PACKs | `RPC` | Admin; types and macros only: Cedar, Connection | Memory, Network, Object, Pack, Str; types and macros only: Encrypt | Admin; types and macros only: Command. Programs: `vpntest` |
| RpcField | The field-descriptor engine: table-driven In, Out and Free of the admin RPC structures | `RPC_FIELD`, `RPC_TABLE`, `RPC_HOOK` | none | Memory, Pack, Str; types and macros only: IpAddr | Account, Admin, Server |
| Admin: `Admin.c`, `AdminMarshal.c`, `AdminClient.c`, 15 area files (`Admin<Area>.c`), `AdminInternal.h` | Admin RPC: `AdminAccept`, the `AdminInvoke` dispatch to the `St*` handler of each RPC area, the marshalling (`AdminMarshal.c`) and the vpncmd client side (`AdminClient.c`: `Sc*` stubs, `AdminConnectEx`) | `ADMIN`, 62 `RPC_*` structs | Account, Bridge, BridgeWin32, Cedar, Connection, Hub, HubLog, Link, Listener, Protocol, Remote, RpcField, Server, Session | Cfg, Encrypt, FileIO, HTTP, Internat, IpAddr, Kernel, Mayaqua, Memory, Network, Object, Pack, Str, Table, Tick64, Win32 | BridgeWin32, Command, Protocol, Remote; types and macros only: Cedar, Hub, HubLog, Server. Programs: `vpntest` |
| Command: `Command.c`, `CommandServer.c`, 9 area files (`Command<Area>.c`), `CommandTable.c`, `CommandInternal.h` | `vpncmd`: `CommandMain`, the server admin commands (`Ps*`) by RPC area, tools (`Pt*`), the traffic test (`Tt*`) and table output (`Ct*`) | `PS`, `PT`, `CT`, `TTC`, `TTS`, `TT_RESULT` | Account, Admin, Cedar, Console, Hub, Server; types and macros only: Connection, LogWriter, Remote, Session, Syslog | Encrypt, FileIO, HTTP, Internat, IpAddr, Kernel, Mayaqua, Memory, Microsoft, Network, Object, Pack, Str, Table, Tick64; types and macros only: Proxy, TcpIp | Programs: `vpncmd`, `vpntest` |
| Console | The console abstraction of vpncmd: parameter parser, command tables and prompts | `CONSOLE`, `PARAM`, `CMD` | types and macros only: Cedar | Cfg, FileIO, Internat, Memory, Microsoft, Object, Str; types and macros only: Table | Command. Programs: `vpntest` |
| LogWriter | The threaded log writer: records of a `LOG` to files that switch by date and size | `LOG`, `RECORD` | none | FileIO, Internat, Kernel, Memory, Microsoft, Object, Str, Tick64; types and macros only: Table | Eraser, Hub, HubLog, Node, PacketLog, Sam, Server, Syslog; types and macros only: Command. Programs: `vpntest` |
| HubLog | The server log (`SLog`) and the Hub security logs (`HLog`), to their files or to syslog, with the log directories and the log file list | `HUB_LOG`, `LOG_FILE` | LogWriter, Server; types and macros only: Admin, Cedar, Hub | FileIO, Internat, Memory, Str; types and macros only: Mayaqua, Table | Admin, Bridge, Cedar, Connection, Hub, Link, Listener, Protocol, Server, Session, UdpAccel; types and macros only: PacketLog. Programs: `vpntest` |
| PacketLog | The packet log of a Hub: which frames are logged, and their CSV line | `PACKET_LOG` | Cedar, Hub, LogWriter, Server, Session; types and macros only: HubLog | Internat, IpAddr, Kernel, Memory, Object, Str, TcpIp | Hub. Programs: `vpntest` |
| Syslog | The syslog sender: one UDP datagram per log line | `SLOG` | LogWriter | DNS, Internat, IpAddr, Memory, Network, Object, Str, Tick64 | Server; types and macros only: Command. Programs: `vpntest` |
| Eraser | Deletes the oldest log files while the free disk space is below the minimum | `ERASER` | LogWriter | FileIO, Internat, Kernel, Memory, Object, Str; types and macros only: Mayaqua | Server. Programs: `vpntest` |
| Node: `Node.c`, `NodeTable.c`, `NodeWorker.c`, `NodeInternal.h` | The Node of the new core (`ranz-node`, service `ranzvpnserver`): its data directory under ProgramData with a protected DACL, Roles from its Configuration store and the control plane (`NodeSetRoles`), the one-time import of a fork Config file found there, one Worker per core, one I/O thread per Adapter queue, the Table snapshot swapped by pointer, the Hubs of the server role and their credential gate through Sam (`NodeAuthenticate`) | `NODE`, `NODE_WORKER`, `NODE_QUEUE`, `NODE_READER`, `NODE_TABLES` | Cedar, ConfigStore, Hub, LogWriter, Sam, Server | FileIO, Internat, Memory, Object, Str | Programs: `ranz-node`, `vpntest` |
| ConfigStore: `ConfigStore.c`, `ConfigStoreImport.c`, `ConfigStoreInternal.h` | The Configuration store of the new core: a SQLite database through the `winsqlite3.dll` of System32 (settings, networks, users with PBKDF2 password hashes and pinned keys, listeners, certificates, named admin accounts with roles), its text dump, and the one-time import of a fork Config file (`CsImportForkConfig`) | `CONFIG_STORE`, `CS_NETWORK`, `CS_USER`, `CS_ADMIN`, `CS_IMPORT` | Account; types and macros only: Cedar | Cfg, Encrypt, FileIO, Internat, Kernel, Memory, Object, Str | Node. Programs: `vpntest` |

### Core (`src/Core`)

The new core (ADR-0022). Each of its modules is a static library of its own that links nothing of Mayaqua or Cedar, and no OpenSSL or liboqs; `ranz_core_check_links` (`src/Core/CMakeLists.txt`) stops the configure when one does.

| Module | Contract | Main types | Uses | Used by |
|---|---|---|---|---|
| Crypto: `Crypto.h`, `Crypto.c`, `CryptoX25519.c`, `CryptoMlKem.c`, `CryptoCert.c`, `CryptoInternal.h` (library `corecrypto`) | X25519, AES-GCM, SHA-256, HMAC-SHA256, HKDF and random bytes on CNG; the X25519MLKEM768 hybrid where CNG has ML-KEM; the node identity key in the Microsoft Software Key Storage Provider; self-signed ECDSA P-256 certificates, PFX import and the certificate stores through CryptoAPI | `CRYPTO_SHA256`, `CRYPTO_AEAD`, `CRYPTO_IDENTITY`, `CRYPTO_HYBRID` | none (the system libraries bcrypt, ncrypt and crypt32) | Programs: `coretest` |

### Dependency cycles

Cycles are counted at call level: a call to a function or a use of a global. Types and macros alone do not count. The header include graph has no cycle; the forward declarations in MayaType.h and CedarType.h keep it so. The call graph has two strongly connected components:

- Mayaqua, 18 modules: Cfg, DNS, Encrypt, FileIO, Internat, IpAddr, Kernel, Mayaqua, Memory, Microsoft, Network, Object, Str, Table, Tick64, Trace, Tracking, Win32. Outside it, and depending one way: HTTP, Pack, Proxy, Stun, TcpIp. Without the Mayaqua module (start-up, fatal exit) it splits into 12 modules (Encrypt, FileIO, Internat, Kernel, Memory, Microsoft, Object, Str, Tick64, Trace, Tracking, Win32) and 2 modules (DNS, Network). Cfg, IpAddr, Tick64 have no pair of their own and are in it only through longer paths.
- Cedar, 17 modules: Account, Admin, Bridge, BridgeWin32, Cedar, Connection, Hub, HubLog, Link, Listener, PacketLog, Protocol, Remote, Sam, Server, Session, UdpAccel. Outside it, and depending one way: Command, ConfigStore, Console, Eraser, LogWriter, Node, RpcField, SeLowUser, Syslog, Tunables, WaterMark, Win32Com. Without Hub, Session and Connection it is still 13 modules (Account, Admin, Bridge, BridgeWin32, Cedar, HubLog, Link, Listener, Protocol, Remote, Sam, Server, UdpAccel). Link has no pair of its own and is in it only through longer paths.

Inside them, 47 pairs of modules call each other directly. The Hub, Session and Connection cycle is allowed: it is the protocol core, which the new core replaces as one piece (ADR-0003 item 12, ADR-0017 step 7). At call level it is two pairs, Hub and Session, and Session and Connection; Hub calls Connection one way only. The other 45 pairs are known exceptions. A pair is broken only by moving whole functions (#29), never by adding a callback or a function pointer. The table names the functions that each side calls, or their count when there are more than six. The first module of a pair is the side with more calls.

| Cycle | Status | Calls from the first | Calls from the second |
|---|---|---|---|
| Hub and Session | allowed | 7 functions | `AddSession`, `DelSession`, `GetHubPacketAdapter` |
| Session and Connection | allowed | 9 functions | `GetNextDelayedPacketTickDiff` |
| Admin and BridgeWin32 | known exception | `EnumEthWin32`, `Win32EthGetNameAndIdFromCombinedName`, `Win32EthInstallSu`, `Win32EthIsSuSupported` | `FreeRpcEnumEth` |
| Admin and Remote | known exception | `NewRpc`, `RpcCall`, `RpcFree`, `RpcServer` | `AdminReconnect` |
| Bridge and Connection | known exception | `FreeBlock`, `InsertReceivedBlockToQueue`, `NewBlock`, `NewServerConnection`, `ReleaseConnection` | `BrReceiveBlocks`, `BrSendBlocks` |
| Bridge and Session | known exception | `GetNextDelayedPacketTickDiff`, `NewServerSession`, `ReleaseSession`, `SessionMain`, `StopSession` | `BrSessionCleanup` |
| Cedar and Hub | known exception | `CompareHub`, `IsHub`, `LockHubList`, `ReleaseHub`, `StopHub`, `UnlockHubList` | `CedarAddCurrentTcpQueueSize`, `CedarGetCurrentTcpQueueSize`, `FreeTraffic`, `NewTraffic`, `ReleaseCedar` |
| Connection and Cedar | known exception | 9 functions | `CompareConnection`, `ReleaseConnection`, `StopConnection` |
| Connection and UdpAccel | known exception | `UdpAccelCalcMss`, `UdpAccelIsRecvBudgetSpent`, `UdpAccelIsSendReady`, `UdpAccelPoll`, `UdpAccelSendBlock`, `UdpAccelSetTick` | `FreeBlockQueue`, `NewBlock` |
| Hub and Bridge | known exception | `BrFreeBridge`, `BrNewBridge` | `ReleaseHub` |
| Hub and PacketLog | known exception | `PacketLog` | `CheckMaxLoggedPacketsPerMinute` |
| Hub and Sam | known exception | `ParseNtUsername` | `IsValidCertInHub` |
| Listener and Cedar | known exception | `AddConnection`, `AddListener`, `GetUnestablishedConnections`, `IsInNoSsl`, `ReleaseCedar` | `CompareListener`, `ReleaseListener`, `StopListener` |
| Protocol and Account | known exception | 11 functions | `PackAddPolicy`, `PackGetPolicy` |
| Protocol and Admin | known exception | `AdminAccept`, `InRpcNodeInfo`, `InRpcWinVer`, `OutRpcNodeInfo`, `OutRpcWinVer` | `DownloadAndSaveIntermediateCertificatesIfNecessary`, `PackAddClientVersion` |
| Protocol and Cedar | known exception | `DecrementNoSsl`, `DelConnection`, `FormatUnsupportedWinVerMsg`, `GetWinVer` | `SetCedarMachineIdSalt` |
| Protocol and Connection | known exception | `NewTcpSock`, `StartTunnelingMode`, `TlsErrToCedarErr` | `ServerAccept`, `ServerRunSession` |
| Protocol and Hub | known exception | 10 functions | `GenerateMachineUniqueHash` |
| Protocol and Server | known exception | `IncrementServerConfigRevision` | `SetCedarMachineIdSalt` |
| Server and HubLog | known exception | `HubPacketLogDir`, `HubSecurityLogDir`, `SLog`, `ServerLogDir` | `SiGetSysLogSaveStatus`, `SiWriteSysLog` |
| Session and Protocol | known exception | `ClientAdditionalConnect`, `ClientConnect`, `ClientConnectToServer`, `ClientDownloadHello`, `ClientUploadSignature` | `GetSessionFromKey`, `NewServerSession`, `ReleaseSession`, `SessionMain` |
| Encrypt and Kernel | known exception | `AbortExitEx`, `NormalizeSystem`, `SystemTime64`, `SystemToUINT64`, `UINT64ToFileTime` | `FreeOpenSSLThreadState`, `Sha0` |
| Encrypt and Memory | known exception | 19 functions | `Md5`, `Rand`, `Sha2_256` |
| FileIO and Memory | known exception | 18 functions | `FileClose`, `FileCreateW`, `FileOpenExW`, `FileRead`, `FileSize`, `FileWrite` |
| Internat and Memory | known exception | 14 functions | `CalcUniToUtf8`, `CopyStrToUni`, `UniStrLen`, `UniToUtf8` |
| Kernel and Memory | known exception | `Copy`, `Free`, `Zero`, `ZeroMalloc` | `AbortExitEx` |
| Kernel and Object | known exception | 9 functions | `AbortExitEx`, `NoticeThreadInit`, `ReleaseThread`, `SleepThread`, `WaitThread`, `WaitThreadInit` |
| Kernel and Win32 | known exception | 7 functions | `HashInstanceName` |
| Mayaqua and FileIO | known exception | `FreeHamcore`, `GetExeNameW`, `InitGetExeName`, `InitHamcore`, `IsFileExistsW`, `MakeDirEx` | `KS_INC`, `MayaFatalExit`, `MayaquaIsMinimalMode` |
| Mayaqua and Kernel | known exception | `FreeThreading`, `InitThreading`, `LocalTime`, `SetLocale` | `KS_INC` |
| Mayaqua and Memory | known exception | 7 functions | `KS_DEC`, `KS_INC` |
| Mayaqua and Microsoft | known exception | `MsFree`, `MsInit`, `MsInitProcessCallOnce`, `MsWriteEventLog` | `FreeMayaqua`, `InitMayaqua`, `MayaFatalExit` |
| Mayaqua and Object | known exception | `DeleteLock`, `NewLock` | `KS_DEC`, `KS_INC` |
| Mayaqua and Str | known exception | `Format`, `GetLine`, `InitStringLibrary`, `Print` | `KS_INC`, `MayaFatalExit`, `g_debug` |
| Mayaqua and Table | known exception | `FreeTable`, `InitTable` | `MayaFatalExit`, `MayaquaIsMinimalMode` |
| Mayaqua and Tracking | known exception | `FreeTracking`, `GetMemoryStatus`, `InitTracking`, `MemoryDebugMenu` | `IsTrackingEnabled`, `g_memcheck` |
| Microsoft and Kernel | known exception | `AbortExitEx`, `FreeSingleInstance`, `NewSingleInstance`, `ReleaseThread`, `SleepThread`, `WaitThread` | `MsRestoreThreadPriority` |
| Microsoft and Win32 | known exception | `Win32Run` | `MsRegReadStr` |
| Network and DNS | known exception | 7 functions | `HasIPv6Address` |
| Object and Memory | known exception | `Free`, `Malloc`, `Zero` | `DeleteLock`, `NewLock` |
| Str and Internat | known exception | 8 functions | `CopyStr`, `StrCpy`, `StrLen`, `ToInti`, `ToStr3` |
| Str and Memory | known exception | 13 functions | `StrCmpi`, `StrLen`, `ToUpper` |
| Str and Trace | known exception | `IsTraceEnabled`, `TraceDebugArgs` | `CopyFormatArgsToUni` |
| Tracking and Memory | known exception | `Add`, `NewListFast`, `ReleaseList`, `Sort` | `TrackChangeObjSize`, `TrackDeleteObj`, `TrackNewObj` |
| Win32 and FileIO | known exception | 7 functions | `Win32MemoryAlloc`, `Win32MemoryFree` |
| Win32 and Internat | known exception | 9 functions | `Win32InputW`, `Win32PrintW` |
| Win32 and Memory | known exception | `Free`, `FreeBuf`, `NewBuf`, `WriteBuf`, `Zero` | `Win32MemoryAlloc`, `Win32MemoryFree`, `Win32MemoryReAlloc` |

## Language

**Hub**:
A virtual Ethernet switch (`HUB`), the Virtual Hub of vpncmd. Sessions attached to it exchange Ethernet frames; it owns users, groups, the access list, logs and Cascades. Servers host many Hubs.
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
_Avoid_: network bridge, bare "Bridge"

**SeLow**:
SoftEther's Microsoft-WHQL-signed NDIS protocol driver (Class `NetTrans`, x64 only) that captures and injects frames for a Local Bridge. Driver sources live in `src/SeLow`; the user-mode side is `SeLowUser`.

**PACK**:
SE-VPN's key/value message: a `PACK` holds named `ELEMENT`s, each with one or more typed `VALUE`s (int, int64, string, wide string, data). It carries the handshake (hello, login, welcome) and every admin RPC request and response.
_Avoid_: packet (an Ethernet frame is a `PKT`; a queued data unit is a `BLOCK`)

**Admin RPC**:
The management protocol. A Connection whose login PACK has `method` = `admin` (`CONNECTION_TYPE_ADMIN_RPC`) is authenticated by `AdminAccept` (`Admin.c`) as server admin or Hub admin (`ADMIN`) and then loops: a request PACK with `function_name` goes through `AdminInvoke` to an `St*` handler, and the reply PACK carries `error_code`. Callers use the `Sc*` stubs of `AdminClient.c`; `vpncmd` is the main caller.
_Avoid_: JSON-RPC (removed from the fork), management API

**RPC area**:
One group of admin RPC calls with its own source file: `AdminServer.c` (server information and status, cipher, certificate, password, listeners), `AdminHub.c` (Virtual Hubs and server connections), `AdminHubOption.c`, `AdminUser.c`, `AdminGroup.c`, `AdminAccess.c` (access lists), `AdminAc.c` (IP access control), `AdminCa.c`, `AdminCrl.c`, `AdminLink.c` (Cascades), `AdminSession.c` (sessions, MAC and IP tables), `AdminBridge.c`, `AdminLog.c`, `AdminSyslog.c` and `AdminMessage.c` (maintenance). `AdminMarshal.c` holds the `InRpc*`, `OutRpc*` and `FreeRpc*` converters of all areas, many of them on RpcField tables.

**vpncmd command**:
A command of vpncmd's server admin mode (`Ps*`, for example `PsUserCreate`), usually one admin RPC call through an `Sc*` stub. A `Command<Area>.c` file holds `Ps*` commands of one RPC area: `CommandAc.c`, `CommandAccess.c`, `CommandCascade.c` (for `AdminLink.c`), `CommandCrl.c`, `CommandGroup.c`, `CommandHubOption.c`, `CommandMessage.c`, `CommandSession.c` and `CommandUser.c`. The other `Ps*` commands are in `Command.c` and `CommandServer.c`. The other command families are the tools (`Pt*`) and the traffic test (`Tt*`) in `Command.c`, and the table output (`Ct*`) in `CommandTable.c`.

**hamcore**:
The files of `src/bin/hamcore/`, compiled into `vpnserver`, `vpncmd`, `ranz-node` and `vpntest` as PE resources of type `HAMCORE` by `cmake/RanzResources.cmake` (one resource per file, and an `INDEX` resource that names them) and read by `ReadHamcore` (FileIO) through `FindResource`/`LoadResource`. Files are named with a `|` prefix in IO paths (for example `|strtable_en.stb`, `|root_certs.dat`, `|watermark.bin`). A loose `hamcore/` folder next to the executable wins over the built-in files. An executable without them is fatal at start-up (`InitHamcore`). There is no `hamcore.se2` archive any more.
_Avoid_: resource file, data pack

**String table**:
The `strtable_<lang>.stb` file in hamcore (`en`, `id`), loaded by `InitTable` into `TABLE` entries. Code looks entries up by key: `_SS` (ANSI), `_UU` (wide), `_II` (integer), `_E` (error code to text). The language comes from `$lang.config` and `languages.txt`. `vpncmd` output is built from `_UU` strings, so the harness goldens depend on it.
_Avoid_: resource strings, locale file

**UDP Acceleration**:
An optional encrypted UDP data path set up inside a Session (`UDP_ACCEL`), with an optional STUN lookup of the mapped address.

**Config file**:
The server's text configuration tree (`$ranz_server.config`, `FOLDER`/`ITEM`), loaded and autosaved by `Server.c` through `CFG_RW`. Its format is frozen. A Config file that exists but cannot be read (no parse, a bad binary hash, or no `ServerConfiguration` folder) is renamed to `<name>.bad` and the server starts with the initial settings (FND-115 start policy); while the rename fails, no save writes over the file. A failed save is logged (`LS_SAVE_CONFIG_FAILED`) and retried from 1 s, doubling up to the autosave span.

**Configuration store**:
The configuration of a Node (`CONFIG_STORE`, the ConfigStore module): the SQLite database `ranz_node.db` in its data directory, read and written through the inbox `winsqlite3.dll` of System32 with a write-ahead log, so readers do not wait for a writer. It holds the settings (`Roles`, `NumWorkers`), the networks (an L2 network is a Hub of the server role), the users of each network with a PBKDF2-HMAC-SHA256 password hash and a pinned key (the Noise static key of trust on first use), the listeners, the certificates (subject and thumbprint; keys stay in a CNG KSP) and the named admin accounts with the roles owner, hub-admin (of one network) and read-only. It replaces the Config file for the new core (ADR-0022). A Config file in the data directory of a Node with an empty store is imported once (`CsImportForkConfig`) and renamed to `ranz_server.config.imported`; its SHA-0 password hashes and server key are left out.
_Avoid_: config file (the fork's text tree), database (alone)

**Machine identity**:
The 20 bytes that `GenerateMachineUniqueHash` returns for a server: a hash of the Windows MachineGuid and the `MachineIdSalt` of the Config file, kept in the `CEDAR`. It sets the MAC address and the 172.31.x.x address of every Hub and the `unique_id` of a Cascade login. It stays the same across restarts, renames and IP changes; servers cloned from one image differ only when each has its own config file, and so its own salt (FIX-5, `docs/upgrade-notes.md`).
_Avoid_: machine ID (Windows' name for the MachineGuid), `UniqueId` (a random value per `CEDAR`, copied into `NODE_INFO`)

**Node**:
One Windows host running `ranz-node`, the data plane, in one or more Roles (`server`, `client`, `bridge`, `relay`). It joins VRFs and applies the desired state that the Controller sends it. `ranz-node` is the new core's one binary, installed as the `ranzvpnserver` service (ADR-0011, ADR-0020 decision 4), and its in-process object is `NODE` (the Node module): the Roles of its configuration, one Worker per core, one I/O thread per Adapter queue and the Table snapshot. It reuses the fork's Hub, Account, Sam and Logging in-process, and Cfg for the one-time import of a fork Config file. Its data directory is `%ProgramData%\Hanzcodes\Ranz VPN` (`NodeDefaultDataDir`), whose protected DACL lets only SYSTEM and the Administrators in (`NodeMakeDataDir`); it holds the Configuration store `ranz_node.db` and `node_log`.
_Avoid_: agent, server (the slim fork's `vpnserver`, or the server Role), peer (the other end of a link), client product

**Role**:
What a Node does: `server` (the Hubs that new-core sessions end in), `client` (client and cascade), `bridge` (an L2 segment joined to a physical NIC or a Hyper-V network) or `relay`, any set of them at once (`NODE_ROLE_*`). The `Roles` setting of the Configuration store selects them (a list of names; no setting means `server`, `none` means no Role) and the control plane switches them at run time (`NodeSetRoles`). The controller is not a Role: it is the `ranz-controller` service (#176).
_Avoid_: mode, product, the controller role

**Worker**:
One per-core run-to-completion loop of a Node (`NODE_WORKER`): a thread bound to one core that takes work items from its own I/O completion port and runs each to completion (`NodePost`), passing a quiescent point of the Table snapshot after every batch. There is no hub-wide forwarding lock.
_Avoid_: thread pool, worker thread of the Mayaqua thread pool (`NewThread`)

**Adapter queue**:
One queue of an adapter (the Wintun ring, the AF_XDP queue of a KM-TEST adapter) attached to a Node with its own I/O thread (`NODE_QUEUE`, `NodeAddQueue`), which waits for the queue's event and drains it to completion.

**Table snapshot**:
The read-mostly MAC, route and policy tables of a Node (`NODE_TABLES`), rebuilt off the data path and installed by pointer (`NodeSwapTables`). Readers (Workers, Adapter queue threads) read it without a lock between two quiescent points; a swap frees the old snapshot only after every online reader passed one (the grace period), so no reader sees a torn or freed table.
_Avoid_: MAC table (the Hub's `MAC_TABLE_ENTRY` hash list), routing table (the Windows one)

## SDN language (new core)

The terms of the new-core SDN (spec #176). Its decisions are ADR-0025 to ADR-0037. Node and Role are defined above.

**VRF**:
A routing domain of the overlay with its own forwarding table, address pools, DNS zone and policy. VRFs are isolated unless the Intent leaks routes between them, and two VRFs may use the same private range.
_Avoid_: tenant, routing compartment, segment

**Network**:
One L2 switched or L3 routed segment inside exactly one VRF, with its own address pools; the successor of the Hub.
_Avoid_: Hub (the slim fork object), VLAN, subnet

**Controller**:
The `ranz-controller` service: the single authority that stores the Intent, allocates addresses and DNS records, and compiles the desired state of every Node. It runs as one member or as a cluster of 3 or 5, each member with its own rqlite member as sidecar. A `Controller` resource of the Intent names one member as Nodes reach it.
_Avoid_: `controller` role (it left the node binary), master, management server

**Leader**:
The member of a Controller cluster that holds the lease in the store and so runs the Controller: it applies the Intent, pushes desired state and stores the acknowledgements. The other members are standbys: they send Nodes to the leader and forward API calls to it, and one of them takes the lease when the leader is lost (ADR-0026 amendment of 2026-10-22).
_Avoid_: master, primary, active controller

**Intent**:
The declared description of the network (VRFs, Networks, Nodes, policy, routes and the other resources) that an administrator applies. Every apply is a revision.
_Avoid_: config, configuration (the slim fork's Config file)

**Generation**:
The number of one version of a Node's desired state. The Controller sends the changes since the Generation the Node last acknowledged, and the Node acknowledges each Generation it applied.
_Avoid_: revision (a version of the whole Intent), version, epoch

**4via6**:
The mapping of an IPv4 address of a VRF into an IPv6 address inside that VRF's ULA prefix, so a host that joins two VRFs with overlapping IPv4 can tell the two addresses apart.
_Avoid_: NAT64, 6to4

**Endpoint**:
One service (an IP address and port) of a source VRF published into a consumer VRF, so the consumer reaches only that service.
_Avoid_: service, port forward; "endpoint" for the end of a connection (say peer or address)

**Mirror**:
A rate-limited copy of matching overlay traffic, sent to a sensor over VXLAN.
_Avoid_: tap, SPAN, monitor (the Local Bridge `Monitor` flag is a different thing)

**Front door**:
The TCP 443 listener of a Node that reads the first bytes of each connection and hands the socket to the process that owns that protocol.
_Avoid_: port sharing, reverse proxy, demultiplexer (the opt-in UDP 443 demultiplexer is a different thing)

**API token**:
A bearer secret that a caller of the Controller's API presents, holding one of the three global API roles: `viewer` reads, `operator` also applies Intent, `admin` also manages the API tokens (ADR-0031). The Controller keeps only its SHA-256; the first start creates the `admin` token.
_Avoid_: API key, password, session (a user login of SDN-32 is a different thing)

**Egress tier**:
How a Node that is an internet exit for a VRF translates its traffic: tier 1 is RRAS NAT, tier 2 is WinNAT, tier 3 is a proxy on the Windows TCP/IP stack.
_Avoid_: SecureNAT, NAT mode

**Capability**:
A fact that a Node reports about its host (SKU, architecture, Hyper-V, LBFO, SeLow, XDP, Egress tier), against which the Controller checks the Intent before an apply.
_Avoid_: `CAPS` (the slim fork's server capability list), feature flag

## Flagged ambiguities

- "Cedar" names both the library and the root `CEDAR` object. "Mayaqua" names the library and the Mayaqua module (`Mayaqua.c`, start-up and shut-down).
- "Bridge" is the Local Bridge feature, the `BRIDGE` object and the `Bridge.c` module. Say Local Bridge for the feature.
- "Link" in code is "Cascade" in vpncmd and in prose. Use Cascade, and `LINK` only for the struct. The RPC area file is `AdminLink.c` and its vpncmd file is `CommandCascade.c`.
- "Console" names two things: the Cedar module Console (`Console.c` and `Console.h`, the console abstraction of vpncmd) and `src/Mayaqua/Console.c`, the console input and output of the Win32 module (declared in `Win32.h`).
- "Win32" names the module (`Win32.c` with `Console.c`, `Diag.c`, `OsInfo.c` and `Proc.c`, all declared in `Win32.h`) and a function prefix. Not every `Win32*` function is in the module: FileIO defines the file ones (`Win32EnumDirExW` and the others that Win32.h declares, and `Win32SetFolderCompress` of Platform.h), and BridgeWin32 defines the adapter ones (`Win32Eth*`).
- "Encrypt" is the API header of the crypto module; there is no Encrypt.c. The code is in `src/Mayaqua/Crypto/` (Hash, Rand, Cipher, Aead, Rsa, Dh, X509, Pem, Init).
- "Crypto" also names the new core's crypto module, `src/Core/Crypto*.c` with the API header `Core/Crypto.h` (functions `Crypto*`), which is not Mayaqua's `Crypto/` directory of the Encrypt module.
- "Logging" is no longer a module. `Logging.c` became five modules: LogWriter (the file writer), HubLog (`SLog`, `HLog`, the log directories and the log file list), PacketLog, Syslog and Eraser. HubLog also holds the server log, despite its name.
- The "Pkt" files (`Pkt.c`, `PktChecksum.c`, `PktIpv6.c`, `PktSniff.c`) and `Dhcp.c` are part of TcpIp, with `TcpIp.h` as their API header. A `PKT` is a parsed frame.
- "DNS" is the resolver module (`DNS.c`). `NetworkDns.c` is part of Network: the machine name, the reverse host name lookup and the NetBIOS name query.
- PACK over HTTP (`PackHttp.c`) is part of HTTP, not of Pack.
- "Network" names three things: the SDN resource (a segment inside a VRF, the successor of the Hub), the Mayaqua Network module (sockets), and a word the Hub entry tells you to avoid. In slim-fork text say Hub; say Network only for the SDN resource.
- "Node" is a new-core host running `ranz-node`, the new core's binary, and its `NODE` object. `NODE_INFO` (Session) is unrelated: the record of a connecting client's host details that a SE-VPN login sends, not a Node.
- "Capability" is what a Node reports to the Controller. `CAPS` (`ServerCaps.c`) is the slim fork's list of server capabilities for admin clients.
- "Role" is what a Node does (`server`, `client`, `bridge`, `relay`). The `admin`, `operator` and `viewer` of the Controller's API are API roles, held by an API token; say API role for them.
- "controller" was a role of the node binary in ADR-0022. Since ADR-0026 the Controller is the separate `ranz-controller` service, and the node has no `controller` role.
- "Leader" is the member of a Controller cluster that holds the lease. The Raft leader of rqlite is a different thing: any member's rqlite may be it, and rqlite forwards writes to it by itself.
- "Generation" and "revision" are different versions: a revision is a version of the whole Intent (what `ranz rollback` returns to); a Generation is a version of one Node's desired state.
- "Configuration" is the Config file of the slim fork (`ranz_server.config`, Cfg) or the Configuration store of a Node (`ranz_node.db`, ConfigStore). Say which one.
- "Server" names the slim fork's `vpnserver` and its `SERVER` object, and the server Role of a Node. The service of the Node is `ranzvpnserver`; the one of `vpnserver` is still `sevpnserverdev`.
