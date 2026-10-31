# Ranz VPN

Slimmed fork of SoftEther VPN (C, CMake): native SE-VPN protocol only, Windows 10 / Server 2016 and later on x64 and arm64, headless `vpnserver` and `vpncmd`, no GUI. Almost all code lives in two static libraries: `mayaqua` (runtime) and `cedar` (VPN logic, links `mayaqua`). Scope decisions are in `docs/adr/` (start with ADR-0001, ADR-0012, ADR-0013).

## Module map

A module is one `X.c` / `X.h` pair under `src/Mayaqua`, `src/Cedar` or `src/Core` (the new core). The files split out of a god file (#29) belong to that file's module and use its header as their API header. Declarations that only those files need are in the module-internal header `XInternal.h`, which only the module's own files include. Encrypt is named differently: its API header is `Encrypt.h`, its code is `src/Mayaqua/Crypto/*.c` and its internal header is `Crypto/Cng.h`. The tree has 55 modules (23 in Mayaqua, 29 in Cedar, 3 in Core) and four headers without code: MayaType.h, Platform.h, CedarType.h, and `src/GlobalConst.h` (the product name strings, included by Cedar.h, FileIO, Mayaqua and Microsoft).

The Uses and Used by columns are generated from the tree, not written by hand:

- Module A uses module B when a file of A names a function or global that a source file of B defines, or a macro, type, enum constant or inline function that a header of B declares. "Types and macros only" marks a dependency with no call.
- An `#include` that supplies nothing is not counted. MayaType.h and CedarType.h are left out, because every module uses them.
- The Uses column is each module's list of allowed dependencies. A change that calls into a module outside that list adds an edge, and the edge must show up as a change to this map.
- The facts describe the tree at the commit that last rewrote this map. A script over the `#include` lines and identifiers of `src/` computed them, and CodeGraph cross-checked them.

Executables:

- `vpnserver` uses, in Cedar: Cedar, Server; in Mayaqua: Mayaqua, Microsoft.
- `vpncmd` uses, in Cedar: Cedar, Command; in Mayaqua: Internat, Kernel, Mayaqua, Memory, Microsoft.
- `ranz-node` uses, in Cedar: Cedar, Node; in Mayaqua: Mayaqua, Microsoft.
- `vpntest` uses, in Cedar: all except Bridge, Link, RpcField, Win32Com (Sam for its types and macros only); in Mayaqua: all except Tracking; in Core: Crypto, Noise, Peer.
- `fuzz` uses, in Cedar: Protocol; in Mayaqua: Cfg, Encrypt, HTTP, IpAddr, Mayaqua, Memory, Network, Pack, Stun, TcpIp; in Core: Noise, Peer.
- `coretest` uses, in Core: Crypto, Noise, Peer; nothing of Cedar or Mayaqua.

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
| Encrypt: `Encrypt.h`, `Crypto/*.c` (9 files), `Crypto/Cng.h` | Cryptography: hashes, random numbers and RC4 on CNG; AEAD, RSA, DH, X.509 and PEM on OpenSSL; SHA-0 own code; the start-up of both libraries | `X`, `K`, `NAME`, `X_SERIAL`, `CIPHER`, `CRYPT`, `DH_CTX` | Internat, Kernel, Memory, Str, Trace, Win32; types and macros only: Mayaqua | In Mayaqua: Cfg, Kernel, Mayaqua, Memory, Microsoft, Network, Pack, Stun. In Cedar: Account, Admin, BridgeWin32, Cedar, Command, ConfigStore, Connection, Hub, Link, Node, Protocol, Sam, SeLowUser, Server, Session, UdpAccel, WaterMark; types and macros only: Remote. Programs: `vpntest`, `fuzz` |
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
| Node: `Node.c`, `NodeBgp.c`, `NodeTable.c`, `NodeWorker.c`, `NodeInternal.h` | The Node of the new core (`ranz-node`, service `ranzvpnserver`): its data directory under ProgramData with a protected DACL, Roles from its Configuration store and the control plane (`NodeSetRoles`), the one-time import of a fork Config file found there, one Worker per core, one I/O thread per Adapter queue, the Table snapshot swapped by pointer, the Hubs of the server role and their credential gate through Sam (`NodeAuthenticate`), which checks the Login of a Noise session (`NodeLogin`), the relay role on the Peer module of the new core, under the node identity key, with the peers that the control plane sets (`NodeSetPeers`), and the BGP sidecar with its learned routes in the Windows routing table through IP Helper (`NodeBgp.c`) | `NODE`, `NODE_WORKER`, `NODE_QUEUE`, `NODE_READER`, `NODE_TABLES`, `NODE_BGP` | Cedar, ConfigStore, Hub, LogWriter, Sam, Server; in Core: Peer; in Core, types and macros only: Noise | Encrypt, FileIO, Internat, Memory, Object, Str | Programs: `ranz-node`, `vpntest` |
| ConfigStore: `ConfigStore.c`, `ConfigStoreImport.c`, `ConfigStoreInternal.h` | The Configuration store of the new core: a SQLite database through the `winsqlite3.dll` of System32 (settings, networks, users with PBKDF2 password hashes and pinned keys, listeners, certificates, named admin accounts with roles), its text dump, and the one-time import of a fork Config file (`CsImportForkConfig`) | `CONFIG_STORE`, `CS_NETWORK`, `CS_USER`, `CS_ADMIN`, `CS_IMPORT` | Account; types and macros only: Cedar | Cfg, Encrypt, FileIO, Internat, Kernel, Memory, Object, Str | Node. Programs: `vpntest` |

### Core (`src/Core`)

The new core (ADR-0022). Each of its modules is a static library of its own that links nothing of Mayaqua or Cedar, and no OpenSSL or liboqs; `ranz_core_check_links` (`src/Core/CMakeLists.txt`) stops the configure when one does.

| Module | Contract | Main types | Uses | Used by |
|---|---|---|---|---|
| Crypto: `Crypto.h`, `Crypto.c`, `CryptoX25519.c`, `CryptoMlKem.c`, `CryptoCert.c`, `CryptoInternal.h` (library `corecrypto`) | X25519, AES-GCM, SHA-256, HMAC-SHA256, HKDF and random bytes on CNG; the X25519MLKEM768 hybrid where CNG has ML-KEM; the node identity key in the Microsoft Software Key Storage Provider; self-signed ECDSA P-256 certificates, PFX import and the certificate stores through CryptoAPI | `CRYPTO_SHA256`, `CRYPTO_AEAD`, `CRYPTO_IDENTITY`, `CRYPTO_HYBRID`, `CRYPTO_MLKEM` | none (the system libraries bcrypt, ncrypt and crypt32) | In Core: Noise, Peer. Programs: `coretest`, `vpntest`, `fuzz` |
| Noise: `Noise.h`, `Noise.c`, `NoiseSession.c` (library `corenoise`) | The session module: the Noise_IK handshake (`Noise_IK_25519_AESGCM_SHA256`, and `Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256` where CNG has ML-KEM); the Noise session over it, bound to its outer TLS or QUIC session by the Channel binding, with a data stream and a control stream, keepalive, rekey on a schedule and the dead-peer timeout; the Login; the Tunnel | `NOISE_CIPHER`, `NOISE_HANDSHAKE`, `NOISE_SESSION`, `NOISE_LOGIN`, `NOISE_TUNNEL` | Crypto | Programs: `coretest`, `vpntest`, `fuzz`; types and macros only: Node |
| Peer: `Peer.h`, `Peer.c`, `PeerSignal.c`, `PeerUdp.c`, `PeerInternal.h` (library `corepeer`) | The peer layer of a node (ADR-0015): the peer table and the Relays that the control plane sets, the Bindings of the node to its relays, the Path to each peer, the relay role, and `PeerInput`, the one ingress of every datagram with one policy check for a datagram the node takes and one its relay role forwards; Signals and binds sealed with the Noise one-way pattern K between node static keys; a UDP socket on Winsock that stands in for the QUIC datagrams of CORE-S1-1; ICE on libjuice, in its peer mode, on the socket of the layer, and the port mapping of the home gateway on libplum, with the host addresses of that socket read through IP Helper (CORE-S5-6) | `PEER_AGENT`, `PEER_KEY`, `PEER_INFO`, `PEER_RELAY_INFO`, `PEER_SIGNAL`, `PEER_UDP` | Crypto (and the system libraries ws2_32 and iphlpapi) | In Cedar: Node. Programs: `coretest`, `vpntest`, `fuzz` |

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

**Policy schema**:
Schema 2 of the Configuration store: the groups of each network, the VLAN of users and groups, the VLAN settings of each network and the rules of the Policy engine, which `CsPolicyDocument` writes as a Document of rules. A store of schema 1 gets the new tables when it is opened.

**Policy import**:
The part of the import of a fork Config file (`CsImportForkConfig`) that carries the access lists, groups and VLAN policy of its hubs into the Policy schema.

**Machine identity**:
The 20 bytes that `GenerateMachineUniqueHash` returns for a server: a hash of the Windows MachineGuid and the `MachineIdSalt` of the Config file, kept in the `CEDAR`. It sets the MAC address and the 172.31.x.x address of every Hub and the `unique_id` of a Cascade login. It stays the same across restarts, renames and IP changes; servers cloned from one image differ only when each has its own config file, and so its own salt (FIX-5, `docs/upgrade-notes.md`).
_Avoid_: machine ID (Windows' name for the MachineGuid), `UniqueId` (a random value per `CEDAR`, copied into `NODE_INFO`)

**Node**:
One Windows host running `ranz-node`, the data plane, in one or more Roles (`server`, `client`, `bridge`, `relay`). It joins VRFs and applies the desired state that the Controller sends it. `ranz-node` is the new core's one binary, installed as the `ranzvpnserver` service (ADR-0011, ADR-0020 decision 4), and its in-process object is `NODE` (the Node module): the Roles of its configuration, one Worker per core, one I/O thread per Adapter queue and the Table snapshot. It reuses the fork's Hub, Account, Sam and Logging in-process, and Cfg for the one-time import of a fork Config file. Its data directory is `%ProgramData%\Hanzcodes\Ranz VPN` (`NodeDefaultDataDir`), whose protected DACL lets only SYSTEM and the Administrators in (`NodeMakeDataDir`); it holds the Configuration store `ranz_node.db` and `node_log`. Its identity key, the Noise static key, is a key of the software KSP named by the `IdentityKey` setting of the Configuration store (`Ranz Node` without it), in the machine key set when the process runs elevated, as the service does.
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

**Forwarding table**:
The immutable longest-prefix-match table of one VRF in a Node (`NODE_VRF_TABLE`, `NodeVrf.c`): DIR-24-8 for IPv4, a trie for IPv6. It is built for each Generation and installed together with the other tables of that Generation (`NodeSwapVrfs`), so two VRFs can use the same range and a lookup never sees a half-built table.
_Avoid_: routing table (the Windows one), MAC table

**Next hop**:
What a route of a Forwarding table leads to: the host (`NODE_VRF_LOCAL`) or one of the next hops of its Generation, a peer reached over the overlay.

**VRF tag**:
The VRF id, 4 bytes big-endian, before the IP packet in a data record of the overlay (`NODE_OVERLAY_VRF_TAG`), so the receiving Node looks the packet up in the Forwarding table of the right VRF.

**Overlay** (of a Node):
The part of a Node (`NodeOverlay.c`) that joins its VRFs: the control stream to the Controller, the Noise sessions to its peers and the packets of the host's own IP stack on the overlay adapter.

**Noise session**:
One connection between two Nodes after a Noise_IK handshake that authenticated both by their node identity keys (`NOISE_SESSION`, the Noise module): the records of a data stream and a control stream, keepalive, rekey on a schedule and the dead-peer timeout. The Channel binding ties it to the outer TLS or QUIC session, which encrypts its records once (ADR-0023); only a session that nothing binds, the CDN path of phase 2, encrypts its records under the Noise keys.
_Avoid_: Session (the Hub's `SESSION`), Connection (`CONNECTION`), Tunnel (several connections)

**Channel binding**:
The value of the outer TLS or QUIC session in the prologue of a Noise handshake: its TLS exporter, or `tls-server-end-point` (the hash of the pinned server certificate) where the stack has no exporter. A handshake whose two sides saw different values fails, so an outer session that a third party terminates is closed.

**Transport**:
A pluggable carrier of streams between two Nodes (`TRANSPORT`): dial, listen, accept, stream read and write, close, and optionally the Channel binding and the rekey of an outer TLS or QUIC session. QUIC, TLS-443 and the phase-2 transports each implement one; the Noise session above it does not change.

**Fallback list**:
A client's configured, ordered list of Transport and address entries (`TRANSPORT_TARGET`), raced happy-eyeballs style: the first Transport to connect wins.

**Loopback transport**:
The in-process Transport of the vpntest harness (`TransportLoopbackNew`): in-memory streams between a dialler and a listener of one process.

**Login**:
The first control message of a Noise session (`NOISE_LOGIN`): the hub, the user and a password, or a certificate with its signature of the session's challenge. The server Role's Sam checks it (`NodeLogin`); a further connection of a Tunnel sends the Tunnel's id instead.
_Avoid_: the SE-VPN login (`ServerAccept`), which the Login replaces in the new core

**Tunnel**:
The Noise sessions of up to 16 connections between the same two Nodes (`NOISE_TUNNEL`), each bound to its own outer session. Inner flows are spread over them by a flow hash, so one flow keeps its order; a lost connection's flows move to the others, and the Tunnel stays up while one connection is left. In the Hub, a Connection of type `CONNECTION_NOISE` (`CONNECTION.Protocol`) carries the Tunnel of a client Node of the new core, and the Cedar object around the `NOISE_TUNNEL` is a `TUNNEL`: its Noise sessions, their readers and the frames queued for the Session (CORE-S1-2).
_Avoid_: Cascade, link

**Flow hash**:
The hash of a frame that picks its connection in a Tunnel (`NoiseTunnelFlowHash`): over the IP 5-tuple, else over the MAC pair, with the EtherType and the VLAN ids. It is symmetric, so both directions of a flow take the same connection and keep their order.

**BGP sidecar**:
`ranz-bgp` (`ranz-bgp/`, Go), a separate process that embeds GoBGP as a library and peers with the operator's own routers on TCP 179 (ADR-0010, ADR-0022). A Node starts it only when its `Bgp` setting names peers (`NodeBgp.c`), talks to it over a named pipe with JSON messages, one per line (start, announce and withdraw from the Node; ready, peer, learned, withdrawn and error from the sidecar), and installs the learned routes into the Windows routing table through IP Helper; the sidecar installs none itself. Since ONE-1 (#310) it is the subcommand `ranz bgp` of `ranz.exe` (ADR-0011 amendment of 2026-10-22), which the Node starts as a process of its own. Besides the one toward the routers of the operator (`NodeBgp.c`), a Node runs a second `ranz bgp` for its VRFs whose **Peering** is `bgp` (`NodePeering.c`, log `ranz-bgp-peering.log`), on the address of its tunnel endpoint (ADR-0010, SDN-77).
_Avoid_: BGP daemon, BGP role (it is no Role), RRAS BGP

**Peering (of a VRF)**:
`VRF.peering`: how the Nodes of a VRF of the standard mode exchange their routes: `bgp`, by BGP in a full mesh, or left out, by the routes of the Controller.

**Accept list (of a peer)**:
`PeerPeering.accept`: the prefixes that a peer may announce in each VRF of the session, with their more specific ones: its addresses and its LAN subnets there.

**Refused session**:
A BGP session from an address that no Peer object names, which the sidecar refuses and the Node counts (`PeeringReport.refused`).

**Peering report**:
`Telemetry.peering`: the peers of the sidecar of a Node, the state of each session, the prefixes learned from each and the refused sessions, which `ranz explain NODE` shows.

**ranz.exe**:
The one signed executable of the product, one per architecture (ADR-0011 amendment of 2026-10-22): a Go multi-call binary (`ranz controller`, `ranz bgp`, `ranz tray` and the CLI verbs) that carries the Node and what it needs as Payloads. `ranz install` unpacks and registers them and `ranz uninstall` reverses it. Decided and ticketed (ONE-1 to ONE-5, #310 to #314). ONE-1 built the Go part: `ranz controller`, `ranz bgp`, `ranz notice`, `ranz version` and the CLI verbs are one executable. The Payloads, `ranz install` and the thin MSI come with ONE-2 to ONE-5; until then `ranz-node` is a separate file.
_Avoid_: installer (the MSI is only a thin wrapper that runs `ranz install`), launcher, bundle

**Payload**:
A file embedded in `ranz.exe` that `ranz install` writes out after checking its Authenticode signature and its hash: `ranz-node`, the Wintun driver, the SeLow package, the XDP runtime and the rqlite member of a Controller. A component under the GPL or MPL stays a separate process; it enters the file only as an optional Payload, after its licence terms are checked (ADR-0036).
_Avoid_: resource (an Intent resource is a different thing), plugin, dependency

**Subcommand**:
A command that `ranz` runs when its name is the first argument (`controller`, `bgp`, `notice`, `version`); every other first argument starts a command of the Controller's API. A subcommand registers itself from its own file.

**NOTICE**:
The file of licence texts of the components inside `ranz` (today GoBGP), embedded in the executable and printed by `ranz notice`.

**Self-integrity check**:
The start-up check of the running executable: WinVerifyTrust plus a hash of its `.text` section (SEC-3).

**Degrade or deceive**:
The response to a detection (ADR-0036): lock a feature, return wrong data, or fail later, never an instant crash.

**Authenticode signing**:
The code signing of the shipped executables and of the MSI.

**Symbol stripping**:
Go `-trimpath -ldflags "-s -w"` and a private PDB for the C binaries, so a shipped binary carries no symbols.

**ranzguard**:
The release-only hardened licence-gate and key-handling binary.

**Hardened variant** (`RANZ_HARDENED`):
The x64 release-only build that adds the anti-debug and anti-RE cover. It is off by default.

**VMProtect marker** (`RANZ_VMP_BEGIN`, `RANZ_VMP_END`):
The markers around the two routines that the selective virtualization protects.

**Virtual service account**:
`NT SERVICE\<service>`, the account that each new-core service runs as.

**Process mitigation**:
One `SetProcessMitigationPolicy` policy of a new-core process (`NODE_MITIGATION`, `mitigation.Policy`).

**Binary hardening gate**:
The dumpbin check of the shipped binaries in CI, with its recorded exceptions.

**SBOM**:
The SPDX bill of materials that the supply-chain job produces.


## SDN language (new core)

The terms of the new-core SDN (spec #176). Its decisions are ADR-0025 to ADR-0037. Node and Role are defined above.

**VRF**:
A routing domain of the overlay with its own forwarding table, address pools, DNS zone and policy. VRFs are isolated unless the Intent leaks routes between them, and two VRFs may use the same private range.
_Avoid_: tenant, routing compartment, segment

**Network**:
One L2 switched or L3 routed segment inside exactly one VRF, with its own address pools; the successor of the Hub.
_Avoid_: Hub (the slim fork object), VLAN, subnet

**Policy**:
The resource kind of one rule of a VRF's policy (its VRF, its action, what it matches).
_Avoid_: `POLICY` (the slim fork's per-Session policy of a Hub user or group)

**Starter rule**:
The Policy `default-allow-all` that the first start creates: allow all inside VRF `default` (ADR-0034).

**First start**:
The revision 1 that a Controller makes on an empty store (revision operation `first-start`): VRF `default`, its Network `default` with the Automatic pool, and the Starter rule (ADR-0034).

**Automatic pool**:
The IPv4 pool `100.64.0.0/10` of Network `default`.

**Node address**:
The address of a Node in an L3 Network, allocated by the Controller (`addresses` of the Node spec, `Address` of the control protocol).

**Reservation**:
A prefix or an address of a Network's pools (`Network.reserved`) that the Controller never gives a Node.

**LAN subnet**:
A prefix behind a gateway Node (`Node.lanSubnets`, by VRF). It is a Route, never an allocation.

**Route**:
A LAN subnet that a gateway Node advertises in a VRF (`intent.Route`, listed by `GET /api/v1/ipam`).
_Avoid_: Path (how a Node reaches a peer), the Windows routing table

**Pool threshold**:
The percentage of a pool in use at which the pool Event fires (`Network.poolThreshold`, 80 by default).

**Controller**:
The `ranz-controller` service: the single authority that stores the Intent, allocates addresses and DNS records, and compiles the desired state of every Node. It runs as one member or as a cluster of 3 or 5, each member with its own rqlite member as sidecar. A `Controller` resource of the Intent names one member as Nodes reach it.
_Avoid_: `controller` role (it left the node binary), master, management server

**Leader**:
The member of a Controller cluster that holds the lease in the store and so runs the Controller: it applies the Intent, pushes desired state and stores the acknowledgements. The other members are standbys: they send Nodes to the leader and forward API calls to it, and one of them takes the lease when the leader is lost (ADR-0026 amendment of 2026-10-22).
_Avoid_: master, primary, active controller

**Controller API registries**:
The controller Go module adds its HTTP routes and its store tables through two registries, so feature lanes stop colliding on shared files. A route lives in its own file under `controller/internal/api/`: the file's `init()` calls `register` with the route's method, path, the least API role it needs and its handler, and `api.Routes` builds the mux from them; the SDN-14 Guard still turns every request into the role it needs through `api.Needs`, the one place roles are decided. A table lives in its own file under `controller/internal/store/`: the file's `init()` calls `store.RegisterSchema(name, ddl...)`, and `Open` runs the registered statements sorted by name, which creates the same tables as before. A new feature is a new file in each package, never an edit of `api.go`, `store.go` or this document. The control protocol (`proto/ranz/control/v1/control.proto` and the generated `control.pb.go`) stays a shared file.
_Avoid_: appending routes to a shared `Routes`, appending DDL to a shared schema slice

**Intent**:
The declared description of the network (VRFs, Networks, Nodes, policy, routes and the other resources) that an administrator applies. Every apply is a revision.
_Avoid_: config, configuration (the slim fork's Config file)

**Generation**:
The number of one version of a Node's desired state. The Controller sends the changes since the Generation the Node last acknowledged, and the Node acknowledges each Generation it applied.
_Avoid_: revision (a version of the whole Intent), version, epoch

**Revision**:
The number of one version of the whole Intent, from 1. Every apply, delete and rollback makes the next one, and the Controller stores each with its whole Intent; revision 0 is the empty Intent before the first apply. `ranz diff` shows the resource changes between two, and `ranz rollback` makes the Intent of an earlier one the Intent again, as a new revision. An apply with `--confirm` makes a revision that waits for `ranz confirm`; without it in time, the Controller rolls it back by itself (an automatic rollback) and raises an Event. While a revision waits, the Controller takes no other change but a rollback.
_Avoid_: Generation (a version of one Node's desired state), version, commit

**Intent export**:
The whole Intent as one intent document, with the values the Controller filled in (the id and the ULA of each VRF), taken with `ranz export`. `ranz import` makes such a document the whole Intent again, as a new Revision, and deletes the resources it leaves out.
_Avoid_: dump, backup (the Store backup), snapshot

**Store backup**:
The rqlite backup of the Controller's whole store: the Intent with every Revision, the Node states, Capabilities, Events, API tokens, the Licence key and the lease. `ranz controller backup` writes it and `ranz controller restore` puts it back, on the Controller's host. A restore under a running cluster first takes the lease, so the Leader steps down.
_Avoid_: snapshot (a Table snapshot of a Node), dump, export (the Intent alone)

**Event**:
A condition the Controller reports to operators (ADR-0030), kept with the change that raised it and listed by the API (`ranz get events`): so far the automatic rollback of an unconfirmed revision. SDN-16 delivers them by webhook and as metrics.
_Avoid_: alert, log entry, ETW event (a local Node event)

**4via6**:
The mapping of an IPv4 address of a VRF into an IPv6 address inside that VRF's ULA prefix, so a host that joins two VRFs with overlapping IPv4 can tell the two addresses apart.
_Avoid_: NAT64, 6to4

**4via6 subnet**:
The last /64 of a VRF's ULA, reserved for 4via6 and outside every pool.

**Endpoint**:
One service (an IP address and port) of a source VRF published into a consumer VRF, so the consumer reaches only that service.
_Avoid_: service, port forward; "endpoint" for the end of a connection (say peer or address)

**Mirror**:
A rate-limited copy of matching overlay traffic, sent to a sensor over VXLAN.
_Avoid_: tap, SPAN, monitor (the Local Bridge `Monitor` flag is a different thing)

**VTEP**:
A VXLAN tunnel endpoint: an IP address and UDP port that sends and receives VXLAN datagrams. The Node's VXLAN module is one; the VTEPs of a fabric and the sensor of a Mirror are others.

**Flood list**:
The VTEPs of one VNI that each get a copy of a frame the VXLAN module sends on that VNI (ingress replication). For the EVPN gateway, the type-3 routes of the fabric fill it.

**Stretch**:
The binding of one Gateway to one L2 Network that extends the Network into a data-centre fabric over EVPN and VXLAN (ADR-0032 amendment of 2026-10-22). It holds the L2 VNI, the route targets, the ESI, the BUM rate limit, the MAC import limit, the stale timer and the `irb` flag. A Network has one Stretch gateway unless an ESI is set.
_Avoid_: L2 extension, bridge (the Local Bridge and the `bridge` Role are different things), tunnel

**VNI**:
The VXLAN network identifier. An L2 VNI belongs to one stretched Network and is set in its Stretch; an L3 VNI belongs to one VRF and is set in its `EvpnPeer`, where type-5 routes and IRB use it. The administrator of the fabric fixes the values and the Controller only validates them.
_Avoid_: VLAN id, segment id

**ESI**:
The Ethernet segment identifier that two gateways of one Network share for active-active multihoming (EVPN type-1 and type-4). The administrator sets it in the Stretch; the Node elects the designated forwarder.
_Avoid_: LAG, bond, team

**EVPN VRF**:
A VRF of a gateway Node that the gateway hands to a data-centre fabric as **IP prefix routes**: its L3 VNI, route distinguisher, import and export route targets and accept list (the `vrfs` of the `evpn` object of the `Bgp` setting).

**IP prefix route**:
An EVPN route of type 5 (RFC 9136): a prefix of one VRF with its route distinguisher, route targets, L3 VNI and **Router MAC**, and the VTEP that holds it as next hop.

**Router MAC**:
The MAC address of a VTEP in an EVPN VRF, carried in the Router's MAC extended community of its IP prefix routes. It is the inner source of the frames that a gateway sends on an L3 VNI and the inner destination of the frames sent to it. The default is `02:52:5a:00:00:05`, the same in the Node and in the sidecar.

**Front door**:
The TCP 443 listener of a Node that reads the first bytes of each connection and hands the socket to the process that owns that protocol.
_Avoid_: port sharing, reverse proxy, demultiplexer (the opt-in UDP 443 demultiplexer is a different thing)

**Default VPN listener**:
The one listener that a fresh configuration registers: TCP 443, or 5555 after a fallback (ADR-0020).

**First-start probe**:
The bind test of 443, then 5555, that a server makes only when it creates its default configuration (`ListenProbe`).

**HTTP listener**:
The listener kind, on port 80 by default, that answers only the HTTPS redirect and ACME HTTP-01 challenges, never VPN sessions or the Admin RPC.

**VPN listener**:
A TCP listener of the SE-VPN protocol and the Admin RPC (the `ListenerCreate` kind), as opposed to the HTTP listener.

**HTTP responder**:
The pure function of the HTTP listener that turns one parsed request into one answer.

**ACME webroot** (`acme_webroot`):
The folder in the data directory whose `.well-known/acme-challenge` holds one challenge file per token.

**API token**:
A bearer secret that a caller of the Controller's API presents, holding one of the three API roles: `viewer` reads, `operator` also applies Intent, `admin` also manages the API tokens (ADR-0031). The role is held for the whole API or, as a **Scoped role**, for one Network. The Controller keeps only its SHA-256; the first start creates the `admin` token.
_Avoid_: API key, password, session (a user login of SDN-32 is a different thing)

**Admin source allowlist**:
The source prefixes (CIDR prefixes or single addresses, at most 256) that the Controller's API and web UI accept connections from (`api.Sources`). Empty means no restriction, and a loopback address always passes, before the list is read. It is kept in the store, not in the Intent, and an admin sets it with `ranz admin-sources`. A request from outside it is answered 403 before its token is looked at and is recorded as an Event.
_Avoid_: IP filter, firewall rule, `$adminip.txt`

**Enrolment sources**:
The `enrolSources` of a Network: the source prefixes that its Nodes may open their control stream from. The Controller checks every stream against the Networks of the VRFs of its Node and refuses one that a Network does not allow.
_Avoid_: source IP access control (the Hub's AC list of the slim fork), allowed prefixes

**UI action**:
One call of the public API that the web UI makes, named in the action table `controller/internal/webui/ui/assets/actions.json` with its method, path pattern and the least API role it needs (the role `api.Needs` gives the call). Every control of the UI names its UI action in `data-action` and shows only to a role that allows it.
_Avoid_: endpoint, route (the API's side of the call)

**Egress tier**:
How a Node that is an internet exit for a VRF translates its traffic: tier 1 is RRAS NAT, tier 2 is WinNAT, tier 3 is a proxy on the Windows TCP/IP stack.
_Avoid_: SecureNAT, NAT mode

**Exit (of a VRF)**:
The member Node that the `egress` of a VRF names. It takes the traffic of the VRF to the addresses outside it, with its **Egress tier**. A VRF has one Exit at most (its **Hub node** when the topology is hub-and-spoke), and a Node can be the Exit of several VRFs (SDN-12).

**Interface that carries the egress**:
An interface of the host of an Exit, other than the loopback, that holds an IPv4 default route. It has Forwarding, WeakHostSend and WeakHostReceive on while the Node is the Exit of a VRF, and gets back what it had after.

**NAT network of the Node**:
`RanzVPN-Egress`, the one NAT network of WinNAT that tier 2 creates over the supernet of the VRFs whose Exit the Node is. A NAT network of another name is never the Node's and is never touched.

**Fallback to the proxy**:
An Exit whose NAT of Windows cannot serve its VRFs uses the proxy, tier 3, for the rest of the run. The causes are a VRF seen through 4via6, a supernet wider than /8, a NAT network of another program, and three failed reconciles in a row. Its status says from which tier it fell back.

**Capability**:
A fact that a Node reports about its host (SKU, architecture, Hyper-V, LBFO, SeLow, XDP, Egress tier, the fallback to 5555), against which the Controller checks the Intent before an apply. Only a gateway or edge feature, or one a platform cannot carry (an L2 Network on arm64), needs one.
_Avoid_: `CAPS` (the slim fork's server capability list), feature flag

**bgpPeering (a Capability)**:
`Capabilities.bgp_peering`, reported in the Hello by a Node whose release has the BGP peering of the standard mode and whose `ranz.exe`, which holds the **BGP sidecar** that it starts, is next to it. The Controller refuses a Node that does not report it as a member of a VRF whose **Peering** is `bgp` (ADR-0033 amendment of 2026-10-30, SDN-77-R2).

**Relay**:
A Node with the relay Role (ADR-0015). It binds the nodes of its VRFs and forwards a datagram from one of them to another only when the two share a VRF, through `PeerInput`, the same ingress where a node takes its own datagrams. It holds no state beyond the Bindings that its nodes renew, so a restart loses nothing for good. The Relay objects of a node's desired state are the relays it may use; the first one is its home relay. The `relay` item of a Node resource is the address its relay role listens on.
_Avoid_: TURN server, DERP (the systems it is modelled on), hub

**Binding**:
The soft state of one node at a Relay: the address that the node's last bind came from. A bind is an envelope sealed with the node's static key; the node renews it every 25 s and the relay drops it after 90 s without one. The relay's answer tells the node the address it saw: the node's server reflexive candidate.
_Avoid_: allocation (TURN), session

**Path**:
How a node reaches a peer: the relay path through a Relay, up as soon as the two have exchanged one Signal each (relay-first), or the direct path that ICE validates later (CORE-S5-3). The session layer moves between them (ADR-0015 item 7). A pair where one node has an endpoint that the other dials uses a Stream session instead; the state of a node names it `stream` beside `relay` and `direct`.
_Avoid_: route (a route of a VRF), connection

**Signal**:
A message from a node to one peer that the Controller carries (`Signal` of the control protocol): the relay assignment (the node's home relay) and the node's ICE candidates, as an offer or an answer. It is sealed by the node's static key to the peer's with the Noise one-way pattern K (`PeerSealSignal`), so the Controller can neither forge, alter nor redirect it, and a sequence that grows with the clock makes a replay fail.
_Avoid_: signature (it is authenticated encryption, which only the receiver checks), SDP offer

**ICE socket**:
The one UDP socket of a Node on which all of its ICE sessions run. It is the UDP socket of the Peer agent, which its binds and records go on too, so every ICE session runs in the **Peer mode** of libjuice. One NAT mapping then serves the Relay and every peer, and the address that the home relay saw (the answer of the bind) is the server reflexive candidate.
_Avoid_: ICE port (the port alone), relay socket

**Peer mode (of libjuice)**:
An agent of libjuice that has no socket of its own. It sends through the send procedure of the peer layer and takes the STUN messages that `PeerInput` hands it (`PeerIceInput`). The peer layer reads each STUN message once, whatever the number of ICE sessions (`juice_peer_read`), and hands it to the session that it names: a check by the ufrag of its receiver, an answer by its transaction (`juice_peer_take`). `src/Core/3rdparty/juice-peer.c` takes the place of `conn_thread.c` of libjuice. It is the one changed file of libjuice, and it keeps the licence of libjuice (MPL-2.0).

**ICE session**:
A Node's ICE agent with one peer, which checks candidate pairs in the background while the Path stays on the Relay. The Node's offer starts it controlling, and the peer's offer starts it controlled. It ends when the peer goes. A session of the Node's offer whose answer does not come in 40 s fails (`PEER_ICE_ANSWER_TIMEOUT`). A new offer replaces it after it failed, which the Node that offers the pair makes 20 s after the failure (a delay that doubles up to 30 min while the new ones fail), or while it still checks when the home gateway granted its public port since it started.
_Avoid_: ICE connection, P2P session

**Mapped candidate**:
The public port that a Node's home gateway granted to its ICE socket through PCP, NAT-PMP or UPnP (`PEER_CANDIDATE_MAPPED`). A Node asks for one only when its **PortMapping** setting is 1. It goes first in the Node's Signals.
_Avoid_: port forward, UPnP candidate

**PortMapping (a setting of a Node)**:
`PortMapping` in the Configuration store (`NODE_SETTING_PORT_MAPPING`). With 1 the Peer agent asks the home gateway for a public port of the ICE socket with PCP, NAT-PMP or UPnP (libplum). Without it, or with 0, libplum never starts and no request of it leaves the Node. It is off by default, because a port that a gateway opens is attack surface.

**Upgrade** and **Fallback**:
A Path moving from the Relay to the direct path once an ICE session validates a pair (Upgrade), and back when consent freshness fails it (Fallback). Both are counted per Node in `PEER_STATS`, and reported in its Telemetry as the **Path counters** (`Telemetry.paths`). After a Fallback ICE runs again for the pair, so it moves back once a direct path validates again.
_Avoid_: switchover, failover

**Path counters**:
`Telemetry.paths`, the message `PathCounters`: the Upgrades and the Fallbacks of a Node since it started. The Node reports them on its control stream after each Hello, whenever they change (at most once a second) and again every 15 s while they stay the same, because the Controller drops a counter that its node did not report for 5 minutes. The Controller exports them as `ranz_path_upgrades_total` and `ranz_path_fallbacks_total`, and in the JSON of its telemetry API. `ranz node state` shows them too.

**Punch**:
A Node's attempt at a direct path to a symmetric-NAT peer that ICE leaves on the Relay: it predicts the peer's next mapping port and sends authenticated probes to it on the peer layer's own socket (`PeerPunch.c`, `PEER_MSG_PUNCH`). The Controller triggers it with the Signal exchange, and on a meeting the Path moves off the Relay.
_Avoid_: ICE restart, STUN check

**Predicted candidate**:
The public port that a Node's own NAT will give its next mapping, learned from two reflexive observations and offered in the Node's Signals (`PEER_CANDIDATE_PREDICTED`), so a symmetric-NAT peer knows where to aim its probes.
_Avoid_: next port, guessed candidate

**Licence key**:
The vendor-signed key of one installation that names its Tier, its node cap, its expiry and the version of its Perpetual fallback licence (ADR-0036). Only the Controller checks it (`internal/licence`), and it caps the Nodes in name order: a Node above the cap gets no desired state and its control stream is refused. Without a key the Personal Tier of 10 Nodes is in force.
_Avoid_: licence file, serial, activation code

**Tier**:
What a Licence key sells: Personal (free, non-commercial, all core features, a small node cap), Business (per Node per year) or Enterprise (adds EVPN and BGP, controller high availability and priority support).
_Avoid_: plan, edition, SKU (a Windows SKU is a Capability)

**Perpetual fallback licence**:
What a subscription leaves after 12 paid months: once it expires, the version its Licence key names (major.minor, with its bugfix releases and every older version) stays licensed with the Tier and node cap of the subscription. A subscription that expires without one for the running version leaves the Personal Tier.
_Avoid_: lifetime licence, grace period

**Watermark**:
The per-customer mark embedded in a Licence key, so a leaked key names the customer it was issued to.

**Revocation list**:
The vendor-signed list of revoked Licence ids that the Controller reads from the update channel and refuses keys against. The Activation service distributes it.

**Activation token**:
A vendor-signed, node-locked, time-limited grant of a Tier and its features for one installation, issued by the Activation service. It is distinct from the Licence key, which the Controller checks offline.

**Machine fingerprint**:
The per-install identity that an Activation token is locked to. It derives from the Machine identity (the MachineGuid, FIX-5).

**Activation service**:
The vendor server (the Hanzcodes licensing server) that issues Activation tokens, holds the Enterprise feature key and distributes the Revocation list.

**Heartbeat**:
The periodic re-validation that renews an Activation token.

**Enterprise feature key**:
The in-memory key that the Activation service releases only against an Enterprise token, and that unlocks the Enterprise feature blob.

**Software KSP**:
The in-memory `crypto.Signer` that stands in for the HSM or the CNG KSP in CI.

**Audit log**:
The Controller's record of who did what, kept in the store, sent to the Audit targets and trimmed by the Audit retention. `ranz get audit` and the API list it. It is not the Events (conditions reported to operators) and not the slim fork's security log.

**Audit record**:
One entry of the Audit log: kind (`login`, `logout`, `auth-failed`, `enrolment`, `intent-change`, `operation`), actor, source, outcome, time, and for an intent change its revision.

**Audit target**:
Where the Audit log is sent: a webhook or a syslog receiver, managed under `/api/v1/audit/targets`.

**Audit retention**:
The policy (days and maximum number of records) that removes old Audit records.

**Origin**:
The actor and the source address of an API call. The Guard of the API carries it in the context of the call, so that the records the call makes name them.

**Live operation**:
What an operator asks of the Controller at the moment they ask it: a session list, a disconnect, a ban, a read or a clear of a table. The Intent never holds one.

**Operation**:
The frame of the control protocol by which the Controller asks a Node to read or clear a table (`Operation`); the Node answers with an `OperationResult`. A Node that answers them reports the Capability `operations`.

**Ban**:
A User that an operator cut off. It is kept in the store, not in the Intent. While it holds, the Nodes of that user are left out of the desired state of every other Node.

**Key life**:
The span in which the Controller admits the static key of a Node. It is kept in the store (table `node_keys`) by key, begins when the Node is admitted or its User authenticates again, and ends at the end of the **Key lifetime**, so a revision, a rollback or an import does not give an expired key another life.

**Key lifetime**:
`Network.keyLifetimeDays`, 90 days when left out. A Node takes the shortest one of the Networks of its VRFs.

**Non-expiring Node**:
A Node marked `nonExpiring` in the Intent. Its key has no end. Only a Node that has no owner can be marked: the key of a device of a User lives by the login of its User, so the Intent refuses the mark on a Node that has an `owner`.

**Refresh (of a key)**:
The new period that a key gets when its User logs in again with the device (`EnrolDevice`), or when an operator refreshes the key of a Node that has no owner (`ranz node-key refresh`). A User that is banned or no longer valid cannot refresh.

**Approval mode**:
`Network.approval`, `auto` (the default) or `manual`. In `manual` a new Node waits until an operator gives it its **Approval** (`ranz node-key approve`). Turning approval on cuts off no Node that was admitted.

**Held back (Node)**:
A Node whose key ended or that waits for approval. Like the Nodes of a Ban, it is left out of the desired state of every other Node, and its control stream is refused with `REFUSE_REASON_UNKNOWN_NODE` and a message that says why.

**Key announcement**:
One of the Events of the life of a key: `node-key-expiring`, `node-key-ended` and `node-waiting`. The Controller raises each once for each key and state. What was announced is noted in the row of the key in `node_keys` (column `announced`), in the same transaction as the Event, so a restart and the next leader of a cluster raise none twice and lose none. Each Event is also an `operation` record of the audit log under the actor `system`.

**Key warning**:
The Event `node-key-expiring`, raised when the key of a Node enters the span of 14 days before its end and again when 3 days are left. A key with no end raises none.

**Diagnostics bundle**:
One ZIP archive with the logs, the configuration and the status of a Controller or of a host, a manifest, and no secret. The term always carries "diagnostics": `ranz.exe` is not called a bundle.

**Redaction**:
The replacement of secrets with `[redacted]` (`Redact`, `RedactJSON`), found by the name written before them and by their form, before a part enters a Diagnostics bundle.

**Log limits**:
The two limits, age and disk, that the log of a Controller, of a Node and of the BGP sidecar keep within: the flags `-log-days` and `-log-mb`, and the Node settings `LogDays` and `LogMB`.

**Source (of a bundle)**:
What gives the parts of a Diagnostics bundle. A **Part** is one file of the archive.

**Throughput test**:
`ranz test throughput`: a test server on one Node (`-listen ADDRESS`, port 9821 unless the address names one) and a client on another that open TCP connections (32 by default) which carry data for a span (15 s by default), in one direction or both. The rate of each direction is what its receivers counted from the first data to the last, in Ethernet frames unless `-raw`. It runs on the TCP/IP stack of the hosts, so over the overlay it measures the path that a Node's traffic takes. It succeeds the traffic test of vpncmd (`TrafficServer`, `TrafficClient`, the `Tt*` functions).
_Avoid_: speed test, iperf, traffic test (the vpncmd one)

**System check**:
`ranz doctor`: the six checks of the vpncmd Check command (Kernel System, Memory Operation System, ANSI / Unicode string processing system, File system, Thread processing system, Network system), run on the host of `ranz`. It exits with 0 when all pass.
_Avoid_: health check, Check (the vpncmd command), Diagnostics bundle (another thing)

**Key link**:
The property of a certificate in the My store that names its private key (the provider, the key name and the key set, `CERT_KEY_PROV_INFO`), by which Schannel and `CryptoCertFindByThumbprint` find the key. `ranz cert -ksp NAME` creates the key in the Microsoft Software Key Storage Provider and the certificate with this link, in the store of the user, or with `-machine` in LocalMachine\My and the machine key set.
_Avoid_: key association, key binding

**Ingress queue**:
The queue of a session's data records in front of the stream of a transport over TCP (TLS-443), which CoDel runs, so that an inner TCP flow backs off at the first drop instead of filling a buffer behind a stalled outer TCP (`TRANSPORT.Queue`, `TransportQueue.c`).

**Peer session**:
The Noise_IK session between two Nodes over UDP that carries every data datagram of the peer layer (`PeerSession.c`), whatever the Path. It belongs to the pair, not to a path, and moves between the relay path and a direct path with its keys (ADR-0015 item 7).

**Peer agent**:
The part of the overlay of a Node that runs the peer layer of the new core, on a UDP socket of its own, once a desired state names a Relay. It binds to the home relay and to the Relay that a Signal of a peer names, renews the Bindings, and offers and answers the Signals (`NodeAgent.c`).

**Datagram path**:
How a pair of Nodes that cannot dial each other (neither has an endpoint), or whose dial failed, exchanges the records of the overlay: as datagrams in the Peer session of the pair, through a Relay (the relay path), or on a direct path once ICE or a punch finds one.

**Stream session**:
The Noise session of a Tunnel over a stream transport (QUIC, TLS or mimic) that a pair keeps when one Node has an endpoint that the other dials. A Node holds Stream sessions and the Datagram path at the same time, for different peers.

**Bind challenge**:
A Relay's answer to a bind from an address it has no cookie for: a cookie for that address, sealed to the Node (`PEER_MSG_CHALLENGE`, `PeerChallenge.c`).

**Connection exporter**:
The TLS exporter of RFC 8446 section 7.5 and RFC 9001 that msquic gives for one QUIC connection. It is the channel binding of the streams of that connection.

**Fallback after a handshake**:
A transport of a fallback list whose stream connected but whose Noise handshake then failed stays out of the races of that list for `TRANSPORT_FALLBACK_HOLD`, so the next dial goes to the next transport of the list.

**Transport log**:
The log of the transport module (`TransportLog`), which a Node puts into its node log.

**Outbound path**:
How the connection of a client transport reaches its server: direct, or through an outbound proxy (the system's, an HTTP CONNECT proxy or a SOCKS5 proxy), from its Underlay binding (`TRANSPORT_PATH`).

**Underlay binding**:
The interface (by alias or index) and the local address that the connections of a client to its server or to its proxy leave from.

**Handshake pool**:
The threads that run the Noise handshakes of the streams that the overlay of a Node accepted, with a cap on the handshakes in flight (`NodeHandshake.c`).

**Waiting**:
The control streams of a Controller that wait for a Hello, with a cap in all and one for each Source (`control.Waiting`).

**Source (of a limit)**:
An IPv4 address, or the /64 that an IPv6 address is in; an IPv4-mapped IPv6 address is its IPv4 address. The Limits for a source count by it, and so does `control.Waiting`.

**Pending connection**:
A connection that a listener took and whose handshake is not finished: the front door's until its owner has it, QUIC's until `CONNECTED`, the TLS port's until its TLS handshake is done.

**Limits for a source**:
The caps on the Pending connections in all and for one Source, and the rates of the new connections and of the handshake attempts of a Source (`SOURCE_LIMIT_CONFIG`, `port.Limits`).

**Retry limit**:
The memory of the handshakes above which msquic answers a new connection with a retry (`TRANSPORT_QUIC_RETRY_DEFAULT`).

**Login throttle**:
The per-user and per-source count of the failed Logins of a Node in a window. Above its limit the Node refuses further Logins without a check.

**Front door owner**:
The process, or the part of the Node, that takes the connections of one entry of the owner table of the front door on TCP 443.

**Owner table**:
The ordered entries (TLS by server name and ALPN, or first bytes) that tell the front door which Front door owner gets a connection.

**Handoff pipe**:
The named pipe of an owner process through which the front door hands it a socket (`WSAPROTOCOL_INFOW` in a handoff message, one byte of answer).

**Handoff**:
The moment the owner took the socket. After it the front door holds no handle of the connection.

**Mimic transport**:
The transport named `mimic`, made of the data pipes of the Mimicry sidecar (`NodeMimicTransport.c`).

**Mimicry sidecar**:
`ranz mimic`, the process that carries the mimicry transport between two Nodes (`controller/internal/mimic`). A Node starts one for each role that has a `MimicServer` or `MimicClient` setting (`NodeMimic.c`).

**Control pipe**:
The pipe between a Node and its Mimicry sidecar that carries JSON lines (start, ready, accepted, probe, stats, error). The **Data pipe** carries one pipe connection for each inner stream, with the channel binding as its first line.

**Decoy**:
The site that a connection which is no Ranz client is spliced to. A server with the Trojan posture reverse-proxies a peer to a website on its loopback interface when the first handshake message of that peer does not authenticate (`TRANSPORT_TLS_CONFIG.Decoy`, `TransportDecoy.c`). In the mimic transport the own decoy is a landing page with a certificate from an ACME service, and the borrow decoy is a big site whose real certificate the prober sees and whose key the sidecar never holds.

**ClientHello split**:
The client option that sends the ClientHello as two TCP segments, cut in the middle of the server name (`SplitClientHello`).

**Short id**:
Up to 8 bytes that a client puts into its Proof so that the server can tell its clients apart. The REALITY server keeps a list of them, and a ClientHello that names none of them goes to the Decoy.

**Parrot**:
The ClientHello of a browser version that uTLS reproduces (Edge sends the parrot of Chrome).

**Padding profile**:
`off`, `size` or `shape`: what a Mimicry sidecar does to the sizes and the timing of the frames it sends.

**Probe**:
A connection to the REALITY listener that is no Ranz client. It is spliced to the Decoy, counted and never logged one by one.

**Mimic link**:
One server in the `MimicClient` setting: its address, the public key of the REALITY server and the Short id.

**Proof**:
The session id of the ClientHello of a Mimic link, which seals the version and the Short id under the auth key.

**Temporary certificate**:
The certificate that a REALITY server presents to a client that proved the key. It is signed with the HMAC of its key under the auth key, and it is the pin check of the mimic path.

**PinsInterval**:
The least time between two changes of the keys of one Node that the Controller applies: 10 s (`controller/internal/controller/mimic.go`, AUD1-DT-20). The keys are the public key of the mimic server of the Node, which the Node reports in `Pins`. A change that is applied gives each client of that server a **Mimic link** with the new key, in one Generation. The limit is for each Node and is kept in memory.

**Held report**:
A `Pins` report that differs from the keys in force and comes within the **PinsInterval** of its Node. The Controller keeps the last one of them, drops it when the Node reports the keys in force again, and applies it at the first look at the keys after the interval ends.

**Switch**:
The forwarding plane of one L2 Network (`SWITCH`, the Switch module), in place of the forwarding of the Hub. It is not a name for the Hub, whose entry avoids "virtual switch".

**Port (of a Switch)**:
The attachment of one member (a user session, a cascade, a bridge, a loopback adapter): an access port, or a trunk port with a native VLAN, as decision 2 of ADR-0019 has them. **TPID** is the tag protocol id of the VLAN tags of a Network.

**Untagged VLAN (of a Network)**:
The VLAN of the untagged frames of a member without a VLAN of its own, which is the native VLAN of its trunk port. The Policy import gives a Network the lowest VLAN that no user or group of its hub has.

**Group subscription**:
The subscription of a port to a group address of a VLAN (the broadcast group, a multicast group, or every group). Broadcast and multicast frames go to the subscribers only.

**Policy engine**:
The stateful firewall of the Networks of a Node (`POLICY_ENGINE`, the Policy module of the new core). It is not `POLICY`, the per-Session policy of the slim fork, and not a Policy, one rule of the Intent.

**Member**:
A sender of frames in one Network of a Policy engine (a user session, a cascade, a bridge, a Node) with its identity and its guard.

**Guard (of a member)**:
The isolation set of a Member: client isolation, the MAC and IP checks, ARP and DHCP only, no DHCP server, the RA filter, the protocol filters. The Guard of the API, which sets the Origin, is another thing.

**Document (of rules)**:
The JSON rules, Networks and Address groups that the Policy engine puts in force at once, numbered from 1.

**Rule table**:
The rules of one Network in the order that the Policy engine evaluates them, each with its action and match, ending in the default action of the Network, as `PolicyTableText` writes them. A **golden rule table** is one kept under `tests/golden`.

**Inactive rule**:
A rule that the Configuration store keeps for the operator and leaves out of the Document of rules: an entry that was inactive in the fork or matched nothing there, or an allow entry with a match that the engine lacks.

**Widened entry**:
A deny entry of a fork access list that the Policy import carries without a match that the engine lacks, so that it denies more than the fork did, never less.

**Address group**:
A named list of IP prefixes that the ends of rules name.

**Conntrack table**:
The bounded table of the flows of a Network that the rules allowed. The frames of a **flow** take the fast path.

**Rule (of a Node)**:
A Policy as a Node enforces it, the `Rule` object of the control protocol: its VRF, priority, action, ends, protocol and ports.

**End (of a Policy)**:
`from`, the end that opens a flow, or `to`: tags and addresses; any without either. An **End outside a VRF** is the Member that the engine keeps in a VRF for a Peer that is no member of it, which has no tag.

**VRF policy**:
`Vrf.policy`: the conntrack quota and the timeouts of a VRF on a Node. A VRF that has it is under default deny.

**1:1 NAT rule**:
A rule of a VRF (the `NAT` resource, `NODE_NAT_RULE`) that one Node applies between its host and the overlay, from its **inside prefix** to its **outside prefix**, address for address. The inside prefix is the prefix as the host of the Node sees it, and the outside prefix as the VRF sees it. The 4via6 of a VRF is such a rule between the families.

**Peer route**:
A prefix of a shared VRF that leads to a Peer besides its addresses (`Peer.routes`, `CONTROL_ROUTE`). So far these are the outside prefixes of its 1:1 NAT rules.

**Route target**:
A tag of the BGP form `ASN:NUMBER` or `IPV4:NUMBER` that a VRF imports or exports (`importTargets`, `exportTargets`). The routes of a VRF leak into every other VRF that imports a Route target that it exports.

**Leak**:
A route of one VRF that a Route target puts into the forwarding table of another VRF (a leaked route). On the wire it is a `Peer.routes` entry with `peer_vrf_id`.

**Connect**:
The "connect VRF" shortcut: `ranz connect vrf A B`, `POST /api/v1/connect` and the UI action `connect`. It makes the two route-target edits of a two-way Leak in one revision.

**DHCP responder**:
The DHCP server that one Node runs for an L2 Network (`dhcp` of the Network), from the IPv4 pool of the Network, while no DHCP server of the bridged LAN answers.

**Lease**:
An address of the pool that a client of a DHCP responder holds until it expires, as the Node reports it to the Controller and IPAM lists it (`GET /api/v1/ipam/leases`).

**L2 adapter**:
The L2 port of a Node on a KM-TEST Loopback Adapter (`NODE_L2`, `NodeL2.c`): the adapter, the backend that carries its frames, and the capture and send rings between them and the owner.

**L2 backend**:
The driver behind an L2 adapter (`NODE_L2_BACKEND`: attach, inject, health, detach): XDP (`NodeL2Xdp.c`) or SeLow (`NodeL2SeLow.c`).

**Capture ring**:
The bounded ring from the drain thread of an L2 backend to the owner. A full ring drops the frame and counts it, and never pushes back into the driver.

**Receive-path probe**:
The Neighbor Solicitation that the health check of an L2 backend injects, which the host must learn within 2 s.

**Overlay suffix**:
The DNS suffix of the zone of a VRF (`dnsSuffix`, else `<vrf>.ranz.internal`). The NRPT sends the names under it, and only those, to the Stub resolver.

**DnsRecord**:
The Intent resource that adds a name to the zone of a VRF: the addresses of a Node of the VRF, or the addresses it lists.

**Stub resolver**:
The DNS responder of a Node on UDP 53 of its addresses in each VRF. It answers the zone of that VRF and nothing else.

**VRF adapter**:
The Wintun adapter of one VRF on a host (`NodeVrfAdapter.c`). Its requested GUID derives from the static key of the Node and the VRF id, so the interface of the VRF on that host is the same on every start.

**Forwarding setting**:
`"forwarding": true` in the Client setting makes the Node a gateway or an exit. Each of its VRF adapters then gets Forwarding, WeakHostSend and WeakHostReceive.

**Encapsulation (of a VTEP)**:
VXLAN or Geneve: the header in which the module sends to a VTEP and reads what it receives from it. It belongs to the VTEP, not to the VNI.

**Critical option**:
A Geneve option whose type has its high bit set. A tunnel endpoint that does not know it drops the datagram.

**Link kind**:
`noise`, `vxlan` or `geneve` (`VRF.link`, `LinkKind`): the kind of the links between the Nodes of a VRF. A **Plain link** is a link of kind `vxlan` or `geneve`, which carries the packets of a VRF without encryption on a network that the operator trusts. The Capability `plainLinks` says that a Node runs them.

**Tunnel endpoint of a Node**:
`Node.vtep`, `Vtep`: the address and ports of the Node for Plain links. It is a VTEP in the sense of this glossary.

**Client setting**:
The `Client` setting of the Configuration store: one JSON object that names the Wintun adapter, the DNS servers and suffix, the pipe of the logged-in user and each server (node name, certificate thumbprint, fallback list). Without it the client role holds nothing.

**Dialler**:
The data transport of the overlay of a client Node. It dials a server by its node name through the race of the fallback list of that server, and listens nowhere.

**Pipe of the logged-in user**:
`\\.\pipe\ranz-node-client` (or the pipe of the Client setting), through which an interactive user reads the status of the client role and takes it down and up. Besides `status`, `up` and `down` it takes `exit` (the choice of an **Exit node**: `exit NAME [VRF]`, or `exit none`), `key` (the public half of the static key of the Node) and `enrol` (the Controller settings that a sign-in brought, taken only while the Node has none).

**Tray**:
`ranz tray` (`controller/cmd/ranz/tray*.go`, SDN-55): the notification icon of a laptop. It is a face of the Node service on the **Pipe of the logged-in user** (status, sign-in, on and off, exit node), one for each user and session. It is a subcommand of `ranz.exe`, not an executable of its own.

**Exit node**:
A peer of the desired state of a client Node whose Peer object holds the default route of a VRF (`0.0.0.0/0`, `::/0` or both), such as the **Exit (of a VRF)** that the Controller names. The logged-in user chooses one on the Pipe of the logged-in user, and the adapter of its VRF then holds both default routes. A client takes the default route of a peer through its chosen Exit node only.

**Bypass route**:
The host route that the client role puts on a server address, and on the address of its Controller, through the interface of the default route of the host. It is there while the default routes of an **Exit node** are on the adapter, so that the streams of the role do not enter the adapter that they carry.

**Controller settings**:
The address, static key and TLS fingerprint of the Controller in the Configuration store of a Node, which `ranz node controller` sets, shows and clears.

**Admin pipe**:
The named pipe `\\.\pipe\ranz-node-admin` of the Node service (`NODE_ADMIN_PIPE`), for the verbs of `ranz node` (`key`, `controller`, `state`). Only SYSTEM, the Administrators and the service account open it.

**State of a Node**:
What the Node service does now, as `ranz node state` shows it. It is not the desired state that the Controller compiles for the Node, and the Generation is one field of it.

**Redial delay**:
The delay before a Node opens its control stream again: 1 s after a stream that was open, doubled by each attempt that fails, at most 60 s.

**Ranz folder**:
The fixed folder under Program Files (`C:\Program Files\Ranz VPN`) that `ranz install` makes, with an access list for SYSTEM, the Administrators and the two service accounts. It holds `ranz-node.exe` and the `ranz.exe` that the services run. `ranz uninstall` removes it and keeps the data directories.

**Unsigned Payload**:
A Payload that cannot carry an Authenticode signature (the INF and the counter manifest of a driver package, the NOTICE). `ranz install` checks its hash only. Windows checks the INF against the signed catalog of its package when it publishes the package.

**Install record**:
The registry key `HKLM\SOFTWARE\Hanzcodes\Ranz VPN\Drivers`, one value for each driver that `ranz install` put on the machine. `ranz uninstall` reads it to remove those drivers and no other.

**Firewall group**:
The Windows Firewall group `Ranz VPN` (`FirewallGroup`) that holds every rule that `ranz install` makes, and the rule of `ranz test throughput -listen` while it serves. `ranz uninstall` removes the whole group.

**Stand-in Node**:
A Node that `vpntest firsttest` runs in place of the Node service, which cannot join a Controller yet. It opens the control stream of a Node resource of the Intent.

**First test**:
The test of the product on two PCs that `docs/first-test.md` describes.

**Gap (of the runbook)**:
Something that the runbook needs and the code does not have, listed with its ticket or the words "no ticket".

**Credential of the store**:
The user `controller` and its random password in `rqlite-auth.json`, which rqlited reads with `-auth` and the store client sends.

**Cluster CA**:
The CA that signs the certificates of the members of the store for the mutual TLS between them. It is not the TLS certificate of the Controller.

**Key check**:
The comparison of the static key of a session with the key pinned to the user, after Sam accepted the Login (`NodeLoginPinned`); `kp_on` and `kp_none` in the models.

**Overlay session**:
A Noise session between two Nodes of the overlay, with no Login. The static key is the Peer.

**Production path**:
Code that a Node service or the Controller runs outside the tests. The page of a model says which models stand for it.

**Identity kind**:
Which key protects the identity of a Node: `software` (the Noise static key alone, the default) or `tpm` (the Noise static key and a TPM-held key, pinned together). The Node resource holds it.

**TPM pin**:
The SHA-256 of the SubjectPublicKeyInfo of the TPM-held key of a Node, kept in its Node resource.

**TPM proof**:
The signature of the TPM-held key over a label, the handshake hash of a Noise session and its public key. A Node of the `tpm` kind sends it in the first control record of a Tunnel.

**Certificate setting**:
The setting that names where the certificate of the TLS port of the Controller comes from (a file with its key, a thumbprint of Windows key storage, or ACME) and the hosts it must name. One row of the store, outside the Intent.

**TLS pin set**:
The TLS fingerprints that a Node accepts for the certificate of its Controller (`NodeConfig.controller_tls`, `CONTROL_STATE.TlsPins`, `tlsFingerprints` of the Controller settings), the certificate in use first. It has two members while the certificate changes and one otherwise.

**`endpoints` of a Node**:
The list of a transport and an address under which the other Nodes reach the Node (Node resource, `NodeConfig`, `Peer`; the Go type `intent.Endpoint`, the message `Endpoint` of `control.proto`). It follows the words of SDN-93. **Dialable** (`NODE_OVERLAY_CONFIG.Dialable`) says whether a data transport can dial a Peer that has the endpoints it has.

**Listener resource**:
The resource of the Intent that says where a Node listens: the ports and the certificate source, with a fixed TLS policy for each surface. It is not the Listener module of Cedar, which holds the TCP listeners of the slim fork.

**ACME sidecar**:
`ranz acme`, the subcommand that a Node runs to get and renew the certificate of a Listener resource that has an ACME source.

**User**:
The Intent resource of a local account: a display name, groups, an expiry, may-change-password, a maximum number of devices and no-saved-password. It holds no API role. Its password is the **User password**: a PBKDF2 hash kept in the store, outside the Intent. A **Saved password** is a password that a client took from its own storage, not from a person, and a User with no-saved-password is refused it.

**Group**:
The Intent resource that names a set of Users. Its name is a tag of policy. The **Group tag** is that name, which the devices of its members carry (`intent.NodeTags`), so a Policy written for the Group applies to them.

**Owner (of a Node)**:
The User that a Node or a WireGuard Device is a device of (`Node.owner`, `Device.owner`). A Device with an owner carries the Group tags of the owner (`intent.DeviceTags`). Not a Front door owner.

**Maximum devices**:
`maxDevices` of a User. An Intent that holds more devices of the User is refused. The Nodes and the Devices of a User count against it.

**SessionProfile**:
The Intent resource of the limits of the sessions of people: upload and download limits, maximum sessions, MAC, IPv4 and IPv6 counts, idle timeout, automatic disconnect, no-bridge, no-routing, no-server and privacy filter. A User or a Group names one in `sessionProfile`.

**Effective profile**:
The SessionProfile that the devices of a User run under: its own, else the one of its first Group in name order that names one (`EffectiveProfile`).

**Device**:
A phone, laptop or router that joins exactly one Network over standard WireGuard, without `ranz.exe`, through its gateway Node. It is not a Peer.

**Gateway (of a Device)**:
The Node that terminates the WireGuard of its Devices with WireGuardNT and reports the Capability `wireguard`.

**WireGuard end**:
The `wireguard` field of a gateway Node: the DNS name that its Devices reach it at, and its UDP port.

**Battery saver**:
The flag of a Device that turns the keepalive of its configuration off.

**PresharedKey (of a Device)**:
The 32-byte secret that a Device and its gateway both mix into the WireGuard handshake, the only protection of a recorded session against a future quantum computer. The Controller makes one for every Device unless `noPresharedKey`, keeps it as a **Sealed secret** in the table `device_keys` (never in the Intent), gives it in clear inside the control stream to the gateway alone, and shows it once (ADR-0026 amendment of 2026-10-29, SDN-82).

**Finished configuration (of a Device)**:
The `.conf` text that a stock client imports, with the `PrivateKey` and the `PresharedKey` in it, which only the answer to the making of a Device holds (`DeviceCreated.Config`). The configuration that `GET /api/v1/devices/NAME/config` renders later has a comment in place of each key.

**QR code (of a Device)**:
The QR code of the finished configuration, carried as its modules (`DeviceCreated.QR`: a string of 1 and 0 for each row, without the quiet zone), drawn by the web UI on a canvas, by `ranz device create -qr` on a terminal and by `-qr-file` into a PNG. Shown once.

**Standalone Device**:
A Device with no owner, a router for one. It takes the tags set on it and no others.

**Formal model**:
The ProVerif models in `tests/formal`, checked in CI against `expected.tsv`. A **Scenario (of a model)** is a set of compromises that a model gives the attacker (none, cert, cert-client, noise-client, both, fs). A **Negative control** is a model with a protection left out (the binding, the pin, the key comparison of a join) that must show its attack. The **Table from the model to the code** is `tests/formal/model-to-code.tsv`.

**Plane (of the threat model)**:
One of the parts of the system that the threat model treats on its own: the Noise session, the transports, the front door, the control stream, the API with the web UI and the tokens, the store and the licence, and the data plane. It is not the control plane or the data plane that name a split of the traffic.

**Trust boundary**:
A line that data crosses between parties that are trusted differently, numbered B1 to B12 on the diagram of the threat model.

**Attacker class**:
One of the six who attack in the threat model: an attacker on the path, a malicious peer, a malicious tenant, a thief of a node key, a token holder and a local user. The page uses "tenant" only for a party that controls Nodes or Devices in another VRF, because a VRF is not called a tenant here.

**Gap (of the threat model)**:
A threat that no control answers, numbered G-n, answered by an open ticket, a **Draft ticket** (DT-n, the text of a ticket that the page proposes for the integrator to file) or an amendment of an open ticket.

**Scenario (of explain)**:
A topology, an Intent and test packets with their verdicts, in `tests/explain`. The **Plan** is what `ranz-explainplan` writes of a Scenario for `vpntest explain`: the states of its Nodes as control frames and its packets with the verdicts of explain. A **Fault** is the rule that the Plan leaves out of the state of one Node in a broken Scenario, and the packets whose verdict that must break.

**Lane**:
One agent that builds one ticket, or continues one pull request, in its own worktree (docs/agents/integrator.md).

**Integrator**:
The session that launches Lanes, merges green pull requests and closes tickets. A **Tick** is one round of its job, from the heartbeat to the report.

**Integrator heartbeat**:
The comments on the issue `Integrator heartbeat`, by which an Integrator shows that it is alive. It is not the licence Heartbeat. The pages always say "integrator heartbeat" or "the heartbeat issue".

**Fast set, full set**:
The two sets of CI jobs of a pull request (see `.github/scripts/ci-plan.py`).

**Fuzz campaign**:
The run of every fuzz target of the registry (`.github/quality/fuzz-targets.txt`) for a long time against a **Stored corpus** (`.github/workflows/fuzz.yml`, AUD-3). It has three kinds: the **nightly run** (15 minutes for each target), the **campaign** by hand (an hour by default) and the **smoke run** of a pull request (20 seconds). The full set of `windows.yml` and `ranz.yml` keeps its own runs of 60 and 20 seconds for each target.

**Stored corpus**:
The artifact `fuzz-corpus-<target>` of the newest run on the default branch: the inputs that reach coverage that the seeds of `src/fuzz/corpus` do not (for a Go test, the fuzz cache of its engine), and `manifest.json` with the runs, the seconds of fuzzing in all of them and the report of the last one.

**Planted fault (of the fuzz campaign)**:
A target with a known fault (`.github/scripts/fuzz-fault.c` and `fuzz-fault_test.go`) whose leg must end in a finding. So a campaign that reports nothing cannot pass for one that found nothing.

**Security (of an L2 Network)**:
The protections of the fork that the switch of an L2 Network applies to the frames of its clients: the MAC and IP checks with their limits, ARP and DHCP only, the DHCP guard and the RA guard (`Network.security`, `SWITCH_SECURITY`, SDN-41). The Policy engine enforces them as the guard of the switch.

**Gateway (of an L2 Network)**:
A Node behind which the real gateway of an L2 Network is (its router and the DHCP server of its LAN), or the Node that answers DHCP for it. No protection holds for its ports, and the addresses that it sends from are its own before a client's. **Client (of an L2 Network)** is any member that is not a gateway; the protections of the Network hold for it.

**User login**:
A User proves its password at the Controller (`internal/login`), and the login gives a user token or enrols a device (SDN-32), or gives a token of the **Self scope** (SDN-58). It is not the Login of a Noise session (`NOISE_LOGIN`), nor the SE-VPN login.
_Avoid_: session (the slim fork's `SESSION` and the Controller's session of SDN-50 are other things)

**Password login**, **Browser login**, **Device code login**:
The three ways in of a User login. The browser login is the authorization code grant with PKCE, the S256 method only, for the public client `ranz`; the device code login is RFC 8628. The **Authorization page** is the page of the Controller where the user signs in for a browser login (`GET /api/v1/login/authorize`), and its **Loopback redirect** is `http://127.0.0.1:PORT/PATH`, where `ranz` listens for the code (RFC 8252). The **Device page** is where the user types the **User code** that a device shows (`XXXX-XXXX` of 8 consonants).

**User token**:
The bearer secret (`ranz_u_` and 128 random bits) that a login gives a User that holds an API role: 12 hours at most and never past the expiry of the User. The store keeps its SHA-256 (table `user_tokens`), and its name in the API and the actor of its audit records is `user:NAME`. It carries the role of the User for the whole API or for one Network (a **Scoped role**). It is not an API token, and not a token of the **Self scope**.

**API role of a User**:
The role (viewer, operator or admin) that an admin gives a User (table `user_roles`, outside the Intent): with `ranz user role set` for the whole API, or with the call `PUT /api/v1/tokens/users/NAME` and its `network` for one Network, as a **Scoped role**. A User with none logs in to enrol a device but gets no user token. Say API role of a User, not "user role".

**Scoped role**:
An API role that is held for one Network and not for the whole API (`rbac.Grant`, stored as `role@network`, for example `operator@branch-a`). An API token, a User (its **API role of a User**) or a login through a **Provider group** holds one. The Guard lets it call `whoami` and the calls under `/api/v1/networks/{network}` of its own Network, and nothing else (403), so a scope only narrows a role. What it may change in its Network is bound by the **Delegation** of the Network (ADR-0031 amendment of 2026-10-29, SDN-38).

**Delegation**:
What an admin of the whole API sets for a Network to bound its **Scoped roles** (`scope.Delegation`, `PUT /api/v1/tokens/delegations/NETWORK`). Its quotas are the most Users, Groups, Nodes and Policies in the scope of the Network, the most control streams that its Nodes have open at once, and the greatest rate limit in bit/s that a scoped role gives a Node. Its permissions are the kinds of resource that its scoped roles may change: `network`, `nodes`, `users`, `groups`, `rules` and `sessions`. A quota that is left out, or 0, is no limit. A Network with no Delegation permits its scoped roles nothing, so they only read. It is kept in the store (table `scope_delegations`), not in the Intent, so that a role cannot change its own limits. It is the successor of the admin options of a Hub of the slim fork.

**Scope of a resource**:
The Network whose **Scoped roles** administer a resource: the `scope` of a User, a Group, a Node and a Policy, which must name a Network (`intent.ScopeOf`). A Network is in its own scope. A Node that names none is in the scope of its owner, so the device that a User of a Network enrols is in that Network. A resource with none, and every resource of another kind (a VRF, a Controller and the rest), is changed by the roles of the whole API alone. The scope is in the Intent, so a revision, a rollback and an export carry it. A Network that is the scope of a resource cannot be deleted.

**Provider group**:
A group of an identity provider, as the provider names it, that an admin maps to an API role held for the whole API or for one Network (`rbac.GroupMapping`, `PUT /api/v1/tokens/provider-groups/PROVIDER`, table `provider_groups`, outside the Intent). A login through the provider gives its User a user token with the role that the groups of the person give, for the scope of their mapping, and nothing more. The role is fixed when the token is made, so a person that changes team gets the new role at the next login. The identity providers (SDN-34 to SDN-36) are not built yet, so no login uses the mappings.
_Avoid_: Group (the Intent resource that names Users)

**Enrolment (of a device)**:
The Node resource that a login of its User makes (`Controller.EnrolDevice`): owned by the User, one revision, under the actor `user:NAME`. The User also makes one from the **Portal** (a **Self call**), and a device makes one with a **Join token**. It is not **Enrolment sources**.

**User login throttle**:
Five failed user logins in a row for one name or from one source (an IPv4 address or an IPv6 /64): the next is refused with 429 without a check of the password, and one try comes back each minute. It is not the **Login throttle** of a Node.

**Portal**:
The pages of the web UI for a User: `/portal-sign-in`, `/portal` (My devices) and `/portal-join` (Join tokens), each its own module. A client of the **Self calls** with the token of the **Self scope**, which the tab keeps under its own key (`ranz.selfToken`), apart from the API token of the administrator's pages (`ranz.apiToken`). Every control of it is a **UI action** with the role `self`, or `public` for the sign-in.

**Self scope**:
What a password login that asks for `"scope": "self"` gives the User (`POST /api/v1/login`): a token `ranz_s_` and 128 random bits that holds no API role and reaches the **Self calls** and no other call (403, `whoami` included). It needs no API role of the User, so a User that holds only a **Scoped role** signs in to the **Portal** with it. The store keeps its SHA-256 (table `self_tokens`). It ends 12 hours after the login, or at the expiry of the User when that comes first, and at once at a ban, when a change of the Intent removes the User and at a logout. `rbac.Self` is no fourth API role: an admin cannot give it. It is not a **User token**, and not the **Scope of a resource**.

**Self call**:
A call under `/api/v1/self`, which `api.Needs` gives the role `self`. It is about the User that holds the token and about nothing else: its devices (the Nodes and the Devices that name it as owner) and its **Join tokens**. A device of another User is not found (404). An API token names no User and is refused (403). The user token of a role of the whole API makes the calls, and the user token of a **Scoped role** does not (403).

**Join token**:
The secret `ranz_j_` and 128 random bits that a User makes in the **Portal** for a device of its own that cannot sign in itself, such as a Node without a browser. The device presents it with its static key at `POST /api/v1/login/join`, which `ranz node join` does. The Controller then enrols it as a Node that the User owns, in VRF default, with the tags of the Groups of the User, and the token is spent. It works once and ends after a day, and a User has 16 that wait at most. The store keeps its SHA-256 (table `join_tokens`), outside the Intent.

**Sealing key**:
The Controller's own key for the secrets of its store: a persisted key of the Microsoft Software Key Storage Provider on Windows, a file `store.key` elsewhere. It sits beside the Noise static key and the TLS key. A member of a cluster seals no secret with it: it opens the member's **Copy** of the **Cluster key** with it.

**Sealed secret**:
The form in which the store keeps a secret that a reader of the store must not get: the secret of an export or audit target (`ranz-sealed:1:` and the base64 of a sealed box) and the PresharedKey of a Device (the base64 of the box, in the table `device_keys`). Only the **Sealing key** opens it, or in a cluster the **Cluster key**. The label of its row is part of what the box authenticates, so a Sealed secret copied into another row does not open. The label of the secret of a target also holds the SHA-256 of its URL, so a Sealed secret in a row whose URL was changed does not open either.

**Migrated secret**:
The secret of a target that an earlier release kept in clear and that `SealTargetSecrets` sealed by changing its row. It is sealed in the table and in every backup that the upgraded Controller makes. But its old text stays in the data of rqlite (its Raft log, its snapshots, the free space of its file) until that is truncated, replaced or vacuumed. So the operator puts the target again with a new secret, and changes it at the receiver (AUD1-DT-17).

**Cluster key**:
The key that seals the secrets of a Controller cluster in the place of the **Sealing key** of a host: the secrets of its export and audit targets and the PresharedKeys of its Devices. It is a random X25519 key that seals as a Sealing key does (`keys.Sealer`), so a **Sealed secret** of a cluster has the form of the one of a single Controller. A member holds it in memory only. The store holds its public half (table `cluster_key`) and a **Copy** for each member, and never a private key. A member that holds none keeps no secret: it refuses a target with a secret and a Device with a PresharedKey. A restore keeps the Cluster key of the store that it replaces (`controller/internal/clusterkey`, ADR-0026 amendment of 2026-10-29, AUD1-DT-16).

**Copy (of the Cluster key)**:
The Cluster key sealed to the public half of the Sealing key of one member, under the label of that member's row of the table `cluster_key_copies`. Only that member opens it, with its own Sealing key, inside its key storage provider. A member that holds the Cluster key gives a copy to every row that has none. A copy that does not open is removed and given again.

**Access record**:
An audit record of the kind `access`, made for a read of the API tokens, the API roles of users, the delegations, the provider groups, the audit log or the licence. Its actor is the caller (`token:NAME`, or `user:NAME` for a **User token**), and the Log keeps at most one for each actor and read in a minute.

**Token life**:
The expiry and the last use of an API token, kept in the table `api_token_life` (`ranz token create -expires`, `ranz tokens`). A **User token** has an end of its own and no token life.

**TLS fingerprint file**:
`tls.fingerprint` in the data directory of the Controller: the TLS fingerprint of the certificate that it serves, written at every start and at every change of the certificate. `ranz` on the same host trusts a loopback address only when its certificate has this fingerprint, or the one that `-tls-fingerprint` names. On Windows `ranz` trusts the file only when SYSTEM, the Administrators or the account of the Controller service (`NT SERVICE\ranz-controller`) own it and its folder, and no other account may write either (`controllercmd.ReadFingerprint`, ADR-0031 amendment of 2026-10-29, AUD1-DT-14). Otherwise it sends no token, connects to nothing and asks for `-tls-fingerprint`.

**Untrusted fingerprint file**:
A `tls.fingerprint` that `ranz` does not take (`controllercmd.UntrustedError`): another account owns the file or its folder or may write one of them (an access list that is missing lets every account write), one of them is a link, or the volume keeps no access lists. The refusal names the file or the folder and says why, in one line. A file that is not there, or that holds no fingerprint, is refused too, but it is no Untrusted fingerprint file.

**Hub node**:
In a VRF of topology hub-and-spoke, the Node that the other members reach each other through. Say Hub node, not plain "Hub", which is the slim fork's Virtual Hub.
_Avoid_: Hub (the slim fork's object)

**Spoke**:
A member of a hub-and-spoke VRF other than its **Hub node**. Two spokes are no peers in the VRF.

**Gateway group**:
The gateway Nodes that advertise one LAN subnet in one VRF. It has a next hop of its own in the forwarding tables, after those of the peers and of the leaked routes. It is not the **Gateway (of an L2 Network)**.

**Gateway probe**:
The control record that a Node sends each gateway of a **Gateway group** every 100 ms inside its Noise session, and its answer. A gateway whose answers stop for 500 ms, or whose session closes, is down, and it is up again after 3 answers in a row.


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
- "Session" is the slim fork's `SESSION`, one peer attached to a Hub. The new core's connection between two Nodes is the Noise session (`NOISE_SESSION`); say Noise session for it.
- "Login" is the Login of a Noise session (`NOISE_LOGIN`). The slim fork's login is the SE-VPN login (`ServerAccept`, `ClientUploadAuth`); both end in Sam. The User login of SDN-32 is a third thing: a User proves its password at the Controller.
- "Capability" is what a Node reports to the Controller. `CAPS` (`ServerCaps.c`) is the slim fork's list of server capabilities for admin clients.
- "Role" is what a Node does (`server`, `client`, `bridge`, `relay`). The `admin`, `operator` and `viewer` of the Controller's API are API roles, held by an API token; say API role for them.
- "controller" was a role of the node binary in ADR-0022. Since ADR-0026 the Controller is the separate `ranz-controller` service, and the node has no `controller` role.
- "Leader" is the member of a Controller cluster that holds the lease. The Raft leader of rqlite is a different thing: any member's rqlite may be it, and rqlite forwards writes to it by itself.
- "Generation" and "revision" are different versions: a revision is a version of the whole Intent (what `ranz rollback` returns to); a Generation is a version of one Node's desired state.
- "Licence" is the noun in prose and code (`licence`, `REFUSE_REASON_LICENCE`); "license" is the verb ("licensed") and the name of the `LICENSE` file at the repository root.
- "Configuration" is the Config file of the slim fork (`ranz_server.config`, Cfg) or the Configuration store of a Node (`ranz_node.db`, ConfigStore). Say which one.
- "Server" names the slim fork's `vpnserver` and its `SERVER` object, and the server Role of a Node. The service of the Node is `ranzvpnserver`; the one of `vpnserver` is still `sevpnserverdev`.
- "Peer" names the other end of a link, the Peer object of a node's desired state (another node that shares a VRF with it), and the Peer module of the new core (`src/Core/Peer*.c`), which keeps a node's peers.
- "Relay" names the relay Role, a Node that runs it, and the Relay object of the desired state, which tells a node about such a Node.
- "Policy" is the SDN resource kind, one rule of a VRF's policy. The slim fork's `POLICY` is the per-Session policy of a Hub user or group, a different thing.
- "Route" is a LAN subnet that a gateway Node advertises in a VRF (`intent.Route`). A route inside a Forwarding table, a route of the Windows routing table and the Path of a peer are different things.
- "Tunnel" is the Noise sessions of up to 16 connections between two Nodes (`NOISE_TUNNEL`), and the Cedar `TUNNEL` is the object around one, held by a Connection of type `CONNECTION_NOISE`. A Cascade is not a Tunnel.
- "Endpoint" is one service published into another VRF (SDN-24). The `endpoints` of a Node (SDN-93, the Go type `intent.Endpoint`, the message `Endpoint` of `control.proto`) are the transports and addresses under which other Nodes reach it. Whichever of the two merges second may need a new name for its type.
- "Listener" in the slim fork is the TCP listener of Cedar (the `Listener` module). The new core has the Listener resource of the Intent, which says where a Node listens.
- "Owner" is the User that a Node is a device of (`Node.owner`), and also the Front door owner, the process that takes the connections of one entry of the owner table. They are unrelated.
- "Guard" is the isolation set of a Member of the Policy engine, and also the Guard of the Controller's API, which sets the Origin of a call. They are unrelated.
- "Gap" is a gap of the first-test runbook, and also a gap of the threat model (G-n). "Scenario" is a compromise set of a formal model, and also a topology with verdicts of the explain conformance. "Source" is the address that the limits of a listener count by, and also what gives the parts of a Diagnostics bundle. Say which one.
- "Port" is the attachment of a member to a Switch, and also a TCP or UDP port. "Switch" is the new core's forwarding plane of an L2 Network, never a word for the Hub.
- "Plane" in the threat model is one of its parts of the system (the Noise session, the front door and so on). The control plane and the data plane name a split of the traffic.
- "Bundle" is a Diagnostics bundle, always with "diagnostics" before it. `ranz.exe` is not called a bundle.
- "Heartbeat" is the licence re-validation of an Activation token. The integrator heartbeat is the comments on the heartbeat issue, and has nothing to do with it.
- "Software KSP" is the in-memory signer of CI in this glossary. ADR-0022 uses "software KSP" for the Microsoft Software Key Storage Provider. Say which one.
- "Gateway" is the Node that terminates the WireGuard of Devices (Gateway of a Device), and also the Node behind which the real gateway of an L2 Network is (Gateway of an L2 Network, SDN-41), and a Node that advertises a LAN subnet in a VRF (a member of a Gateway group, SDN-19). Say which one.
- "Hub" in the SDN language is the slim fork's Virtual Hub, which the Network replaced. The Node of a hub-and-spoke VRF is the Hub node (SDN-19).
- "Device" is a stock WireGuard client or router behind a gateway Node (spec #374). A Node that a User owns also counts against the maximum devices of that User, but it is not a Device.
- "Scope" is the Network that a resource is in or that an API role is held for (the Scope of a resource and the Scoped role, SDN-38), and also the Self scope of a login (SDN-58), a token that holds no role. They share the word and nothing else.
- "Group" is the Intent resource that names Users, whose name is a tag of policy. A Provider group (SDN-38) is a group of an identity provider that an admin maps to an API role. Say Provider group for the second.