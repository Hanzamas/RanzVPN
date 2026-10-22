// sdntrace.c
// Named default VRF tracer of vpntest ("sdntrace" command, SDN-3 #179)
//
// Two real nodes of the new core join the VRF default that the first start of a ranz-controller created, and ping
// each other over the overlay. .github/scripts/sdn-tracer.ps1 runs the controller with its rqlited, applies the Node
// resources node-a and node-b with the static keys of this test (they name no VRF, so they join VRF default), and runs
// "vpntest sdntrace <address> <key> [<file>]": the address of the controller's TLS port, its static key in base64, and
// the file that the test creates once the echoes went both ways with the controller. Each node opens its control
// stream to the controller (Core/Control.h, through NodeOverlayStart): TLS 1.3 with the ALPN protocol of the control
// stream and its TLS exporter, which the TLS transport of this file gives on OpenSSL until the Schannel transport of
// CORE-S2-1 (#69) does, and the Noise_IK handshake bound to it. It applies the desired state, acknowledges its
// Generation and gets its address from the automatic pool of VRF default. The Noise sessions between the two nodes
// run over the in-process loopback transport, and a fake adapter stands in for the host of each node: an ICMP echo
// request from the address of one node reaches the host of the other, and the echo reply comes back.
// The test then prints "SDNTRACE PINGED" and creates the file; the script checks that the API shows the Generation
// each node acknowledged and stops the controller. Once both control streams are down, the echo goes both ways again:
// the nodes forward on the state they applied last. Print "SDNTRACE TEST OK" only when every check passes.

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>
#include <string.h>

// OpenSSL after the Windows headers: its headers undo the names that wincrypt.h defines
#include <openssl/err.h>
#include <openssl/ssl.h>

#define	SDNTRACE_BUDGET			300000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	SDNTRACE_JOIN			60000		// Both nodes applied their state, with an address, and their session is up within this time (ms)
#define	SDNTRACE_ARRIVE			10000		// A packet reaches the host of the other node within this time (ms)
#define	SDNTRACE_CONTROLLER		180000		// The script stops the controller within this time after SDNTRACE PINGED (ms)
#define	SDNTRACE_POLL			100			// Poll interval of the state of the nodes (ms)
#define	SDNTRACE_PAYLOAD		32			// The data of an ICMP echo
#define	SDNTRACE_NUM_NODES		2

// The two nodes: their names in the intent, and the X25519 public keys of their static scalars 1, 2, ... 32 and 33,
// 34, ... 64, which the controller conformance tests use as well (controller/internal/controller)
static char *sdntrace_names[SDNTRACE_NUM_NODES] = {"node-a", "node-b"};
static char *sdntrace_keys[SDNTRACE_NUM_NODES] = {"B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=", "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns="};

// The checks of the test
typedef struct SDNTRACE_CTX
{
	UINT NumChecks;
	UINT NumFailed;
} SDNTRACE_CTX;

// One node of the test and the fake adapter of its host
typedef struct SDNTRACE_NODE
{
	char *Name;
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's forwarding tables, online while it sends
	HANDLE Arrived;						// The adapter took a packet (auto-reset)
	SRWLOCK Lock;						// Packet and Size
	UCHAR Packet[2048];					// The packet that the adapter took last
	UINT Size;
} SDNTRACE_NODE;

// A stream of the TLS transport: a TLS 1.3 client on a TCP socket, and the exporter of its session
typedef struct SDNTRACE_TLS
{
	SOCKET Socket;
	SSL_CTX *Ctx;
	SSL *Ssl;
	UCHAR Exporter[CONTROL_EXPORTER_SIZE];
} SDNTRACE_TLS;

static bool SdnTraceCheck(SDNTRACE_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SdnTraceCheck(SDNTRACE_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// The watchdog: a native thread that ends a run that hangs, so that a lost packet is a failed test instead of a hung
// CI step
static DWORD WINAPI SdnTraceWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, SDNTRACE_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "SDNTRACE TEST FAILED (did not finish within %u ms)\n", SDNTRACE_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The TLS transport of the control stream: a TLS 1.3 client on OpenSSL that offers the ALPN protocol of the control
// stream and gives the TLS exporter of the control stream as the binding of its streams. The controller's certificate
// is not checked: the Noise handshake authenticates the controller by its static key, and the exporter binds that
// handshake to this TLS session (ADR-0023), as controller/internal/control dials. An address is host:port.
//
// One thread runs a stream at a time (the control client's), which an OpenSSL session needs.
//

static void SdnTraceTlsFree(SDNTRACE_TLS *t)
{
	if (t->Ssl != NULL)
	{
		SSL_shutdown(t->Ssl);
		SSL_free(t->Ssl);
	}
	if (t->Ctx != NULL)
	{
		SSL_CTX_free(t->Ctx);
	}
	if (t->Socket != INVALID_SOCKET)
	{
		closesocket(t->Socket);
	}

	Zero(t, sizeof(SDNTRACE_TLS));
	Free(t);
}

// A TCP connection to host:port
static SOCKET SdnTraceTcpConnect(const char *address)
{
	char host[MAX_SIZE];
	struct addrinfo hints, *res = NULL;
	SOCKET s = INVALID_SOCKET;

	StrCpy(host, sizeof(host), address);
	char *colon = strrchr(host, ':');
	if (colon == NULL)
	{
		return INVALID_SOCKET;
	}
	*colon = 0;

	Zero(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(host, colon + 1, &hints, &res) != 0)
	{
		return INVALID_SOCKET;
	}

	for (struct addrinfo *a = res;a != NULL && s == INVALID_SOCKET;a = a->ai_next)
	{
		s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
		if (s != INVALID_SOCKET && connect(s, a->ai_addr, (int)a->ai_addrlen) != 0)
		{
			closesocket(s);
			s = INVALID_SOCKET;
		}
	}
	freeaddrinfo(res);

	if (s != INVALID_SOCKET)
	{
		BOOL nodelay = TRUE;

		// One frame is one send: no wait for the acknowledgement of the one before
		setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(nodelay));
	}

	return s;
}

static bool SdnTraceTlsDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	static const unsigned char alpn[] = "\x0e" CONTROL_ALPN;
	const unsigned char *selected = NULL;
	unsigned int selected_size = 0;

	*stream = NULL;
	if (cancel != NULL && WaitForSingleObject(cancel, 0) != WAIT_TIMEOUT)
	{
		return false;
	}

	SDNTRACE_TLS *t = ZeroMalloc(sizeof(SDNTRACE_TLS));
	t->Socket = SdnTraceTcpConnect(address);
	if (t->Socket == INVALID_SOCKET)
	{
		SdnTraceTlsFree(t);
		return false;
	}

	t->Ctx = SSL_CTX_new(TLS_client_method());
	bool ok = (t->Ctx != NULL);
	if (ok)
	{
		// A read that took a record of no application data, such as the server's session tickets, returns: the
		// control client reads with a timeout
		SSL_CTX_clear_mode(t->Ctx, SSL_MODE_AUTO_RETRY);
		SSL_CTX_set_verify(t->Ctx, SSL_VERIFY_NONE, NULL);
		ok = SSL_CTX_set_min_proto_version(t->Ctx, TLS1_3_VERSION) == 1 && SSL_CTX_set_alpn_protos(t->Ctx, alpn, sizeof(alpn) - 1) == 0;
	}
	if (ok)
	{
		t->Ssl = SSL_new(t->Ctx);
		ok = (t->Ssl != NULL && SSL_set_fd(t->Ssl, (int)t->Socket) == 1 && SSL_connect(t->Ssl) == 1);
	}
	if (ok)
	{
		SSL_get0_alpn_selected(t->Ssl, &selected, &selected_size);
		ok = (selected_size == StrLen(CONTROL_ALPN) && Cmp(selected, CONTROL_ALPN, selected_size) == 0);
	}
	if (ok)
	{
		ok = SSL_export_keying_material(t->Ssl, t->Exporter, sizeof(t->Exporter), CONTROL_EXPORTER_LABEL, StrLen(CONTROL_EXPORTER_LABEL), NULL, 0, 0) == 1;
	}

	if (ok == false)
	{
		Print("  [INFO] TLS to %s: %s\n", address, ERR_error_string(ERR_get_error(), NULL));
		SdnTraceTlsFree(t);
		return false;
	}

	*stream = t;
	return true;
}

static bool SdnTraceTlsListen(void *param, const char *address, void **listener)
{
	// A client only
	*listener = NULL;
	return false;
}

static bool SdnTraceTlsAccept(void *listener, UINT timeout, void **stream)
{
	*stream = NULL;
	return false;
}

static void SdnTraceTlsCloseListener(void *listener)
{
	// No listener
	return;
}

static UINT SdnTraceTlsRead(void *stream, void *buf, UINT size, UINT timeout)
{
	SDNTRACE_TLS *t = (SDNTRACE_TLS *)stream;

	if (SSL_pending(t->Ssl) <= 0)
	{
		WSAPOLLFD p;

		Zero(&p, sizeof(p));
		p.fd = t->Socket;
		p.events = POLLRDNORM;

		int ready = WSAPoll(&p, 1, (timeout == INFINITE ? -1 : (INT)timeout));
		if (ready == 0)
		{
			return TRANSPORT_LATER;
		}
		if (ready < 0)
		{
			return 0;
		}
	}

	int n = SSL_read(t->Ssl, buf, (int)MIN(size, 65536));
	if (n > 0)
	{
		return (UINT)n;
	}

	return (SSL_get_error(t->Ssl, n) == SSL_ERROR_WANT_READ ? TRANSPORT_LATER : 0);
}

static bool SdnTraceTlsWrite(void *stream, const void *buf, UINT size)
{
	SDNTRACE_TLS *t = (SDNTRACE_TLS *)stream;
	const UCHAR *p = (const UCHAR *)buf;

	while (size != 0)
	{
		int n = SSL_write(t->Ssl, p, (int)MIN(size, 65536));
		if (n <= 0)
		{
			return false;
		}

		p += n;
		size -= (UINT)n;
	}

	return true;
}

static void SdnTraceTlsClose(void *stream)
{
	SdnTraceTlsFree((SDNTRACE_TLS *)stream);
}

static UINT SdnTraceTlsBinding(void *stream, UCHAR *binding, UINT max, UINT *size)
{
	SDNTRACE_TLS *t = (SDNTRACE_TLS *)stream;

	*size = 0;
	if (max < sizeof(t->Exporter))
	{
		return NOISE_BINDING_NONE;
	}

	Copy(binding, t->Exporter, sizeof(t->Exporter));
	*size = sizeof(t->Exporter);

	return NOISE_BINDING_EXPORTER;
}

static void SdnTraceTlsInit(TRANSPORT *t)
{
	Zero(t, sizeof(TRANSPORT));
	StrCpy(t->Name, sizeof(t->Name), "tls");
	t->Dial = SdnTraceTlsDial;
	t->Listen = SdnTraceTlsListen;
	t->Accept = SdnTraceTlsAccept;
	t->CloseListener = SdnTraceTlsCloseListener;
	t->Read = SdnTraceTlsRead;
	t->Write = SdnTraceTlsWrite;
	t->Close = SdnTraceTlsClose;
	t->Binding = SdnTraceTlsBinding;
}

//
// The nodes and their hosts
//

// The fake adapter of a host: it keeps the packet that the overlay delivered last, in VRF default
static void SdnTraceAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	SDNTRACE_NODE *t = (SDNTRACE_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	t->Size = MIN(size, (UINT)sizeof(t->Packet));
	Copy(t->Packet, packet, t->Size);
	ReleaseSRWLockExclusive(&t->Lock);

	SetEvent(t->Arrived);
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void SdnTraceNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"sdntrace_%S_%u", name, Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s != NULL)
	{
		CsSetSetting(s, NODE_SETTING_ROLES, "none");
		CsSetSetting(s, NODE_SETTING_WORKERS, "1");
		CsClose(s);
	}
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void SdnTraceDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		if (e->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, e->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// An ICMP echo (type 8) or echo reply (type 0) from src to dst, with its checksums: its size
static UINT SdnTraceEcho(UCHAR *buf, UINT src, UINT dst, UCHAR type, USHORT seq)
{
	UINT size = 20 + 8 + SDNTRACE_PAYLOAD;
	USHORT sum;

	Zero(buf, size);
	buf[0] = 0x45;
	buf[2] = (UCHAR)(size >> 8);
	buf[3] = (UCHAR)size;
	buf[4] = (UCHAR)(seq >> 8);
	buf[5] = (UCHAR)seq;
	buf[8] = 64;
	buf[9] = IP_PROTO_ICMPV4;
	Copy(buf + 12, &src, 4);
	Copy(buf + 16, &dst, 4);
	sum = IpChecksum(buf, 20);
	Copy(buf + 10, &sum, 2);

	UCHAR *icmp = buf + 20;
	icmp[0] = type;
	icmp[4] = 'R';
	icmp[5] = 'z';
	icmp[6] = (UCHAR)(seq >> 8);
	icmp[7] = (UCHAR)seq;
	for (UINT i = 0;i < SDNTRACE_PAYLOAD;i++)
	{
		icmp[8 + i] = (UCHAR)('a' + i % 26);
	}
	sum = IpChecksum(icmp, 8 + SDNTRACE_PAYLOAD);
	Copy(icmp + 2, &sum, 2);

	return size;
}

// Whether the host of t took a packet with the bytes of want within SDNTRACE_ARRIVE
static bool SdnTraceArrived(SDNTRACE_NODE *t, UCHAR *want, UINT size)
{
	UINT64 end = Tick64() + SDNTRACE_ARRIVE;

	while (Tick64() < end)
	{
		bool same;

		WaitForSingleObject(t->Arrived, SDNTRACE_POLL);
		AcquireSRWLockExclusive(&t->Lock);
		same = (t->Size == size && Cmp(t->Packet, want, size) == 0);
		ReleaseSRWLockExclusive(&t->Lock);
		if (same)
		{
			return true;
		}
	}

	return false;
}

// The address of a node in VRF default: the first IPv4 address of its overlay
static UINT SdnTraceAddress(SDNTRACE_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return (st.NumAddresses != 0 ? st.Addresses[0] : 0);
}

// The VRF of that address: VRF default
static UINT SdnTraceVrf(SDNTRACE_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return (st.NumAddresses != 0 ? st.VrfIds[0] : 0);
}

// A packet of the host of t in VRF default, sent while the test thread is an online reader of the node's forwarding
// tables
static bool SdnTraceSend(SDNTRACE_NODE *t, UCHAR *packet, UINT size)
{
	UINT vrf = SdnTraceVrf(t);

	NodeReaderOnline(t->Node, &t->Reader);
	bool sent = NodeOverlayInput(t->Node, vrf, packet, size);
	NodeReaderOffline(&t->Reader);

	return sent;
}

// An echo request from the host of a to the host of b and its reply back: both arrive byte for byte
static void SdnTracePing(SDNTRACE_CTX *ctx, SDNTRACE_NODE *a, SDNTRACE_NODE *b, USHORT seq, char *when)
{
	UCHAR request[128], reply[128];
	char from[64], to[64], what[MAX_SIZE];
	UINT addr_a = SdnTraceAddress(a), addr_b = SdnTraceAddress(b);

	IPToStr32(from, sizeof(from), addr_a);
	IPToStr32(to, sizeof(to), addr_b);

	AcquireSRWLockExclusive(&b->Lock);
	b->Size = 0;
	ReleaseSRWLockExclusive(&b->Lock);
	UINT size = SdnTraceEcho(request, addr_a, addr_b, 8, seq);
	bool sent = SdnTraceSend(a, request, size);
	Format(what, sizeof(what), "%s: the echo request of %s (%s) reaches the host of %s (%s) over the overlay", when, a->Name, from, b->Name, to);
	if (SdnTraceCheck(ctx, sent && SdnTraceArrived(b, request, size), what, "sent %u", (UINT)sent) == false)
	{
		return;
	}

	AcquireSRWLockExclusive(&a->Lock);
	a->Size = 0;
	ReleaseSRWLockExclusive(&a->Lock);
	size = SdnTraceEcho(reply, addr_b, addr_a, 0, seq);
	sent = SdnTraceSend(b, reply, size);
	Format(what, sizeof(what), "%s: the echo reply of %s reaches the host of %s", when, b->Name, a->Name);
	SdnTraceCheck(ctx, sent && SdnTraceArrived(a, reply, size), what, "sent %u", (UINT)sent);
}

// Whether every node is connected (or every node is not) within timeout, with a state applied
static bool SdnTraceWaitConnected(SDNTRACE_NODE *nodes, bool connected, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < SDNTRACE_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Connected != connected || st.Generation == 0)
			{
				all = false;
			}
		}

		if (all)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}
		SleepThread(SDNTRACE_POLL);
	}
}

// Whether both nodes applied a state with an address and their Noise session is up, within SDNTRACE_JOIN
static bool SdnTraceWaitJoined(SDNTRACE_NODE *nodes)
{
	UINT64 end = Tick64() + SDNTRACE_JOIN;

	while (Tick64() < end)
	{
		bool all = true;

		for (UINT i = 0;i < SDNTRACE_NUM_NODES;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(nodes[i].Node, &st);
			if (st.Generation == 0 || st.NumAddresses == 0 || st.NumPeers != SDNTRACE_NUM_NODES - 1 || st.NumLinks != st.NumPeers)
			{
				all = false;
			}
		}

		if (all)
		{
			return true;
		}
		SleepThread(SDNTRACE_POLL);
	}

	return false;
}

static void SdnTraceShowNodes(SDNTRACE_NODE *nodes)
{
	for (UINT i = 0;i < SDNTRACE_NUM_NODES;i++)
	{
		NODE_OVERLAY_STATUS st;
		char addr[64] = "";

		NodeOverlayGetStatus(nodes[i].Node, &st);
		if (st.NumAddresses != 0)
		{
			IPToStr32(addr, sizeof(addr), st.Addresses[0]);
		}
		Print("  [INFO] %s: control stream %s, generation %I64u, name %s, address %s, %u peers, %u sessions, %I64u forwarded, %I64u delivered, %I64u dropped\n",
			nodes[i].Name, (st.Connected ? "open" : "down"), st.Generation, st.Name, addr, st.NumPeers, st.NumLinks, st.Forwarded, st.Delivered, st.Dropped);
	}
}

void sdntrace_test(UINT num, char **arg)
{
	SDNTRACE_CTX *ctx = ZeroMalloc(sizeof(SDNTRACE_CTX));
	SDNTRACE_NODE *nodes = ZeroMalloc(sizeof(SDNTRACE_NODE) * SDNTRACE_NUM_NODES);
	TRANSPORT *tls = ZeroMalloc(sizeof(TRANSPORT));
	TRANSPORT *loopback = NULL;
	UCHAR controller_key[PEER_KEY_SIZE];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, SdnTraceWatchdog, done, 0, NULL) : NULL);
	bool ok = false;

	Print("Default VRF tracer: two nodes join VRF default of the controller and ping each other over the overlay\n");

	// The controller: its address and its static key
	Zero(controller_key, sizeof(controller_key));
	if (num >= 2)
	{
		UINT key_size = 0;
		void *key = Base64ToBin(&key_size, arg[1], StrLen(arg[1]));

		ok = (key != NULL && key_size == PEER_KEY_SIZE);
		if (ok)
		{
			Copy(controller_key, key, PEER_KEY_SIZE);
		}
		Free(key);
	}
	if (SdnTraceCheck(ctx, ok, "the controller: its address and its static key", "usage: sdntrace <host:port of the controller> <its static key in base64>") == false)
	{
		goto END;
	}

	// The transports: TLS to the controller, loopback between the nodes
	SdnTraceTlsInit(tls);
	loopback = TransportLoopbackNew("loopback", 0, false);
	SdnTraceCheck(ctx, loopback != NULL, "the in-process loopback transport between the nodes", "TransportLoopbackNew failed");

	// The nodes, each with its static key and the fake adapter of its host
	for (UINT i = 0;i < SDNTRACE_NUM_NODES && loopback != NULL;i++)
	{
		SDNTRACE_NODE *t = &nodes[i];
		NODE_OVERLAY_CONFIG c;
		UCHAR scalar[PEER_KEY_SIZE];
		UINT size = 0;
		char what[MAX_SIZE];

		t->Name = sdntrace_names[i];
		t->Arrived = CreateEventW(NULL, FALSE, FALSE, NULL);
		InitializeSRWLock(&t->Lock);
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(1 + PEER_KEY_SIZE * i + j);
		}
		bool keyed = PeerKeyFromScalar(&t->Key, scalar);
		Zero(scalar, sizeof(scalar));

		void *pub = Base64ToBin(&size, sdntrace_keys[i], StrLen(sdntrace_keys[i]));
		Format(what, sizeof(what), "%s: its static key is the one of its Node resource", t->Name);
		SdnTraceCheck(ctx, keyed && pub != NULL && size == PEER_KEY_SIZE && Cmp(pub, t->Key.Public, PEER_KEY_SIZE) == 0, what, "%s", sdntrace_keys[i]);
		Free(pub);

		SdnTraceNewDir(t->Dir, sizeof(t->Dir), t->Name);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);
		NodeReaderRegister(t->Node, &t->Reader);
		NodeReaderOffline(&t->Reader);

		Zero(&c, sizeof(c));
		c.Control = tls;
		StrCpy(c.Controller, sizeof(c.Controller), arg[0]);
		Copy(c.ControllerKey, controller_key, PEER_KEY_SIZE);
		c.Data = loopback;
		c.Key = &t->Key;
		c.Adapter = SdnTraceAdapter;
		c.AdapterParam = t;
		Format(what, sizeof(what), "%s: its overlay runs, with its control stream to %s", t->Name, arg[0]);
		SdnTraceCheck(ctx, NodeOverlayStart(t->Node, &c), what, "NodeOverlayStart failed");
	}

	if (loopback != NULL)
	{
		// Both join VRF default: a state with an address from its pool, the other node as the peer, the session up
		bool joined = SdnTraceWaitJoined(nodes);
		SdnTraceShowNodes(nodes);
		SdnTraceCheck(ctx, joined && SdnTraceWaitConnected(nodes, true, SDNTRACE_ARRIVE), "both nodes applied their state from the controller, with an address, and their Noise session is up",
			"not within %u ms", SDNTRACE_JOIN);
		SdnTraceCheck(ctx, SdnTraceAddress(&nodes[0]) != SdnTraceAddress(&nodes[1]) && SdnTraceAddress(&nodes[0]) != 0, "the two addresses differ", "the same address");

		if (joined)
		{
			SdnTracePing(ctx, &nodes[0], &nodes[1], 1, "with the controller");
			SdnTracePing(ctx, &nodes[1], &nodes[0], 2, "with the controller");

			// The script checks the acknowledged Generations through the API, then stops the controller
			Print("SDNTRACE PINGED\n");
			if (num >= 3)
			{
				HANDLE f = CreateFileA(arg[2], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

				SdnTraceCheck(ctx, f != INVALID_HANDLE_VALUE, "the file of the script that the echoes went both ways", "CreateFile %s: error %u", arg[2], (UINT)GetLastError());
				if (f != INVALID_HANDLE_VALUE)
				{
					CloseHandle(f);
				}
			}
			bool down = SdnTraceWaitConnected(nodes, false, SDNTRACE_CONTROLLER);
			SdnTraceShowNodes(nodes);
			if (SdnTraceCheck(ctx, down, "the controller stopped: both control streams are down", "not within %u ms", SDNTRACE_CONTROLLER))
			{
				SdnTracePing(ctx, &nodes[0], &nodes[1], 3, "without the controller");
				SdnTracePing(ctx, &nodes[1], &nodes[0], 4, "without the controller");
				SdnTraceShowNodes(nodes);
			}
		}
	}

	for (UINT i = 0;i < SDNTRACE_NUM_NODES;i++)
	{
		SDNTRACE_NODE *t = &nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node == NULL)
		{
			continue;
		}

		NodeReaderUnregister(t->Node, &t->Reader);
		NodeStop(t->Node);
		FreeNode(t->Node);
		PeerKeyClose(&t->Key);
		CloseHandle(t->Arrived);
		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		SdnTraceDeleteDir(log_dir);
		SdnTraceDeleteDir(t->Dir);
	}

END:
	TransportLoopbackFree(loopback);

	if (watchdog != NULL)
	{
		SetEvent(done);
		WaitForSingleObject(watchdog, INFINITE);
		CloseHandle(watchdog);
	}
	if (done != NULL)
	{
		CloseHandle(done);
	}

	if (ctx->NumFailed == 0)
	{
		Print("SDNTRACE TEST OK\n");
	}
	else
	{
		Print("SDNTRACE TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(tls);
	Free(nodes);
	Free(ctx);
}
