// frontdoor.c
// The front door of the new core (src/Core/FrontDoor*.c; SDN-29, #205; ADR-0035) with the node, its owners and the
// clients in processes of their own on this machine: coretest starts itself as the node and as each owner
// (coretest frontdoor-child ...). The seam of the ticket, several node processes on one runner each with its own
// KM-TEST adapter, needs the KM-TEST adapters of CORE-S3-2 (#72); these processes have none. The front door does not
// use one: it routes the TCP connections of the host's own stack. An adapter would add the overlay traffic behind the
// node's TLS, the packets that the Noise session carries to a VRF.
//
// - The first bytes, in this process: the ClientHello parser on hellos made here, whole, cut at every byte, in records
//   of 7 bytes, without extensions and malformed; the owner that the table gives, by ALPN, by server name without case
//   and under a wildcard, by the first bytes while a longer prefix is pending, and none; the handoff message.
// - The node (a coretest process): the front door on a test port of the loopback interface, never 443, with the owner
//   table of a node beside its Controller: TLS with ALPN h2 or http/1.1 and TLS with the server name of the web UI to
//   the Controller, the test signature to the signature owner, an ALPN whose owner process does not run, and every
//   other TLS to the node itself, whose TLS transport takes the connection (TransportTake) and runs the TLS handshake
//   and the Noise session of the new protocol.
// - The Controller and the signature owner (a coretest process each): each takes the sockets that the front door
//   hands over through its pipe and answers with its name and process id, then with every byte it reads, from the
//   first.
// The checks: TLS for the new protocol stays in the node (the Noise session comes up with the node's static key); TLS
// with another ALPN or server name reaches the Controller, in one TCP segment, in three and in records of 7 bytes; the
// signature reaches its owner, also when its first bytes come apart; what no owner takes, and what the absent owner
// cannot take, is closed; each owner reads the first bytes of its connection itself; and a connection that a second
// node handed to the Controller carries bytes both ways after that node's process was killed, while the node's port is
// gone: no byte passes through the node after the handoff. The node's counters add up at the end.

#include "coretest.h"

#include "Core/FrontDoor.h"
#include "Core/Transport.h"

#include <ws2tcpip.h>

#include <stdlib.h>
#include <string.h>

#define FRONTDOOR_TIMEOUT   15000                  // A child's line, a handshake, an answer or an echo within this time (ms)
#define FRONTDOOR_POLL      200                    // How often a child looks whether its standard input ended (ms)
#define FRONTDOOR_GAP       100                    // The time between the TCP segments of a client (ms)
#define FRONTDOOR_LISTEN    "127.0.0.1:0"          // A test port of the loopback interface, never 443
#define FRONTDOOR_CN        L"CN=localhost"        // The subject of the node's certificate
#define FRONTDOOR_SAN       L"localhost"           // ... and its subject alternative name
#define FRONTDOOR_SIGNATURE "RANZ-FRONT-DOOR-TEST" // The first bytes of the signature owner's connections
#define FRONTDOOR_BULK      16384                  // Bytes of one exchange after the node is gone ...
#define FRONTDOOR_ROUNDS    16                     // ... and the exchanges: 256 KiB each way
#define FRONTDOOR_LINE      512                    // A line of a child or of an owner
#define FRONTDOOR_BUF       4096                   // A ClientHello and its records

// The owner table of the test's nodes, in this order
#define FRONTDOOR_CONTROLLER 0 // TLS with ALPN h2, http/1.1 or ranz-control/1: the Controller's web UI, API and control stream
#define FRONTDOOR_WEB_UI     1 // TLS with the server name of the web UI: the Controller
#define FRONTDOOR_SIGNED     2 // The test signature: the signature owner
#define FRONTDOOR_ABSENT     3 // TLS with an ALPN whose owner process does not run
#define FRONTDOOR_NODE       4 // Every other TLS: the new protocol, in the node
#define FRONTDOOR_NUM_OWNERS 5

// What a ClientHello made here holds besides its names
#define FRONTDOOR_HELLO_TWICE      0x00000001 // server_name twice
#define FRONTDOOR_HELLO_EMPTY_ALPN 0x00000002 // an empty ALPN protocol after the others

// A child process: the node or an owner
typedef struct FRONTDOOR_CHILD {
	PROCESS_INFORMATION Process; // The process and its thread
	HANDLE Input;                // The write end of its standard input: closed, it ends the child
	HANDLE Output;               // The read end of its standard output
	char Buf[FRONTDOOR_BUF];     // What it wrote that no line took yet ...
	UINT Size;                   // ... its bytes
} FRONTDOOR_CHILD;

// The node of a child process
typedef struct FRONTDOOR_NODE_STATE {
	TRANSPORT_LISTENER *Listener; // The listener of its TLS transport, on no socket of its own
	UCHAR Key[NOISE_KEY_SIZE];    // Its static key
	volatile LONG Stop;           // Set once its standard input ended
	UINT Sessions;                // The Noise sessions that came up
} FRONTDOOR_NODE_STATE;

static void frontdoor_put16(UCHAR *p, UINT v) {
	p[0] = (UCHAR)(v >> 8);
	p[1] = (UCHAR)v;
}

// A ClientHello message as a TLS 1.3 client sends it, into buf (FRONTDOOR_BUF bytes): with server_name when name is
// not NULL, with ALPN when num protocols are given, and what flags adds; its size
static UINT frontdoor_hello(UCHAR *buf, const char *name, const char *const *protocols, UINT num, UINT flags) {
	UINT p = 0;

	buf[p] = 1;
	p += 4;
	frontdoor_put16(buf + p, 0x0303);
	p += 2;
	for (UINT i = 0; i < 32; i++)
		buf[p++] = (UCHAR)(0xA0 + i);
	buf[p++] = 32;
	for (UINT i = 0; i < 32; i++)
		buf[p++] = (UCHAR)i;
	frontdoor_put16(buf + p, 6);
	frontdoor_put16(buf + p + 2, 0x1301);
	frontdoor_put16(buf + p + 4, 0x1302);
	frontdoor_put16(buf + p + 6, 0x1303);
	p += 8;
	buf[p++] = 1;
	buf[p++] = 0;

	UINT extensions = p;
	p += 2;

	// supported_versions (TLS 1.3), supported_groups (X25519), signature_algorithms (ECDSA P-256 SHA-256)
	frontdoor_put16(buf + p, 0x002B);
	frontdoor_put16(buf + p + 2, 3);
	buf[p + 4] = 2;
	frontdoor_put16(buf + p + 5, 0x0304);
	p += 7;
	frontdoor_put16(buf + p, 0x000A);
	frontdoor_put16(buf + p + 2, 4);
	frontdoor_put16(buf + p + 4, 2);
	frontdoor_put16(buf + p + 6, 0x001D);
	p += 8;
	frontdoor_put16(buf + p, 0x000D);
	frontdoor_put16(buf + p + 2, 4);
	frontdoor_put16(buf + p + 4, 2);
	frontdoor_put16(buf + p + 6, 0x0403);
	p += 8;

	for (UINT n = 0; name != NULL && n < ((flags & FRONTDOOR_HELLO_TWICE) != 0 ? 2 : 1); n++) {
		UINT len = (UINT)strlen(name);

		frontdoor_put16(buf + p, 0x0000);
		frontdoor_put16(buf + p + 2, len + 5);
		frontdoor_put16(buf + p + 4, len + 3);
		buf[p + 6] = 0;
		frontdoor_put16(buf + p + 7, len);
		memcpy(buf + p + 9, name, len);
		p += 9 + len;
	}

	if (num != 0) {
		UINT list = ((flags & FRONTDOOR_HELLO_EMPTY_ALPN) != 0 ? 1 : 0);

		for (UINT i = 0; i < num; i++)
			list += 1 + (UINT)strlen(protocols[i]);
		frontdoor_put16(buf + p, 0x0010);
		frontdoor_put16(buf + p + 2, list + 2);
		frontdoor_put16(buf + p + 4, list);
		p += 6;
		for (UINT i = 0; i < num; i++) {
			UINT len = (UINT)strlen(protocols[i]);

			buf[p++] = (UCHAR)len;
			memcpy(buf + p, protocols[i], len);
			p += len;
		}
		if ((flags & FRONTDOOR_HELLO_EMPTY_ALPN) != 0)
			buf[p++] = 0;
	}

	// key_share: one X25519 key
	frontdoor_put16(buf + p, 0x0033);
	frontdoor_put16(buf + p + 2, 38);
	frontdoor_put16(buf + p + 4, 36);
	frontdoor_put16(buf + p + 6, 0x001D);
	frontdoor_put16(buf + p + 8, 32);
	for (UINT i = 0; i < 32; i++)
		buf[p + 10 + i] = (UCHAR)(0x40 + i);
	p += 42;

	frontdoor_put16(buf + extensions, p - extensions - 2);
	buf[1] = (UCHAR)((p - 4) >> 16);
	buf[2] = (UCHAR)((p - 4) >> 8);
	buf[3] = (UCHAR)(p - 4);

	return p;
}

// A message in handshake records of at most fragment bytes each, into out (FRONTDOOR_BUF bytes); their size
static UINT frontdoor_records(UCHAR *out, const UCHAR *msg, UINT size, UINT fragment) {
	UINT p = 0;

	for (UINT done = 0; done < size;) {
		UINT n = (size - done < fragment ? size - done : fragment);

		out[p] = 22;
		out[p + 1] = 3;
		out[p + 2] = 1;
		frontdoor_put16(out + p + 3, n);
		memcpy(out + p + 5, msg + done, n);
		p += 5 + n;
		done += n;
	}

	return p;
}

// Whether hello holds the server name name (NULL: none) and the protocols (num of them)
static bool frontdoor_names(const FRONT_DOOR_HELLO *hello, const char *name, const char *const *protocols, UINT num) {
	if (name == NULL ? hello->ServerName != NULL : (hello->ServerName == NULL || hello->ServerNameSize != strlen(name) || memcmp(hello->ServerName, name, hello->ServerNameSize) != 0))
		return false;
	if (hello->NumProtocols != num)
		return false;

	for (UINT i = 0; i < num; i++)
		if (hello->ProtocolSizes[i] != strlen(protocols[i]) || memcmp(hello->Protocols[i], protocols[i], hello->ProtocolSizes[i]) != 0)
			return false;

	return true;
}

// The owner procedure of the node: its TLS transport takes the connection
static bool frontdoor_take(void *param, SOCKET s) {
	FRONTDOOR_NODE_STATE *n = (FRONTDOOR_NODE_STATE *)param;

	return TransportTake(n->Listener, (UINT_PTR)s);
}

// The owner table of a node beside its Controller: the pipes of the Controller, of the signature owner and of the
// owner that does not run, and the node's own procedure
static void frontdoor_owners(FRONT_DOOR_OWNER *owners, const wchar_t *controller, const wchar_t *signature, const wchar_t *absent, void *node) {
	ZeroMemory(owners, sizeof(FRONT_DOOR_OWNER) * FRONTDOOR_NUM_OWNERS);

	strcpy_s(owners[FRONTDOOR_CONTROLLER].Name, FRONT_DOOR_NAME_SIZE, "controller");
	owners[FRONTDOOR_CONTROLLER].Kind = FRONT_DOOR_TLS;
	strcpy_s(owners[FRONTDOOR_CONTROLLER].Protocols, FRONT_DOOR_LIST_SIZE, FRONT_DOOR_CONTROLLER_PROTOCOLS);
	wcscpy_s(owners[FRONTDOOR_CONTROLLER].Pipe, FRONT_DOOR_PIPE_SIZE, controller);

	strcpy_s(owners[FRONTDOOR_WEB_UI].Name, FRONT_DOOR_NAME_SIZE, "controller-web-ui");
	owners[FRONTDOOR_WEB_UI].Kind = FRONT_DOOR_TLS;
	strcpy_s(owners[FRONTDOOR_WEB_UI].ServerNames, FRONT_DOOR_LIST_SIZE, "admin.frontdoor.test, *.admin.frontdoor.test");
	wcscpy_s(owners[FRONTDOOR_WEB_UI].Pipe, FRONT_DOOR_PIPE_SIZE, controller);

	strcpy_s(owners[FRONTDOOR_SIGNED].Name, FRONT_DOOR_NAME_SIZE, "signature");
	owners[FRONTDOOR_SIGNED].Kind = FRONT_DOOR_BYTES;
	owners[FRONTDOOR_SIGNED].PrefixSize = (UINT)strlen(FRONTDOOR_SIGNATURE);
	memcpy(owners[FRONTDOOR_SIGNED].Prefix, FRONTDOOR_SIGNATURE, owners[FRONTDOOR_SIGNED].PrefixSize);
	wcscpy_s(owners[FRONTDOOR_SIGNED].Pipe, FRONT_DOOR_PIPE_SIZE, signature);

	strcpy_s(owners[FRONTDOOR_ABSENT].Name, FRONT_DOOR_NAME_SIZE, "absent");
	owners[FRONTDOOR_ABSENT].Kind = FRONT_DOOR_TLS;
	strcpy_s(owners[FRONTDOOR_ABSENT].Protocols, FRONT_DOOR_LIST_SIZE, "ranz-absent/1");
	wcscpy_s(owners[FRONTDOOR_ABSENT].Pipe, FRONT_DOOR_PIPE_SIZE, absent);

	strcpy_s(owners[FRONTDOOR_NODE].Name, FRONT_DOOR_NAME_SIZE, "node");
	owners[FRONTDOOR_NODE].Kind = FRONT_DOOR_TLS;
	owners[FRONTDOOR_NODE].Take = frontdoor_take;
	owners[FRONTDOOR_NODE].Param = node;
}

//
// The first bytes, in this process
//

// The ClientHello parser on hellos made here
static void frontdoor_parser() {
	FRONT_DOOR_HELLO *h = (FRONT_DOOR_HELLO *)HeapAlloc(GetProcessHeap(), 0, sizeof(FRONT_DOOR_HELLO));
	UCHAR *msg = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	UCHAR *rec = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	const char *both[2] = {"h2", "http/1.1"};
	char long_name[301];

	if (coretest_check(h != NULL && msg != NULL && rec != NULL, "the parser's buffers") == false) {
		if (h != NULL)
			HeapFree(GetProcessHeap(), 0, h);
		if (msg != NULL)
			HeapFree(GetProcessHeap(), 0, msg);
		if (rec != NULL)
			HeapFree(GetProcessHeap(), 0, rec);
		return;
	}

	UINT size = frontdoor_hello(msg, "node.frontdoor.test", both, 2, 0);
	UINT rsize = frontdoor_records(rec, msg, size, 16384);
	coretest_check(FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_DONE && frontdoor_names(h, "node.frontdoor.test", both, 2) && h->MessageSize == size &&
	                   h->RecordsSize == rsize,
	               "a ClientHello in one record: its server name, its two ALPN protocols and its size");

	bool cut = true;
	for (UINT i = 0; i < rsize; i++)
		cut = cut && FrontDoorParseHello(rec, i, h) == FRONT_DOOR_HELLO_MORE;
	coretest_check(cut, "cut short at any byte, it is the start of one: the front door waits for more");

	rsize = frontdoor_records(rec, msg, size, 7);
	coretest_check(FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_DONE && frontdoor_names(h, "node.frontdoor.test", both, 2) && h->RecordsSize == rsize,
	               "in records of 7 bytes, put together: the same names");
	cut = true;
	for (UINT i = 0; i < rsize; i++)
		cut = cut && FrontDoorParseHello(rec, i, h) == FRONT_DOOR_HELLO_MORE;
	coretest_check(cut, "in records of 7 bytes, cut short at any byte: the start of one");

	size = frontdoor_hello(msg, NULL, NULL, 0, 0);
	rsize = frontdoor_records(rec, msg, size, 16384);
	coretest_check(FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_DONE && frontdoor_names(h, NULL, NULL, 0), "without server_name and ALPN: no names");

	// TLS 1.2 without extensions: the version, the random, no session id, one suite, the null compression
	ZeroMemory(msg, FRONTDOOR_BUF);
	msg[0] = 1;
	msg[3] = 2 + 32 + 1 + 4 + 2;
	frontdoor_put16(msg + 4, 0x0303);
	frontdoor_put16(msg + 4 + 2 + 32 + 1, 2);
	frontdoor_put16(msg + 4 + 2 + 32 + 3, 0xC02F);
	msg[4 + 2 + 32 + 5] = 1;
	rsize = frontdoor_records(rec, msg, 4 + 41, 16384);
	coretest_check(FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_DONE && frontdoor_names(h, NULL, NULL, 0), "a ClientHello of TLS 1.2 without extensions");

	// Malformed: none of these is a ClientHello
	size = frontdoor_hello(msg, "node.frontdoor.test", both, 2, 0);
	rsize = frontdoor_records(rec, msg, size, 16384);
	rec[0] = 21;
	bool alert = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	rec[0] = 22;
	rec[1] = 2;
	bool version = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	rec[1] = 3;
	rec[5] = 2;
	bool server_hello = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	rec[5] = 1;
	coretest_check(alert && version && server_hello, "an alert record, a record of another major version and a ServerHello are no ClientHello");

	UCHAR empty[5] = {22, 3, 1, 0, 0};
	UCHAR large[9] = {22, 3, 1, 0, 4, 1, 0x00, 0x4E, 0x20};
	coretest_check(FrontDoorParseHello(empty, sizeof(empty), h) == FRONT_DOOR_HELLO_NONE && FrontDoorParseHello(large, sizeof(large), h) == FRONT_DOOR_HELLO_NONE,
	               "an empty record and a ClientHello of 20000 bytes, above FRONT_DOOR_MAX_HELLO, are none");

	size = frontdoor_hello(msg, "node.frontdoor.test", both, 2, FRONTDOOR_HELLO_TWICE);
	rsize = frontdoor_records(rec, msg, size, 16384);
	bool twice = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	size = frontdoor_hello(msg, "node.frontdoor.test", both, 2, FRONTDOOR_HELLO_EMPTY_ALPN);
	rsize = frontdoor_records(rec, msg, size, 16384);
	bool empty_alpn = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	memset(long_name, 'a', 300);
	long_name[300] = 0;
	size = frontdoor_hello(msg, long_name, NULL, 0, 0);
	rsize = frontdoor_records(rec, msg, size, 16384);
	bool too_long = (FrontDoorParseHello(rec, rsize, h) == FRONT_DOOR_HELLO_NONE);
	coretest_check(twice && empty_alpn && too_long, "server_name twice, an empty ALPN protocol and a server name of 300 bytes are malformed");

	HeapFree(GetProcessHeap(), 0, rec);
	HeapFree(GetProcessHeap(), 0, msg);
	HeapFree(GetProcessHeap(), 0, h);
}

// The owner that the table of a node gives a ClientHello of the server name name (NULL: none) and one protocol (NULL:
// no ALPN), sent in one record
static UINT frontdoor_route_hello(const FRONT_DOOR_OWNER *owners, const char *name, const char *protocol) {
	UCHAR *msg = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	UCHAR *rec = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	UINT ret = FRONT_DOOR_NONE;

	if (msg != NULL && rec != NULL) {
		UINT size = frontdoor_hello(msg, name, &protocol, (protocol != NULL ? 1 : 0), 0);
		UINT rsize = frontdoor_records(rec, msg, size, 16384);
		ret = FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, rec, rsize, false);
	}

	if (msg != NULL)
		HeapFree(GetProcessHeap(), 0, msg);
	if (rec != NULL)
		HeapFree(GetProcessHeap(), 0, rec);

	return ret;
}

// The owner table as data: what it gives each connection by its first bytes
static void frontdoor_table() {
	FRONT_DOOR_OWNER *owners = (FRONT_DOOR_OWNER *)HeapAlloc(GetProcessHeap(), 0, sizeof(FRONT_DOOR_OWNER) * FRONTDOOR_NUM_OWNERS);
	FRONT_DOOR_OWNER bytes[2];
	const char *signature = FRONTDOOR_SIGNATURE " hello";
	const char *http = "GET / HTTP/1.1\r\nHost: admin.frontdoor.test\r\n\r\n";
	UCHAR tls[3] = {22, 3, 1};

	if (coretest_check(owners != NULL, "the owner table's buffer") == false)
		return;

	frontdoor_owners(owners, L"\\\\.\\pipe\\controller", L"\\\\.\\pipe\\signature", L"\\\\.\\pipe\\absent", NULL);

	coretest_check(frontdoor_route_hello(owners, "node.frontdoor.test", "h2") == FRONTDOOR_CONTROLLER &&
	                   frontdoor_route_hello(owners, NULL, "http/1.1") == FRONTDOOR_CONTROLLER,
	               "TLS with ALPN h2, or http/1.1 without a server name: the Controller");
	coretest_check(frontdoor_route_hello(owners, "Admin.FrontDoor.TEST", NULL) == FRONTDOOR_WEB_UI &&
	                   frontdoor_route_hello(owners, "eu.admin.frontdoor.test", NULL) == FRONTDOOR_WEB_UI,
	               "TLS with the web UI's server name in another case, or a name under *.admin.frontdoor.test: the Controller");
	coretest_check(frontdoor_route_hello(owners, "admin.frontdoor.test.example", NULL) == FRONTDOOR_NODE &&
	                   frontdoor_route_hello(owners, ".admin.frontdoor.test", "h3") == FRONTDOOR_NODE,
	               "a name that only starts like the web UI's, and an empty label under the wildcard: not the Controller");
	coretest_check(frontdoor_route_hello(owners, "node.frontdoor.test", "ranz-absent/1") == FRONTDOOR_ABSENT,
	               "TLS with the ALPN of the absent owner: that owner");
	coretest_check(frontdoor_route_hello(owners, "node.frontdoor.test", NULL) == FRONTDOOR_NODE && frontdoor_route_hello(owners, NULL, NULL) == FRONTDOOR_NODE &&
	                   frontdoor_route_hello(owners, "node.frontdoor.test", "ranz/1") == FRONTDOOR_NODE,
	               "TLS with another server name, none, or an ALPN that no owner lists: the node");

	coretest_check(FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, (const UCHAR *)signature, (UINT)strlen(signature), false) == FRONTDOOR_SIGNED,
	               "the test signature: its owner");
	coretest_check(FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, (const UCHAR *)signature, 10, false) == FRONT_DOOR_MORE &&
	                   FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, (const UCHAR *)signature, 10, true) == FRONT_DOOR_NONE,
	               "the first 10 bytes of the signature: more bytes decide, and none when no more come");
	coretest_check(FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, (const UCHAR *)http, (UINT)strlen(http), false) == FRONT_DOOR_NONE,
	               "an HTTP request in plain text: no owner");
	coretest_check(FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, NULL, 0, false) == FRONT_DOOR_MORE && FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, NULL, 0, true) == FRONT_DOOR_NONE &&
	                   FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, tls, sizeof(tls), false) == FRONT_DOOR_MORE &&
	                   FrontDoorRoute(owners, FRONTDOOR_NUM_OWNERS, tls, sizeof(tls), true) == FRONT_DOOR_NONE,
	               "no bytes, and the first 3 bytes of a TLS record: more bytes decide, and none when no more come");

	// A longer prefix first: while it may still match, a later owner with a shorter one waits
	ZeroMemory(bytes, sizeof(bytes));
	bytes[0].Kind = FRONT_DOOR_BYTES;
	bytes[0].PrefixSize = (UINT)strlen(FRONTDOOR_SIGNATURE);
	memcpy(bytes[0].Prefix, FRONTDOOR_SIGNATURE, bytes[0].PrefixSize);
	bytes[1].Kind = FRONT_DOOR_BYTES;
	bytes[1].PrefixSize = 4;
	memcpy(bytes[1].Prefix, "RANZ", 4);
	coretest_check(FrontDoorRoute(bytes, 2, (const UCHAR *)signature, 10, false) == FRONT_DOOR_MORE && FrontDoorRoute(bytes, 2, (const UCHAR *)signature, 10, true) == 1 &&
	                   FrontDoorRoute(bytes, 2, (const UCHAR *)"RANZ-X", 6, false) == 1 &&
	                   FrontDoorRoute(bytes, 2, (const UCHAR *)signature, (UINT)strlen(signature), false) == 0,
	               "a longer prefix first: the shorter one's owner waits while it may match, and gets what it cannot");

	coretest_check(FrontDoorRoute(NULL, 0, tls, sizeof(tls), false) == FRONT_DOOR_NONE && FrontDoorRoute(owners, FRONT_DOOR_MAX_OWNERS + 1, tls, sizeof(tls), false) == FRONT_DOOR_NONE,
	               "no table, or a table above FRONT_DOOR_MAX_OWNERS: no owner");

	HeapFree(GetProcessHeap(), 0, owners);
}

// The handoff message that an owner process reads
static void frontdoor_message() {
	FRONT_DOOR_HANDOFF m;
	WSAPROTOCOL_INFOW info;

	ZeroMemory(&m, sizeof(m));
	m.Magic = FRONT_DOOR_HANDOFF_MAGIC;
	m.Size = sizeof(m);
	m.Info.iAddressFamily = AF_INET;
	m.Info.iSocketType = SOCK_STREAM;
	m.Info.iProtocol = IPPROTO_TCP;
	bool ok = (FrontDoorHandoffDecode(&m, sizeof(m), &info) && info.iAddressFamily == AF_INET);
	m.Info.iAddressFamily = AF_INET6;
	ok = ok && FrontDoorHandoffDecode(&m, sizeof(m), &info) && info.iAddressFamily == AF_INET6;
	coretest_check(ok, "a handoff message of a TCP socket of IPv4 or IPv6 is read");

	bool short_one = (FrontDoorHandoffDecode(&m, sizeof(m) - 1, &info) == false);
	m.Magic ^= 1;
	bool magic = (FrontDoorHandoffDecode(&m, sizeof(m), &info) == false);
	m.Magic ^= 1;
	m.Size++;
	bool version = (FrontDoorHandoffDecode(&m, sizeof(m), &info) == false);
	m.Size--;
	m.Info.iSocketType = SOCK_DGRAM;
	bool udp = (FrontDoorHandoffDecode(&m, sizeof(m), &info) == false);
	coretest_check(short_one && magic && version && udp, "a short message, another magic, another version and a UDP socket are refused");
}

//
// The processes
//

static bool frontdoor_send(SOCKET s, const void *buf, UINT size) {
	const char *p = (const char *)buf;

	while (size != 0) {
		int n = send(s, p, (int)size, 0);

		if (n <= 0)
			return false;
		p += n;
		size -= (UINT)n;
	}

	return true;
}

static bool frontdoor_recv_all(SOCKET s, void *buf, UINT size) {
	char *p = (char *)buf;

	while (size != 0) {
		int n = recv(s, p, (int)size, 0);

		if (n <= 0)
			return false;
		p += n;
		size -= (UINT)n;
	}

	return true;
}

// A line that the peer sends, without its end, into line
static bool frontdoor_recv_line(SOCKET s, char *line, UINT size) {
	UINT len = 0;

	line[0] = 0;
	while (len + 1 < size) {
		char c = 0;

		if (recv(s, &c, 1, 0) != 1)
			return false;
		if (c == '\n') {
			line[len] = 0;
			return true;
		}
		line[len++] = c;
	}

	return false;
}

// A connection to a port of the loopback interface, which sends each send as a segment of its own and whose reads
// give up after FRONTDOOR_TIMEOUT; INVALID_SOCKET when nothing listens there
static SOCKET frontdoor_connect(USHORT port) {
	struct sockaddr_in sa;
	BOOL nodelay = TRUE;
	DWORD timeout = FRONTDOOR_TIMEOUT;
	SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_NO_HANDLE_INHERIT);

	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay)) != 0 ||
	    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) != 0 || connect(s, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// A connection to the front door that sends data, cut into TCP segments at the num cuts (FRONTDOOR_GAP apart), and
// reads the owner's answer: its line, then the bytes it read, which must be data. True when the owner of name and
// process id pid read them all, from the first. The connection goes to keep when it is given, else it is closed.
static bool frontdoor_echo(USHORT port, const UCHAR *data, UINT size, const UINT *cuts, UINT num, const char *name, DWORD pid, SOCKET *keep) {
	char line[FRONTDOOR_LINE], expect[FRONTDOOR_LINE];
	UCHAR *back = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, size);
	SOCKET s = frontdoor_connect(port);
	bool ok = (s != INVALID_SOCKET && back != NULL);
	UINT from = 0;

	for (UINT i = 0; ok && i <= num; i++) {
		UINT to = (i < num ? cuts[i] : size);

		ok = frontdoor_send(s, data + from, to - from);
		from = to;
		if (i < num)
			Sleep(FRONTDOOR_GAP);
	}

	line[0] = 0;
	snprintf(expect, sizeof(expect), "OWNER %s %lu", name, pid);
	ok = ok && frontdoor_recv_line(s, line, sizeof(line)) && strcmp(line, expect) == 0 && frontdoor_recv_all(s, back, size) && memcmp(back, data, size) == 0;
	if (ok == false)
		coretest_info("expected \"%s\" and the %u bytes sent, the owner answered \"%s\"", expect, size, line);

	if (ok && keep != NULL)
		*keep = s;
	else if (s != INVALID_SOCKET)
		closesocket(s);
	if (back != NULL)
		HeapFree(GetProcessHeap(), 0, back);

	return ok;
}

// Whether the front door closes a connection that sends data: its end or a reset, within FRONTDOOR_TIMEOUT
static bool frontdoor_dropped(USHORT port, const void *data, UINT size) {
	SOCKET s = frontdoor_connect(port);
	char c = 0;

	if (s == INVALID_SOCKET)
		return false;

	bool sent = frontdoor_send(s, data, size);
	int n = recv(s, &c, 1, 0);
	bool dropped = (sent && (n == 0 || (n == SOCKET_ERROR && WSAGetLastError() != WSAETIMEDOUT)));
	closesocket(s);

	return dropped;
}

// Start coretest as a child of the front door test with the arguments args; only its standard input and output are
// inherited
static bool frontdoor_start(FRONTDOOR_CHILD *c, const char *args) {
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOEXA si;
	HANDLE in_read = NULL, out_write = NULL;
	char exe[MAX_PATH], cmd[2048];
	SIZE_T attr_size = 0;

	ZeroMemory(c, sizeof(FRONTDOOR_CHILD));
	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;

	bool ok = (CreatePipe(&in_read, &c->Input, &sa, 0) && CreatePipe(&c->Output, &out_write, &sa, 0) && SetHandleInformation(c->Input, HANDLE_FLAG_INHERIT, 0) &&
	           SetHandleInformation(c->Output, HANDLE_FLAG_INHERIT, 0) && GetModuleFileNameA(NULL, exe, sizeof(exe)) != 0);
	if (ok)
		ok = (snprintf(cmd, sizeof(cmd), "\"%s\" %s %s", exe, CORETEST_FRONTDOOR_CHILD, args) < (int)sizeof(cmd));

	ZeroMemory(&si, sizeof(si));
	if (ok) {
		(void)InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
		si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attr_size);
		ok = (si.lpAttributeList != NULL && InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size));
		if (ok == false && si.lpAttributeList != NULL) {
			HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
			si.lpAttributeList = NULL;
		}
	}
	if (ok) {
		HANDLE inherit[2] = {in_read, out_write};

		si.StartupInfo.cb = sizeof(si);
		si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
		si.StartupInfo.hStdInput = in_read;
		si.StartupInfo.hStdOutput = out_write;
		si.StartupInfo.hStdError = out_write;
		ok = (UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof(inherit), NULL, NULL) &&
		      CreateProcessA(exe, cmd, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &c->Process));
	}
	if (si.lpAttributeList != NULL) {
		DeleteProcThreadAttributeList(si.lpAttributeList);
		HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
	}

	if (in_read != NULL)
		CloseHandle(in_read);
	if (out_write != NULL)
		CloseHandle(out_write);
	if (ok == false) {
		if (c->Input != NULL)
			CloseHandle(c->Input);
		if (c->Output != NULL)
			CloseHandle(c->Output);
		ZeroMemory(c, sizeof(FRONTDOOR_CHILD));
	}

	return ok;
}

// The next line of a child that starts with prefix, within FRONTDOOR_TIMEOUT, into line; the lines before it are
// printed. False when none came or the child ended before.
static bool frontdoor_line(FRONTDOOR_CHILD *c, const char *prefix, char *line, UINT size) {
	UINT64 end = GetTickCount64() + FRONTDOOR_TIMEOUT;

	line[0] = 0;
	if (c->Output == NULL)
		return false;

	while (true) {
		char *nl = (char *)memchr(c->Buf, '\n', c->Size);

		if (nl != NULL) {
			UINT len = (UINT)(nl - c->Buf);
			UINT copy = (len > 0 && c->Buf[len - 1] == '\r' ? len - 1 : len);

			if (copy >= size)
				copy = size - 1;
			memcpy(line, c->Buf, copy);
			line[copy] = 0;
			c->Size -= len + 1;
			MoveMemory(c->Buf, nl + 1, c->Size);
			if (strncmp(line, prefix, strlen(prefix)) == 0)
				return true;
			coretest_info("process %lu: %s", c->Process.dwProcessId, line);
			continue;
		}

		DWORD avail = 0, got = 0;
		if (GetTickCount64() >= end || PeekNamedPipe(c->Output, NULL, 0, NULL, &avail, NULL) == FALSE)
			return false;
		if (avail == 0) {
			Sleep(10);
			continue;
		}

		// A line longer than the buffer is dropped
		if (c->Size == sizeof(c->Buf))
			c->Size = 0;
		DWORD room = (DWORD)(sizeof(c->Buf) - c->Size);
		if (ReadFile(c->Output, c->Buf + c->Size, (avail < room ? avail : room), &got, NULL) == FALSE)
			return false;
		c->Size += got;
	}
}

// End a child whose standard input is closed, or whose process went: its exit code, a kill when it does not end within
// FRONTDOOR_TIMEOUT; true when it ended by itself
static bool frontdoor_end(FRONTDOOR_CHILD *c, DWORD *code) {
	*code = 1;
	if (c->Process.hProcess == NULL)
		return false;

	if (c->Input != NULL) {
		CloseHandle(c->Input);
		c->Input = NULL;
	}
	bool ended = (WaitForSingleObject(c->Process.hProcess, FRONTDOOR_TIMEOUT) == WAIT_OBJECT_0);
	if (ended == false) {
		TerminateProcess(c->Process.hProcess, 1);
		WaitForSingleObject(c->Process.hProcess, INFINITE);
	}
	GetExitCodeProcess(c->Process.hProcess, code);

	CloseHandle(c->Process.hProcess);
	CloseHandle(c->Process.hThread);
	CloseHandle(c->Output);
	ZeroMemory(c, sizeof(FRONTDOOR_CHILD));

	return ended;
}

// The port and the static key of a node from its line "PORT <port> KEY <hex>"
static bool frontdoor_port_key(const char *line, USHORT *port, UCHAR *key) {
	unsigned int p = 0;
	char hex[2 * NOISE_KEY_SIZE + 1];

	if (sscanf_s(line, "PORT %u KEY %64s", &p, hex, (unsigned int)sizeof(hex)) != 2 || p == 0 || p > 65535)
		return false;

	*port = (USHORT)p;
	return (coretest_unhex(key, NOISE_KEY_SIZE, hex) == NOISE_KEY_SIZE);
}

// The configuration of an end of a test session
static void frontdoor_noise(NOISE_SESSION_CONFIG *c, const UCHAR *key, const UCHAR *remote) {
	ZeroMemory(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 1000;
	c->DeadTimeout = FRONTDOOR_TIMEOUT;
	c->RekeyInterval = 60000;
}

// TLS for the new protocol: a client of the TLS transport, which offers no ALPN and pins the node's certificate,
// completes the TLS handshake through the front door and the Noise session with the node's static key
static void frontdoor_in_node(USHORT port, const UCHAR *node_key, const char *thumbprint, UINT scope) {
	TRANSPORT_TLS_CONFIG cfg;
	NOISE_SESSION_CONFIG c;
	UCHAR key[NOISE_KEY_SIZE], pub[NOISE_KEY_SIZE];
	UCHAR buf[64];
	char address[64];
	UINT size = 0;

	TransportTlsDefaultConfig(&cfg, thumbprint, scope == CRYPTO_MACHINE);
	cfg.SetGroups = false;
	TRANSPORT *client = TransportTlsClientNew(&cfg);
	TRANSPORT_NOISE *n = (TRANSPORT_NOISE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_NOISE));

	snprintf(address, sizeof(address), "127.0.0.1:%u", (UINT)port);
	TRANSPORT_STREAM *s = (client != NULL && n != NULL ? TransportDial(client, address, NULL) : NULL);
	coretest_check(s != NULL, "TLS of the new protocol (no ALPN): the TLS handshake through the front door completes with the node's certificate, which the client pins");

	CryptoX25519GenerateKey(key, pub);
	frontdoor_noise(&c, key, node_key);
	bool connected = (s != NULL && TransportNoiseConnect(n, s, &c, FRONTDOOR_TIMEOUT));
	coretest_check(connected && (n->Session.Flags & NOISE_SESSION_ENCRYPT) == 0,
	               "... the Noise session comes up with the node's static key, bound to the TLS exporter: the TLS of the new protocol stays in the node");
	bool echoed = (connected && TransportNoiseSend(n, NOISE_RECORD_DATA, "frontdoor", 9) &&
	               TransportNoiseReceive(n, buf, sizeof(buf), &size, FRONTDOOR_TIMEOUT) == NOISE_RECEIVE_DATA && size == 9 && memcmp(buf, "frontdoor", 9) == 0);
	coretest_check(echoed, "... and carries records both ways");

	if (n != NULL) {
		TransportNoiseClose(n);
		HeapFree(GetProcessHeap(), 0, n);
	}
	TransportTlsFree(client);
	SecureZeroMemory(key, sizeof(key));
}

// TLS with another ALPN or server name, and the signature, reach their owners' processes, whatever the TCP segments
// and the records; what no owner takes and what the absent owner cannot take are closed
static void frontdoor_to_owners(USHORT port, DWORD controller, DWORD signer) {
	UCHAR *msg = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	UCHAR *rec = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	const char *both[2] = {"h2", "http/1.1"};
	const char *http11 = "http/1.1";
	const char *absent = "ranz-absent/1";
	const char *signed_data = FRONTDOOR_SIGNATURE " and then the bytes of the owner's own protocol";
	const char *http = "GET / HTTP/1.1\r\nHost: admin.frontdoor.test\r\n\r\n";
	UINT cuts[2];

	if (coretest_check(msg != NULL && rec != NULL, "the clients' buffers") == false) {
		if (msg != NULL)
			HeapFree(GetProcessHeap(), 0, msg);
		if (rec != NULL)
			HeapFree(GetProcessHeap(), 0, rec);
		return;
	}

	UINT size = frontdoor_hello(msg, "node.frontdoor.test", both, 2, 0);
	UINT rsize = frontdoor_records(rec, msg, size, 16384);
	coretest_check(frontdoor_echo(port, rec, rsize, NULL, 0, "controller", controller, NULL),
	               "TLS with ALPN h2 and http/1.1 reaches the Controller's process, which reads the ClientHello from the socket itself");

	cuts[0] = 3;
	cuts[1] = rsize / 2;
	coretest_check(frontdoor_echo(port, rec, rsize, cuts, 2, "controller", controller, NULL),
	               "... also in three TCP segments, the first of them 3 bytes: the front door waits for the whole ClientHello");

	size = frontdoor_hello(msg, NULL, &http11, 1, 0);
	rsize = frontdoor_records(rec, msg, size, 7);
	coretest_check(frontdoor_echo(port, rec, rsize, NULL, 0, "controller", controller, NULL), "... and in records of 7 bytes, with ALPN http/1.1 only");

	size = frontdoor_hello(msg, "admin.frontdoor.test", NULL, 0, 0);
	rsize = frontdoor_records(rec, msg, size, 16384);
	coretest_check(frontdoor_echo(port, rec, rsize, NULL, 0, "controller", controller, NULL), "TLS with the server name of the web UI and no ALPN reaches the Controller");

	cuts[0] = 8;
	coretest_check(frontdoor_echo(port, (const UCHAR *)signed_data, (UINT)strlen(signed_data), cuts, 1, "signature", signer, NULL),
	               "the signature reaches its owner's process, its first 8 bytes in a segment of their own; the owner reads them from the socket itself");

	coretest_check(frontdoor_dropped(port, http, (UINT)strlen(http)), "an HTTP request in plain text, which no owner takes, is closed");

	size = frontdoor_hello(msg, "node.frontdoor.test", &absent, 1, 0);
	rsize = frontdoor_records(rec, msg, size, 16384);
	coretest_check(frontdoor_dropped(port, rec, rsize), "TLS for an owner whose process does not run is closed");

	HeapFree(GetProcessHeap(), 0, rec);
	HeapFree(GetProcessHeap(), 0, msg);
}

// 256 KiB each way on a connection whose owner echoes
static bool frontdoor_bulk(SOCKET s) {
	UCHAR *out = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, FRONTDOOR_BULK);
	UCHAR *in = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, FRONTDOOR_BULK);
	bool ok = (out != NULL && in != NULL);

	for (UINT round = 0; ok && round < FRONTDOOR_ROUNDS; round++) {
		for (UINT i = 0; i < FRONTDOOR_BULK; i++)
			out[i] = (UCHAR)(i * 7 + round);
		ok = (frontdoor_send(s, out, FRONTDOOR_BULK) && frontdoor_recv_all(s, in, FRONTDOOR_BULK) && memcmp(in, out, FRONTDOOR_BULK) == 0);
	}

	if (out != NULL)
		HeapFree(GetProcessHeap(), 0, out);
	if (in != NULL)
		HeapFree(GetProcessHeap(), 0, in);

	return ok;
}

// No byte passes through the node after the handoff: a second node hands a connection to the Controller, its process is
// killed, and the connection carries 256 KiB each way between the client and the Controller, while the node's port is
// gone
static void frontdoor_after_kill(const char *node_args, DWORD controller) {
	FRONTDOOR_CHILD *doomed = (FRONTDOOR_CHILD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FRONTDOOR_CHILD));
	UCHAR *msg = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	UCHAR *rec = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FRONTDOOR_BUF);
	const char *h2 = "h2";
	char line[FRONTDOOR_LINE];
	UCHAR key[NOISE_KEY_SIZE];
	USHORT port = 0;
	SOCKET s = INVALID_SOCKET;
	DWORD code = 0;

	bool started = (doomed != NULL && msg != NULL && rec != NULL && frontdoor_start(doomed, node_args) && frontdoor_line(doomed, "PORT", line, sizeof(line)) &&
	                frontdoor_port_key(line, &port, key));
	coretest_check(started, "a second node runs, a process of its own with the same owner table");

	UINT size = (msg != NULL ? frontdoor_hello(msg, "node.frontdoor.test", &h2, 1, 0) : 0);
	UINT rsize = (rec != NULL ? frontdoor_records(rec, msg, size, 16384) : 0);
	bool handed = (started && frontdoor_echo(port, rec, rsize, NULL, 0, "controller", controller, &s));
	coretest_check(handed, "TLS with ALPN h2 through the second node reaches the Controller");

	bool killed = (started && TerminateProcess(doomed->Process.hProcess, 9) && WaitForSingleObject(doomed->Process.hProcess, FRONTDOOR_TIMEOUT) == WAIT_OBJECT_0);
	coretest_check(killed, "the second node's process is killed");

	coretest_check(handed && killed && frontdoor_bulk(s),
	               "with the node's process gone, 256 KiB go to the Controller and come back on the connection it took: no byte passes through the node after the handoff");
	SOCKET again = (killed ? frontdoor_connect(port) : INVALID_SOCKET);
	coretest_check(killed && again == INVALID_SOCKET, "... while the node's port takes no connection any more");

	if (again != INVALID_SOCKET)
		closesocket(again);
	if (s != INVALID_SOCKET)
		closesocket(s);
	if (doomed != NULL) {
		if (doomed->Process.hProcess != NULL)
			(void)frontdoor_end(doomed, &code);
		HeapFree(GetProcessHeap(), 0, doomed);
	}
	if (msg != NULL)
		HeapFree(GetProcessHeap(), 0, msg);
	if (rec != NULL)
		HeapFree(GetProcessHeap(), 0, rec);
}

// The node, the Controller and the signature owner, each a coretest process, and the checks against them
static void frontdoor_processes(const char *thumbprint, UINT scope) {
	FRONTDOOR_CHILD *children = (FRONTDOOR_CHILD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FRONTDOOR_CHILD) * 3);
	char pipes[3][FRONT_DOOR_PIPE_SIZE];
	char args[1024], line[FRONTDOOR_LINE];
	UCHAR node_key[NOISE_KEY_SIZE];
	unsigned long long st[8];
	unsigned int sessions = 0;
	USHORT port = 0;
	DWORD code = 0;

	if (coretest_check(children != NULL, "the children's buffers") == false)
		return;

	FRONTDOOR_CHILD *controller = &children[0], *signer = &children[1], *node = &children[2];
	const char *names[3] = {"controller", "signature", "absent"};
	for (UINT i = 0; i < 3; i++)
		snprintf(pipes[i], sizeof(pipes[i]), "\\\\.\\pipe\\ranz-frontdoor-%lu-%s", GetCurrentProcessId(), names[i]);

	snprintf(args, sizeof(args), "owner %s controller", pipes[0]);
	bool owners = (frontdoor_start(controller, args) && frontdoor_line(controller, "READY", line, sizeof(line)));
	snprintf(args, sizeof(args), "owner %s signature", pipes[1]);
	owners = (owners && frontdoor_start(signer, args) && frontdoor_line(signer, "READY", line, sizeof(line)));
	coretest_check(owners, "the Controller and the signature owner run, each a process of its own with its handoff pipe");

	snprintf(args, sizeof(args), "node %s %u %s %s %s", thumbprint, (scope & CRYPTO_MACHINE) != 0 ? 1u : 0u, pipes[0], pipes[1], pipes[2]);
	bool started = (owners && frontdoor_start(node, args) && frontdoor_line(node, "PORT", line, sizeof(line)) && frontdoor_port_key(line, &port, node_key));
	coretest_check(started, "the node runs, a process of its own with the front door on a test port and its TLS transport behind it");

	if (owners && started) {
		frontdoor_in_node(port, node_key, thumbprint, scope);
		frontdoor_to_owners(port, controller->Process.dwProcessId, signer->Process.dwProcessId);
		frontdoor_after_kill(args, controller->Process.dwProcessId);
	}

	// The node ends: its counters add up to the connections above
	if (node->Input != NULL) {
		CloseHandle(node->Input);
		node->Input = NULL;
	}
	bool stats = (started && frontdoor_line(node, "STATS", line, sizeof(line)) &&
	              sscanf_s(line, "STATS %llu %llu %llu %llu %llu %llu %llu %llu %u", &st[0], &st[1], &st[2], &st[3], &st[4], &st[5], &st[6], &st[7], &sessions) == 9);
	if (stats)
		coretest_info("the node's counters: %s", line);
	coretest_check(stats && st[0] == 8 && st[1] == 1 && st[2] == 1 && st[3 + FRONTDOOR_CONTROLLER] == 3 && st[3 + FRONTDOOR_WEB_UI] == 1 && st[3 + FRONTDOOR_SIGNED] == 1 &&
	                   st[3 + FRONTDOOR_NODE] == 1 && sessions == 1,
	               "the node accepted 8 connections: 3 to the Controller by ALPN, 1 by the web UI's name, 1 to the signature owner, 1 to itself with its "
	               "Noise session, 1 that no owner takes and 1 that the absent owner could not");

	bool ended = (node->Process.hProcess != NULL && frontdoor_end(node, &code) && code == 0);
	coretest_check(ended, "the node stops at the end of its input: the front door first, then its TLS transport");
	DWORD controller_code = 1, signer_code = 1;
	ended = (controller->Process.hProcess != NULL && frontdoor_end(controller, &controller_code) && controller_code == 0);
	ended = (signer->Process.hProcess != NULL && frontdoor_end(signer, &signer_code) && signer_code == 0) && ended;
	coretest_check(ended, "the Controller and the signature owner stop at the end of their input");

	HeapFree(GetProcessHeap(), 0, children);
}

void frontdoor_test() {
	WSADATA wsa;
	char thumbprint[64];
	UINT scope = coretest_scope();

	ZeroMemory(&wsa, sizeof(wsa));
	if (coretest_check(WSAStartup(MAKEWORD(2, 2), &wsa) == 0, "Winsock") == false)
		return;

	frontdoor_parser();
	frontdoor_table();
	frontdoor_message();

	// The certificate of the node's TLS: self-signed, in the store of the scope, its key in the KSP
	coretest_info("the node's certificate: %s", coretest_scope_name());
	thumbprint[0] = 0;
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(FRONTDOOR_CN, FRONTDOOR_SAN, NULL, 30, scope);
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));
	if (coretest_check(have, "the node's certificate is in the store, its key in the CNG key storage provider"))
		frontdoor_processes(thumbprint, scope);

	if (cert != NULL) {
		if (have)
			CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}

	WSACleanup();
}

//
// The children
//

// Whether the standard input of a child is still open: the test closes it to end the child
static bool frontdoor_input_open() {
	DWORD avail = 0;

	return (PeekNamedPipe(GetStdHandle(STD_INPUT_HANDLE), NULL, 0, NULL, &avail, NULL) != FALSE);
}

// One connection that the front door handed to an owner: the owner's name and process id in a line, then every byte
// that it reads, from the first, back to the client until the client closes. The first bytes come off the socket
// here: the front door only peeked at them.
static void frontdoor_serve(SOCKET s, const char *name) {
	char line[FRONTDOOR_LINE];
	DWORD timeout = FRONTDOOR_TIMEOUT;
	char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, FRONTDOOR_BULK);

	int len = snprintf(line, sizeof(line), "OWNER %s %lu\n", name, GetCurrentProcessId());
	bool ok = (buf != NULL && len > 0 && setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) == 0 && frontdoor_send(s, line, (UINT)len));
	while (ok) {
		int n = recv(s, buf, FRONTDOOR_BULK, 0);

		ok = (n > 0 && frontdoor_send(s, buf, (UINT)n));
	}

	closesocket(s);
	if (buf != NULL)
		HeapFree(GetProcessHeap(), 0, buf);
}

// An owner process: its handoff pipe, and each connection that comes through it, until its input ends
static int frontdoor_owner_child(const char *pipe, const char *name) {
	wchar_t wide[FRONT_DOOR_PIPE_SIZE];
	UINT served = 0;

	if (MultiByteToWideChar(CP_ACP, 0, pipe, -1, wide, FRONT_DOOR_PIPE_SIZE) == 0)
		return 2;

	FRONT_DOOR_PIPE *p = FrontDoorPipeNew(wide, NULL);
	if (p == NULL) {
		printf("FAILED the pipe %s could not be made\n", pipe);
		fflush(stdout);
		return 1;
	}

	printf("READY %lu\n", GetCurrentProcessId());
	fflush(stdout);

	while (frontdoor_input_open()) {
		SOCKET s = FrontDoorPipeAccept(p, FRONTDOOR_POLL);

		if (s != INVALID_SOCKET) {
			frontdoor_serve(s, name);
			served++;
		}
	}

	FrontDoorPipeFree(p);
	printf("SERVED %u\n", served);
	fflush(stdout);

	return 0;
}

// The sessions of a node: each stream that its TLS transport accepted runs the responder of a Noise session and echoes
// its records until the client closes
static DWORD WINAPI frontdoor_sessions(LPVOID param) {
	FRONTDOOR_NODE_STATE *n = (FRONTDOOR_NODE_STATE *)param;
	UCHAR *buf = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, NOISE_MAX_PAYLOAD);
	NOISE_SESSION_CONFIG c;

	while (buf != NULL && InterlockedCompareExchange(&n->Stop, 0, 0) == 0) {
		TRANSPORT_STREAM *s = TransportAccept(n->Listener, FRONTDOOR_POLL);
		if (s == NULL)
			continue;

		TRANSPORT_NOISE *t = (TRANSPORT_NOISE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TRANSPORT_NOISE));
		if (t == NULL) {
			TransportClose(s);
			continue;
		}

		frontdoor_noise(&c, n->Key, NULL);
		if (TransportNoiseAccept(t, s, &c, FRONTDOOR_TIMEOUT)) {
			TransportNoiseAcceptLogin(t);
			n->Sessions++;

			while (true) {
				UINT size = 0;
				UINT r = TransportNoiseReceive(t, buf, NOISE_MAX_PAYLOAD, &size, FRONTDOOR_TIMEOUT);

				if (r != NOISE_RECEIVE_DATA && r != NOISE_RECEIVE_CONTROL)
					break;
				TransportNoiseSend(t, (r == NOISE_RECEIVE_DATA ? NOISE_RECORD_DATA : NOISE_RECORD_CONTROL), buf, size);
			}
		}

		TransportNoiseClose(t);
		HeapFree(GetProcessHeap(), 0, t);
	}

	if (buf != NULL)
		HeapFree(GetProcessHeap(), 0, buf);

	return 0;
}

// A node process: its TLS transport with the certificate of the thumbprint, a listener of it on no socket of its own,
// and the front door on a test port with the owner table of the test, until its input ends; then its counters
static int frontdoor_node_child(const char *thumbprint, bool machine, const char *controller, const char *signature, const char *absent) {
	FRONTDOOR_NODE_STATE *n = (FRONTDOOR_NODE_STATE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FRONTDOOR_NODE_STATE));
	FRONT_DOOR_OWNER *owners = (FRONT_DOOR_OWNER *)HeapAlloc(GetProcessHeap(), 0, sizeof(FRONT_DOOR_OWNER) * FRONTDOOR_NUM_OWNERS);
	wchar_t pipes[3][FRONT_DOOR_PIPE_SIZE];
	TRANSPORT_TLS_CONFIG cfg;
	FRONT_DOOR_CONFIG fc;
	FRONT_DOOR_STATS st;
	UCHAR pub[NOISE_KEY_SIZE];
	char hex[2 * NOISE_KEY_SIZE + 1];
	TRANSPORT *tls = NULL;
	FRONT_DOOR *fd = NULL;

	bool ok = (n != NULL && owners != NULL && CryptoInit() && MultiByteToWideChar(CP_ACP, 0, controller, -1, pipes[0], FRONT_DOOR_PIPE_SIZE) != 0 &&
	           MultiByteToWideChar(CP_ACP, 0, signature, -1, pipes[1], FRONT_DOOR_PIPE_SIZE) != 0 &&
	           MultiByteToWideChar(CP_ACP, 0, absent, -1, pipes[2], FRONT_DOOR_PIPE_SIZE) != 0);
	if (ok) {
		TransportTlsDefaultConfig(&cfg, thumbprint, machine);
		cfg.SetGroups = false;
		tls = TransportTlsServerNew(&cfg);
		n->Listener = (tls != NULL ? TransportListen(tls, "") : NULL);
		ok = (n->Listener != NULL && CryptoX25519GenerateKey(n->Key, pub));
	}
	if (ok) {
		frontdoor_owners(owners, pipes[0], pipes[1], pipes[2], n);
		ZeroMemory(&fc, sizeof(fc));
		strcpy_s(fc.Address, sizeof(fc.Address), FRONTDOOR_LISTEN);
		fc.Owners = owners;
		fc.NumOwners = FRONTDOOR_NUM_OWNERS;
		fd = FrontDoorStart(&fc);
		ok = (fd != NULL);
	}

	HANDLE thread = (ok ? CreateThread(NULL, 0, frontdoor_sessions, n, 0, NULL) : NULL);
	if (thread != NULL) {
		for (UINT i = 0; i < NOISE_KEY_SIZE; i++)
			snprintf(hex + 2 * i, 3, "%02x", (unsigned int)pub[i]);
		printf("PORT %u KEY %s\n", (UINT)FrontDoorPort(fd), hex);
		fflush(stdout);

		while (frontdoor_input_open())
			Sleep(FRONTDOOR_POLL);
	} else {
		printf("FAILED the node could not start: TLS transport %u, listener %u, front door %u\n", (UINT)(tls != NULL), (UINT)(n != NULL && n->Listener != NULL), (UINT)(fd != NULL));
		fflush(stdout);
	}

	// The front door stops before the listener closes: no connection reaches a closed listener
	FrontDoorGetStats(fd, &st);
	FrontDoorStop(fd);
	if (n != NULL)
		InterlockedExchange(&n->Stop, 1);
	if (thread != NULL) {
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
		printf("STATS %llu %llu %llu %llu %llu %llu %llu %llu %u\n", st.Accepted, st.Unrouted, st.Refused, st.Handed[0], st.Handed[1], st.Handed[2], st.Handed[3],
		       st.Handed[4], n->Sessions);
		fflush(stdout);
	}
	if (n != NULL) {
		TransportCloseListener(n->Listener);
		SecureZeroMemory(n->Key, sizeof(n->Key));
		HeapFree(GetProcessHeap(), 0, n);
	}
	TransportTlsFree(tls);
	if (owners != NULL)
		HeapFree(GetProcessHeap(), 0, owners);

	return (thread != NULL ? 0 : 1);
}

int frontdoor_child(int argc, char *argv[]) {
	if (argc == 8 && strcmp(argv[2], "node") == 0)
		return frontdoor_node_child(argv[3], strcmp(argv[4], "1") == 0, argv[5], argv[6], argv[7]);
	if (argc == 5 && strcmp(argv[2], "owner") == 0)
		return frontdoor_owner_child(argv[3], argv[4]);

	printf("FAILED usage: coretest %s node <thumbprint> <machine> <controller pipe> <signature pipe> <absent pipe> | owner <pipe> <name>\n", CORETEST_FRONTDOOR_CHILD);
	return 2;
}
