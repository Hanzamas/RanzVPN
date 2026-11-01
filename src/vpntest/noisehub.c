// noisehub.c
// Named Noise-to-Hub test of vpntest ("noisehub" command, CORE-S1-2 #68)
//
// The L2 frames of a Noise session of the new core enter a Hub of the node's server role as a Session whose Connection
// is of the new type CONNECTION_NOISE (NodeAcceptSession, Cedar/NodeSession.c and ConnectionTunnel.c), and the Hub
// forwards them as it forwarded the frames of a SE-VPN session, the oracle that CORE-S8-3 (#577) retired:
// - On the Hub NOISEHUB_N of the node the sender is the Session that a client's Noise session logged in to, and the
//   receiver is an in-process session with the hub packet adapter. What each side got, byte for byte, the MAC table and
//   the results of the access list make the report of the Hub, which must be the golden file
//   noisehub/noisehub_frames.txt (golden family "noisehub"): the Hub output of the oracle, an in-process session of the
//   SE-VPN kind, at the last run against it. The Hub fills in the IPv4 header checksum 0 of one frame, so a golden
//   frame is the Hub's output, not its input.
// - The Noise path runs over the bound loopback transport, over the QUIC transport (CORE-S1-1, #67) where msquic.dll is
//   present, and over the TLS transport on Schannel (TLS-443, CORE-S2-1 #69) on a test port of the loopback interface.
// - A Tunnel of four connections carries many inner flows both ways: the frames of each flow arrive complete, in order
//   and over one connection, and the flows spread over all four (ADR-0022, multi-connection tunnels).
// - A wrong password and a join Login of a Tunnel that no Session carries are refused, and the Session of a Tunnel
//   ends once the client closed every connection.
// Print "NOISEHUB TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Node.h"
#include "Cedar/Session.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Core/Transport.h"

#include <stdio.h>

#define	NOISEHUB_HUB_N			"NOISEHUB_N"		// The Hub whose sender is the Session of a Noise session
#define	NOISEHUB_USER			"nhuser"			// The password user of the Hub
#define	NOISEHUB_PASSWORD		"NoiseHub-Pass-1"	// Its password
#define	NOISEHUB_WRONG			"NoiseHub-Wrong-1"	// No user's password
#define	NOISEHUB_RECEIVER		"receiver"			// The user name of the receivers
#define	NOISEHUB_OTHER			"someone"			// The user of access list entry 3, which no session is
#define	NOISEHUB_GOLDEN			"noisehub_frames.txt"	// The golden file of the Hub output
#define	NOISEHUB_WATCHDOG		180000				// The test process is aborted after this (ms)
#define	NOISEHUB_TIMEOUT		15000				// A handshake, a Login, a Session or a frame within this (ms)
#define	NOISEHUB_POLL			10					// ms between two looks at a queue
#define	NOISEHUB_ACCEPT			100					// ms that the accept thread waits for a stream before it looks at its halt
#define	NOISEHUB_LOOPBACK		"noisehub-node"		// The address of the node on the loopback transport
#define	NOISEHUB_QUIC			"127.0.0.1:0"		// ... and on QUIC: an ephemeral port of the loopback interface
#define	NOISEHUB_TLS			"127.0.0.1:0"		// ... and on TLS-443: an ephemeral TCP port of the loopback interface, never 443
#define	NOISEHUB_CN				L"CN=localhost"		// The subject of the QUIC server certificate
#define	NOISEHUB_SAN			L"localhost"		// Its subject alternative name
#define	NOISEHUB_FRAME_MAX		128					// Bytes of a test frame at most
#define	NOISEHUB_MARKER_SIZE	60					// Bytes of the marker frame that ends a case
#define	NOISEHUB_IP_SENDER		0x0A440001			// 10.68.0.1
#define	NOISEHUB_IP_RECEIVER	0x0A440002			// 10.68.0.2
#define	NOISEHUB_IP_UNKNOWN		0x0A440009			// 10.68.0.9, behind the MAC that no session has
#define	NOISEHUB_FLOW_PORT		20000				// The client end of inner flow f: the sender's port 20000 + f, ...
#define	NOISEHUB_RECEIVER_PORT	30000				// ... to the receiver's port 30000
#define	NOISEHUB_CONNECTIONS	4					// The connections of the Tunnel case
#define	NOISEHUB_FLOWS			64					// Its inner flows ...
#define	NOISEHUB_FLOW_FRAMES	8					// ... and the frames of each, both ways
#define	NOISEHUB_BATCH			32					// Frames that the receiver stores between two flushes of the Hub

static UCHAR noisehub_mac_sender[6] = {0x02, 0x4E, 0x48, 0x00, 0x00, 0x01};
static UCHAR noisehub_mac_receiver[6] = {0x02, 0x4E, 0x48, 0x00, 0x00, 0x02};
static UCHAR noisehub_mac_unknown[6] = {0x02, 0x4E, 0x48, 0x00, 0x00, 0x0F};	// No session has it
static UCHAR noisehub_mac_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// The state of the test
typedef struct NOISEHUB_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	NODE *Node;							// The node of the server role
	HUB *HubN;							// Its Hub NOISEHUB_N, referenced
	THREAD *IdleThread;					// The thread of the connections of the in-process sessions; it has nothing to run
	UCHAR ServerKey[NOISE_KEY_SIZE];	// The node's Noise static key ...
	UCHAR ServerPub[NOISE_KEY_SIZE];	// ... and its public half, which the client knows in advance
	UCHAR ClientKey[NOISE_KEY_SIZE];	// The client node's static key, which its first Login pins
	UCHAR ClientPub[NOISE_KEY_SIZE];
	char OutDir[MAX_SIZE];				// The output and golden directories of the golden family "noisehub"
	char GoldenDir[MAX_SIZE];
	bool Update;						// Update mode: the golden file is written, not compared
} NOISEHUB_CTX;

// The listener of the node on one transport, with its accept thread
typedef struct NOISEHUB_SERVER
{
	NOISEHUB_CTX *Ctx;
	TRANSPORT_LISTENER *Listener;
	THREAD *Thread;
	volatile bool Halt;					// Ends the accept thread; through FlagRead and FlagWrite
} NOISEHUB_SERVER;

// The two sides of the cases in the Hub. The sender is the client's Noise session; the receiver is an in-process
// session.
typedef struct NOISEHUB_PATH
{
	HUB *Hub;
	TRANSPORT_NOISE *Client;			// The client's Noise session
	SESSION *Sender;					// The sender's Session in the Hub: the Tunnel's
	SESSION *Receiver;					// The in-process receiver
} NOISEHUB_PATH;

static bool NoiseHubCheck(NOISEHUB_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool NoiseHubCheck(NOISEHUB_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so a lost wake-up is a failed test instead of a hung CI step
static DWORD WINAPI NoiseHubWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, NOISEHUB_WATCHDOG) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "NOISEHUB TEST FAILED (did not finish within %u ms)\n", NOISEHUB_WATCHDOG);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The configuration of a Noise session of the test: the static key, the responder's key on the client, short timers
static void NoiseHubConfig(NOISE_SESSION_CONFIG *c, UCHAR *key, UCHAR *remote)
{
	Zero(c, sizeof(NOISE_SESSION_CONFIG));
	c->Suite = NOISE_SUITE_IK;
	c->StaticKey = key;
	c->RemoteStatic = remote;
	c->KeepaliveInterval = 2000;
	c->DeadTimeout = NOISEHUB_TIMEOUT;
	c->RekeyInterval = 60000;
}

//
// The frames
//

// Put a 32-bit value at p, big-endian
static void NoiseHubPut32(UCHAR *p, UINT v)
{
	p[0] = (UCHAR)(v >> 24);
	p[1] = (UCHAR)(v >> 16);
	p[2] = (UCHAR)(v >> 8);
	p[3] = (UCHAR)v;
}

// An ARP request of mac and ip (host order) for target, to the broadcast address, padded to the Ethernet minimum; its
// size
static UINT NoiseHubArp(UCHAR *buf, UCHAR *mac, UINT ip, UINT target)
{
	Zero(buf, 60);
	Copy(buf, noisehub_mac_broadcast, 6);
	Copy(buf + 6, mac, 6);
	buf[12] = 0x08;								// ARP
	buf[13] = 0x06;
	buf[15] = 0x01;								// Ethernet
	buf[16] = 0x08;								// IPv4
	buf[18] = 6;
	buf[19] = 4;
	buf[21] = 0x01;								// Request
	Copy(buf + 22, mac, 6);
	NoiseHubPut32(buf + 28, ip);
	NoiseHubPut32(buf + 38, target);

	return 60;
}

// An IPv4 UDP datagram of 8 bytes (tag, then 4 bytes 0xEE) from src_mac and src:sport to dst_mac and dst:dport, the
// addresses in host order. With checksum false the IPv4 header checksum stays 0, which the Hub fills in. Its size.
static UINT NoiseHubUdp(UCHAR *buf, UCHAR *dst_mac, UCHAR *src_mac, UINT src, UINT sport, UINT dst, UINT dport, UINT tag, bool checksum)
{
	UCHAR *ip = buf + 14;
	UCHAR *udp = ip + 20;

	Zero(buf, 50);
	Copy(buf, dst_mac, 6);
	Copy(buf + 6, src_mac, 6);
	buf[12] = 0x08;								// IPv4
	buf[13] = 0x00;

	ip[0] = 0x45;								// Version 4, 20-byte header
	ip[3] = 20 + 16;							// Total length
	ip[8] = 64;									// TTL
	ip[9] = IP_PROTO_UDP;
	NoiseHubPut32(ip + 12, src);
	NoiseHubPut32(ip + 16, dst);
	if (checksum)
	{
		USHORT sum = IpChecksum(ip, 20);
		Copy(ip + 10, &sum, sizeof(USHORT));
	}

	udp[0] = (UCHAR)(sport >> 8);
	udp[1] = (UCHAR)sport;
	udp[2] = (UCHAR)(dport >> 8);
	udp[3] = (UCHAR)dport;
	udp[5] = 16;								// Length; checksum 0 (none)
	NoiseHubPut32(udp + 8, tag);
	for (UINT i = 12; i < 16; i++)
	{
		udp[i] = 0xEE;
	}

	return 50;
}

// The marker that ends case seq: a frame of EtherType 0x88B5 (IEEE local experimental) from src_mac to dst_mac with
// "NHMK" and seq. No entry of the access list matches it, as it is no IP. Its size.
static UINT NoiseHubMarker(UCHAR *buf, UCHAR *dst_mac, UCHAR *src_mac, UINT seq)
{
	Zero(buf, NOISEHUB_MARKER_SIZE);
	Copy(buf, dst_mac, 6);
	Copy(buf + 6, src_mac, 6);
	buf[12] = 0x88;
	buf[13] = 0xB5;
	Copy(buf + 14, "NHMK", 4);
	NoiseHubPut32(buf + 18, seq);

	return NOISEHUB_MARKER_SIZE;
}

// Whether a frame is the marker of case seq
static bool NoiseHubIsMarker(UCHAR *frame, UINT size, UINT seq)
{
	UCHAR expect[4];

	NoiseHubPut32(expect, seq);

	return size >= 22 && frame[12] == 0x88 && frame[13] == 0xB5 && Cmp(frame + 14, "NHMK", 4) == 0 && Cmp(frame + 18, expect, 4) == 0;
}

// Frame seq of inner flow f: a UDP datagram over IPv4 from the sender's address, port 20000 + f, to the receiver's port
// 30000, or back the other way; its size. The flows differ by their port alone, as the flows of one client do: the
// Session of a client node asks for no routing, so the Hub learns IP_MIN_LIMIT_COUNT IPv4 addresses of it at most and
// drops a frame from another (IpTableSessionAtLimit), as it did for the oracle.
static UINT NoiseHubFlowFrame(UCHAR *buf, UINT f, UINT seq, bool back)
{
	UINT tag = (f << 16) | seq;

	if (back)
	{
		return NoiseHubUdp(buf, noisehub_mac_sender, noisehub_mac_receiver, NOISEHUB_IP_RECEIVER, NOISEHUB_RECEIVER_PORT,
			NOISEHUB_IP_SENDER, NOISEHUB_FLOW_PORT + f, tag, true);
	}

	return NoiseHubUdp(buf, noisehub_mac_receiver, noisehub_mac_sender, NOISEHUB_IP_SENDER, NOISEHUB_FLOW_PORT + f,
		NOISEHUB_IP_RECEIVER, NOISEHUB_RECEIVER_PORT, tag, true);
}

// Whether a frame belongs to one of the inner flows (back: on its way to the client), with its flow and frame number
static bool NoiseHubIsFlowFrame(UCHAR *frame, UINT size, bool back, UINT *f, UINT *seq)
{
	if (size < 50 || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != IP_PROTO_UDP)
	{
		return false;
	}

	UINT sport = ((UINT)frame[34] << 8) | frame[35];
	UINT dport = ((UINT)frame[36] << 8) | frame[37];
	UINT flow_port = (back ? dport : sport);
	UINT receiver_port = (back ? sport : dport);

	if (receiver_port != NOISEHUB_RECEIVER_PORT || flow_port < NOISEHUB_FLOW_PORT || flow_port >= NOISEHUB_FLOW_PORT + NOISEHUB_FLOWS)
	{
		return false;
	}

	*f = flow_port - NOISEHUB_FLOW_PORT;
	*seq = ((UINT)frame[44] << 8) | frame[45];

	return true;
}

//
// The sessions
//

// The connections of the in-process sessions have nothing to run
static void NoiseHubIdleThread(THREAD *thread, void *param)
{
}

// An in-process session of a Hub with the hub packet adapter, as the server session of a SE-VPN login runs it: a copy
// of policy, the user and group, a normal client
static SESSION *NoiseHubNewSession(NOISEHUB_CTX *ctx, HUB *h, char *username, char *realname, char *groupname, POLICY *policy)
{
	CONNECTION *c = NewServerConnection(h->Cedar, NULL, ctx->IdleThread);
	SESSION *s = NewServerSession(h->Cedar, c, h, username, ClonePolicy(policy));

	c->Session = s;
	ReleaseConnection(c);

	s->Username = CopyStr(username);
	StrCpy(s->UserNameReal, sizeof(s->UserNameReal), realname);
	StrCpy(s->GroupName, sizeof(s->GroupName), groupname);
	s->NormalClient = true;
	s->VLanId = s->Policy->VLanId;
	s->IsBridgeMode = (s->Policy->NoBridge == false) || (s->Policy->NoRouting == false);
	s->IsMonitorMode = s->Policy->MonitorPort;

	s->PacketAdapter->Init(s);

	return s;
}

// Release an in-process session in the order of the end of SessionMain: leave the Hub, free the packet adapter, release
static void NoiseHubFreeSession(SESSION *s)
{
	if (s == NULL)
	{
		return;
	}

	DelSession(s->Hub, s);
	s->PacketAdapter->Free(s);
	ReleaseSession(s);
}

// Hand a frame of an in-process session to the Hub as SessionMain does (the Hub takes the copy); flush: the end of a
// receive loop, which sends the frames on
static void NoiseHubStore(SESSION *s, UCHAR *frame, UINT size, bool flush)
{
	s->PacketAdapter->PutPacket(s, Clone(frame, size), size);

	if (flush)
	{
		s->PacketAdapter->PutPacket(s, NULL, 0);
	}
}

// The number of the Hub's Sessions whose Connection carries a Tunnel
static UINT NoiseHubNumTunnels(HUB *h)
{
	UINT num = 0;

	LockList(h->SessionList);
	{
		for (UINT i = 0; i < LIST_NUM(h->SessionList); i++)
		{
			SESSION *s = LIST_DATA(h->SessionList, i);

			if (s->Connection != NULL && s->Connection->Protocol == CONNECTION_NOISE)
			{
				num++;
			}
		}
	}
	UnlockList(h->SessionList);

	return num;
}

// The Session of a Tunnel of the Hub, referenced, once the Hub has one whose Tunnel runs (with a connection up, so the
// node set the Session up completely) within NOISEHUB_TIMEOUT; NULL when it has none
static SESSION *NoiseHubWaitTunnel(HUB *h)
{
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;

	while (true)
	{
		SESSION *ret = NULL;

		LockList(h->SessionList);
		{
			for (UINT i = 0; i < LIST_NUM(h->SessionList) && ret == NULL; i++)
			{
				SESSION *s = LIST_DATA(h->SessionList, i);
				TUNNEL_STATUS st;

				if (s->Connection == NULL || s->Connection->Protocol != CONNECTION_NOISE)
				{
					continue;
				}

				TunnelGetStatus(s->Connection, &st);
				if (st.NumConnections != 0)
				{
					AddRef(s->ref);
					ret = s;
				}
			}
		}
		UnlockList(h->SessionList);

		if (ret != NULL || Tick64() >= end)
		{
			return ret;
		}

		SleepThread(NOISEHUB_POLL);
	}
}

// Whether the Tunnel of a Session has num connections up within NOISEHUB_TIMEOUT
static bool NoiseHubWaitConnections(SESSION *s, UINT num)
{
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;

	while (true)
	{
		TUNNEL_STATUS st;

		TunnelGetStatus(s->Connection, &st);
		if (st.NumConnections == num)
		{
			return true;
		}
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(NOISEHUB_POLL);
	}
}

// Whether the Hub's Sessions of Tunnels are gone within NOISEHUB_TIMEOUT
static bool NoiseHubWaitNoTunnel(HUB *h)
{
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;

	while (NoiseHubNumTunnels(h) != 0)
	{
		if (Tick64() >= end)
		{
			return false;
		}

		SleepThread(NOISEHUB_POLL);
	}

	return true;
}

//
// The node and its listener
//

// A new empty data directory with the configuration store of the server role: one worker, the Hub as an online L2
// network, and the password user in it, so that a Login pins the client's key
static void NoiseHubNewDir(wchar_t *dir, UINT size)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	CS_USER u;

	UniFormat(tmp, sizeof(tmp), L"noisehub_test_%u", Rand32());
	ConbinePathW(dir, size, MsGetMyTempDirW(), tmp);
	MakeDirExW(dir);

	ConbinePathW(path, sizeof(path), dir, CS_FILE_NAME);
	CONFIG_STORE *s = CsOpen(path);
	if (s == NULL)
	{
		Print("  configuration store %S cannot be opened\n", path);
		return;
	}

	CsSetSetting(s, NODE_SETTING_ROLES, "server");
	CsSetSetting(s, NODE_SETTING_WORKERS, "1");
	CsAddNetwork(s, NOISEHUB_HUB_N, CS_MODE_L2, true);

	Zero(&u, sizeof(u));
	StrCpy(u.Network, sizeof(u.Network), NOISEHUB_HUB_N);
	StrCpy(u.Name, sizeof(u.Name), NOISEHUB_USER);
	u.AuthType = AUTHTYPE_PASSWORD;
	CsAddUser(s, &u);

	CsClose(s);
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void NoiseHubDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0; d != NULL && i < d->NumFiles; i++)
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

// One entry of the access list of the cases: discard the UDP datagrams over IPv4 to port, of the user username, or of
// every user for NULL
static void NoiseHubAddAccess(HUB *h, UINT priority, UINT port, char *username)
{
	ACCESS a;

	Zero(&a, sizeof(a));
	a.Active = true;
	a.Priority = priority;
	a.Discard = true;
	a.Protocol = IP_PROTO_UDP;
	a.DestPortStart = port;
	a.DestPortEnd = port;
	if (username != NULL)
	{
		StrCpy(a.SrcUsername, sizeof(a.SrcUsername), username);
	}

	AddAccessListEx(h, &a, false, false);
}

// The Hub of the node as the test needs it, referenced: the password user, no ARP or neighbor polling of the watchdog
// (it would send probes into the sessions), no log files, and the access list of the cases
static HUB *NoiseHubPrepare(NOISEHUB_CTX *ctx, char *name)
{
	HUB *h = NodeGetHub(ctx->Node, name);

	if (h == NULL)
	{
		return NULL;
	}

	USER *u = NewUser(NOISEHUB_USER, L"", L"", AUTHTYPE_PASSWORD, NewPasswordAuthData(NOISEHUB_USER, NOISEHUB_PASSWORD));
	AcLock(h);
	AcAddUser(h, u);
	AcUnlock(h);
	ReleaseUser(u);

	h->Option->NoArpPolling = true;
	h->Option->NoIPv6AddrPolling = true;
	h->LogSetting.SavePacketLog = false;
	h->LogSetting.SaveSecurityLog = false;

	NoiseHubAddAccess(h, 1, 9, NULL);
	NoiseHubAddAccess(h, 2, 7, NOISEHUB_USER);
	NoiseHubAddAccess(h, 3, 13, NOISEHUB_OTHER);

	return h;
}

// The accept thread of a listener of the node: each stream that dials it runs the responder of a Noise session with
// the node's static key, then the node takes the session (NodeAcceptSession), until the listener stops
static void NoiseHubAcceptThread(THREAD *thread, void *param)
{
	NOISEHUB_SERVER *srv = (NOISEHUB_SERVER *)param;
	NOISE_SESSION_CONFIG c;

	NoiseHubConfig(&c, srv->Ctx->ServerKey, NULL);
	NoticeThreadInit(thread);

	while (FlagRead(&srv->Halt) == false)
	{
		TRANSPORT_STREAM *stream = TransportAccept(srv->Listener, NOISEHUB_ACCEPT);

		if (stream == NULL)
		{
			continue;
		}

		TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
		if (TransportNoiseAccept(n, stream, &c, NOISEHUB_TIMEOUT) == false)
		{
			Free(n);
			continue;
		}

		// The node takes n, also when it refuses the Login
		NodeAcceptSession(srv->Ctx->Node, n, NOISEHUB_TIMEOUT);
	}
}

// The listener of the node on a transport and its accept thread; NULL when it cannot listen
static NOISEHUB_SERVER *NoiseHubListen(NOISEHUB_CTX *ctx, TRANSPORT *t, char *address)
{
	TRANSPORT_LISTENER *l = TransportListen(t, address);

	if (l == NULL)
	{
		return NULL;
	}

	NOISEHUB_SERVER *srv = ZeroMalloc(sizeof(NOISEHUB_SERVER));
	srv->Ctx = ctx;
	srv->Listener = l;
	srv->Thread = NewThread(NoiseHubAcceptThread, srv);
	WaitThreadInit(srv->Thread);

	return srv;
}

// Stop the accept thread of a listener, then close it
static void NoiseHubStopListen(NOISEHUB_SERVER *srv)
{
	if (srv == NULL)
	{
		return;
	}

	FlagWrite(&srv->Halt, true);
	WaitThread(srv->Thread, INFINITE);
	ReleaseThread(srv->Thread);
	TransportCloseListener(srv->Listener);
	Free(srv);
}

// A connection of the client node to the node on a transport: the Noise session with the client's static key, then its
// Login to NOISEHUB_N: a password Login, or a join Login of the Tunnel id join. NULL when the connection or the
// handshake fails.
static TRANSPORT_NOISE *NoiseHubConnect(NOISEHUB_CTX *ctx, TRANSPORT *client, char *address, char *password, UCHAR *join)
{
	NOISE_SESSION_CONFIG c;
	NOISE_LOGIN login;
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT size = 0;

	NoiseHubConfig(&c, ctx->ClientKey, ctx->ServerPub);
	TRANSPORT_STREAM *stream = TransportDial(client, address, NULL);
	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));

	if (stream == NULL || TransportNoiseConnect(n, stream, &c, NOISEHUB_TIMEOUT) == false)
	{
		Free(n);
		Free(buf);
		return NULL;
	}

	Zero(&login, sizeof(login));
	login.Method = (join != NULL ? NOISE_LOGIN_JOIN : NOISE_LOGIN_PASSWORD);
	StrCpy(login.HubName, sizeof(login.HubName), NOISEHUB_HUB_N);
	StrCpy(login.UserName, sizeof(login.UserName), NOISEHUB_USER);
	if (join != NULL)
	{
		Copy(login.TunnelId, join, NOISE_TUNNEL_ID_SIZE);
	}
	else
	{
		StrCpy(login.Password, sizeof(login.Password), password);
	}

	bool sent = NoiseLoginEncode(&login, buf, NOISE_MAX_PAYLOAD, &size) && TransportNoiseSend(n, NOISE_RECORD_CONTROL, buf, size);
	Zero(&login, sizeof(login));
	Free(buf);

	if (sent == false)
	{
		TransportNoiseClose(n);
		Free(n);
		return NULL;
	}

	return n;
}

// Close and free a Noise session of the client
static void NoiseHubClose(TRANSPORT_NOISE *n)
{
	if (n == NULL)
	{
		return;
	}

	TransportNoiseClose(n);
	Free(n);
}

// Whether the node closed a Noise session of the client within NOISEHUB_TIMEOUT; the session is closed and freed then
static bool NoiseHubWaitClose(TRANSPORT_NOISE *n)
{
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;
	bool closed = false;

	while (closed == false && Tick64() < end)
	{
		UINT size = 0;
		UINT ret = TransportNoiseReceive(n, buf, NOISE_MAX_PAYLOAD, &size, NOISEHUB_POLL);

		closed = (ret == NOISE_RECEIVE_CLOSE || ret == NOISE_RECEIVE_ERROR);
	}

	Free(buf);
	NoiseHubClose(n);

	return closed;
}

//
// The cases of the golden file
//

// Send one frame into the Hub from a side of the path: the sender's over the client's Noise session, the receiver's
// through the hub packet adapter of its in-process session, as SessionMain hands it over
static void NoiseHubSend(NOISEHUB_PATH *p, bool sender, UCHAR *frame, UINT size)
{
	if (sender)
	{
		TransportNoiseSend(p->Client, NOISE_RECORD_DATA, frame, size);
		return;
	}

	NoiseHubStore(p->Receiver, frame, size, true);
}

// The next frame that a side of the path got within timeout, into buf (NOISE_MAX_PAYLOAD bytes); its size, 0 for none
static UINT NoiseHubTake(NOISEHUB_PATH *p, bool sender, UCHAR *buf, UINT timeout)
{
	UINT64 end = Tick64() + timeout;

	while (true)
	{
		if (sender)
		{
			UINT size = 0;
			UINT ret = TransportNoiseReceive(p->Client, buf, NOISE_MAX_PAYLOAD, &size, NOISEHUB_POLL);

			if (ret == NOISE_RECEIVE_DATA)
			{
				return size;
			}
			if (ret != NOISE_RECEIVE_NONE && ret != NOISE_RECEIVE_CONTROL)
			{
				return 0;
			}
		}
		else
		{
			SESSION *s = p->Receiver;
			void *data = NULL;
			UINT size = s->PacketAdapter->GetNextPacket(s, &data);

			if (size != 0)
			{
				Copy(buf, data, MIN(size, NOISE_MAX_PAYLOAD));
				Free(data);
				return size;
			}

			SleepThread(NOISEHUB_POLL);
		}

		if (Tick64() >= end)
		{
			return 0;
		}
	}
}

// What a side of the path got up to the marker of case seq: each frame before the marker goes to the report as
// "<seq> <name>: <side> got <hex>", none as "<seq> <name>: <side> got nothing". false when the marker did not come.
static bool NoiseHubCollect(NOISEHUB_PATH *p, bool sender, UINT seq, char *name, BUF *report)
{
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	char hex[NOISEHUB_FRAME_MAX * 2 + 1];
	char line[MAX_SIZE * 2];
	char *side = (sender ? "sender" : "receiver");
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;
	UINT num = 0;
	bool marker = false;

	while (marker == false)
	{
		UINT64 now = Tick64();
		UINT size = (now < end ? NoiseHubTake(p, sender, buf, (UINT)(end - now)) : 0);

		if (size == 0)
		{
			break;
		}

		if (NoiseHubIsMarker(buf, size, seq))
		{
			marker = true;
		}
		else
		{
			BinToStr(hex, sizeof(hex), buf, MIN(size, NOISEHUB_FRAME_MAX));
			Format(line, sizeof(line), "%u %s: %s got %s\n", seq, name, side, hex);
			WriteBuf(report, line, StrLen(line));
			num++;
		}
	}

	if (num == 0)
	{
		Format(line, sizeof(line), "%u %s: %s got nothing\n", seq, name, side);
		WriteBuf(report, line, StrLen(line));
	}

	Free(buf);

	return marker;
}

// One case: frame (none for NULL), then the marker of the case, go into the Hub from one side of the path, and what the
// other side got up to the marker goes to the report. false when the marker did not come.
static bool NoiseHubCase(NOISEHUB_PATH *p, bool from_sender, UINT seq, char *name, UCHAR *frame, UINT size, BUF *report)
{
	UCHAR marker[NOISEHUB_MARKER_SIZE];
	UCHAR *to = (from_sender ? noisehub_mac_receiver : noisehub_mac_sender);
	UCHAR *from = (from_sender ? noisehub_mac_sender : noisehub_mac_receiver);
	UINT marker_size = NoiseHubMarker(marker, to, from, seq);

	if (frame != NULL)
	{
		NoiseHubSend(p, from_sender, frame, size);
	}
	NoiseHubSend(p, from_sender, marker, marker_size);

	return NoiseHubCollect(p, from_sender == false, seq, name, report);
}

// The sender's Session as the Hub admitted it: its user and group, the policy items that its forwarding reads, its
// modes
static void NoiseHubSessionLine(SESSION *s, BUF *report)
{
	char line[MAX_SIZE * 2];
	POLICY *y = s->Policy;

	Format(line, sizeof(line), "sender: user %s, group %s, Access %u, NoBridge %u, NoRouting %u, MonitorPort %u, MaxConnection %u, TimeOut %u, VLanId %u, bridge mode %u, monitor mode %u\n",
		s->Username, IsEmptyStr(s->GroupName) ? "-" : s->GroupName, (UINT)y->Access, (UINT)y->NoBridge, (UINT)y->NoRouting,
		(UINT)y->MonitorPort, y->MaxConnection, y->TimeOut, y->VLanId, (UINT)s->IsBridgeMode, (UINT)s->IsMonitorMode);
	WriteBuf(report, line, StrLen(line));
}

// The MAC table of the Hub of the path, sorted: each address, its VLAN and the side whose session the Hub learnt it on
static void NoiseHubMacLines(NOISEHUB_PATH *p, BUF *report)
{
	LIST *lines = NewListFast(CompareStr);
	UINT num = 0;

	HubLockTables(p->Hub);
	{
		MAC_TABLE_ENTRY **pp = MacTableEnum(p->Hub, &num);

		for (UINT i = 0; i < num; i++)
		{
			char mac[MAX_SIZE];
			char line[MAX_SIZE];
			SESSION *s = pp[i]->Session;
			char *side = (s == p->Sender ? "sender" : (s == p->Receiver ? "receiver" : "another session"));

			MacToStr(mac, sizeof(mac), pp[i]->MacAddress);
			Format(line, sizeof(line), "mac %s vlan %u: %s\n", mac, pp[i]->VlanId, side);
			Insert(lines, CopyStr(line));
		}

		Free(pp);
	}
	HubUnlockTables(p->Hub);

	for (UINT i = 0; i < LIST_NUM(lines); i++)
	{
		char *line = LIST_DATA(lines, i);

		WriteBuf(report, line, StrLen(line));
		Free(line);
	}

	ReleaseList(lines);
}

// The cases on one path, and its report: the sender's Session, what each side got case by case, the MAC table.
// *complete: every case ended with its marker.
static char *NoiseHubReport(NOISEHUB_PATH *p, bool *complete)
{
	BUF *report = NewBuf();
	UCHAR frame[NOISEHUB_FRAME_MAX];
	UINT size;
	bool ok = true;

	NoiseHubSessionLine(p->Sender, report);

	// The receiver's ARP request reaches the sender; the Hub learns the receiver's MAC
	size = NoiseHubArp(frame, noisehub_mac_receiver, NOISEHUB_IP_RECEIVER, NOISEHUB_IP_SENDER);
	ok = NoiseHubCase(p, false, 1, "arp_request_of_receiver", frame, size, report) && ok;

	// A datagram whose IPv4 header checksum is 0: the Hub fills it in on the way
	size = NoiseHubUdp(frame, noisehub_mac_receiver, noisehub_mac_sender, NOISEHUB_IP_SENDER, 40000, NOISEHUB_IP_RECEIVER, 40001, 2, false);
	ok = NoiseHubCase(p, true, 2, "udp_to_receiver_checksum_0", frame, size, report) && ok;

	size = NoiseHubArp(frame, noisehub_mac_sender, NOISEHUB_IP_SENDER, NOISEHUB_IP_RECEIVER);
	ok = NoiseHubCase(p, true, 3, "arp_request_of_sender", frame, size, report) && ok;

	// To a MAC that no session has: the Hub floods it
	size = NoiseHubUdp(frame, noisehub_mac_unknown, noisehub_mac_sender, NOISEHUB_IP_SENDER, 40000, NOISEHUB_IP_UNKNOWN, 40001, 4, true);
	ok = NoiseHubCase(p, true, 4, "udp_to_unknown_mac", frame, size, report) && ok;

	// The access list discards port 9 of every user and port 7 of the sender's user, and not port 13, which it
	// discards for another user only
	size = NoiseHubUdp(frame, noisehub_mac_receiver, noisehub_mac_sender, NOISEHUB_IP_SENDER, 40000, NOISEHUB_IP_RECEIVER, 9, 5, true);
	ok = NoiseHubCase(p, true, 5, "access_discard_port_9", frame, size, report) && ok;
	size = NoiseHubUdp(frame, noisehub_mac_receiver, noisehub_mac_sender, NOISEHUB_IP_SENDER, 40000, NOISEHUB_IP_RECEIVER, 7, 6, true);
	ok = NoiseHubCase(p, true, 6, "access_discard_user_port_7", frame, size, report) && ok;
	size = NoiseHubUdp(frame, noisehub_mac_receiver, noisehub_mac_sender, NOISEHUB_IP_SENDER, 40000, NOISEHUB_IP_RECEIVER, 13, 7, true);
	ok = NoiseHubCase(p, true, 7, "access_other_user_port_13", frame, size, report) && ok;

	// The receiver's datagram to the sender's MAC, which the Hub learnt
	size = NoiseHubUdp(frame, noisehub_mac_sender, noisehub_mac_receiver, NOISEHUB_IP_RECEIVER, 40001, NOISEHUB_IP_SENDER, 40000, 8, true);
	ok = NoiseHubCase(p, false, 8, "udp_to_sender", frame, size, report) && ok;

	// Nothing else came to either side
	ok = NoiseHubCase(p, true, 9, "nothing_more", NULL, 0, report) && ok;
	ok = NoiseHubCase(p, false, 10, "nothing_more", NULL, 0, report) && ok;

	NoiseHubMacLines(p, report);

	*complete = ok;

	char *ret = HarnessBufToStr(report);
	FreeBuf(report);

	return ret;
}

// Compare a report with the golden file of the Hub output (in update mode: write it)
static void NoiseHubGolden(NOISEHUB_CTX *ctx, char *report, char *what)
{
	HARNESS h;

	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, NOISEHUB_GOLDEN, report, ctx->Update);
	NoiseHubCheck(ctx, h.NumFail == 0, what, "it differs from the golden file %s (the diff is above)", NOISEHUB_GOLDEN);
}

// The cases on the Noise path over one transport: a client logs in to NOISEHUB_N, its frames go through the Session of
// its Tunnel, and the report must be the golden file, the Hub output of the oracle at the last run against it. The
// Session ends once the client closes.
static void NoiseHubFrames(NOISEHUB_CTX *ctx, TRANSPORT *client, char *address, char *what)
{
	char tmp[MAX_SIZE];
	bool complete = false;

	TRANSPORT_NOISE *n = NoiseHubConnect(ctx, client, address, NOISEHUB_PASSWORD, NULL);
	SESSION *s = (n != NULL ? NoiseHubWaitTunnel(ctx->HubN) : NULL);

	Format(tmp, sizeof(tmp), "%s: the Login passes Sam and the Noise session enters %s as a Session of the connection type CONNECTION_NOISE", what, NOISEHUB_HUB_N);
	if (NoiseHubCheck(ctx, s != NULL, tmp, "no Session of a Tunnel (the client %s)", n != NULL ? "connected" : "did not connect"))
	{
		NOISEHUB_PATH p;

		Zero(&p, sizeof(p));
		p.Hub = ctx->HubN;
		p.Client = n;
		p.Sender = s;
		p.Receiver = NoiseHubNewSession(ctx, ctx->HubN, NOISEHUB_RECEIVER, NOISEHUB_RECEIVER, "", GetDefaultPolicy());

		char *report = NoiseHubReport(&p, &complete);

		Format(tmp, sizeof(tmp), "%s: every case ends with its marker", what);
		NoiseHubCheck(ctx, complete, tmp, "a marker did not come within %u ms", NOISEHUB_TIMEOUT);

		Format(tmp, sizeof(tmp), "%s: the Hub output of the Noise path matches the golden file %s, byte for byte: forwarding, MAC learning, access list", what, NOISEHUB_GOLDEN);
		NoiseHubGolden(ctx, report, tmp);

		Free(report);
		NoiseHubFreeSession(p.Receiver);
	}

	NoiseHubClose(n);
	Format(tmp, sizeof(tmp), "%s: the Session ends once the client closed its connection", what);
	NoiseHubCheck(ctx, NoiseHubWaitNoTunnel(ctx->HubN), tmp, "a Session of a Tunnel is still in %s", NOISEHUB_HUB_N);

	if (s != NULL)
	{
		ReleaseSession(s);
	}
}

// A Login that the node refuses closes the session and starts no Session: a wrong password, and a join Login of a
// Tunnel that no Session carries
static void NoiseHubRefused(NOISEHUB_CTX *ctx, TRANSPORT *client, char *address, char *what)
{
	UCHAR id[NOISE_TUNNEL_ID_SIZE];
	char tmp[MAX_SIZE];

	TRANSPORT_NOISE *n = NoiseHubConnect(ctx, client, address, NOISEHUB_WRONG, NULL);
	bool connected = (n != NULL);
	bool refused = (connected && NoiseHubWaitClose(n) && NoiseHubNumTunnels(ctx->HubN) == 0);
	Format(tmp, sizeof(tmp), "%s: a wrong password is refused: the node closes the session, no Session enters the Hub", what);
	NoiseHubCheck(ctx, refused, tmp, "the client %s", connected ? "was not closed, or a Session entered the Hub" : "did not connect");

	CryptoRandom(id, sizeof(id));
	n = NoiseHubConnect(ctx, client, address, NULL, id);
	connected = (n != NULL);
	refused = (connected && NoiseHubWaitClose(n) && NoiseHubNumTunnels(ctx->HubN) == 0);
	Format(tmp, sizeof(tmp), "%s: a join Login of a Tunnel that no Session carries is refused", what);
	NoiseHubCheck(ctx, refused, tmp, "the client %s", connected ? "was not closed, or a Session entered the Hub" : "did not connect");
}

// The flow frames that the receiver got within NOISEHUB_TIMEOUT, until every frame of every flow came: frame seq of
// flow f must come as frame next[f]; *in_order is cleared by one that does not. The number of flow frames.
static UINT NoiseHubReceiverFlows(SESSION *r, UINT *next, bool *in_order)
{
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;
	UINT num = 0;

	*in_order = true;
	Zero(next, sizeof(UINT) * NOISEHUB_FLOWS);

	while (num < NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES && Tick64() < end)
	{
		void *data = NULL;
		UINT size = r->PacketAdapter->GetNextPacket(r, &data);
		UINT f = 0, seq = 0;

		if (size == 0)
		{
			SleepThread(NOISEHUB_POLL);
			continue;
		}

		if (NoiseHubIsFlowFrame((UCHAR *)data, size, false, &f, &seq))
		{
			if (seq != next[f])
			{
				*in_order = false;
			}
			next[f] = seq + 1;
			num++;
		}

		Free(data);
	}

	return num;
}

// The flow frames that the client got back over its connections within NOISEHUB_TIMEOUT, taken from each connection in
// turn, until every frame of every flow came: frame seq of flow f must come as frame next[f] (else *in_order is
// cleared) and over the connection route[f] of the flow's first frame (else *one_connection is cleared); got[i] counts
// the flow frames of connection i. The number of flow frames.
static UINT NoiseHubClientFlows(TRANSPORT_NOISE **conns, UINT *next, UINT *route, UINT64 *got, bool *in_order, bool *one_connection)
{
	UCHAR *buf = ZeroMalloc(NOISE_MAX_PAYLOAD);
	UINT64 end = Tick64() + NOISEHUB_TIMEOUT;
	UINT num = 0;

	*in_order = true;
	*one_connection = true;
	Zero(next, sizeof(UINT) * NOISEHUB_FLOWS);
	for (UINT f = 0; f < NOISEHUB_FLOWS; f++)
	{
		route[f] = NOISEHUB_CONNECTIONS;
	}

	while (num < NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES && Tick64() < end)
	{
		for (UINT i = 0; i < NOISEHUB_CONNECTIONS; i++)
		{
			UINT size = 0;
			UINT f = 0, seq = 0;

			if (TransportNoiseReceive(conns[i], buf, NOISE_MAX_PAYLOAD, &size, 1) != NOISE_RECEIVE_DATA || NoiseHubIsFlowFrame(buf, size, true, &f, &seq) == false)
			{
				continue;
			}

			if (seq != next[f])
			{
				*in_order = false;
			}
			if (route[f] == NOISEHUB_CONNECTIONS)
			{
				route[f] = i;
			}
			else if (route[f] != i)
			{
				*one_connection = false;
			}
			next[f] = seq + 1;
			got[i]++;
			num++;
		}
	}

	Free(buf);

	return num;
}

// The Tunnel case: a client Tunnel of NOISEHUB_CONNECTIONS connections carries NOISEHUB_FLOWS inner flows to the
// receiver and back, each frame over the connection that its flow hash selects. Each flow arrives complete, in order and
// over one connection, and the flows spread over every connection both ways. The Session ends once the client closed
// every connection.
static void NoiseHubTunnel(NOISEHUB_CTX *ctx, TRANSPORT *client, char *address, char *what)
{
	TRANSPORT_NOISE *conns[NOISEHUB_CONNECTIONS];
	NOISE_TUNNEL tunnel;
	UCHAR id[NOISE_TUNNEL_ID_SIZE];
	UCHAR frame[NOISEHUB_FRAME_MAX];
	UINT next[NOISEHUB_FLOWS];
	UINT route[NOISEHUB_FLOWS];
	UINT64 sent[NOISEHUB_CONNECTIONS];
	UINT64 got[NOISEHUB_CONNECTIONS];
	char tmp[MAX_SIZE];
	bool joined = false;

	Zero(conns, sizeof(conns));
	Zero(sent, sizeof(sent));
	Zero(got, sizeof(got));

	// Connection 0 logs in; the others join its Tunnel by the Tunnel id, on the client and on the node
	conns[0] = NoiseHubConnect(ctx, client, address, NOISEHUB_PASSWORD, NULL);
	SESSION *s = (conns[0] != NULL ? NoiseHubWaitTunnel(ctx->HubN) : NULL);
	if (s != NULL && NoiseTunnelId(&conns[0]->Session, id) && NoiseTunnelInit(&tunnel, &conns[0]->Session, NOISEHUB_CONNECTIONS))
	{
		joined = true;
		for (UINT i = 1; i < NOISEHUB_CONNECTIONS; i++)
		{
			conns[i] = NoiseHubConnect(ctx, client, address, NULL, id);
			joined = joined && conns[i] != NULL && NoiseTunnelJoin(&tunnel, i, &conns[i]->Session);
		}
	}

	Format(tmp, sizeof(tmp), "%s: a Tunnel of %u connections: the first logs in, the others join it by the Tunnel id", what, NOISEHUB_CONNECTIONS);
	if (NoiseHubCheck(ctx, joined && NoiseHubWaitConnections(s, NOISEHUB_CONNECTIONS), tmp, "%s", s == NULL ? "no Session of a Tunnel" : "the Tunnel of the Session does not have every connection"))
	{
		SESSION *r = NoiseHubNewSession(ctx, ctx->HubN, NOISEHUB_RECEIVER, NOISEHUB_RECEIVER, "", GetDefaultPolicy());
		TUNNEL_STATUS st;
		bool in_order = false, one_connection = false, spread = true;

		// The Hub learns the receiver's MAC; its ARP request reaches the client, which leaves it
		UINT size = NoiseHubArp(frame, noisehub_mac_receiver, NOISEHUB_IP_RECEIVER, NOISEHUB_IP_SENDER);
		NoiseHubStore(r, frame, size, true);

		// To the receiver: frame seq of every flow, then the next, each over the connection that its flow hash selects
		for (UINT seq = 0; seq < NOISEHUB_FLOW_FRAMES; seq++)
		{
			for (UINT f = 0; f < NOISEHUB_FLOWS; f++)
			{
				size = NoiseHubFlowFrame(frame, f, seq, false);
				NOISE_SESSION *route_to = NoiseTunnelRoute(&tunnel, NoiseTunnelFlowHash(frame, size));

				for (UINT i = 0; i < NOISEHUB_CONNECTIONS; i++)
				{
					if (route_to == &conns[i]->Session && TransportNoiseSend(conns[i], NOISE_RECORD_DATA, frame, size))
					{
						sent[i]++;
					}
				}
			}
		}

		UINT num = NoiseHubReceiverFlows(r, next, &in_order);
		Format(tmp, sizeof(tmp), "%s: %u inner flows of %u frames each reach the receiver complete and in order", what, NOISEHUB_FLOWS, NOISEHUB_FLOW_FRAMES);
		NoiseHubCheck(ctx, num == NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES && in_order, tmp, "%u of %u frames, in order %u", num, NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES, (UINT)in_order);

		TunnelGetStatus(s->Connection, &st);
		for (UINT i = 0; i < NOISEHUB_CONNECTIONS; i++)
		{
			spread = spread && sent[i] != 0 && st.Received[i] != 0;
		}
		Format(tmp, sizeof(tmp), "%s: the flows spread over all %u connections to the Hub (by the flow hash, never per frame)", what, NOISEHUB_CONNECTIONS);
		NoiseHubCheck(ctx, spread, tmp, "the client sent %I64u %I64u %I64u %I64u frames, the Tunnel received %I64u %I64u %I64u %I64u",
			sent[0], sent[1], sent[2], sent[3], st.Received[0], st.Received[1], st.Received[2], st.Received[3]);

		// Back to the client: the receiver stores frame seq of every flow, then the next
		for (UINT seq = 0; seq < NOISEHUB_FLOW_FRAMES; seq++)
		{
			for (UINT f = 0; f < NOISEHUB_FLOWS; f++)
			{
				size = NoiseHubFlowFrame(frame, f, seq, true);
				NoiseHubStore(r, frame, size, ((seq * NOISEHUB_FLOWS + f) % NOISEHUB_BATCH) == NOISEHUB_BATCH - 1);
			}
		}
		r->PacketAdapter->PutPacket(r, NULL, 0);

		num = NoiseHubClientFlows(conns, next, route, got, &in_order, &one_connection);
		Format(tmp, sizeof(tmp), "%s: back to the client, every flow comes complete, in order and over one connection", what);
		NoiseHubCheck(ctx, num == NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES && in_order && one_connection, tmp, "%u of %u frames, in order %u, one connection per flow %u",
			num, NOISEHUB_FLOWS * NOISEHUB_FLOW_FRAMES, (UINT)in_order, (UINT)one_connection);

		TunnelGetStatus(s->Connection, &st);
		spread = true;
		for (UINT i = 0; i < NOISEHUB_CONNECTIONS; i++)
		{
			spread = spread && got[i] != 0 && st.Sent[i] != 0;
		}
		Format(tmp, sizeof(tmp), "%s: back to the client, the flows spread over all %u connections of the Tunnel", what, NOISEHUB_CONNECTIONS);
		NoiseHubCheck(ctx, spread, tmp, "the Tunnel sent %I64u %I64u %I64u %I64u frames, the client got %I64u %I64u %I64u %I64u",
			st.Sent[0], st.Sent[1], st.Sent[2], st.Sent[3], got[0], got[1], got[2], got[3]);

		NoiseHubFreeSession(r);
	}

	for (UINT i = 0; i < NOISEHUB_CONNECTIONS; i++)
	{
		NoiseHubClose(conns[i]);
	}
	Format(tmp, sizeof(tmp), "%s: the Session ends once the client closed every connection of the Tunnel", what);
	NoiseHubCheck(ctx, NoiseHubWaitNoTunnel(ctx->HubN), tmp, "a Session of a Tunnel is still in %s", NOISEHUB_HUB_N);

	if (s != NULL)
	{
		ReleaseSession(s);
	}
}

// The Noise path over one transport: the cases of the golden file, the refused Logins and the Tunnel case. bound_port,
// for QUIC and TLS: the listener takes the port the system picks, which bound_port gives and the client dials.
static void NoiseHubRun(NOISEHUB_CTX *ctx, TRANSPORT *server, TRANSPORT *client, char *listen, USHORT (*bound_port)(TRANSPORT *t), char *what)
{
	char address[TRANSPORT_ADDRESS_SIZE];
	char tmp[MAX_SIZE];

	Print("[the Noise path over %s]\n", what);

	NOISEHUB_SERVER *srv = NoiseHubListen(ctx, server, listen);
	Format(tmp, sizeof(tmp), "%s: the node listens", what);
	if (NoiseHubCheck(ctx, srv != NULL, tmp, "TransportListen failed on %s", listen) == false)
	{
		return;
	}

	if (bound_port != NULL)
	{
		Format(address, sizeof(address), "127.0.0.1:%u", (UINT)bound_port(server));
	}
	else
	{
		StrCpy(address, sizeof(address), listen);
	}

	NoiseHubFrames(ctx, client, address, what);
	NoiseHubRefused(ctx, client, address, what);
	NoiseHubTunnel(ctx, client, address, what);

	NoiseHubStopListen(srv);
}

// The Noise path over QUIC (CORE-S1-1) where msquic.dll is present: the listener of the node presents a real
// certificate of the store, which the client pins
static void NoiseHubQuic(NOISEHUB_CTX *ctx)
{
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	if (TransportQuicAvailable() == false)
	{
		Print("  msquic.dll is not present: the QUIC transport cannot run; the Noise path over QUIC is skipped\n");
		return;
	}

	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(NOISEHUB_CN, NOISEHUB_SAN, NULL, 30, scope);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));

	if (NoiseHubCheck(ctx, have_cert, "QUIC: a self-signed ECDSA P-256 certificate in the My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed"))
	{
		TRANSPORT_QUIC_CONFIG server_cfg, client_cfg;

		TransportQuicDefaultConfig(&server_cfg, thumbprint, false);
		TransportQuicDefaultConfig(&client_cfg, thumbprint, false);

		TRANSPORT *server = TransportQuicServerNew(&server_cfg);
		TRANSPORT *client = TransportQuicClientNew(&client_cfg);

		if (NoiseHubCheck(ctx, server != NULL && client != NULL, "QUIC: the server and client transports open on msquic", "a transport could not open"))
		{
			NoiseHubRun(ctx, server, client, NOISEHUB_QUIC, TransportQuicBoundPort, "QUIC");
		}

		TransportQuicFree(client);
		TransportQuicFree(server);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
}

// The Noise path over TLS-443 (CORE-S2-1) on Schannel, for a client that cannot use UDP: the listener of the node, on a
// test port of the loopback interface, presents a real certificate of the store whose key is in the CNG key storage
// provider, and the client pins it
static void NoiseHubTls(NOISEHUB_CTX *ctx)
{
	char thumbprint[MAX_SIZE];
	UINT scope = 0;

	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(NOISEHUB_CN, NOISEHUB_SAN, NULL, 30, scope);
	bool have_cert = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, scope));

	if (NoiseHubCheck(ctx, have_cert, "TLS-443: a self-signed ECDSA P-256 certificate in the My store, by its thumbprint", "CryptoCertCreateSelfSigned or the store failed"))
	{
		TRANSPORT_TLS_CONFIG server_cfg, client_cfg;

		TransportTlsDefaultConfig(&server_cfg, thumbprint, false);
		TransportTlsDefaultConfig(&client_cfg, thumbprint, false);

		TRANSPORT *server = TransportTlsServerNew(&server_cfg);
		TRANSPORT *client = TransportTlsClientNew(&client_cfg);

		if (NoiseHubCheck(ctx, server != NULL && client != NULL, "TLS-443: the server and client transports open on Schannel", "a transport could not open"))
		{
			NoiseHubRun(ctx, server, client, NOISEHUB_TLS, TransportTlsBoundPort, "TLS-443");
		}

		TransportTlsFree(client);
		TransportTlsFree(server);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, scope);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
}

RANZ_TEST("noisehub", noisehub_test, "Noise to Hub: the L2 frames of a Noise session enter a Hub as a Session of type CONNECTION_NOISE and come out as the golden file of the Hub output (golden family noisehub); a Tunnel of four connections keeps each flow in order and spreads the flows over all four.");
void noisehub_test(UINT num, char **arg)
{
	NOISEHUB_CTX *ctx = ZeroMalloc(sizeof(NOISEHUB_CTX));
	wchar_t dir[MAX_PATH];
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, NoiseHubWatchdog, done, 0, NULL) : NULL);

	Print("Noise-to-Hub test: the L2 frames of a Noise session of the new core in the existing Hub, against the golden file\n");

	HarnessGetFamilyDirs("noisehub", ctx->OutDir, sizeof(ctx->OutDir), ctx->GoldenDir, sizeof(ctx->GoldenDir), &ctx->Update);
	MakeDirEx(ctx->OutDir);
	Print("NOISEHUB GOLDEN MODE %s\n", ctx->Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx->GoldenDir);

	if (NoiseHubCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed"))
	{
		CryptoX25519GenerateKey(ctx->ServerKey, ctx->ServerPub);
		CryptoX25519GenerateKey(ctx->ClientKey, ctx->ClientPub);

		NoiseHubNewDir(dir, sizeof(dir));
		ctx->Node = NewNode(dir);
		NodeStart(ctx->Node);
		ctx->IdleThread = NewThread(NoiseHubIdleThread, NULL);
		ctx->HubN = NoiseHubPrepare(ctx, NOISEHUB_HUB_N);

		if (NoiseHubCheck(ctx, ctx->HubN != NULL, "the server role of the node runs the Hub", "NodeGetHub failed"))
		{
			// The bound loopback transport: each stream has a binding of its own, as an outer TLS or QUIC session gives
			TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, true);
			NoiseHubRun(ctx, loopback, loopback, NOISEHUB_LOOPBACK, NULL, "loopback");
			TransportLoopbackFree(loopback);

			NoiseHubQuic(ctx);
			NoiseHubTls(ctx);
		}

		ReleaseHub(ctx->HubN);
		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ReleaseThread(ctx->IdleThread);
		NoiseHubDeleteFiles(dir);
	}

	Zero(ctx->ServerKey, sizeof(ctx->ServerKey));
	Zero(ctx->ClientKey, sizeof(ctx->ClientKey));

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
		Print("NOISEHUB TEST OK\n");
	}
	else
	{
		Print("NOISEHUB TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
