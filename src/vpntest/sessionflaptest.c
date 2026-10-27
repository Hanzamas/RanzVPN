// sessionflaptest.c
// Session flap test of vpntest ("sessionflap" command, AUD1-DT-11 #459; NS-12 and G-30 of docs/threat-model.md)
//
// A new handshake of a key closes the session that a node holds for it, so a thief of the key and the real node can keep each
// other off by taking turns. The overlay of a node (Cedar/NodeFlap.c) counts the replacements of the session of each peer in
// a window and, above a limit, raises the Event session-flap with the name of the peer and the addresses that the sessions
// came from. The test runs the overlay of in-process nodes as seam 2 of #45 does (fake adapters, the in-process loopback
// transport, the desired states applied with NodeOverlayApply, no control stream), and the dialers that hold the key of a
// peer are the test itself: each dials a node from an address that the loopback transport tells (TransportLoopbackSetSource),
// as a TCP connection tells its source, and runs the initiator of the Noise session with that key.
// - The address of a stream: the end of a stream that a listener accepted tells the source of the dial, the end that dialled
//   tells the address that it dialled, and a dial with no source tells none.
// - The events on the control stream: the events that wait go out as the events of one Telemetry message, each with its type,
//   its subject and its message, and leave the queue; a queue that is full drops its oldest events. The frame is read here
//   field by field from the schema (proto/ranz/control/v1/control.proto), not through nanopb.
// - A peer that roams once: its session is replaced once, and node-a raises nothing.
// - Two holders of one key: dialling node-a again and again from two addresses, the session of the peer is replaced; at the
//   limit nothing is raised, and one replacement above it raises the Event, with the peer as its subject and both addresses,
//   without a port, in its message. Replacements that go on do not raise it again within the window.
// - The window: node-b, whose window is short, sees the same replacements spread over more than its window, and raises none.
// Print "SESSIONFLAP TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Transport.h"

#include <stdio.h>

#define	SESSIONFLAPTEST_BUDGET		120000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	SESSIONFLAPTEST_BOUND		10000		// A bounded wait on observable state (ms)
#define	SESSIONFLAPTEST_POLL		10			// Poll interval of observable state (ms)
#define	SESSIONFLAPTEST_HANDSHAKE	10000		// The handshake of a dialer ends within this time (ms)
#define	SESSIONFLAPTEST_VRF			101			// The one VRF
#define	SESSIONFLAPTEST_LIMIT		3			// The replacements in the window above which the overlay reports a peer
#define	SESSIONFLAPTEST_LONG		30000		// The window of node-a (ms): the replacements of a case all fall in it
#define	SESSIONFLAPTEST_SHORT		1500		// The window of node-b (ms)
#define	SESSIONFLAPTEST_GAP			700			// The time between two replacements of node-b (ms): at most 3 of them in its window
#define	SESSIONFLAPTEST_SLOW		5			// The replacements of the slow case: more than the limit, none of them above it in the window
#define	SESSIONFLAPTEST_WIRE		4096		// A frame of the events case at most
#define	SESSIONFLAPTEST_DIALERS		32			// The dials of all the cases at most

// The addresses that the dialers dial from, and the ports that tell connections of one host apart
#define	SESSIONFLAPTEST_HOST_1		"198.51.100.7"
#define	SESSIONFLAPTEST_HOST_2		"203.0.113.9"
#define	SESSIONFLAPTEST_HOST_R		"198.51.100.21"
#define	SESSIONFLAPTEST_HOST_R2		"203.0.113.21"
#define	SESSIONFLAPTEST_HOST_S		"198.51.100.33"
#define	SESSIONFLAPTEST_HOST_S2		"203.0.113.33"

// The nodes: node-a and node-b, each with the peers that the test holds the keys of
#define	SESSIONFLAPTEST_NODE_A		0
#define	SESSIONFLAPTEST_NODE_B		1
#define	SESSIONFLAPTEST_NODES		2

// The peers: peer-roam and peer-flap are peers of node-a, peer-slow is the peer of node-b
#define	SESSIONFLAPTEST_ROAM		0
#define	SESSIONFLAPTEST_FLAP		1
#define	SESSIONFLAPTEST_SLOWPEER	2
#define	SESSIONFLAPTEST_PEERS		3

static char *sessionflaptest_node_names[SESSIONFLAPTEST_NODES] = {"node-a", "node-b"};
static char *sessionflaptest_node_addrs[SESSIONFLAPTEST_NODES] = {"10.0.0.1", "10.0.0.2"};
static char *sessionflaptest_peer_names[SESSIONFLAPTEST_PEERS] = {"peer-roam", "peer-flap", "peer-slow"};
static char *sessionflaptest_peer_addrs[SESSIONFLAPTEST_PEERS] = {"10.0.1.1", "10.0.1.2", "10.0.1.3"};

// One peer: the key that its holders use
typedef struct SESSIONFLAPTEST_PEER
{
	PEER_KEY Key;
} SESSIONFLAPTEST_PEER;

// One node and the fake adapter of its host
typedef struct SESSIONFLAPTEST_NODE
{
	wchar_t Dir[MAX_PATH];				// Its data directory
	PEER_KEY Key;						// Its static key, above the keys of its peers: it never dials them
	NODE *Node;
	UINT FirstPeer;						// Its peers are the ones of the table of peers from this index ...
	UINT NumPeers;						// ... this many
	UINT Window;						// Its window (ms)
} SESSIONFLAPTEST_NODE;

// One holder of the key of a peer: where it dials from, and its session once it dialled
typedef struct SESSIONFLAPTEST_DIALER
{
	UINT Node;
	UINT Peer;
	TRANSPORT_NOISE *Session;
} SESSIONFLAPTEST_DIALER;

// The test
typedef struct SESSIONFLAPTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	TRANSPORT *Loopback;
	SESSIONFLAPTEST_NODE Nodes[SESSIONFLAPTEST_NODES];
	SESSIONFLAPTEST_PEER Peers[SESSIONFLAPTEST_PEERS];
	SESSIONFLAPTEST_DIALER Dialers[SESSIONFLAPTEST_DIALERS];	// The holders that the cases use, in the order that they make them
	UINT NumDialers;
} SESSIONFLAPTEST_CTX;

static bool SessionFlapTestCheck(SESSIONFLAPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool SessionFlapTestCheck(SESSIONFLAPTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

// The watchdog: a native thread that ends a run that hangs, so that a stalled overlay is a failed test instead of a hung CI
// step
static DWORD WINAPI SessionFlapTestWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, SESSIONFLAPTEST_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "SESSIONFLAP TEST FAILED (did not finish within %u ms)\n", SESSIONFLAPTEST_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

// The IPv4 address of a text into addr, in network byte order
static void SessionFlapTestAddress(UCHAR *addr, char *str)
{
	IP ip;

	Zero(addr, 4);
	if (StrToIP(&ip, str) && IsIP4(&ip))
	{
		Copy(addr, IPV4(ip.address), 4);
	}
}

// The address of a host in the one VRF into a
static void SessionFlapTestControlAddress(CONTROL_ADDRESS *a, char *str)
{
	Zero(a, sizeof(CONTROL_ADDRESS));
	StrCpy(a->Network, sizeof(a->Network), "red");
	a->VrfId = SESSIONFLAPTEST_VRF;
	a->AddressSize = 4;
	SessionFlapTestAddress(a->Address, str);
	a->Length = 24;
}

//
// The address of a stream
//

// A stream of the loopback transport between a dial and an accept on a listener of its own, from the source that the test
// sets: the address that each end tells
static void SessionFlapTestRemote(SESSIONFLAPTEST_CTX *ctx)
{
	char remote[TRANSPORT_ADDRESS_SIZE];
	char tiny[8];

	Print("[the address of a stream]\n");

	TRANSPORT_LISTENER *l = TransportListen(ctx->Loopback, "remote-probe");
	if (SessionFlapTestCheck(ctx, l != NULL, "  a listener on the loopback transport", "TransportListen failed") == false)
	{
		return;
	}

	TransportLoopbackSetSource(ctx->Loopback, "198.51.100.77:4433");
	TRANSPORT_STREAM *dialled = TransportDial(ctx->Loopback, "remote-probe", NULL);
	TRANSPORT_STREAM *accepted = (dialled != NULL ? TransportAccept(l, SESSIONFLAPTEST_BOUND) : NULL);
	if (SessionFlapTestCheck(ctx, dialled != NULL && accepted != NULL, "  a dial from a source is accepted", "dialled %u, accepted %u",
		(UINT)(dialled != NULL), (UINT)(accepted != NULL)) == false)
	{
		TransportClose(dialled);
		TransportCloseListener(l);
		return;
	}

	bool got = TransportRemote(accepted, remote, sizeof(remote));
	SessionFlapTestCheck(ctx, got && StrCmp(remote, "198.51.100.77:4433") == 0, "  the end that accepted the stream tells the source of the dial", "%s: \"%s\"", got ? "gave" : "gave none", remote);
	got = TransportRemote(dialled, remote, sizeof(remote));
	SessionFlapTestCheck(ctx, got && StrCmp(remote, "remote-probe") == 0, "  the end that dialled tells the address that it dialled", "%s: \"%s\"", got ? "gave" : "gave none", remote);
	got = TransportRemote(accepted, tiny, sizeof(tiny));
	SessionFlapTestCheck(ctx, got == false && tiny[0] == 0, "  an address that does not fit the buffer is not given, and the buffer is left empty", "%s: \"%s\"", got ? "gave" : "gave none", tiny);
	TransportClose(dialled);
	TransportClose(accepted);

	// A dial with no source: the listener's end tells none
	TransportLoopbackSetSource(ctx->Loopback, "");
	dialled = TransportDial(ctx->Loopback, "remote-probe", NULL);
	accepted = (dialled != NULL ? TransportAccept(l, SESSIONFLAPTEST_BOUND) : NULL);
	got = (accepted != NULL && TransportRemote(accepted, remote, sizeof(remote)));
	SessionFlapTestCheck(ctx, accepted != NULL && got == false && remote[0] == 0, "  a dial with no source gives the listener's end no address", "accepted %u, %s: \"%s\"", (UINT)(accepted != NULL), got ? "gave" : "gave none", remote);
	TransportClose(dialled);
	TransportClose(accepted);
	TransportCloseListener(l);
}

//
// The events on the control stream
//

// The varint at *pos of buf, size bytes, into *value; false when it is cut short or does not fit
static bool SessionFlapTestVarint(UCHAR *buf, UINT size, UINT *pos, UINT *value)
{
	UINT v = 0;

	for (UINT shift = 0;shift < 32 && *pos < size;shift += 7)
	{
		UCHAR b = buf[(*pos)++];

		v |= (UINT)(b & 0x7F) << shift;
		if ((b & 0x80) == 0)
		{
			*value = v;
			return true;
		}
	}

	return false;
}

// The field of buf at *pos that is a length-delimited one (wire type 2) of number number: its bytes are buf + *pos with
// *size bytes, and *pos moves behind them; false when the field is another or is cut short
static bool SessionFlapTestField(UCHAR *buf, UINT size, UINT *pos, UINT number, UINT *start, UINT *len)
{
	UINT tag = 0;

	if (SessionFlapTestVarint(buf, size, pos, &tag) == false || tag != ((number << 3) | 2))
	{
		return false;
	}
	if (SessionFlapTestVarint(buf, size, pos, len) == false || *len > size - *pos)
	{
		return false;
	}

	*start = *pos;
	*pos += *len;

	return true;
}

// The events of one frame that ControlWriteEvents wrote, as the schema says: 4 bytes of length, then a ControlMessage whose
// field 7 is the Telemetry, whose field 5 repeats the NodeEvent (the varint type 1, the string subject 2 and the string
// message 3). They go into list, max at most: their number, or INFINITE when the frame is no such message.
static UINT SessionFlapTestDecode(UCHAR *frame, UINT size, CONTROL_EVENT *list, UINT max)
{
	UINT num = 0;
	UINT pos = 4, start = 0, len = 0;

	if (size < 4 || (((UINT)frame[0] << 24) | ((UINT)frame[1] << 16) | ((UINT)frame[2] << 8) | frame[3]) != size - 4)
	{
		return INFINITE;
	}

	// The Telemetry, the only field of the ControlMessage
	if (SessionFlapTestField(frame, size, &pos, 7, &start, &len) == false || pos != size)
	{
		return INFINITE;
	}

	UCHAR *t = frame + start;
	UINT t_size = len;
	UINT t_pos = 0;

	while (t_pos < t_size)
	{
		if (SessionFlapTestField(t, t_size, &t_pos, 5, &start, &len) == false || num >= max)
		{
			return INFINITE;
		}

		UCHAR *e = t + start;
		UINT e_size = len;
		UINT e_pos = 0;
		CONTROL_EVENT *ev = &list[num++];
		UINT type = 0;

		Zero(ev, sizeof(CONTROL_EVENT));
		if (e_size == 0 || e[e_pos++] != 0x08 || SessionFlapTestVarint(e, e_size, &e_pos, &type) == false)
		{
			return INFINITE;
		}
		ev->Type = type;

		if (SessionFlapTestField(e, e_size, &e_pos, 2, &start, &len) == false || len >= sizeof(ev->Subject))
		{
			return INFINITE;
		}
		Copy(ev->Subject, e + start, len);

		if (SessionFlapTestField(e, e_size, &e_pos, 3, &start, &len) == false || len >= sizeof(ev->Message) || e_pos != e_size)
		{
			return INFINITE;
		}
		Copy(ev->Message, e + start, len);
	}

	return num;
}

// Read one frame (its 4 bytes of length and the message) from s into buf, size bytes at most: its size, 0 when none came
// whole within SESSIONFLAPTEST_BOUND
static UINT SessionFlapTestReadFrame(TRANSPORT_STREAM *s, UCHAR *buf, UINT size)
{
	UINT have = 0;
	UINT need = 4;
	UINT64 end = Tick64() + SESSIONFLAPTEST_BOUND;

	while (have < need && Tick64() < end)
	{
		UINT got = TransportRead(s, buf + have, need - have, SESSIONFLAPTEST_POLL);

		if (got == 0)
		{
			return 0;
		}
		if (got != TRANSPORT_LATER)
		{
			have += got;
		}
		if (have >= 4 && need == 4)
		{
			need = 4 + (((UINT)buf[0] << 24) | ((UINT)buf[1] << 16) | ((UINT)buf[2] << 8) | buf[3]);
			if (need > size)
			{
				return 0;
			}
		}
	}

	return (have == need ? need : 0);
}

// A transport whose streams fail every write, for a stream that cannot take the events: a dial gives a stream, and a write
// to it gives false
static bool SessionFlapTestFailDial(void *param, const char *address, HANDLE cancel, void **stream)
{
	*stream = param;

	return true;
}

static bool SessionFlapTestFailWrite(void *stream, const void *buf, UINT size)
{
	return false;
}

static void SessionFlapTestFailClose(void *stream)
{
}

// The queue of the events of a client: the events that wait go out as one Telemetry message, with the fields of the schema,
// and leave the queue once written; a write that fails keeps them, and a queue that is full drops its oldest events
static void SessionFlapTestWire(SESSIONFLAPTEST_CTX *ctx)
{
	CONTROL_EVENT list[CONTROL_EVENT_QUEUE + 2];
	CONTROL_EVENT got[CONTROL_MAX_EVENTS + 2];
	UCHAR *frame = ZeroMalloc(SESSIONFLAPTEST_WIRE);
	char subject[CONTROL_EVENT_SUBJECT_SIZE + 8];
	char message[CONTROL_EVENT_MESSAGE_SIZE + 8];
	TRANSPORT failing;

	Print("[the events on the control stream]\n");

	Zero(got, sizeof(got));
	Zero(&failing, sizeof(failing));
	StrCpy(failing.Name, sizeof(failing.Name), "failing");
	failing.Param = ctx;
	failing.Dial = SessionFlapTestFailDial;
	failing.Write = SessionFlapTestFailWrite;
	failing.Close = SessionFlapTestFailClose;

	CONTROL_EVENTS *e = ControlNewEvents();
	TRANSPORT_LISTENER *l = TransportListen(ctx->Loopback, "events-probe");
	TRANSPORT_STREAM *dialled = (l != NULL ? TransportDial(ctx->Loopback, "events-probe", NULL) : NULL);
	TRANSPORT_STREAM *accepted = (dialled != NULL ? TransportAccept(l, SESSIONFLAPTEST_BOUND) : NULL);
	if (SessionFlapTestCheck(ctx, e != NULL && accepted != NULL && frame != NULL, "  a queue of events and a stream to write them to", "queue %u, stream %u",
		(UINT)(e != NULL), (UINT)(accepted != NULL)) == false)
	{
		TransportClose(dialled);
		TransportClose(accepted);
		TransportCloseListener(l);
		ControlFreeEvents(e);
		Free(frame);
		return;
	}

	// Nothing waits: nothing is written
	SessionFlapTestCheck(ctx, ControlWriteEvents(e, dialled) && TransportRead(accepted, frame, 1, 100) == TRANSPORT_LATER, "  a client with no events to report writes nothing", "it wrote a frame");

	// Two events, the second with a subject and a message over their fields: they are cut to them, and a type of 0 is no event
	Zero(message, sizeof(message));
	for (UINT i = 0;i < sizeof(message) - 1;i++)
	{
		message[i] = 'm';
	}
	bool raised = ControlRaiseEvent(e, CONTROL_EVENT_SESSION_FLAP, "peer-a", "the session of peer peer-a was replaced");
	Zero(subject, sizeof(subject));
	for (UINT i = 0;i < sizeof(subject) - 1;i++)
	{
		subject[i] = 's';
	}
	raised = raised && ControlRaiseEvent(e, CONTROL_EVENT_SESSION_FLAP, subject, message);
	SessionFlapTestCheck(ctx, raised && ControlRaiseEvent(e, 0, "none", "none") == false && ControlRaiseEvent(NULL, CONTROL_EVENT_SESSION_FLAP, "none", "none") == false,
		"  two events are raised, and a type of 0 and a missing queue are refused", "raised %u", (UINT)raised);
	SessionFlapTestCheck(ctx, ControlGetEvents(e, list, CONTROL_EVENT_QUEUE) == 2, "  they wait in the queue", "%u wait", ControlGetEvents(e, list, CONTROL_EVENT_QUEUE));

	bool wrote = ControlWriteEvents(e, dialled);
	UINT size = (wrote ? SessionFlapTestReadFrame(accepted, frame, SESSIONFLAPTEST_WIRE) : 0);
	UINT num = (size != 0 ? SessionFlapTestDecode(frame, size, got, CONTROL_MAX_EVENTS + 2) : INFINITE);
	SessionFlapTestCheck(ctx, wrote && size != 0 && num == 2, "  they go out as the events of one Telemetry message of the schema", "wrote %u, a frame of %u bytes, %u events", (UINT)wrote, size, num);
	SessionFlapTestCheck(ctx, num == 2 && got[0].Type == CONTROL_EVENT_SESSION_FLAP && StrCmp(got[0].Subject, "peer-a") == 0 && StrCmp(got[0].Message, "the session of peer peer-a was replaced") == 0,
		"  the first has its type, its subject and its message", "type %u, \"%s\", \"%s\"", got[0].Type, got[0].Subject, got[0].Message);
	SessionFlapTestCheck(ctx, num == 2 && got[1].Type == CONTROL_EVENT_SESSION_FLAP && StrLen(got[1].Subject) == CONTROL_EVENT_SUBJECT_SIZE - 1 && StrLen(got[1].Message) == CONTROL_EVENT_MESSAGE_SIZE - 1,
		"  the second is cut to the fields of the schema", "type %u, a subject of %u and a message of %u bytes", got[1].Type, StrLen(got[1].Subject), StrLen(got[1].Message));
	SessionFlapTestCheck(ctx, ControlGetEvents(e, list, CONTROL_EVENT_QUEUE) == 0, "  what was written left the queue", "%u wait", ControlGetEvents(e, list, CONTROL_EVENT_QUEUE));

	// A queue that is full drops its oldest events: the first CONTROL_EVENT_QUEUE + 6 events leave the last CONTROL_EVENT_QUEUE
	for (UINT i = 0;i < CONTROL_EVENT_QUEUE + 6;i++)
	{
		Format(subject, sizeof(subject), "p%u", i);
		ControlRaiseEvent(e, CONTROL_EVENT_SESSION_FLAP, subject, "flap");
	}
	UINT held = ControlGetEvents(e, list, CONTROL_EVENT_QUEUE + 2);
	SessionFlapTestCheck(ctx, held == CONTROL_EVENT_QUEUE && StrCmp(list[0].Subject, "p6") == 0, "  a full queue holds the newest events and drops the oldest", "%u wait, the oldest is \"%s\"", held, list[0].Subject);

	// A write that fails keeps the events: the stream that comes next has them
	TRANSPORT_STREAM *broken = TransportDial(&failing, "broken", NULL);
	bool failed = (broken != NULL && ControlWriteEvents(e, broken) == false);
	held = ControlGetEvents(e, list, CONTROL_EVENT_QUEUE + 2);
	SessionFlapTestCheck(ctx, failed && held == CONTROL_EVENT_QUEUE && StrCmp(list[0].Subject, "p6") == 0, "  a write that fails fails, and keeps the events in the queue", "failed %u, %u wait, the oldest is \"%s\"", (UINT)failed, held, list[0].Subject);
	TransportClose(broken);

	// A message holds CONTROL_MAX_EVENTS of them, the oldest first, and the rest waits for the next
	wrote = ControlWriteEvents(e, dialled);
	size = (wrote ? SessionFlapTestReadFrame(accepted, frame, SESSIONFLAPTEST_WIRE) : 0);
	Zero(got, sizeof(got));
	num = (size != 0 ? SessionFlapTestDecode(frame, size, got, CONTROL_MAX_EVENTS + 2) : INFINITE);
	SessionFlapTestCheck(ctx, wrote && num == CONTROL_MAX_EVENTS && StrCmp(got[0].Subject, "p6") == 0 && StrCmp(got[CONTROL_MAX_EVENTS - 1].Subject, "p13") == 0,
		"  a message holds the first events that wait, CONTROL_MAX_EVENTS of them", "wrote %u, %u events, from \"%s\" to \"%s\"", (UINT)wrote, num, got[0].Subject, got[CONTROL_MAX_EVENTS - 1].Subject);
	held = ControlGetEvents(e, list, CONTROL_EVENT_QUEUE + 2);
	SessionFlapTestCheck(ctx, held == CONTROL_EVENT_QUEUE - CONTROL_MAX_EVENTS && StrCmp(list[0].Subject, "p14") == 0, "  the others wait for the next message", "%u wait, the oldest is \"%s\"", held, list[0].Subject);

	TransportClose(dialled);
	TransportClose(accepted);
	TransportCloseListener(l);
	ControlFreeEvents(e);
	Free(frame);
}

//
// The nodes
//

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role on one
// worker
static void SessionFlapTestNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"sessionflaptest_%S_%u", name, Rand32());
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

// Delete the files of a directory, which holds no subdirectory, and then the directory
static void SessionFlapTestDeleteFiles(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		wchar_t path[MAX_PATH];

		if (d->File[i]->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The fake adapter of a host: the test sends nothing to it
static void SessionFlapTestAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
}

// Apply the state of node i at Generation 1: its address, and its peers with theirs, each in the one VRF
static bool SessionFlapTestApply(SESSIONFLAPTEST_CTX *ctx, UINT i)
{
	SESSIONFLAPTEST_NODE *n = &ctx->Nodes[i];
	CONTROL_STATE *st = ZeroMalloc(sizeof(CONTROL_STATE));

	st->Generation = 1;
	StrCpy(st->Name, sizeof(st->Name), sessionflaptest_node_names[i]);
	st->NumAddresses = 1;
	SessionFlapTestControlAddress(&st->Addresses[0], sessionflaptest_node_addrs[i]);

	st->Peers = ZeroMalloc(sizeof(CONTROL_PEER) * MAX(n->NumPeers, 1));
	st->NumPeers = n->NumPeers;
	for (UINT j = 0;j < n->NumPeers;j++)
	{
		UINT peer = n->FirstPeer + j;
		CONTROL_PEER *p = &st->Peers[j];

		StrCpy(p->Name, sizeof(p->Name), sessionflaptest_peer_names[peer]);
		Copy(p->Key, ctx->Peers[peer].Key.Public, PEER_KEY_SIZE);
		p->NumVrfs = 1;
		p->VrfIds[0] = SESSIONFLAPTEST_VRF;
		p->NumAddresses = 1;
		SessionFlapTestControlAddress(&p->Addresses[0], sessionflaptest_peer_addrs[peer]);
	}

	bool ok = NodeOverlayApply(n->Node, st);

	Free(st->Peers);
	Free(st);

	return ok;
}

// A key from a scalar that depends on seed, above the key of every peer in first..first + num - 1 of the peers: a node whose
// key is above its peers' dials none of them, and the test's dialers are the only ones that reach it
static bool SessionFlapTestNodeKey(SESSIONFLAPTEST_CTX *ctx, PEER_KEY *key, UINT seed, UINT first, UINT num)
{
	UCHAR scalar[PEER_KEY_SIZE];

	for (UINT attempt = 0;attempt < 64;attempt++)
	{
		bool above = true;

		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x71 + seed * 17 + attempt * 31 + j);
		}
		if (PeerKeyFromScalar(key, scalar) == false)
		{
			return false;
		}

		for (UINT j = 0;j < num;j++)
		{
			above = above && Cmp(key->Public, ctx->Peers[first + j].Key.Public, PEER_KEY_SIZE) > 0;
		}
		if (above)
		{
			Zero(scalar, sizeof(scalar));
			return true;
		}

		PeerKeyClose(key);
	}

	Zero(scalar, sizeof(scalar));

	return false;
}

// The nodes and their overlays, with the states applied
static bool SessionFlapTestOpen(SESSIONFLAPTEST_CTX *ctx)
{
	UCHAR scalar[PEER_KEY_SIZE];
	char what[MAX_SIZE];
	bool ok = (ctx->Loopback != NULL);

	Print("[the nodes and their overlays]\n");

	// The keys that the holders use: one for each peer
	for (UINT i = 0;i < SESSIONFLAPTEST_PEERS && ok;i++)
	{
		for (UINT j = 0;j < PEER_KEY_SIZE;j++)
		{
			scalar[j] = (UCHAR)(0x21 + PEER_KEY_SIZE * i + j);
		}
		ok = PeerKeyFromScalar(&ctx->Peers[i].Key, scalar);
	}
	Zero(scalar, sizeof(scalar));

	// node-a has the first two peers, node-b the third
	ctx->Nodes[SESSIONFLAPTEST_NODE_A].FirstPeer = SESSIONFLAPTEST_ROAM;
	ctx->Nodes[SESSIONFLAPTEST_NODE_A].NumPeers = 2;
	ctx->Nodes[SESSIONFLAPTEST_NODE_A].Window = SESSIONFLAPTEST_LONG;
	ctx->Nodes[SESSIONFLAPTEST_NODE_B].FirstPeer = SESSIONFLAPTEST_SLOWPEER;
	ctx->Nodes[SESSIONFLAPTEST_NODE_B].NumPeers = 1;
	ctx->Nodes[SESSIONFLAPTEST_NODE_B].Window = SESSIONFLAPTEST_SHORT;

	for (UINT i = 0;i < SESSIONFLAPTEST_NODES && ok;i++)
	{
		SESSIONFLAPTEST_NODE *t = &ctx->Nodes[i];
		NODE_OVERLAY_CONFIG c;

		ok = SessionFlapTestNodeKey(ctx, &t->Key, i, t->FirstPeer, t->NumPeers);

		SessionFlapTestNewDir(t->Dir, sizeof(t->Dir), sessionflaptest_node_names[i]);
		t->Node = NewNode(t->Dir);
		NodeStart(t->Node);

		Zero(&c, sizeof(c));
		c.Data = ctx->Loopback;
		c.Key = &t->Key;
		c.Adapter = SessionFlapTestAdapter;
		c.AdapterParam = t;
		c.FlapLimit = SESSIONFLAPTEST_LIMIT;
		c.FlapWindow = t->Window;
		Format(what, sizeof(what), "  %s: its overlay runs without a control stream, and reports a peer above %u replacements in %u ms", sessionflaptest_node_names[i], SESSIONFLAPTEST_LIMIT, t->Window);
		ok = SessionFlapTestCheck(ctx, ok && NodeOverlayStart(t->Node, &c), what, "PeerKeyFromScalar or NodeOverlayStart failed") && ok;
	}

	for (UINT i = 0;i < SESSIONFLAPTEST_NODES && ok;i++)
	{
		ok = SessionFlapTestApply(ctx, i);
	}
	SessionFlapTestCheck(ctx, ok, "  node-a and node-b apply their states", "NodeOverlayApply failed");

	return ok;
}

// The sessions of the dialers, then the nodes, whose overlays stop with every thread joined
static void SessionFlapTestClose(SESSIONFLAPTEST_CTX *ctx)
{
	for (UINT i = 0;i < ctx->NumDialers;i++)
	{
		if (ctx->Dialers[i].Session != NULL)
		{
			TransportNoiseClose(ctx->Dialers[i].Session);
			Free(ctx->Dialers[i].Session);
			ctx->Dialers[i].Session = NULL;
		}
	}

	for (UINT i = 0;i < SESSIONFLAPTEST_NODES;i++)
	{
		SESSIONFLAPTEST_NODE *t = &ctx->Nodes[i];
		wchar_t log_dir[MAX_PATH];

		if (t->Node != NULL)
		{
			NodeStop(t->Node);
			FreeNode(t->Node);

			ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
			SessionFlapTestDeleteFiles(log_dir);
			SessionFlapTestDeleteFiles(t->Dir);
		}
		PeerKeyClose(&t->Key);
	}

	for (UINT i = 0;i < SESSIONFLAPTEST_PEERS;i++)
	{
		PeerKeyClose(&ctx->Peers[i].Key);
	}
}

//
// The holders
//

// A holder of the key of peer, which dials node from source: the Noise session of its initiator, which the holder keeps in
// place of the one that it had. The dial is tried again while the overlay of the node has no listener yet. The holder, its
// index in the list of the dialers, or INFINITE when it could not connect.
static UINT SessionFlapTestDial(SESSIONFLAPTEST_CTX *ctx, UINT node, UINT peer, char *source)
{
	NOISE_SESSION_CONFIG c;
	UINT64 end = Tick64() + SESSIONFLAPTEST_BOUND;
	TRANSPORT_STREAM *stream = NULL;

	TransportLoopbackSetSource(ctx->Loopback, source);
	while (stream == NULL && Tick64() < end)
	{
		stream = TransportDial(ctx->Loopback, sessionflaptest_node_names[node], NULL);
		if (stream == NULL)
		{
			SleepThread(SESSIONFLAPTEST_POLL);
		}
	}
	if (stream == NULL || ctx->NumDialers >= SESSIONFLAPTEST_DIALERS)
	{
		TransportClose(stream);
		return INFINITE;
	}

	Zero(&c, sizeof(c));
	c.Suite = NOISE_SUITE_IK;
	c.StaticKey = ctx->Peers[peer].Key.Private;
	c.RemoteStatic = ctx->Nodes[node].Key.Public;

	// The connect closes the stream when the handshake fails
	TRANSPORT_NOISE *s = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	if (TransportNoiseConnect(s, stream, &c, SESSIONFLAPTEST_HANDSHAKE) == false)
	{
		Free(s);
		return INFINITE;
	}

	SESSIONFLAPTEST_DIALER *d = &ctx->Dialers[ctx->NumDialers];

	d->Node = node;
	d->Peer = peer;
	d->Session = s;

	return ctx->NumDialers++;
}

// The status of the overlay of node i, once the sessions that a new handshake replaced and the peers with a session up are
// what the case expects, or once SESSIONFLAPTEST_BOUND passed
static void SessionFlapTestWait(SESSIONFLAPTEST_CTX *ctx, UINT i, UINT64 replaced, UINT links, NODE_OVERLAY_STATUS *st)
{
	UINT64 end = Tick64() + SESSIONFLAPTEST_BOUND;

	while (true)
	{
		NodeOverlayGetStatus(ctx->Nodes[i].Node, st);
		if ((st->SessionsReplaced == replaced && st->NumLinks == links) || Tick64() >= end)
		{
			return;
		}
		SleepThread(SESSIONFLAPTEST_POLL);
	}
}

// The events that node i holds, max of them at most into list, once it holds num or SESSIONFLAPTEST_BOUND passed: their number
static UINT SessionFlapTestEvents(SESSIONFLAPTEST_CTX *ctx, UINT i, UINT num, CONTROL_EVENT *list, UINT max)
{
	UINT64 end = Tick64() + SESSIONFLAPTEST_BOUND;
	UINT held = 0;

	while (true)
	{
		held = NodeOverlayGetEvents(ctx->Nodes[i].Node, list, max);
		if (held >= num || Tick64() >= end)
		{
			return held;
		}
		SleepThread(SESSIONFLAPTEST_POLL);
	}
}

// One dial of a holder that replaces the session of its peer at node i, and the wait until the node counts it: whether the
// node holds the replacement count and the sessions that the case expects
static bool SessionFlapTestReplace(SESSIONFLAPTEST_CTX *ctx, UINT node, UINT peer, char *source, UINT64 replaced, UINT links)
{
	NODE_OVERLAY_STATUS st;
	UINT holder = SessionFlapTestDial(ctx, node, peer, source);

	if (holder == INFINITE)
	{
		return false;
	}

	SessionFlapTestWait(ctx, node, replaced, links, &st);

	return (st.SessionsReplaced == replaced && st.NumLinks == links);
}

//
// The cases
//

// A peer that roams once: node-a sees its session replaced once and raises nothing
static void SessionFlapTestRoam(SESSIONFLAPTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;
	CONTROL_EVENT list[4];

	Print("[a peer that roams once]\n");

	// The holder dials from one address, then, on another network, from another: node-a closes the old session
	UINT first = SessionFlapTestDial(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_ROAM, SESSIONFLAPTEST_HOST_R ":50001");
	SessionFlapTestWait(ctx, SESSIONFLAPTEST_NODE_A, 0, 1, &st);
	SessionFlapTestCheck(ctx, first != INFINITE && st.SessionsReplaced == 0 && st.NumLinks == 1, "  the first session of peer-roam comes up, and replaces none", "dialler %u, %I64u replaced, %u links", first, st.SessionsReplaced, st.NumLinks);

	bool roamed = SessionFlapTestReplace(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_ROAM, SESSIONFLAPTEST_HOST_R2 ":50002", 1, 1);
	SessionFlapTestCheck(ctx, roamed, "  it dials again from another address: node-a replaces the old session with the new one", "no link after the roam, or the replacement was not counted");

	// The session that the roam left is closed by node-a: its holder reads the end
	UCHAR buf[64];
	UINT size = 0;
	UINT ret = (first != INFINITE ? TransportNoiseReceive(ctx->Dialers[first].Session, buf, sizeof(buf), &size, SESSIONFLAPTEST_BOUND) : NOISE_RECEIVE_NONE);
	SessionFlapTestCheck(ctx, ret == NOISE_RECEIVE_ERROR || ret == NOISE_RECEIVE_CLOSE, "  the old session reads its end", "the receive gave %u", ret);

	// Node-a counted the replacement and raised nothing: one replacement is not above the limit
	NodeOverlayGetStatus(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, &st);
	UINT held = NodeOverlayGetEvents(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, list, sizeof(list) / sizeof(list[0]));
	SessionFlapTestCheck(ctx, st.SessionsReplaced == 1 && st.SessionFlaps == 0 && held == 0, "  node-a counts one replacement and raises no Event", "%I64u replaced, %I64u flaps, %u events", st.SessionsReplaced, st.SessionFlaps, held);
}

// Two holders of one key: node-a is dialled again and again from two addresses, and raises the Event above the limit
static void SessionFlapTestTwoHolders(SESSIONFLAPTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;
	CONTROL_EVENT list[4];
	char what[MAX_SIZE];

	Print("[two holders of one key]\n");

	// The first session comes up, then the two holders replace each other's session: the limit is reached, not passed
	UINT first = SessionFlapTestDial(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_FLAP, SESSIONFLAPTEST_HOST_1 ":40001");
	SessionFlapTestWait(ctx, SESSIONFLAPTEST_NODE_A, 1, 2, &st);
	bool up = (first != INFINITE && st.NumLinks == 2);
	char *sources[SESSIONFLAPTEST_LIMIT + 2] = {SESSIONFLAPTEST_HOST_2 ":40002", SESSIONFLAPTEST_HOST_1 ":40003", SESSIONFLAPTEST_HOST_2 ":40004", SESSIONFLAPTEST_HOST_1 ":40005", SESSIONFLAPTEST_HOST_2 ":40006"};
	bool replaced = up;

	// Replacement k + 1 of the series: the one of the roam case is the first that node-a counted
	for (UINT k = 0;k < SESSIONFLAPTEST_LIMIT && replaced;k++)
	{
		replaced = SessionFlapTestReplace(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_FLAP, sources[k], 2 + k, 2);
	}
	Format(what, sizeof(what), "  the holders replace each other's session %u times: node-a counts them, and has one session of the peer up", SESSIONFLAPTEST_LIMIT);
	SessionFlapTestCheck(ctx, replaced, what, "the first dial %u, the replacements were not all counted", (UINT)up);

	UINT held = NodeOverlayGetEvents(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, list, sizeof(list) / sizeof(list[0]));
	NodeOverlayGetStatus(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, &st);
	Format(what, sizeof(what), "  the limit of %u is reached, not passed: no Event yet", SESSIONFLAPTEST_LIMIT);
	SessionFlapTestCheck(ctx, held == 0 && st.SessionFlaps == 0, what, "%u events, %I64u flaps", held, st.SessionFlaps);

	// One more replacement is above the limit: the Event appears, within the window, with both addresses
	bool above = SessionFlapTestReplace(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_FLAP, sources[SESSIONFLAPTEST_LIMIT], 2 + SESSIONFLAPTEST_LIMIT, 2);
	held = SessionFlapTestEvents(ctx, SESSIONFLAPTEST_NODE_A, 1, list, sizeof(list) / sizeof(list[0]));
	NodeOverlayGetStatus(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, &st);
	SessionFlapTestCheck(ctx, above && held == 1 && st.SessionFlaps == 1, "  one more replacement raises the Event, once", "replaced %u, %u events, %I64u flaps", (UINT)above, held, st.SessionFlaps);
	if (held == 1)
	{
		CONTROL_EVENT *e = &list[0];

		SessionFlapTestCheck(ctx, e->Type == CONTROL_EVENT_SESSION_FLAP && StrCmp(e->Subject, "peer-flap") == 0, "  its type is session-flap, and its subject the peer", "type %u, subject \"%s\"", e->Type, e->Subject);
		SessionFlapTestCheck(ctx, InStr(e->Message, SESSIONFLAPTEST_HOST_1) && InStr(e->Message, SESSIONFLAPTEST_HOST_2),
			"  its message names both addresses", "\"%s\"", e->Message);
		SessionFlapTestCheck(ctx, InStr(e->Message, "40001") == false && InStr(e->Message, "40002") == false && InStr(e->Message, "peer-flap") && InStr(e->Message, "4 times") && InStr(e->Message, "30 s"),
			"  and the peer, the count and the window, and no port, which changes with each connection", "\"%s\"", e->Message);
	}

	// The replacements go on: the peer is not reported again in the window, and the other peer, which roamed once, never was
	bool more = SessionFlapTestReplace(ctx, SESSIONFLAPTEST_NODE_A, SESSIONFLAPTEST_FLAP, sources[SESSIONFLAPTEST_LIMIT + 1], 3 + SESSIONFLAPTEST_LIMIT, 2);
	SleepThread(100);
	held = NodeOverlayGetEvents(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, list, sizeof(list) / sizeof(list[0]));
	NodeOverlayGetStatus(ctx->Nodes[SESSIONFLAPTEST_NODE_A].Node, &st);
	SessionFlapTestCheck(ctx, more && held == 1 && st.SessionFlaps == 1, "  replacements that go on within the window raise no second Event, and the peer that roamed once raised none", "replaced %u, %u events, %I64u flaps", (UINT)more, held, st.SessionFlaps);
}

// The window: node-b sees five replacements of the session of its peer, each SESSIONFLAPTEST_GAP ms after the one before, so
// that no window of SESSIONFLAPTEST_SHORT ms holds more than the limit of them at a time, and it raises none
static void SessionFlapTestWindow(SESSIONFLAPTEST_CTX *ctx)
{
	NODE_OVERLAY_STATUS st;
	CONTROL_EVENT list[4];
	char what[MAX_SIZE];

	Print("[replacements spread over more than the window]\n");

	UINT first = SessionFlapTestDial(ctx, SESSIONFLAPTEST_NODE_B, SESSIONFLAPTEST_SLOWPEER, SESSIONFLAPTEST_HOST_S ":41001");
	SessionFlapTestWait(ctx, SESSIONFLAPTEST_NODE_B, 0, 1, &st);
	bool ok = (first != INFINITE && st.NumLinks == 1);

	for (UINT k = 0;k < SESSIONFLAPTEST_SLOW && ok;k++)
	{
		SleepThread(SESSIONFLAPTEST_GAP);
		ok = SessionFlapTestReplace(ctx, SESSIONFLAPTEST_NODE_B, SESSIONFLAPTEST_SLOWPEER, (k % 2 == 0 ? SESSIONFLAPTEST_HOST_S2 ":41002" : SESSIONFLAPTEST_HOST_S ":41003"), k + 1, 1);
	}
	SleepThread(100);

	NodeOverlayGetStatus(ctx->Nodes[SESSIONFLAPTEST_NODE_B].Node, &st);
	UINT held = NodeOverlayGetEvents(ctx->Nodes[SESSIONFLAPTEST_NODE_B].Node, list, sizeof(list) / sizeof(list[0]));
	Format(what, sizeof(what), "  %u replacements, %u ms apart, are more than the limit of %u, and not above it in the window of %u ms: node-b raises none",
		SESSIONFLAPTEST_SLOW, SESSIONFLAPTEST_GAP, SESSIONFLAPTEST_LIMIT, SESSIONFLAPTEST_SHORT);
	SessionFlapTestCheck(ctx, ok && st.SessionsReplaced == SESSIONFLAPTEST_SLOW && st.SessionFlaps == 0 && held == 0, what, "%u, %I64u replaced, %I64u flaps, %u events", (UINT)ok, st.SessionsReplaced, st.SessionFlaps, held);
}

// sessionflap: a session that two holders of one key replace again and again is reported
RANZ_TEST_TAGS("sessionflap", sessionflap_test, "core", "Session flap (AUD1-DT-11): the end of a stream tells where it came from; the events of a node go out as the events of a Telemetry message of the schema; a peer that roams once is replaced once and raises nothing; two holders of one key that replace each other's session above the limit raise the Event session-flap with the peer and both addresses, once in the window; replacements spread over more than the window raise none.");
void sessionflap_test(UINT num, char **arg)
{
	SESSIONFLAPTEST_CTX *ctx = ZeroMalloc(sizeof(SESSIONFLAPTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, SessionFlapTestWatchdog, done, 0, NULL) : NULL);

	Print("Session flap test: a session that two holders of one key replace again and again is reported\n");

	ctx->Loopback = TransportLoopbackNew("loopback", 0, false);
	SessionFlapTestRemote(ctx);
	SessionFlapTestWire(ctx);
	if (SessionFlapTestOpen(ctx))
	{
		SessionFlapTestRoam(ctx);
		SessionFlapTestTwoHolders(ctx);
		SessionFlapTestWindow(ctx);
	}

	SessionFlapTestClose(ctx);
	TransportLoopbackFree(ctx->Loopback);

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
		Print("SESSIONFLAP TEST OK\n");
	}
	else
	{
		Print("SESSIONFLAP TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
