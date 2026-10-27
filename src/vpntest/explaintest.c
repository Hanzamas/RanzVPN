// explaintest.c
// Named test of vpntest ("explain" command, SDN-15 #191): the data plane half of the explain conformance (ADR-0031
// decision 8)
//
// Explain is checked against the real data plane. Each scenario of tests/explain, a topology, an intent and test
// packets, runs through `ranz explain` in the controller and through the data plane here, and both must give the same
// verdict for each packet. ranz-explainplan (controller/cmd/ranz-explainplan) compiles the intent of each scenario as
// the controller does and writes its plan (controller/internal/explain, scenario.go): the desired state of each Node
// as the ControlMessage that carries its Update of Generation 1, each test packet as the host of its Node sends it, and
// the verdict of explain for it: the Node that delivers it to its host, in which VRF and with which addresses, or the
// Node that drops it, and the rule of the policy that judges it at each Node.
//
// "vpntest explain <plan directory>" runs every plan of the directory. For each scenario, real nodes of the new core
// start their overlay with the fake adapter of a host and a control stream to a stand-in controller of this file,
// which runs the controller's end of the handshake of the control protocol (Core/Control.h) on the in-process
// loopback transport, whose streams give a channel binding as the TLS exporter of the real one, and sends each node the
// frame of its plan: the node takes its state through its own control client, as from a real controller. Once every
// node applied Generation 1 and its Noise sessions are up, each packet goes in at the host of its node
// (NodeOverlayInput), and the test finds where it ends: the adapter of a host took it, in a VRF and with its addresses,
// or the overlay of a node dropped it; and which rule of the policy of a VRF judged it at each node, from the counters
// of the policy engine of each node (NodePolicyCountersText). The verdict of the data plane must be the one of explain.
// A packet whose verdicts differ is a failed check named "EXPLAIN DIFFER <scenario> <packet>"; the deliberately broken
// scenario of tests/explain/broken, whose plan gives a node a state without one of its rules, must fail on the packets
// that its fault names (.github/scripts/explain-conformance.ps1 checks both runs).
// Print "EXPLAIN TEST OK" only when every check passes.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"

#include "Mayaqua/Cfg.h"
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
#include "Core/Noise.h"
#include "Core/Transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	EXPLAIN_BUDGET			600000		// The whole test ends within this time, or the watchdog ends the process (ms)
#define	EXPLAIN_JOIN			30000		// Every node applied its state and has its Noise sessions up within this time (ms)
#define	EXPLAIN_BOUND			10000		// A packet ends at a node within this time (ms)
#define	EXPLAIN_POLL			5			// Poll interval of observable state (ms)
#define	EXPLAIN_ACCEPT			100			// The stand-in controller looks at its halt flag once in this time (ms)
#define	EXPLAIN_FRAME_WAIT		10000		// A frame of a control stream comes whole within this time (ms), CONTROL_TIMEOUT
#define	EXPLAIN_MAX_NODES		8			// The nodes of a scenario at most
#define	EXPLAIN_MAX_PACKETS		64			// The test packets of a scenario at most
#define	EXPLAIN_MAX_JUDGES		8			// The rules that judge one packet, at most
#define	EXPLAIN_MAX_PACKET		2048		// The bytes of a packet that the adapter of a host keeps
#define	EXPLAIN_FRAME_HEADER	4			// The size of a frame of the control stream, big-endian, before its message
#define	EXPLAIN_MAX_FRAME		(EXPLAIN_FRAME_HEADER + NOISE_MAX_MESSAGE)	// A frame of the handshake or the Hello at most
#define	EXPLAIN_CONTROLLER		"controller"	// The address of the stand-in controller on the transport of the control streams
#define	EXPLAIN_PLAN_VERSION	1			// The version of a plan (explain.PlanVersion)
#define	EXPLAIN_TEXT_SIZE		1024		// A verdict as a line

// The checks of the test
typedef struct EXPLAIN_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	UINT NumDiffer;				// ... of which a packet whose verdicts differ
} EXPLAIN_CTX;

// A rule of the policy of a VRF that judged a packet at a node, as "node vrf rule"
typedef struct EXPLAIN_JUDGE
{
	char Text[MAX_SIZE];
} EXPLAIN_JUDGE;

// One test packet of a plan, and the verdict of explain for it
typedef struct EXPLAIN_PACKET
{
	char Name[MAX_SIZE];
	char From[CONTROL_NAME_SIZE];		// The node whose host sends it ...
	UINT VrfId;							// ... in this VRF
	BUF *Bytes;							// The packet
	bool Expected;						// The plan gives the verdict of explain
	char Expect[EXPLAIN_TEXT_SIZE];		// ... as a line: where it ends and the rules that judged it
	UINT NumJudges;						// The rules that judged it, from the plan
	EXPLAIN_JUDGE Judges[EXPLAIN_MAX_JUDGES];
	LIST *Text;							// The steps of explain, lines for the log (char *)
} EXPLAIN_PACKET;

// One node of a scenario and the fake adapter of its host
typedef struct EXPLAIN_NODE
{
	char Name[CONTROL_NAME_SIZE];
	UINT First;							// The first byte of the scalar of its static key
	BUF *Frame;							// The ControlMessage of its Update of Generation 1
	PEER_KEY Key;						// Its static key
	bool Keyed;
	wchar_t Dir[MAX_PATH];				// Its data directory
	NODE *Node;
	NODE_READER Reader;					// The test thread as a reader of the node's tables, online while it sends
	SRWLOCK Lock;						// Packets, Vrf, Last and LastSize
	UINT Packets;						// The packets that the adapter of its host took
	UINT Vrf;							// ... the VRF of the last one
	UCHAR Last[EXPLAIN_MAX_PACKET];		// ... and its bytes
	UINT LastSize;
} EXPLAIN_NODE;

// One plan: a scenario
typedef struct EXPLAIN_PLAN
{
	char Name[MAX_SIZE];
	UINT NumNodes;
	EXPLAIN_NODE Nodes[EXPLAIN_MAX_NODES];
	UINT NumPackets;
	EXPLAIN_PACKET Packets[EXPLAIN_MAX_PACKETS];
} EXPLAIN_PLAN;

// The stand-in controller of a scenario: the controller's end of each control stream
typedef struct EXPLAIN_CONTROLLER
{
	EXPLAIN_PLAN *Plan;
	TRANSPORT_LISTENER *Listener;		// Listens at EXPLAIN_CONTROLLER on the transport of the control streams
	UCHAR Scalar[PEER_KEY_SIZE];		// Its static key ...
	PEER_KEY Key;						// ... with its public half, which the nodes pin
	HANDLE Thread;
	volatile LONG Halt;
	LIST *Streams;						// The streams that it served, open until the end (TRANSPORT_STREAM *)
	volatile LONG Served;				// Streams that got the frame of their node
	volatile LONG Failed;				// Streams whose handshake or frames failed
} EXPLAIN_CONTROLLER;

// A counter of the policy of a node: the packets that a rule, or the default action, of the Network of a VRF matched
typedef struct EXPLAIN_COUNTER
{
	char Network[CONTROL_NAME_SIZE];
	char Rule[CONTROL_NAME_SIZE];
	UINT Packets;
} EXPLAIN_COUNTER;

static bool ExplainCheck(EXPLAIN_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool ExplainCheck(EXPLAIN_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[EXPLAIN_TEXT_SIZE * 2];
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
static DWORD WINAPI ExplainWatchdog(LPVOID param)
{
	char msg[MAX_SIZE];
	DWORD written = 0;

	if (WaitForSingleObject((HANDLE)param, EXPLAIN_BUDGET) != WAIT_TIMEOUT)
	{
		return 0;
	}

	int len = snprintf(msg, sizeof(msg), "EXPLAIN TEST FAILED (did not finish within %u ms)\n", EXPLAIN_BUDGET);
	if (len > 0)
	{
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), msg, (DWORD)MIN((UINT)len, (UINT)sizeof(msg) - 1), &written, NULL);
	}

	TerminateProcess(GetCurrentProcess(), 1);

	return 0;
}

//
// The plans
//

// The node name of a plan, NULL for none
static EXPLAIN_NODE *ExplainNodeOf(EXPLAIN_PLAN *p, char *name)
{
	for (UINT i = 0;i < p->NumNodes;i++)
	{
		if (StrCmp(p->Nodes[i].Name, name) == 0)
		{
			return &p->Nodes[i];
		}
	}

	return NULL;
}

// Test packet number n of a plan (from 1), NULL for none
static EXPLAIN_PACKET *ExplainPacketOf(EXPLAIN_PLAN *p, char *number)
{
	UINT n = ToInt(number);

	if (IsNum(number) == false || n == 0 || n > p->NumPackets)
	{
		return NULL;
	}

	return &p->Packets[n - 1];
}

// The address of a text in its one form, as IPToStr writes it; false for a text that is no address
static bool ExplainAddress(char *dst, UINT size, char *src)
{
	IP ip;

	if (StrToIP(&ip, src) == false)
	{
		return false;
	}

	IPToStr(dst, size, &ip);
	return true;
}

static int ExplainCompareJudges(const void *p1, const void *p2)
{
	return StrCmp(((const EXPLAIN_JUDGE *)p1)->Text, ((const EXPLAIN_JUDGE *)p2)->Text);
}

// The verdict as a line, from where the packet ended (dst, of size bytes) and the rules that judged it, which are
// sorted
static void ExplainVerdictLine(char *dst, UINT size, char *end, EXPLAIN_JUDGE *judges, UINT num)
{
	StrCpy(dst, size, end);
	StrCat(dst, size, "; rules");

	if (num != 0)
	{
		qsort(judges, num, sizeof(EXPLAIN_JUDGE), ExplainCompareJudges);
	}
	for (UINT i = 0;i < num;i++)
	{
		StrCat(dst, size, " ");
		StrCat(dst, size, judges[i].Text);
	}
	if (num == 0)
	{
		StrCat(dst, size, " none");
	}
}

// Read one line of a plan into p: false, with the reason in error, for a line that is not one of a plan
static bool ExplainPlanLine(EXPLAIN_PLAN *p, char *line, char *error, UINT error_size)
{
	TOKEN_LIST *t = ParseToken(line, " ");
	bool ok = true;

	if (t == NULL || t->NumTokens == 0)
	{
		FreeToken(t);
		return true;
	}

	char *kind = t->Token[0];
	EXPLAIN_PACKET *k = (t->NumTokens >= 2 ? ExplainPacketOf(p, t->Token[1]) : NULL);

	if (StrCmp(kind, "plan") == 0)
	{
		ok = (t->NumTokens == 2 && ToInt(t->Token[1]) == EXPLAIN_PLAN_VERSION);
	}
	else if (StrCmp(kind, "scenario") == 0)
	{
		ok = (t->NumTokens == 2);
		if (ok)
		{
			StrCpy(p->Name, sizeof(p->Name), t->Token[1]);
		}
	}
	else if (StrCmp(kind, "node") == 0)
	{
		ok = (t->NumTokens == 3 && p->NumNodes < EXPLAIN_MAX_NODES && IsNum(t->Token[2]) && ToInt(t->Token[2]) <= 255 && ExplainNodeOf(p, t->Token[1]) == NULL);
		if (ok)
		{
			EXPLAIN_NODE *n = &p->Nodes[p->NumNodes++];

			StrCpy(n->Name, sizeof(n->Name), t->Token[1]);
			n->First = ToInt(t->Token[2]);
			InitializeSRWLock(&n->Lock);
		}
	}
	else if (StrCmp(kind, "frame") == 0)
	{
		EXPLAIN_NODE *n = (t->NumTokens == 3 ? ExplainNodeOf(p, t->Token[1]) : NULL);

		ok = (n != NULL && n->Frame == NULL);
		if (ok)
		{
			n->Frame = StrToBin(t->Token[2]);
			ok = (n->Frame != NULL && n->Frame->Size != 0 && n->Frame->Size * 2 == StrLen(t->Token[2]));
		}
	}
	else if (StrCmp(kind, "packet") == 0)
	{
		ok = (t->NumTokens == 6 && p->NumPackets < EXPLAIN_MAX_PACKETS && IsNum(t->Token[1]) && ToInt(t->Token[1]) == p->NumPackets + 1 &&
			ExplainNodeOf(p, t->Token[3]) != NULL && IsNum(t->Token[4]));
		if (ok)
		{
			k = &p->Packets[p->NumPackets++];
			StrCpy(k->Name, sizeof(k->Name), t->Token[2]);
			StrCpy(k->From, sizeof(k->From), t->Token[3]);
			k->VrfId = ToInt(t->Token[4]);
			k->Bytes = StrToBin(t->Token[5]);
			k->Text = NewListFast(NULL);
			ok = (k->Bytes != NULL && k->Bytes->Size >= 20 && k->Bytes->Size * 2 == StrLen(t->Token[5]));
		}
	}
	else if (StrCmp(kind, "expect") == 0)
	{
		char src[64], dst[64], end[MAX_SIZE];

		ok = (k != NULL && k->Expected == false && t->NumTokens >= 4);
		if (ok && StrCmp(t->Token[2], "delivered") == 0)
		{
			ok = (t->NumTokens == 7 && IsNum(t->Token[4]) && ExplainAddress(src, sizeof(src), t->Token[5]) && ExplainAddress(dst, sizeof(dst), t->Token[6]));
			if (ok)
			{
				Format(end, sizeof(end), "delivered to %s in VRF %u as %s > %s", t->Token[3], ToInt(t->Token[4]), src, dst);
			}
		}
		else if (ok && StrCmp(t->Token[2], "dropped") == 0)
		{
			ok = (t->NumTokens == 4);
			Format(end, sizeof(end), "dropped by %s", t->Token[3]);
		}
		else
		{
			ok = false;
		}
		if (ok)
		{
			StrCpy(k->Expect, sizeof(k->Expect), end);
			k->Expected = true;
		}
	}
	else if (StrCmp(kind, "judge") == 0)
	{
		ok = (k != NULL && t->NumTokens == 5 && k->NumJudges < EXPLAIN_MAX_JUDGES);
		if (ok)
		{
			Format(k->Judges[k->NumJudges++].Text, sizeof(k->Judges[0].Text), "%s/%s/%s", t->Token[2], t->Token[3], t->Token[4]);
		}
	}
	else if (StrCmp(kind, "text") == 0)
	{
		// The rest of the line after the number
		char *rest = line + StrLen(kind) + 1 + (t->NumTokens >= 2 ? StrLen(t->Token[1]) + 1 : 0);

		ok = (k != NULL && StrLen(line) >= (UINT)(rest - line));
		if (ok)
		{
			Add(k->Text, CopyStr(rest));
		}
	}
	else
	{
		ok = false;
	}

	if (ok == false)
	{
		Format(error, error_size, "the line \"%.120s\" is not a line of a plan of version %u", line, EXPLAIN_PLAN_VERSION);
	}

	FreeToken(t);
	return ok;
}

// Free what a plan holds
static void ExplainFreePlan(EXPLAIN_PLAN *p)
{
	for (UINT i = 0;i < p->NumNodes;i++)
	{
		FreeBuf(p->Nodes[i].Frame);
	}

	for (UINT i = 0;i < p->NumPackets;i++)
	{
		EXPLAIN_PACKET *k = &p->Packets[i];

		FreeBuf(k->Bytes);
		for (UINT j = 0;k->Text != NULL && j < LIST_NUM(k->Text);j++)
		{
			Free(LIST_DATA(k->Text, j));
		}
		if (k->Text != NULL)
		{
			ReleaseList(k->Text);
		}
	}

	Free(p);
}

// Read the plan of the file path: NULL, with the reason in error, when it is not a whole plan
static EXPLAIN_PLAN *ExplainReadPlan(char *path, char *error, UINT error_size)
{
	BUF *b = ReadDump(path);
	EXPLAIN_PLAN *p = ZeroMalloc(sizeof(EXPLAIN_PLAN));
	bool ok = (b != NULL);
	char *line;

	if (ok == false)
	{
		Format(error, error_size, "%s cannot be read", path);
	}

	while (ok && (line = CfgReadNextLine(b)) != NULL)
	{
		Trim(line);
		if (IsEmptyStr(line) == false && line[0] != '#')
		{
			ok = ExplainPlanLine(p, line, error, error_size);
		}
		Free(line);
	}
	FreeBuf(b);

	if (ok && (IsEmptyStr(p->Name) || p->NumNodes == 0 || p->NumPackets == 0))
	{
		Format(error, error_size, "%s names no scenario, node or packet", path);
		ok = false;
	}
	for (UINT i = 0;ok && i < p->NumNodes;i++)
	{
		if (p->Nodes[i].Frame == NULL)
		{
			Format(error, error_size, "%s has no frame of the node %s", path, p->Nodes[i].Name);
			ok = false;
		}
	}
	for (UINT i = 0;ok && i < p->NumPackets;i++)
	{
		if (p->Packets[i].Expected == false)
		{
			Format(error, error_size, "%s has no verdict of the packet %s", path, p->Packets[i].Name);
			ok = false;
		}
	}

	if (ok == false)
	{
		ExplainFreePlan(p);
		return NULL;
	}

	// The verdict of explain as a line, with its rules sorted, as the one of the data plane is written
	for (UINT i = 0;i < p->NumPackets;i++)
	{
		EXPLAIN_PACKET *k = &p->Packets[i];
		char end[EXPLAIN_TEXT_SIZE];

		StrCpy(end, sizeof(end), k->Expect);
		ExplainVerdictLine(k->Expect, sizeof(k->Expect), end, k->Judges, k->NumJudges);
	}

	return p;
}

//
// The stand-in controller
//

// Read one frame of the stream s into buf (max bytes): false when the stream ended or the frame did not come whole
// within EXPLAIN_FRAME_WAIT
static bool ExplainReadFrame(TRANSPORT_STREAM *s, UCHAR *buf, UINT max, UINT *size)
{
	UINT have = 0, need = EXPLAIN_FRAME_HEADER;
	UINT64 end = Tick64() + EXPLAIN_FRAME_WAIT;

	while (have < need)
	{
		UINT64 now = Tick64();
		if (now >= end)
		{
			return false;
		}

		UINT got = TransportRead(s, buf + have, need - have, (UINT)(end - now));
		if (got == TRANSPORT_LATER)
		{
			continue;
		}
		if (got == 0 || got > need - have)
		{
			return false;
		}
		have += got;

		if (have == EXPLAIN_FRAME_HEADER && need == EXPLAIN_FRAME_HEADER)
		{
			UINT len = READ_UINT(buf);
			if (len == 0 || len > max - EXPLAIN_FRAME_HEADER)
			{
				return false;
			}
			need += len;
		}
	}

	*size = need - EXPLAIN_FRAME_HEADER;
	return true;
}

// Write size bytes of data as one frame of the stream s
static bool ExplainWriteFrame(TRANSPORT_STREAM *s, const UCHAR *data, UINT size)
{
	UCHAR *frame = Malloc(EXPLAIN_FRAME_HEADER + size);

	WRITE_UINT(frame, size);
	Copy(frame + EXPLAIN_FRAME_HEADER, data, size);
	bool ok = TransportWrite(s, frame, EXPLAIN_FRAME_HEADER + size);
	Free(frame);

	return ok;
}

// The controller's end of one control stream (Core/Control.c from the other side): the Noise_IK handshake as the
// responder, with the controller's static key and the binding of the stream in the prologue; the Hello of the node;
// then the frame of the plan of the node whose static key the handshake proved. False when one of them fails.
static bool ExplainServe(EXPLAIN_CONTROLLER *c, TRANSPORT_STREAM *s)
{
	UCHAR prologue[sizeof(CONTROL_PROLOGUE_LABEL) - 1 + CONTROL_EXPORTER_SIZE];
	UCHAR binding[NOISE_MAX_BINDING];
	UCHAR *buf = Malloc(EXPLAIN_MAX_FRAME);
	NOISE_HANDSHAKE hs;
	UINT size = 0, payload_size = 0;
	EXPLAIN_NODE *n = NULL;

	Zero(&hs, sizeof(hs));
	bool ok = (TransportBinding(s, binding, sizeof(binding), &size) == NOISE_BINDING_EXPORTER && size == CONTROL_EXPORTER_SIZE);
	if (ok)
	{
		Copy(prologue, CONTROL_PROLOGUE_LABEL, sizeof(CONTROL_PROLOGUE_LABEL) - 1);
		Copy(prologue + sizeof(CONTROL_PROLOGUE_LABEL) - 1, binding, CONTROL_EXPORTER_SIZE);
		ok = NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, sizeof(prologue), c->Scalar, NULL, NULL);
	}
	ok = ok && ExplainReadFrame(s, buf, EXPLAIN_MAX_FRAME, &size) && NoiseHandshakeRead(&hs, buf + EXPLAIN_FRAME_HEADER, size, NULL, 0, &payload_size);
	ok = ok && NoiseHandshakeWrite(&hs, NULL, 0, buf, EXPLAIN_MAX_FRAME, &size) && ExplainWriteFrame(s, buf, size);

	// The node whose key the handshake proved
	for (UINT i = 0;ok && i < c->Plan->NumNodes && n == NULL;i++)
	{
		EXPLAIN_NODE *e = &c->Plan->Nodes[i];

		if (e->Keyed && Cmp(e->Key.Public, hs.RemoteStatic, PEER_KEY_SIZE) == 0)
		{
			n = e;
		}
	}
	NoiseHandshakeFree(&hs);
	Zero(binding, sizeof(binding));
	Zero(prologue, sizeof(prologue));

	// Its Hello, then its state: the node acknowledges it, and its overlay reports the Generation
	ok = ok && n != NULL && ExplainReadFrame(s, buf, EXPLAIN_MAX_FRAME, &size);
	ok = ok && ExplainWriteFrame(s, n->Frame->Buf, n->Frame->Size);

	Free(buf);
	return ok;
}

// The thread of the stand-in controller: it serves each control stream that a node opens, and keeps it open
static DWORD WINAPI ExplainControllerThread(LPVOID param)
{
	EXPLAIN_CONTROLLER *c = (EXPLAIN_CONTROLLER *)param;

	while (InterlockedCompareExchange(&c->Halt, 0, 0) == 0)
	{
		TRANSPORT_STREAM *s = TransportAccept(c->Listener, EXPLAIN_ACCEPT);

		if (s == NULL)
		{
			continue;
		}
		if (ExplainServe(c, s))
		{
			InterlockedIncrement(&c->Served);
			Add(c->Streams, s);
		}
		else
		{
			InterlockedIncrement(&c->Failed);
			TransportClose(s);
		}
	}

	return 0;
}

// Start the stand-in controller of the plan p on the transport t: NULL when it cannot listen
static EXPLAIN_CONTROLLER *ExplainStartController(EXPLAIN_PLAN *p, TRANSPORT *t)
{
	EXPLAIN_CONTROLLER *c = ZeroMalloc(sizeof(EXPLAIN_CONTROLLER));

	c->Plan = p;
	c->Streams = NewListFast(NULL);
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		c->Scalar[i] = (UCHAR)(0xC0 + i);
	}
	c->Listener = TransportListen(t, EXPLAIN_CONTROLLER);

	if (c->Listener != NULL && PeerKeyFromScalar(&c->Key, c->Scalar))
	{
		c->Thread = CreateThread(NULL, 0, ExplainControllerThread, c, 0, NULL);
	}
	if (c->Thread == NULL)
	{
		TransportCloseListener(c->Listener);
		PeerKeyClose(&c->Key);
		ReleaseList(c->Streams);
		Free(c);
		return NULL;
	}

	return c;
}

// Stop the stand-in controller, once the nodes stopped their control streams
static void ExplainStopController(EXPLAIN_CONTROLLER *c)
{
	if (c == NULL)
	{
		return;
	}

	InterlockedExchange(&c->Halt, 1);
	WaitForSingleObject(c->Thread, INFINITE);
	CloseHandle(c->Thread);

	for (UINT i = 0;i < LIST_NUM(c->Streams);i++)
	{
		TransportClose(LIST_DATA(c->Streams, i));
	}
	ReleaseList(c->Streams);
	TransportCloseListener(c->Listener);
	PeerKeyClose(&c->Key);
	Zero(c->Scalar, sizeof(c->Scalar));
	Free(c);
}

//
// The nodes
//

// The fake adapter of a host: it counts the packets that it takes, and keeps the last one with its VRF
static void ExplainAdapter(NODE *n, void *param, UINT vrf_id, const UCHAR *packet, UINT size)
{
	EXPLAIN_NODE *t = (EXPLAIN_NODE *)param;

	AcquireSRWLockExclusive(&t->Lock);
	t->Packets++;
	t->Vrf = vrf_id;
	t->LastSize = MIN(size, EXPLAIN_MAX_PACKET);
	Copy(t->Last, packet, t->LastSize);
	ReleaseSRWLockExclusive(&t->Lock);
}

// The packets that the adapter of the host of t took
static UINT ExplainTaken(EXPLAIN_NODE *t)
{
	AcquireSRWLockShared(&t->Lock);
	UINT ret = t->Packets;
	ReleaseSRWLockShared(&t->Lock);

	return ret;
}

// The packets that the overlay of the node t dropped
static UINT64 ExplainDropped(EXPLAIN_NODE *t)
{
	NODE_OVERLAY_STATUS st;

	NodeOverlayGetStatus(t->Node, &st);

	return st.Dropped;
}

// A new empty data directory under the temp directory of the process, with a configuration store that runs no role
// on one worker
static void ExplainNewDir(wchar_t *dir, UINT size, char *name)
{
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];

	UniFormat(tmp, sizeof(tmp), L"explaintest_%S_%u", name, Rand32());
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
static void ExplainDeleteFiles(wchar_t *dir)
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

// Start the node t: its static key from the first byte of its scalar, the fake adapter of its host, and its overlay
// with the control stream to the stand-in controller c over control, and its Noise sessions over data
static bool ExplainStartNode(EXPLAIN_NODE *t, EXPLAIN_CONTROLLER *c, TRANSPORT *control, TRANSPORT *data)
{
	UCHAR scalar[PEER_KEY_SIZE];
	NODE_OVERLAY_CONFIG cfg;

	for (UINT j = 0;j < PEER_KEY_SIZE;j++)
	{
		scalar[j] = (UCHAR)(t->First + j);
	}
	t->Keyed = PeerKeyFromScalar(&t->Key, scalar);
	Zero(scalar, sizeof(scalar));
	if (t->Keyed == false)
	{
		return false;
	}

	ExplainNewDir(t->Dir, sizeof(t->Dir), t->Name);
	t->Node = NewNode(t->Dir);
	NodeStart(t->Node);
	NodeReaderRegister(t->Node, &t->Reader);
	NodeReaderOffline(&t->Reader);

	Zero(&cfg, sizeof(cfg));
	cfg.Control = control;
	StrCpy(cfg.Controller, sizeof(cfg.Controller), EXPLAIN_CONTROLLER);
	Copy(cfg.ControllerKey, c->Key.Public, PEER_KEY_SIZE);
	cfg.Data = data;
	cfg.Key = &t->Key;
	cfg.Adapter = ExplainAdapter;
	cfg.AdapterParam = t;

	return NodeOverlayStart(t->Node, &cfg);
}

// Stop the node t, every thread joined, and delete its data directory
static void ExplainStopNode(EXPLAIN_NODE *t)
{
	wchar_t log_dir[MAX_PATH];

	if (t->Node != NULL)
	{
		NodeReaderUnregister(t->Node, &t->Reader);
		NodeStop(t->Node);
		FreeNode(t->Node);
		t->Node = NULL;
		ConbinePathW(log_dir, sizeof(log_dir), t->Dir, NODE_LOG_DIR_NAME);
		ExplainDeleteFiles(log_dir);
		ExplainDeleteFiles(t->Dir);
	}
	if (t->Keyed)
	{
		PeerKeyClose(&t->Key);
		t->Keyed = false;
	}
}

// Wait until every node of p runs Generation 1 of its state and has a Noise session to each of its peers
static bool ExplainWaitJoined(EXPLAIN_PLAN *p)
{
	UINT64 end = Tick64() + EXPLAIN_JOIN;

	while (true)
	{
		bool all = true;

		for (UINT i = 0;i < p->NumNodes;i++)
		{
			NODE_OVERLAY_STATUS st;

			NodeOverlayGetStatus(p->Nodes[i].Node, &st);
			if (st.Generation != 1 || st.NumLinks != st.NumPeers)
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
		SleepThread(EXPLAIN_POLL);
	}
}

//
// The packets
//

// The counters of the policy of the node t, *num of them: the packets that each rule and default action of the
// Network of each VRF matched, from the text of the counters (PolicyCountersText); NULL for none
static EXPLAIN_COUNTER *ExplainCounters(EXPLAIN_NODE *t, UINT *num)
{
	char *text = NodePolicyCountersText(t->Node);
	char network[CONTROL_NAME_SIZE];

	*num = 0;
	if (text == NULL)
	{
		return NULL;
	}

	TOKEN_LIST *lines = ParseToken(text, "\r\n");
	EXPLAIN_COUNTER *list = ZeroMalloc(sizeof(EXPLAIN_COUNTER) * MAX(lines->NumTokens, 1));

	StrCpy(network, sizeof(network), "");
	for (UINT i = 0;i < lines->NumTokens;i++)
	{
		TOKEN_LIST *w = ParseToken(lines->Token[i], " ");

		// "network NAME: ..." starts the Network of a VRF; "PRIORITY RULE ACTION FLOWS PACKETS BYTES" is one of its rules
		if (w->NumTokens >= 2 && StrCmp(w->Token[0], "network") == 0)
		{
			StrCpy(network, sizeof(network), w->Token[1]);
			if (EndWith(network, ":"))
			{
				network[StrLen(network) - 1] = 0;
			}
		}
		else if (w->NumTokens == 6 && IsNum(w->Token[4]) && IsEmptyStr(network) == false)
		{
			EXPLAIN_COUNTER *e = &list[(*num)++];

			StrCpy(e->Network, sizeof(e->Network), network);
			StrCpy(e->Rule, sizeof(e->Rule), w->Token[1]);
			e->Packets = ToInt(w->Token[4]);
		}
		FreeToken(w);
	}

	FreeToken(lines);
	Free(text);

	return list;
}

// The rules that matched packets of the node t between the counters before (num_before of them) and after, as judges
// "node vrf rule" added to judges, which holds *num of max at most
static void ExplainJudged(EXPLAIN_NODE *t, EXPLAIN_COUNTER *before, UINT num_before, EXPLAIN_COUNTER *after, UINT num_after, EXPLAIN_JUDGE *judges, UINT *num, UINT max)
{
	for (UINT i = 0;i < num_after;i++)
	{
		UINT was = 0;

		for (UINT j = 0;j < num_before;j++)
		{
			if (StrCmp(before[j].Network, after[i].Network) == 0 && StrCmp(before[j].Rule, after[i].Rule) == 0)
			{
				was = before[j].Packets;
			}
		}
		if (after[i].Packets > was && *num < max)
		{
			Format(judges[(*num)++].Text, sizeof(judges[0].Text), "%s/%s/%s", t->Name, after[i].Network, after[i].Rule);
		}
	}
}

// Send the packet k of the plan p from the host of its node and check that the data plane gives it the verdict of
// explain: where it ends, and the rules that judged it at each node
static void ExplainSend(EXPLAIN_CTX *ctx, EXPLAIN_PLAN *p, EXPLAIN_PACKET *k)
{
	EXPLAIN_NODE *from = ExplainNodeOf(p, k->From);
	UINT taken[EXPLAIN_MAX_NODES];
	UINT64 dropped[EXPLAIN_MAX_NODES];
	EXPLAIN_COUNTER *before[EXPLAIN_MAX_NODES];
	UINT num_before[EXPLAIN_MAX_NODES];
	EXPLAIN_JUDGE judges[EXPLAIN_MAX_JUDGES];
	UINT num_judges = 0;
	char end[EXPLAIN_TEXT_SIZE], seen[EXPLAIN_TEXT_SIZE], what[MAX_SIZE * 2];
	UINT ended_at = INFINITE;
	bool delivered = false;

	for (UINT i = 0;i < p->NumNodes;i++)
	{
		taken[i] = ExplainTaken(&p->Nodes[i]);
		dropped[i] = ExplainDropped(&p->Nodes[i]);
		before[i] = ExplainCounters(&p->Nodes[i], &num_before[i]);
	}

	NodeReaderOnline(from->Node, &from->Reader);
	NodeOverlayInput(from->Node, k->VrfId, k->Bytes->Buf, k->Bytes->Size);
	NodeReaderOffline(&from->Reader);

	// The first node whose host took the packet or whose overlay dropped it
	for (UINT64 limit = Tick64() + EXPLAIN_BOUND;ended_at == INFINITE && Tick64() < limit;SleepThread(EXPLAIN_POLL))
	{
		for (UINT i = 0;i < p->NumNodes && ended_at == INFINITE;i++)
		{
			if (ExplainTaken(&p->Nodes[i]) != taken[i])
			{
				ended_at = i;
				delivered = true;
			}
			else if (ExplainDropped(&p->Nodes[i]) != dropped[i])
			{
				ended_at = i;
			}
		}
	}

	if (ended_at == INFINITE)
	{
		Format(end, sizeof(end), "lost: no node took it or dropped it within %u ms", EXPLAIN_BOUND);
	}
	else if (delivered)
	{
		EXPLAIN_NODE *t = &p->Nodes[ended_at];
		char src[64], dst[64];
		IP a, b;

		Zero(&a, sizeof(a));
		Zero(&b, sizeof(b));
		AcquireSRWLockShared(&t->Lock);
		UINT vrf = t->Vrf;
		if (t->LastSize >= 20 && (t->Last[0] >> 4) == 4)
		{
			SetIP(&a, t->Last[12], t->Last[13], t->Last[14], t->Last[15]);
			SetIP(&b, t->Last[16], t->Last[17], t->Last[18], t->Last[19]);
		}
		else if (t->LastSize >= 40 && (t->Last[0] >> 4) == 6)
		{
			SetIP6(&a, t->Last + 8);
			SetIP6(&b, t->Last + 24);
		}
		ReleaseSRWLockShared(&t->Lock);

		IPToStr(src, sizeof(src), &a);
		IPToStr(dst, sizeof(dst), &b);
		Format(end, sizeof(end), "delivered to %s in VRF %u as %s > %s", t->Name, vrf, src, dst);
	}
	else
	{
		Format(end, sizeof(end), "dropped by %s", p->Nodes[ended_at].Name);
	}

	// The rules that judged it, from the counters of the policy of each node
	for (UINT i = 0;i < p->NumNodes;i++)
	{
		UINT num_after = 0;
		EXPLAIN_COUNTER *after = ExplainCounters(&p->Nodes[i], &num_after);

		ExplainJudged(&p->Nodes[i], before[i], num_before[i], after, num_after, judges, &num_judges, EXPLAIN_MAX_JUDGES);
		Free(after);
		Free(before[i]);
	}
	ExplainVerdictLine(seen, sizeof(seen), end, judges, num_judges);

	for (UINT i = 0;i < LIST_NUM(k->Text);i++)
	{
		Print("    explain: %s\n", (char *)LIST_DATA(k->Text, i));
	}

	if (StrCmp(seen, k->Expect) == 0)
	{
		Format(what, sizeof(what), "%s %s: %s", p->Name, k->Name, seen);
		ExplainCheck(ctx, true, what, "%s", "");
		return;
	}

	ctx->NumDiffer++;
	Format(what, sizeof(what), "EXPLAIN DIFFER %s %s", p->Name, k->Name);
	ExplainCheck(ctx, false, what, "explain: %s; the data plane: %s", k->Expect, seen);
}

// Run the scenario of the plan p: its nodes join the stand-in controller, and each of its packets goes through the
// data plane
static void ExplainScenario(EXPLAIN_CTX *ctx, EXPLAIN_PLAN *p)
{
	TRANSPORT *data = TransportLoopbackNew("loopback", 0, false);
	TRANSPORT *control = TransportLoopbackNew("control", 0, true);
	EXPLAIN_CONTROLLER *c = (control != NULL ? ExplainStartController(p, control) : NULL);
	char what[MAX_SIZE];
	bool started = (data != NULL && c != NULL);

	Print("Scenario %s: %u nodes, %u packets\n", p->Name, p->NumNodes, p->NumPackets);

	Format(what, sizeof(what), "%s: the loopback transports of the sessions and of the control streams, and the stand-in controller", p->Name);
	ExplainCheck(ctx, started, what, "%s", "they could not start");

	for (UINT i = 0;i < p->NumNodes && started;i++)
	{
		EXPLAIN_NODE *t = &p->Nodes[i];

		Format(what, sizeof(what), "%s: %s runs its overlay with its control stream to the stand-in controller", p->Name, t->Name);
		started = ExplainCheck(ctx, ExplainStartNode(t, c, control, data), what, "%s", "NodeOverlayStart failed");
	}

	if (started)
	{
		Format(what, sizeof(what), "%s: every node applied Generation 1 of its state from its control stream, and its Noise sessions are up", p->Name);
		started = ExplainCheck(ctx, ExplainWaitJoined(p), what, "not within %u ms; the stand-in controller served %u streams, %u failed", EXPLAIN_JOIN,
			(UINT)InterlockedCompareExchange(&c->Served, 0, 0), (UINT)InterlockedCompareExchange(&c->Failed, 0, 0));
	}

	for (UINT i = 0;i < p->NumPackets && started;i++)
	{
		ExplainSend(ctx, p, &p->Packets[i]);
	}

	// The nodes stop, with their control streams, before the controller and the transports
	for (UINT i = 0;i < p->NumNodes;i++)
	{
		ExplainStopNode(&p->Nodes[i]);
	}
	ExplainStopController(c);
	TransportLoopbackFree(control);
	TransportLoopbackFree(data);
}

static int ExplainCompareNames(const void *p1, const void *p2)
{
	return StrCmp(*(char *const *)p1, *(char *const *)p2);
}

// explain: the data plane half of the explain conformance
RANZ_TEST("explain", explain_test, "Explain conformance (SDN-15): runs the plans that ranz-explainplan wrote from the scenarios of tests/explain through real nodes, whose states come from a stand-in controller over their control streams, and checks that each test packet ends where explain says, with the rules that explain names. Usage: explain <plan directory>.");
void explain_test(UINT num, char **arg)
{
	EXPLAIN_CTX ctx;
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, ExplainWatchdog, done, 0, NULL) : NULL);
	DIRLIST *d = (num >= 1 ? EnumDir(arg[0]) : NULL);
	char **files = NULL;
	UINT num_files = 0;

	Zero(&ctx, sizeof(ctx));

	Print("Explain conformance: the scenarios of tests/explain through the data plane of real nodes\n");

	// The plans of the directory, in name order
	if (d != NULL)
	{
		files = ZeroMalloc(sizeof(char *) * MAX(d->NumFiles, 1));
		for (UINT i = 0;i < d->NumFiles;i++)
		{
			if (d->File[i]->Folder == false && EndWith(d->File[i]->FileName, ".plan"))
			{
				char path[MAX_PATH];

				ConbinePath(path, sizeof(path), arg[0], d->File[i]->FileName);
				files[num_files++] = CopyStr(path);
			}
		}
		if (num_files != 0)
		{
			qsort(files, num_files, sizeof(char *), ExplainCompareNames);
		}
	}
	ExplainCheck(&ctx, num_files != 0, "the plans of the directory", "%s", "usage: explain <a directory of plans that ranz-explainplan wrote>");

	for (UINT i = 0;i < num_files;i++)
	{
		char error[MAX_SIZE * 2];
		char what[MAX_SIZE];

		StrCpy(error, sizeof(error), "");
		EXPLAIN_PLAN *p = ExplainReadPlan(files[i], error, sizeof(error));

		Format(what, sizeof(what), "the plan %s", files[i]);
		if (ExplainCheck(&ctx, p != NULL, what, "%s", error))
		{
			ExplainScenario(&ctx, p);
			ExplainFreePlan(p);
		}
		Free(files[i]);
	}
	Free(files);
	FreeDir(d);

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

	Print("EXPLAIN SUMMARY %u checks, %u failed, %u packets whose verdicts differ\n", ctx.NumChecks, ctx.NumFailed, ctx.NumDiffer);
	if (ctx.NumFailed == 0)
	{
		Print("EXPLAIN TEST OK\n");
	}
	else
	{
		Print("EXPLAIN TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
