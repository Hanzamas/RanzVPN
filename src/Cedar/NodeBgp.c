// NodeBgp.c
// The BGP sidecar of a node (ADR-0010, ADR-0022; CORE-S7-1, #82; ONE-1, #310): ranz bgp, the subcommand of the one Go
// executable ranz.exe, which embeds GoBGP as a library and peers with the operator's own routers. The node starts
// it as ranz.exe bgp, from the folder of its own executable, when its configuration names BGP peers, talks to it over
// a named pipe with JSON messages, one per line (the protocol of ranz-bgp/internal/sidecar), and installs the routes
// it learns into Windows through IP Helper. There is no BGP in the node and no RRAS; a node without BGP peers never
// starts the sidecar, and a node without ranz.exe next to it has none to start.

#include "Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"

#include "NodeEvpn.h"
#include "NodeInternal.h"

#include <AclAPI.h>
#include <WinDNS.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include <sddl.h>

#include <cjson/cJSON.h>

// The strict DACL of the pipe (ADR-0039 decision 3): the owner alone, the account of the node, which its sidecar
// runs as; not SYSTEM and not the Administrators, and nothing for anyone else. The node creates it before the sidecar
// starts, as the first and only instance, for local clients only, and takes only its own sidecar as the client
// (GetNamedPipeClientProcessId).
#define NODE_BGP_PIPE_SDDL L"D:P(A;;GA;;;OW)"

#define NODE_BGP_CONNECT_WAIT 30000 // How long the node waits for the sidecar to connect to the pipe (ms)
#define NODE_BGP_WRITE_WAIT   5000  // How long one message may take to reach the pipe (ms)
#define NODE_BGP_EXIT_WAIT    10000 // How long the sidecar may take to stop BGP and exit after the pipe closes (ms)
#define NODE_BGP_READ_SIZE    4096  // Bytes of one read of the pipe

// A route that the sidecar learned, and that the node installed into the Windows routing table
typedef struct NODE_BGP_ROUTE {
	char Prefix[MAX_SIZE];  // The prefix, as the sidecar names it
	char NextHop[MAX_SIZE]; // Its next hop
	char Peer[MAX_SIZE];    // The peer it came from
	MIB_IPFORWARD_ROW2 Row; // The route through IP Helper
	bool Installed;         // Whether CreateIpForwardEntry2 took it; false when Windows has the same route already
} NODE_BGP_ROUTE;

// A peer of the settings, with the last state the sidecar reported
typedef struct NODE_BGP_PEER {
	char Address[MAX_SIZE]; // Its address
	char State[MAX_SIZE];   // Its session state (idle, connect, active, opensent, openconfirm, established)
} NODE_BGP_PEER;

// A prefix that the node announces, as a route of an EVPN VRF of a gateway (NodeEvpn.c; SDN-25, #201) or of none
typedef struct NODE_BGP_ANNOUNCED {
	UINT VrfId;            // The EVPN VRF, 0 for none
	char Prefix[MAX_SIZE]; // The prefix
} NODE_BGP_ANNOUNCED;

// The sidecar of a running node
struct NODE_BGP {
	NODE *Node;                 // The node
	LOCK *Lock;                 // The routes, the peers, the announced prefixes and the state below
	LOCK *WriteLock;            // One message at a time on the pipe
	wchar_t PipeName[MAX_PATH]; // The name of the pipe
	HANDLE Pipe;                // The server end of the pipe, overlapped
	char PipeAcl[MAX_SIZE];     // The DACL of the pipe as the system holds it, in SDDL
	HANDLE WriteEvent;          // The event of a write
	HANDLE StopEvent;           // Ends the reader thread
	HANDLE Job;                 // The job of the sidecar: it ends with the node, also when the node does not stop
	HANDLE Process;             // The sidecar
	UINT ProcessId;             // Its process id
	HANDLE Reader;              // The thread that reads the messages of the sidecar
	bool Ready;                 // BGP runs: the sidecar sent ready
	bool Exited;                // The sidecar closed the pipe or exited by itself
	char Version[MAX_SIZE];     // What ready named
	UINT NumErrors;             // Error messages of the sidecar
	LIST *Peers;                // The peers of the settings (NODE_BGP_PEER)
	LIST *Announced;            // The prefixes the node announces (NODE_BGP_ANNOUNCED)
	LIST *Routes;               // The learned routes (NODE_BGP_ROUTE)
	char *Line;                 // The reader thread: the message read so far
	UINT LineSize;              // Its bytes
};

// cJSON allocates through Mayaqua, so the memory check of vpntest covers it. x64 and arm64 have one calling
// convention, so plain functions fit the CJSON_CDECL pointers of cJSON_Hooks.
static void *NodeBgpJsonMalloc(size_t size) {
	return Malloc((UINT)size);
}

static void NodeBgpJsonFree(void *p) {
	Free(p);
}

static INIT_ONCE node_bgp_json_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK NodeBgpJsonInit(PINIT_ONCE once, void *param, void **context) {
	cJSON_Hooks hooks;

	Zero(&hooks, sizeof(hooks));
	hooks.malloc_fn = NodeBgpJsonMalloc;
	hooks.free_fn = NodeBgpJsonFree;
	cJSON_InitHooks(&hooks);

	return TRUE;
}

static bool NodeBgpAnnounceLocked(NODE *n, char *prefix, char *next_hop, UINT vrf_id);

// The string member name of a JSON object; "" when it has none
static char *NodeBgpJsonStr(cJSON *o, char *name) {
	char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));

	return (s != NULL ? s : "");
}

// The number member name of a JSON object as a UINT; 0 when it has none or it is out of range
static UINT NodeBgpJsonUint(cJSON *o, char *name) {
	cJSON *item = cJSON_GetObjectItemCaseSensitive(o, name);

	if (cJSON_IsNumber(item) == false || item->valuedouble < 0 || item->valuedouble > 4294967295.0)
		return 0;

	return (UINT)item->valuedouble;
}

// Parse an IPv4 or IPv6 address, or with types NET_STRING_IP_NETWORK a prefix, into a SOCKADDR_INET; ERROR_SUCCESS
// when it is one
static DWORD NodeBgpParse(char *str, DWORD types, SOCKADDR_INET *addr, BYTE *prefix_len) {
	wchar_t tmp[MAX_SIZE];
	NET_ADDRESS_INFO info;

	Zero(addr, sizeof(SOCKADDR_INET));
	if (IsEmptyStr(str) || StrLen(str) >= MAX_SIZE)
		return ERROR_INVALID_PARAMETER;

	StrToUni(tmp, sizeof(tmp), str);
	Zero(&info, sizeof(info));

	DWORD ret = ParseNetworkString(tmp, types, &info, NULL, prefix_len);
	if (ret != ERROR_SUCCESS)
		return ret;

	if (info.Format == NET_ADDRESS_IPV4)
		addr->Ipv4 = info.Ipv4Address;
	else if (info.Format == NET_ADDRESS_IPV6)
		addr->Ipv6 = info.Ipv6Address;
	else
		return ERROR_INVALID_PARAMETER;

	return ERROR_SUCCESS;
}

// The route of a learned prefix via next_hop, on the interface that Windows reaches the next hop on
static DWORD NodeBgpMakeRoute(char *prefix, char *next_hop, MIB_IPFORWARD_ROW2 *row) {
	SOCKADDR_INET dst;
	SOCKADDR_INET nh;
	SOCKADDR_INET src;
	MIB_IPFORWARD_ROW2 best;
	BYTE prefix_len = 0;

	DWORD ret = NodeBgpParse(prefix, NET_STRING_IP_NETWORK, &dst, &prefix_len);
	if (ret == ERROR_SUCCESS)
		ret = NodeBgpParse(next_hop, NET_STRING_IP_ADDRESS_NO_SCOPE, &nh, NULL);
	if (ret != ERROR_SUCCESS)
		return ret;

	if (dst.si_family != nh.si_family)
		return ERROR_INVALID_PARAMETER;

	Zero(&best, sizeof(best));
	ret = GetBestRoute2(NULL, 0, NULL, &nh, 0, &best, &src);
	if (ret != NO_ERROR)
		return ret;

	InitializeIpForwardEntry(row);
	row->InterfaceLuid = best.InterfaceLuid;
	row->InterfaceIndex = best.InterfaceIndex;
	row->DestinationPrefix.Prefix = dst;
	row->DestinationPrefix.PrefixLength = prefix_len;
	row->NextHop = nh;
	row->SitePrefixLength = 0;
	row->Metric = NODE_BGP_ROUTE_METRIC;
	row->Protocol = MIB_IPPROTO_NETMGMT;
	row->Publish = FALSE;
	row->Immortal = FALSE;

	return NO_ERROR;
}

// The learned route of prefix; the caller holds the lock of the sidecar
static NODE_BGP_ROUTE *NodeBgpFindRoute(NODE_BGP *b, char *prefix) {
	for (UINT i = 0; i < LIST_NUM(b->Routes); i++) {
		NODE_BGP_ROUTE *r = LIST_DATA(b->Routes, i);

		if (StrCmpi(r->Prefix, prefix) == 0)
			return r;
	}

	return NULL;
}

// Take a learned route out of the Windows routing table and out of the list; the caller holds the lock of the
// sidecar
static void NodeBgpDeleteRoute(NODE_BGP *b, NODE_BGP_ROUTE *r) {
	if (r->Installed) {
		DWORD ret = DeleteIpForwardEntry2(&r->Row);

		if (ret == NO_ERROR || ret == ERROR_NOT_FOUND)
			NodeLog(b->Node, "BGP route %s via %s removed", r->Prefix, r->NextHop);
		else
			NodeLog(b->Node, "BGP route %s via %s not removed: error %u", r->Prefix, r->NextHop, (UINT)ret);
	}

	Delete(b->Routes, r);
	Free(r);
}

// Remove every learned route: the sidecar stopped, so the routes are stale. Returns how many there were.
static UINT NodeBgpDeleteAllRoutes(NODE_BGP *b) {
	UINT num = 0;

	Lock(b->Lock);
	{
		num = LIST_NUM(b->Routes);

		while (LIST_NUM(b->Routes) != 0)
			NodeBgpDeleteRoute(b, LIST_DATA(b->Routes, 0));
	}
	Unlock(b->Lock);

	return num;
}

// A learned message: install the route to prefix via next_hop, in place of the route it had before
static void NodeBgpLearned(NODE_BGP *b, char *prefix, char *next_hop, char *peer) {
	MIB_IPFORWARD_ROW2 row;

	DWORD made = NodeBgpMakeRoute(prefix, next_hop, &row);

	Lock(b->Lock);
	{
		NODE_BGP_ROUTE *old = NodeBgpFindRoute(b, prefix);

		if (old != NULL && StrCmpi(old->NextHop, next_hop) == 0 && old->Installed) {
			StrCpy(old->Peer, sizeof(old->Peer), peer);
		} else {
			if (old != NULL)
				NodeBgpDeleteRoute(b, old);

			if (made != NO_ERROR) {
				NodeLog(b->Node, "BGP route %s via %s from %s not installed: no route to the next hop (error %u)", prefix, next_hop, peer, (UINT)made);
			} else if (LIST_NUM(b->Routes) >= NODE_BGP_MAX_ROUTES) {
				NodeLog(b->Node, "BGP route %s via %s from %s not installed: the node holds %u learned routes, the most it takes", prefix, next_hop, peer, (UINT)NODE_BGP_MAX_ROUTES);
			} else {
				NODE_BGP_ROUTE *r = ZeroMalloc(sizeof(NODE_BGP_ROUTE));
				StrCpy(r->Prefix, sizeof(r->Prefix), prefix);
				StrCpy(r->NextHop, sizeof(r->NextHop), next_hop);
				StrCpy(r->Peer, sizeof(r->Peer), peer);
				r->Row = row;

				DWORD ret = CreateIpForwardEntry2(&r->Row);
				r->Installed = (ret == NO_ERROR);
				Add(b->Routes, r);

				if (ret == NO_ERROR)
					NodeLog(b->Node, "BGP route %s via %s from %s installed on interface %u", prefix, next_hop, peer, (UINT)row.InterfaceIndex);
				else if (ret == ERROR_OBJECT_ALREADY_EXISTS)
					NodeLog(b->Node, "BGP route %s via %s from %s: Windows has this route already, the node leaves it alone", prefix, next_hop, peer);
				else
					NodeLog(b->Node, "BGP route %s via %s from %s not installed: error %u", prefix, next_hop, peer, (UINT)ret);
			}
		}
	}
	Unlock(b->Lock);
}

// A withdrawn message: no peer has a route to prefix any more
static void NodeBgpWithdrawn(NODE_BGP *b, char *prefix, char *peer) {
	Lock(b->Lock);
	{
		NODE_BGP_ROUTE *r = NodeBgpFindRoute(b, prefix);

		if (r != NULL)
			NodeBgpDeleteRoute(b, r);
		else
			NodeLog(b->Node, "BGP route %s withdrawn by %s: the node had not installed it", prefix, peer);
	}
	Unlock(b->Lock);
}

// A peer message: the session state of a peer
static void NodeBgpPeerState(NODE_BGP *b, char *address, UINT asn, char *state) {
	NODE_BGP_PEER *p = NULL;

	Lock(b->Lock);
	{
		for (UINT i = 0; i < LIST_NUM(b->Peers); i++) {
			NODE_BGP_PEER *q = LIST_DATA(b->Peers, i);

			if (StrCmpi(q->Address, address) == 0) {
				p = q;
				break;
			}
		}

		if (p != NULL)
			StrCpy(p->State, sizeof(p->State), state);
	}
	Unlock(b->Lock);

	NodeLog(b->Node, "BGP peer %s (AS %u): %s%s", address, asn, state, p == NULL ? " (not a peer of the settings)" : "");
}

// One message of the sidecar
static void NodeBgpOnMessage(NODE_BGP *b, char *line) {
	cJSON *m = cJSON_Parse(line);
	char *type = NodeBgpJsonStr(m, "type");

	if (cJSON_IsObject(m) == false) {
		NodeLog(b->Node, "BGP sidecar: a message that is not a JSON object");
	} else if (StrCmp(type, "ready") == 0) {
		Lock(b->Lock);
		{
			b->Ready = true;
			StrCpy(b->Version, sizeof(b->Version), NodeBgpJsonStr(m, "version"));
		}
		Unlock(b->Lock);

		NodeLog(b->Node, "BGP sidecar ready: %s (protocol %u)", NodeBgpJsonStr(m, "version"), NodeBgpJsonUint(m, "protocol"));
	} else if (StrCmp(type, "peer") == 0) {
		NodeBgpPeerState(b, NodeBgpJsonStr(m, "peer"), NodeBgpJsonUint(m, "asn"), NodeBgpJsonStr(m, "state"));
	} else if (StrCmp(type, "learned") == 0) {
		// An IP prefix route of an EVPN VRF goes to the EVPN of the gateway, never into the Windows routing table (NodeEvpn.c;
		// SDN-25, #201)
		if (NodeEvpnRoute(b->Node, line) == false)
			NodeBgpLearned(b, NodeBgpJsonStr(m, "prefix"), NodeBgpJsonStr(m, "next_hop"), NodeBgpJsonStr(m, "peer"));
	} else if (StrCmp(type, "withdrawn") == 0) {
		if (NodeEvpnRoute(b->Node, line) == false)
			NodeBgpWithdrawn(b, NodeBgpJsonStr(m, "prefix"), NodeBgpJsonStr(m, "peer"));
	} else if (StrCmp(type, "stretch") == 0) {
		// The type-2 and type-3 routes of the fabric on the L2 VNIs of the stretches of a gateway (NodeStretch.c; SDN-64, #291)
		NodeStretchMessage(b->Node, line);
	} else if (StrCmp(type, "error") == 0) {
		Lock(b->Lock);
		{
			b->NumErrors++;
		}
		Unlock(b->Lock);

		char *prefix = NodeBgpJsonStr(m, "prefix");
		NodeLog(b->Node, "BGP sidecar error%s%s: %s", IsEmptyStr(prefix) ? "" : " for ", prefix, NodeBgpJsonStr(m, "error"));
	} else {
		NodeLog(b->Node, "BGP sidecar: a message of the unknown type \"%s\" ignored", type);
	}

	cJSON_Delete(m);
}

// The thread that reads the messages of the sidecar until the stop event, or until the sidecar closes the pipe;
// then the learned routes go, because BGP is gone
static DWORD WINAPI NodeBgpReaderThread(void *param) {
	NODE_BGP *b = (NODE_BGP *)param;
	UCHAR buf[NODE_BGP_READ_SIZE];
	OVERLAPPED ov;
	HANDLE events[2];
	bool stopped = false;

	HANDLE read_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (read_event == NULL)
		return 0;

	// The stop event first: WaitForMultipleObjects reports the lowest signalled index
	events[0] = b->StopEvent;
	events[1] = read_event;

	while (true) {
		DWORD got = 0;

		Zero(&ov, sizeof(ov));
		ov.hEvent = read_event;
		ResetEvent(read_event);

		if (ReadFile(b->Pipe, buf, sizeof(buf), NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
			break;

		if (WaitForMultipleObjects(2, events, FALSE, INFINITE) != WAIT_OBJECT_0 + 1) {
			CancelIoEx(b->Pipe, &ov);
			GetOverlappedResult(b->Pipe, &ov, &got, TRUE);
			stopped = true;
			break;
		}

		if (GetOverlappedResult(b->Pipe, &ov, &got, FALSE) == FALSE)
			break;

		bool too_long = false;

		for (DWORD i = 0; i < got && too_long == false; i++) {
			if (buf[i] != '\n') {
				if (b->LineSize >= NODE_BGP_MAX_LINE)
					too_long = true;
				else
					b->Line[b->LineSize++] = (char)buf[i];
				continue;
			}

			b->Line[b->LineSize] = 0;
			if (b->LineSize != 0)
				NodeBgpOnMessage(b, b->Line);
			b->LineSize = 0;
		}

		// The routes of the EVPN VRFs that the messages of this read changed go in together (NodeEvpn.c; SDN-25, #201), and so do
		// the routes of the fabric of the stretches (NodeStretch.c; SDN-64, #291)
		NodeEvpnCommit(b->Node);
		NodeStretchCommit(b->Node);

		if (too_long) {
			NodeLog(b->Node, "BGP sidecar: a message longer than %u bytes, the node stops reading", (UINT)NODE_BGP_MAX_LINE);
			break;
		}
	}

	CloseHandle(read_event);

	if (stopped == false) {
		Lock(b->Lock);
		{
			b->Exited = true;
			b->Ready = false;
		}
		Unlock(b->Lock);

		// ... and so do the routes of the EVPN VRFs (NodeEvpn.c; SDN-25, #201) and of the stretches (NodeStretch.c; SDN-64, #291)
		UINT num = NodeBgpDeleteAllRoutes(b) + NodeEvpnFlush(b->Node) + NodeStretchFlush(b->Node);
		NodeLog(b->Node, "BGP sidecar closed the pipe: BGP stopped, %u learned routes removed", num);
	}

	return 0;
}

// Send one message to the sidecar; the caller holds the node lock, or is the thread of the stretch of a gateway, which
// NodeBgpStop joins first (NodeStretch.c; SDN-64, #291), so the pipe stays open
bool NodeBgpSend(NODE_BGP *b, cJSON *m) {
	OVERLAPPED ov;
	DWORD done = 0;
	bool ret = false;

	char *s = cJSON_PrintUnformatted(m);
	if (s == NULL)
		return false;

	UINT len = StrLen(s);
	char *line = Malloc(len + 1);
	Copy(line, s, len);
	line[len] = '\n';
	cJSON_free(s);

	if (len + 1 <= NODE_BGP_MAX_LINE) {
		Lock(b->WriteLock);
		{
			Zero(&ov, sizeof(ov));
			ov.hEvent = b->WriteEvent;
			ResetEvent(b->WriteEvent);

			if (WriteFile(b->Pipe, line, len + 1, NULL, &ov) || GetLastError() == ERROR_IO_PENDING) {
				if (WaitForSingleObject(b->WriteEvent, NODE_BGP_WRITE_WAIT) != WAIT_OBJECT_0)
					CancelIoEx(b->Pipe, &ov);

				ret = (GetOverlappedResult(b->Pipe, &ov, &done, TRUE) && done == len + 1);
			}
		}
		Unlock(b->WriteLock);
	}

	Free(line);

	return ret;
}

// Free a sidecar whose reader thread has ended or never started; its process is gone or ends with its job
static void NodeBgpFree(NODE_BGP *b) {
	if (b->Pipe != INVALID_HANDLE_VALUE)
		CloseHandle(b->Pipe);
	if (b->Process != NULL)
		CloseHandle(b->Process);
	// Closing the job ends the sidecar if it still runs (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if (b->Job != NULL)
		CloseHandle(b->Job);
	if (b->WriteEvent != NULL)
		CloseHandle(b->WriteEvent);
	if (b->StopEvent != NULL)
		CloseHandle(b->StopEvent);

	for (UINT i = 0; i < LIST_NUM(b->Peers); i++)
		Free(LIST_DATA(b->Peers, i));
	ReleaseList(b->Peers);

	for (UINT i = 0; i < LIST_NUM(b->Announced); i++)
		Free(LIST_DATA(b->Announced, i));
	ReleaseList(b->Announced);

	// The routes are gone already (NodeBgpDeleteAllRoutes)
	ReleaseList(b->Routes);

	DeleteLock(b->WriteLock);
	DeleteLock(b->Lock);

	Free(b->Line);
	Free(b);
}

// Create the pipe, start the sidecar in its job and wait until it connects. False when one step fails; the caller
// frees b.
static bool NodeBgpLaunch(NODE_BGP *b) {
	NODE *n = b->Node;
	PSECURITY_DESCRIPTOR sd = NULL;
	SECURITY_ATTRIBUTES sa;
	OVERLAPPED ov;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t log_path[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];
	DWORD done = 0;
	ULONG client = 0;
	UINT nonce = 0;
	bool ret = false;

	// A name that another process cannot guess ahead of the node
	BCryptGenRandom(NULL, (UCHAR *)&nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	UniFormat(b->PipeName, sizeof(b->PipeName), L"\\\\.\\pipe\\ranz-bgp-%u-%u", (UINT)GetCurrentProcessId(), nonce);

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_BGP_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE) {
		NodeLog(n, "BGP not started: no security descriptor for the pipe (error %u)", (UINT)GetLastError());
		return false;
	}

	Zero(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = sd;
	sa.bInheritHandle = FALSE;

	DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
	DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
	b->Pipe = CreateNamedPipeW(b->PipeName, open_mode, pipe_mode, 1, NODE_BGP_MAX_LINE, NODE_BGP_MAX_LINE, 0, &sa);
	LocalFree(sd);

	if (b->Pipe == INVALID_HANDLE_VALUE) {
		NodeLog(n, "BGP not started: the pipe %S cannot be created (error %u)", b->PipeName, (UINT)GetLastError());
		return false;
	}

	// The DACL that the pipe got, read back for NodeBgpGetStatus, so that a test sees what the system holds
	PSECURITY_DESCRIPTOR pipe_sd = NULL;
	char *pipe_acl = NULL;

	if (GetSecurityInfo(b->Pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pipe_sd) == ERROR_SUCCESS) {
		if (ConvertSecurityDescriptorToStringSecurityDescriptorA(pipe_sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pipe_acl, NULL)) {
			StrCpy(b->PipeAcl, sizeof(b->PipeAcl), pipe_acl);
			LocalFree(pipe_acl);
		}
		LocalFree(pipe_sd);
	}

	HANDLE connect_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (connect_event == NULL)
		return false;

	// Wait for the client before the sidecar exists, so that it cannot connect too early
	Zero(&ov, sizeof(ov));
	ov.hEvent = connect_event;
	bool pending = false;
	bool connected = false;

	if (ConnectNamedPipe(b->Pipe, &ov) == FALSE) {
		DWORD err = GetLastError();

		pending = (err == ERROR_IO_PENDING);
		connected = (err == ERROR_PIPE_CONNECTED);
	}

	// The job ends the sidecar with the node, also when the node does not stop
	b->Job = CreateJobObjectW(NULL, NULL);
	Zero(&limit, sizeof(limit));
	limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (b->Job == NULL || SetInformationJobObject(b->Job, JobObjectExtendedLimitInformation, &limit, sizeof(limit)) == FALSE) {
		NodeLog(n, "BGP not started: no job for the sidecar (error %u)", (UINT)GetLastError());
	} else if (pending == false) {
		NodeLog(n, "BGP not started: the pipe %S cannot wait for the sidecar%s", b->PipeName, connected ? " (a client connected before the sidecar started)" : "");
	} else {
		ConbinePathW(log_path, sizeof(log_path), n->DataDir, NODE_LOG_DIR_NAME);
		ConbinePathW(log_path, sizeof(log_path), log_path, NODE_BGP_LOG_NAME);

		// The sidecar keeps its log within the limits of the node log (SDN-54, #247)
		UINT log_days;
		UINT log_mb;
		NodeGetLogLimits(n, &log_days, &log_mb);
		UniFormat(cmd, sizeof(cmd), L"\"%s\" bgp -pipe %s -log \"%s\" -log-days %u -log-mb %u", n->BgpSidecar, b->PipeName, log_path, log_days, log_mb);

		Zero(&si, sizeof(si));
		si.cb = sizeof(si);
		Zero(&pi, sizeof(pi));

		// Suspended until it is in the job, so that no child of it can escape the job
		if (CreateProcessW(n->BgpSidecar, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE) {
			NodeLog(n, "BGP not started: %S cannot be started (error %u)", n->BgpSidecar, (UINT)GetLastError());
		} else {
			b->Process = pi.hProcess;
			b->ProcessId = pi.dwProcessId;

			if (AssignProcessToJobObject(b->Job, pi.hProcess) == FALSE) {
				NodeLog(n, "BGP not started: the sidecar cannot join its job (error %u)", (UINT)GetLastError());
				TerminateProcess(pi.hProcess, 1);
			} else {
				ResumeThread(pi.hThread);

				HANDLE waits[2] = {connect_event, pi.hProcess};
				DWORD w = WaitForMultipleObjects(2, waits, FALSE, NODE_BGP_CONNECT_WAIT);

				if (w == WAIT_OBJECT_0 && GetOverlappedResult(b->Pipe, &ov, &done, FALSE)) {
					GetNamedPipeClientProcessId(b->Pipe, &client);

					if (client == pi.dwProcessId) {
						ret = true;
						pending = false;
					} else {
						NodeLog(n, "BGP not started: process %u connected to the pipe, not the sidecar %u", (UINT)client, (UINT)pi.dwProcessId);
					}
				} else {
					NodeLog(n, "BGP not started: the sidecar did not connect to the pipe%s", w == WAIT_OBJECT_0 + 1 ? " (it exited)" : "");
				}

				if (ret == false)
					TerminateJobObject(b->Job, 1);
			}

			CloseHandle(pi.hThread);
		}
	}

	if (pending) {
		CancelIoEx(b->Pipe, &ov);
		GetOverlappedResult(b->Pipe, &ov, &done, TRUE);
	}

	CloseHandle(connect_event);

	return ret;
}

// Start the sidecar when the configuration has the BGP settings (NODE_SETTING_BGP) with at least one peer: send it
// the settings and then the prefixes of announce. The caller holds the node lock. A node without the settings, or
// without the sidecar, runs without BGP.
void NodeBgpStart(NODE *n) {
	DWORD thread_id = 0;
	if (n->ConfigBgp == NULL || n->Bgp != NULL)
		return;

	cJSON *cfg = cJSON_Parse(n->ConfigBgp);
	cJSON *peers = cJSON_GetObjectItemCaseSensitive(cfg, "peers");

	if (cJSON_IsObject(cfg) == false) {
		NodeLog(n, "BGP not started: the %s setting is not a JSON object", NODE_SETTING_BGP);
		cJSON_Delete(cfg);
		return;
	}

	if (cJSON_IsArray(peers) == false || cJSON_GetArraySize(peers) == 0) {
		NodeLog(n, "BGP not started: the %s setting names no peers", NODE_SETTING_BGP);
		cJSON_Delete(cfg);
		return;
	}

	if (IsFileExistsW(n->BgpSidecar) == false) {
		NodeLog(n, "BGP not started: ranz.exe, which holds the sidecar, is not installed at %S", n->BgpSidecar);
		cJSON_Delete(cfg);
		return;
	}

	NODE_BGP *b = ZeroMalloc(sizeof(NODE_BGP));
	b->Node = n;
	b->Lock = NewLock();
	b->WriteLock = NewLock();
	b->Pipe = INVALID_HANDLE_VALUE;
	b->Peers = NewListFast(NULL);
	b->Announced = NewListFast(NULL);
	b->Routes = NewListFast(NULL);
	b->Line = Malloc(NODE_BGP_MAX_LINE + 1);
	b->WriteEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
	b->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

	for (cJSON *p = peers->child; p != NULL; p = p->next) {
		NODE_BGP_PEER *peer = ZeroMalloc(sizeof(NODE_BGP_PEER));

		StrCpy(peer->Address, sizeof(peer->Address), NodeBgpJsonStr(p, "address"));
		StrCpy(peer->State, sizeof(peer->State), "idle");
		Add(b->Peers, peer);
	}

	// The prefixes of announce leave the start message; they are announce messages of their own
	cJSON *announce = cJSON_DetachItemFromObjectCaseSensitive(cfg, "announce");
	cJSON_DeleteItemFromObjectCaseSensitive(cfg, "type");
	cJSON_AddStringToObject(cfg, "type", "start");

	if (b->WriteEvent == NULL || b->StopEvent == NULL || NodeBgpLaunch(b) == false) {
		NodeBgpFree(b);
	} else if (NodeBgpSend(b, cfg) == false) {
		NodeLog(n, "BGP not started: the settings did not reach the sidecar");
		TerminateJobObject(b->Job, 1);
		NodeBgpFree(b);
	} else {
		// The EVPN of a gateway, before the first message of the sidecar (NodeEvpn.c; SDN-25, #201)
		NodeEvpnStart(n, cfg);
		b->Reader = CreateThread(NULL, 0, NodeBgpReaderThread, b, 0, &thread_id);

		if (b->Reader == NULL) {
			NodeLog(n, "BGP not started: no reader thread (error %u)", (UINT)GetLastError());
			NodeEvpnStop(n);
			TerminateJobObject(b->Job, 1);
			NodeBgpFree(b);
		} else {
			n->Bgp = b;
			NodeLog(n, "BGP sidecar %S bgp started: process %u, %u peers, pipe %S", n->BgpSidecar, b->ProcessId, LIST_NUM(b->Peers), b->PipeName);

			// The thread of the stretch of a gateway, whose first round is a full resync (NodeStretch.c; SDN-64, #291)
			NodeStretchRun(n, b);

			// A prefix with a vrf is a route of that EVPN VRF
			for (cJSON *a = (cJSON_IsArray(announce) ? announce->child : NULL); a != NULL; a = a->next) {
				if (cJSON_IsString(a))
					NodeBgpAnnounceLocked(n, cJSON_GetStringValue(a), NULL, 0);
				else
					NodeBgpAnnounceLocked(n, NodeBgpJsonStr(a, "prefix"), NodeBgpJsonStr(a, "next_hop"), NodeBgpJsonUint(a, "vrf"));
			}
		}
	}

	cJSON_Delete(announce);
	cJSON_Delete(cfg);
}

// Stop the sidecar: closing the pipe ends the session, so the sidecar stops BGP, which tells the peers, and exits;
// then the learned routes leave the Windows routing table. The caller holds the node lock.
void NodeBgpStop(NODE *n) {
	DWORD code = 0;
	NODE_BGP *b = n->Bgp;
	if (b == NULL)
		return;

	n->Bgp = NULL;

	// The thread of the stretch of a gateway sends on the pipe: it ends first (NodeStretch.c; SDN-64, #291)
	NodeStretchHalt(n);

	SetEvent(b->StopEvent);
	WaitForSingleObject(b->Reader, INFINITE);
	CloseHandle(b->Reader);

	CloseHandle(b->Pipe);
	b->Pipe = INVALID_HANDLE_VALUE;

	bool exited = (WaitForSingleObject(b->Process, NODE_BGP_EXIT_WAIT) == WAIT_OBJECT_0);
	if (exited == false)
		TerminateJobObject(b->Job, 1);
	GetExitCodeProcess(b->Process, &code);

	UINT num = NodeBgpDeleteAllRoutes(b);

	if (exited)
		NodeLog(n, "BGP stopped: the sidecar exited with code %u, %u learned routes removed", (UINT)code, num);
	else
		NodeLog(n, "BGP stopped: the sidecar did not exit within %u ms and was ended, %u learned routes removed", (UINT)NODE_BGP_EXIT_WAIT, num);

	// The EVPN of the gateway stops with its sidecar, once the reader thread ended (NodeEvpn.c; SDN-25, #201)
	NodeEvpnStop(n);
	NodeBgpFree(b);
}

// Restart the sidecar of a running node: its pipe closes, as NodeBgpStop closes it, and a new sidecar connects to a new pipe with
// the same Bgp setting (NodeBgpStart). The EVPN of a gateway starts again with it, and the stretch of its L2 Networks sends the
// new sidecar a full resync (NodeStretch.c; SDN-64, #291). False when the node does not run, or no sidecar runs afterwards.
bool NodeBgpRestart(NODE *n) {
	bool ret = false;
	if (n == NULL)
		return false;

	Lock(n->Lock);
	{
		if (n->Running) {
			NodeBgpStop(n);
			NodeBgpStart(n);
			ret = (n->Bgp != NULL);
		}
	}
	Unlock(n->Lock);

	return ret;
}

// The prefix of the EVPN VRF vrf_id (0 for none) among the prefixes that the sidecar b announces, NULL for none; the caller
// holds the lock of the sidecar
static NODE_BGP_ANNOUNCED *NodeBgpFindAnnounced(NODE_BGP *b, char *prefix, UINT vrf_id) {
	for (UINT i = 0; i < LIST_NUM(b->Announced); i++) {
		NODE_BGP_ANNOUNCED *a = LIST_DATA(b->Announced, i);

		if (a->VrfId == vrf_id && StrCmpi(a->Prefix, prefix) == 0)
			return a;
	}

	return NULL;
}

// Announce prefix (an IPv4 or IPv6 prefix) to the peers, via next_hop or, for NULL or "", via the address of each
// session; with a vrf_id, as an IP prefix route of that EVPN VRF of a gateway, whose next hop is the VTEP of the gateway
// (NodeEvpn.c; SDN-25, #201). The caller holds the node lock.
static bool NodeBgpAnnounceLocked(NODE *n, char *prefix, char *next_hop, UINT vrf_id) {
	SOCKADDR_INET addr;
	BYTE len = 0;
	bool ret = false;
	NODE_BGP *b = n->Bgp;

	if (b == NULL || NodeBgpParse(prefix, NET_STRING_IP_NETWORK, &addr, &len) != ERROR_SUCCESS)
		return false;

	if (IsEmptyStr(next_hop) == false && NodeBgpParse(next_hop, NET_STRING_IP_ADDRESS_NO_SCOPE, &addr, NULL) != ERROR_SUCCESS)
		return false;

	cJSON *m = cJSON_CreateObject();
	cJSON_AddStringToObject(m, "type", "announce");
	cJSON_AddStringToObject(m, "prefix", prefix);
	if (IsEmptyStr(next_hop) == false)
		cJSON_AddStringToObject(m, "next_hop", next_hop);
	if (vrf_id != 0)
		cJSON_AddNumberToObject(m, "vrf", vrf_id);

	ret = NodeBgpSend(b, m);
	cJSON_Delete(m);

	if (ret) {
		Lock(b->Lock);
		{
			if (NodeBgpFindAnnounced(b, prefix, vrf_id) == NULL) {
				NODE_BGP_ANNOUNCED *a = ZeroMalloc(sizeof(NODE_BGP_ANNOUNCED));

				a->VrfId = vrf_id;
				StrCpy(a->Prefix, sizeof(a->Prefix), prefix);
				Add(b->Announced, a);
			}
		}
		Unlock(b->Lock);

		if (vrf_id != 0)
			NodeLog(n, "BGP prefix %s of VRF %u announced", prefix, vrf_id);
		else
			NodeLog(n, "BGP prefix %s announced%s%s", prefix, IsEmptyStr(next_hop) ? "" : " via ", IsEmptyStr(next_hop) ? "" : next_hop);
	}

	return ret;
}

// Announce prefix to the peers of the BGP sidecar (NodeBgpAnnounceLocked); false when no sidecar runs, prefix or
// next_hop is not an address, or the message does not reach the sidecar. The sidecar answers what it cannot apply
// with an error, which the node log shows.
bool NodeBgpAnnounce(NODE *n, char *prefix, char *next_hop) {
	bool ret = false;
	if (n == NULL)
		return false;

	Lock(n->Lock);
	{
		ret = NodeBgpAnnounceLocked(n, prefix, next_hop, 0);
	}
	Unlock(n->Lock);

	return ret;
}

// Announce prefix as an IP prefix route of the EVPN VRF vrf_id of a gateway (NodeEvpn.c; SDN-25, #201), whose next hop is the
// VTEP of the gateway: false when vrf_id is 0, else as NodeBgpAnnounce. The sidecar answers a VRF that its evpn object does not
// name with an error.
bool NodeBgpAnnounceVrf(NODE *n, UINT vrf_id, char *prefix) {
	bool ret = false;
	if (n == NULL || vrf_id == 0)
		return false;

	Lock(n->Lock);
	{
		ret = NodeBgpAnnounceLocked(n, prefix, NULL, vrf_id);
	}
	Unlock(n->Lock);

	return ret;
}

// Withdraw a prefix that the node announced in the EVPN VRF vrf_id, 0 for none; false when no sidecar runs, the node does not
// announce prefix there, or the message does not reach the sidecar
static bool NodeBgpWithdrawIn(NODE *n, char *prefix, UINT vrf_id) {
	bool ret = false;
	if (n == NULL || IsEmptyStr(prefix))
		return false;

	Lock(n->Lock);
	{
		NODE_BGP *b = n->Bgp;
		NODE_BGP_ANNOUNCED *announced = NULL;

		if (b != NULL) {
			Lock(b->Lock);
			{
				announced = NodeBgpFindAnnounced(b, prefix, vrf_id);
			}
			Unlock(b->Lock);
		}

		if (announced != NULL) {
			cJSON *m = cJSON_CreateObject();
			cJSON_AddStringToObject(m, "type", "withdraw");
			cJSON_AddStringToObject(m, "prefix", announced->Prefix);
			if (vrf_id != 0)
				cJSON_AddNumberToObject(m, "vrf", vrf_id);

			ret = NodeBgpSend(b, m);
			cJSON_Delete(m);

			if (ret) {
				Lock(b->Lock);
				{
					Delete(b->Announced, announced);
				}
				Unlock(b->Lock);

				if (vrf_id != 0)
					NodeLog(n, "BGP prefix %s of VRF %u withdrawn", prefix, vrf_id);
				else
					NodeLog(n, "BGP prefix %s withdrawn", prefix);
				Free(announced);
			}
		}
	}
	Unlock(n->Lock);

	return ret;
}

// Withdraw a prefix that the node announced; false when no sidecar runs, the node does not announce prefix, or the
// message does not reach the sidecar
bool NodeBgpWithdraw(NODE *n, char *prefix) {
	return NodeBgpWithdrawIn(n, prefix, 0);
}

// Withdraw a prefix that the node announced in the EVPN VRF vrf_id of a gateway (NodeBgpAnnounceVrf): false when vrf_id is 0,
// else as NodeBgpWithdraw
bool NodeBgpWithdrawVrf(NODE *n, UINT vrf_id, char *prefix) {
	return (vrf_id != 0 && NodeBgpWithdrawIn(n, prefix, vrf_id));
}

// The state of the BGP sidecar of the node
void NodeBgpGetStatus(NODE *n, NODE_BGP_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_BGP_STATUS));

	if (n == NULL)
		return;

	Lock(n->Lock);
	{
		NODE_BGP *b = n->Bgp;

		if (b != NULL) {
			Lock(b->Lock);
			{
				st->Running = (b->Ready && b->Exited == false);
				st->ProcessId = (b->Exited ? 0 : b->ProcessId);
				st->NumPeers = LIST_NUM(b->Peers);
				st->NumAnnounced = LIST_NUM(b->Announced);
				st->NumErrors = b->NumErrors;
				StrCpy(st->Version, sizeof(st->Version), b->Version);
				StrCpy(st->PipeAcl, sizeof(st->PipeAcl), b->PipeAcl);

				for (UINT i = 0; i < LIST_NUM(b->Peers); i++) {
					NODE_BGP_PEER *p = LIST_DATA(b->Peers, i);

					if (StrCmp(p->State, "established") == 0)
						st->NumEstablished++;
				}

				for (UINT i = 0; i < LIST_NUM(b->Routes); i++) {
					NODE_BGP_ROUTE *r = LIST_DATA(b->Routes, i);

					if (r->Installed)
						st->NumRoutes++;
				}
			}
			Unlock(b->Lock);
		}
	}
	Unlock(n->Lock);
}

// Make cJSON allocate through Mayaqua; once per process, before the first node starts its sidecar
void NodeBgpInit() {
	InitOnceExecuteOnce(&node_bgp_json_once, NodeBgpJsonInit, NULL, NULL);
}
