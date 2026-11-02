// NodeMimic.c
// The mimicry sidecar of a node (ADR-0023; CORE-P2-1 #85, CORE-P2-6 #406): ranz mimic, the subcommand of the one Go
// executable ranz.exe, which terminates REALITY for the server role and dials it with the ClientHello of a browser for
// the client role (controller/internal/mimic). The node starts one sidecar for each role whose settings its
// configuration store holds (NODE_SETTING_MIMIC_SERVER, NODE_SETTING_MIMIC_CLIENT), as it starts the BGP sidecar: from
// the folder of its own executable, as ranz.exe mimic, in a job that ends the sidecar with the node, after the control
// pipe exists, which only the account of the node can open and which takes only that process as its client. The client
// role starts with the node; the server role starts when the mimic transport listens (NodeMimicTransport.c).
//
// The settings of a role are one JSON text, which the node forwards as the server part or the client part of the start
// message without reading a field of it: the sidecar checks them and refuses a field that it does not know. The private
// key of a server is part of them, so it reaches the sidecar over the control pipe only, never on a command line, and
// the node writes no text of the settings into its log; what the sidecar answers goes into the log with every run of
// hexadecimal digits as long as a key blanked. A refused setting is logged, and the role stays unavailable.
//
// A sidecar that ends by itself is started again after a delay that doubles from NODE_MIMIC_RESTART_FIRST to
// NODE_MIMIC_RESTART_MAX; the streams over it end with it, and clients dial again through their fallback list. The
// node asks a running sidecar for its counters (accepted, probes, streams and dropped) every NODE_MIMIC_STATS ms and
// keeps them in its status; they go into the node log at most every NODE_MIMIC_LOG_STATS ms while they change, and when
// a sidecar ends. A probe is counted and never logged on its own, as a stranger can send as many as it likes.

#include "Node.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"

#include "ConfigStore.h"
#include "NodeInternal.h"
#include "NodeMimicInternal.h"

#include <AclAPI.h>
#include <bcrypt.h>
#include <sddl.h>

#include <cjson/cJSON.h>

// The strict DACL of the pipes of the sidecar (ADR-0039 decision 3), as for the BGP sidecar: the owner alone, the
// account of the node, which its sidecar runs as; nothing for anyone else
#define NODE_MIMIC_PIPE_SDDL L"D:P(A;;GA;;;OW)"

#define NODE_MIMIC_CONNECT_WAIT 30000 // How long the node waits for the sidecar to connect to the control pipe (ms)
#define NODE_MIMIC_READY_WAIT   60000 // How long a start waits for ready: the server role first probes its decoy (ms)
#define NODE_MIMIC_WRITE_WAIT   5000  // How long one message may take to reach the pipe (ms)
#define NODE_MIMIC_EXIT_WAIT    10000 // How long the sidecar may take to exit after the pipe closes (ms)
#define NODE_MIMIC_READ_SIZE    4096  // Bytes of one read of the control pipe
#define NODE_MIMIC_HEX_RUN      32    // A run of this many hexadecimal digits or more is blanked in the node log

// How a run of a sidecar ended (NodeMimicRun)
#define NODE_MIMIC_RUN_STOPPED 0 // The node stopped it
#define NODE_MIMIC_RUN_ENDED   1 // It ended by itself, or could not start: it starts again after the delay
#define NODE_MIMIC_RUN_REFUSED 2 // It refused its settings, or they cannot go to it: it does not start again

// One process of a sidecar
typedef struct NODE_MIMIC_PROC {
	HANDLE Pipe;    // The server end of the control pipe, overlapped
	HANDLE Job;     // The job of the sidecar: it ends with the node, also when the node does not stop
	HANDLE Process; // The sidecar
	UINT ProcessId; // Its process id
} NODE_MIMIC_PROC;

// The name of a role in the node log
static char *NodeMimicRoleName(UINT role) {
	return (role == NODE_MIMIC_ROLE_SERVER ? "server" : "client");
}

// Blank every run of NODE_MIMIC_HEX_RUN hexadecimal digits or more in s, in place: a key is such a run, and a text that
// the sidecar sends may quote one
static void NodeMimicBlank(char *s) {
	UINT len = StrLen(s);

	for (UINT i = 0; i < len;) {
		UINT j = i;

		while (j < len && ((s[j] >= '0' && s[j] <= '9') || (s[j] >= 'a' && s[j] <= 'f') || (s[j] >= 'A' && s[j] <= 'F')))
			j++;

		if (j - i >= NODE_MIMIC_HEX_RUN) {
			for (UINT k = i; k < j; k++)
				s[k] = '*';
		}

		i = (j == i ? i + 1 : j);
	}
}

// The string member name of a JSON object, at most size bytes with the NUL; "" when it has none
static void NodeMimicJsonStr(cJSON *o, char *name, char *dst, UINT size) {
	char *s = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(o, name));

	StrCpy(dst, size, (s != NULL ? s : ""));
}

// The number member name of a JSON object as a UINT64; 0 when it has none, it is not a whole number or out of range
static UINT64 NodeMimicJsonUint(cJSON *o, char *name) {
	cJSON *item = cJSON_GetObjectItemCaseSensitive(o, name);

	if (cJSON_IsNumber(item) == false || item->valuedouble < 0 || item->valuedouble > 9007199254740992.0)
		return 0;

	return (UINT64)item->valuedouble;
}

// Read one message that a sidecar sent on its control pipe, the line without its newline: a JSON object with a type,
// whose fields the node reads go into m. False when the line is no JSON object or has no type.
bool NodeMimicParseMessage(const char *line, NODE_MIMIC_MESSAGE *m) {
	if (m == NULL)
		return false;

	Zero(m, sizeof(NODE_MIMIC_MESSAGE));

	if (line == NULL)
		return false;

	cJSON *o = cJSON_Parse(line);
	bool ret = false;

	if (cJSON_IsObject(o)) {
		NodeMimicJsonStr(o, "type", m->Type, sizeof(m->Type));
		NodeMimicJsonStr(o, "version", m->Version, sizeof(m->Version));
		m->Protocol = (UINT)MIN(NodeMimicJsonUint(o, "protocol"), 0xFFFFFFFF);
		NodeMimicJsonStr(o, "listen", m->Listen, sizeof(m->Listen));
		NodeMimicJsonStr(o, "decoy", m->Decoy, sizeof(m->Decoy));
		NodeMimicJsonStr(o, "peer", m->Peer, sizeof(m->Peer));
		NodeMimicJsonStr(o, "reason", m->Reason, sizeof(m->Reason));
		m->Accepted = NodeMimicJsonUint(o, "accepted");
		m->Probes = NodeMimicJsonUint(o, "probes");
		m->Streams = NodeMimicJsonUint(o, "streams");
		m->Dropped = NodeMimicJsonUint(o, "dropped");
		NodeMimicJsonStr(o, "error", m->Error, sizeof(m->Error));

		ret = (IsEmptyStr(m->Type) == false);
	}

	cJSON_Delete(o);

	return ret;
}

// The security attributes of a pipe that only the account of the node opens
SECURITY_ATTRIBUTES *NodeMimicPipeSa() {
	PSECURITY_DESCRIPTOR sd = NULL;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(NODE_MIMIC_PIPE_SDDL, SDDL_REVISION_1, &sd, NULL) == FALSE)
		return NULL;

	SECURITY_ATTRIBUTES *sa = ZeroMalloc(sizeof(SECURITY_ATTRIBUTES));
	sa->nLength = sizeof(SECURITY_ATTRIBUTES);
	sa->lpSecurityDescriptor = sd;
	sa->bInheritHandle = FALSE;

	return sa;
}

void NodeMimicFreePipeSa(SECURITY_ATTRIBUTES *sa) {
	if (sa == NULL)
		return;

	LocalFree(sa->lpSecurityDescriptor);
	Free(sa);
}

// The name of a new pipe of the node
void NodeMimicPipeName(wchar_t *name, UINT size, const wchar_t *what) {
	UINT nonce = 0;

	BCryptGenRandom(NULL, (UCHAR *)&nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	UniFormat(name, size, L"\\\\.\\pipe\\ranz-mimic-%s-%u-%u", what, (UINT)GetCurrentProcessId(), nonce);
}

// Write size bytes to the control pipe of a sidecar; false when they did not reach it within NODE_MIMIC_WRITE_WAIT
static bool NodeMimicWrite(HANDLE pipe, HANDLE event, const void *buf, UINT size) {
	OVERLAPPED ov;
	DWORD done = 0;

	Zero(&ov, sizeof(ov));
	ov.hEvent = event;
	ResetEvent(event);

	if (WriteFile(pipe, buf, size, NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
		return false;

	if (WaitForSingleObject(event, NODE_MIMIC_WRITE_WAIT) != WAIT_OBJECT_0)
		CancelIoEx(pipe, &ov);

	return (GetOverlappedResult(pipe, &ov, &done, TRUE) && done == size);
}

// The start message of a sidecar: the role, the data pipe and the settings of the role, a JSON object that the node
// puts into the message as it is, on one line. NULL when the settings are no JSON object or the message is too long, with
// the reason in error. The caller wipes and frees the message.
static char *NodeMimicStartMessage(NODE_MIMIC_SIDECAR *sc, UINT *size, char *error, UINT error_size) {
	char pipe[MAX_PATH];
	char *ret = NULL;

	cJSON *settings = cJSON_Parse(sc->Settings);
	if (cJSON_IsObject(settings) == false) {
		StrCpy(error, error_size, "the setting is not a JSON object");
		cJSON_Delete(settings);
		return NULL;
	}

	UniToStr(pipe, sizeof(pipe), sc->DataPipe);

	cJSON *m = cJSON_CreateObject();
	cJSON_AddStringToObject(m, "type", "start");
	cJSON_AddStringToObject(m, "role", NodeMimicRoleName(sc->Role));
	cJSON_AddStringToObject(m, "pipe", pipe);
	cJSON_AddItemToObject(m, NodeMimicRoleName(sc->Role), settings);

	char *s = cJSON_PrintUnformatted(m);
	cJSON_Delete(m);

	if (s == NULL) {
		StrCpy(error, error_size, "the start message cannot be made");
		return NULL;
	}

	UINT len = StrLen(s);
	if (len + 1 > NODE_MIMIC_MAX_LINE) {
		Format(error, error_size, "the start message is longer than %u bytes", (UINT)NODE_MIMIC_MAX_LINE);
	} else {
		ret = Malloc(len + 1);
		Copy(ret, s, len);
		ret[len] = '\n';
		*size = len + 1;
	}

	Zero(s, len);
	cJSON_free(s);

	return ret;
}

// Create the control pipe, start the sidecar in its job and wait until it connects. False when one step fails, with the
// reason in the node log; the caller ends what p holds.
static bool NodeMimicLaunch(NODE_MIMIC_SIDECAR *sc, NODE_MIMIC_PROC *p) {
	NODE *n = sc->Mimic->Node;
	char *role = NodeMimicRoleName(sc->Role);
	wchar_t pipe_name[MAX_PATH];
	wchar_t cmd[MAX_PATH * 4];
	OVERLAPPED ov;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	DWORD done = 0;
	ULONG client = 0;
	bool ret = false;

	NodeMimicPipeName(pipe_name, sizeof(pipe_name), L"control");

	SECURITY_ATTRIBUTES *sa = NodeMimicPipeSa();
	if (sa == NULL) {
		NodeLog(n, "Mimic %s sidecar not started: no security descriptor for the pipe (error %u)", role, (UINT)GetLastError());
		return false;
	}

	DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;
	DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
	p->Pipe = CreateNamedPipeW(pipe_name, open_mode, pipe_mode, 1, NODE_MIMIC_MAX_LINE, NODE_MIMIC_MAX_LINE, 0, sa);
	NodeMimicFreePipeSa(sa);

	if (p->Pipe == INVALID_HANDLE_VALUE) {
		NodeLog(n, "Mimic %s sidecar not started: the pipe %S cannot be created (error %u)", role, pipe_name, (UINT)GetLastError());
		return false;
	}

	// The DACL that the pipe got, read back for the status, so that a test sees what the system holds
	PSECURITY_DESCRIPTOR pipe_sd = NULL;
	char *pipe_acl = NULL;

	if (GetSecurityInfo(p->Pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pipe_sd) == ERROR_SUCCESS) {
		if (ConvertSecurityDescriptorToStringSecurityDescriptorA(pipe_sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &pipe_acl, NULL)) {
			Lock(sc->Lock);
			{
				StrCpy(sc->St.PipeAcl, sizeof(sc->St.PipeAcl), pipe_acl);
			}
			Unlock(sc->Lock);
			LocalFree(pipe_acl);
		}
		LocalFree(pipe_sd);
	}

	HANDLE connect_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (connect_event == NULL)
		return false;

	// Wait for the client before the sidecar exists, so that the node sees any client that comes first
	Zero(&ov, sizeof(ov));
	ov.hEvent = connect_event;
	bool pending = false;

	if (ConnectNamedPipe(p->Pipe, &ov) == FALSE) {
		DWORD err = GetLastError();

		pending = (err == ERROR_IO_PENDING);
		if (err == ERROR_PIPE_CONNECTED)
			SetEvent(connect_event);
	}

	if (n->MimicTest.BeforeLaunch != NULL)
		n->MimicTest.BeforeLaunch(n->MimicTest.Param, pipe_name);

	// The job ends the sidecar with the node, also when the node does not stop
	p->Job = CreateJobObjectW(NULL, NULL);
	Zero(&limit, sizeof(limit));
	limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

	if (p->Job == NULL || SetInformationJobObject(p->Job, JobObjectExtendedLimitInformation, &limit, sizeof(limit)) == FALSE) {
		NodeLog(n, "Mimic %s sidecar not started: no job for the sidecar (error %u)", role, (UINT)GetLastError());
	} else {
		// The command line names the pipe and the log; the settings go over the pipe
		UniFormat(cmd, sizeof(cmd), L"\"%s\" mimic -pipe %s -log \"%s\"", n->MimicSidecar, pipe_name, sc->LogPath);

		Zero(&si, sizeof(si));
		si.cb = sizeof(si);
		Zero(&pi, sizeof(pi));

		// Suspended until it is in the job, so that no child of it can escape the job
		if (CreateProcessW(n->MimicSidecar, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == FALSE) {
			NodeLog(n, "Mimic %s sidecar not started: %S cannot be started (error %u)", role, n->MimicSidecar, (UINT)GetLastError());
		} else {
			p->Process = pi.hProcess;
			p->ProcessId = pi.dwProcessId;

			if (AssignProcessToJobObject(p->Job, pi.hProcess) == FALSE) {
				NodeLog(n, "Mimic %s sidecar not started: the sidecar cannot join its job (error %u)", role, (UINT)GetLastError());
				TerminateProcess(pi.hProcess, 1);
			} else {
				ResumeThread(pi.hThread);

				HANDLE waits[2] = {connect_event, pi.hProcess};
				DWORD w = WaitForMultipleObjects(2, waits, FALSE, NODE_MIMIC_CONNECT_WAIT);

				if (w == WAIT_OBJECT_0 && (pending == false || GetOverlappedResult(p->Pipe, &ov, &done, FALSE))) {
					pending = false;
					GetNamedPipeClientProcessId(p->Pipe, &client);

					// Only the process that the node started may be the client of its pipe
					if (client == pi.dwProcessId)
						ret = true;
					else
						NodeLog(n, "Mimic %s sidecar not started: process %u connected to the pipe, not the sidecar %u", role, (UINT)client, (UINT)pi.dwProcessId);
				} else {
					NodeLog(n, "Mimic %s sidecar not started: the sidecar did not connect to the pipe%s", role, w == WAIT_OBJECT_0 + 1 ? " (it exited)" : "");
				}

				if (ret == false)
					TerminateJobObject(p->Job, 1);
			}

			CloseHandle(pi.hThread);
		}
	}

	if (pending) {
		CancelIoEx(p->Pipe, &ov);
		GetOverlappedResult(p->Pipe, &ov, &done, TRUE);
	}

	CloseHandle(connect_event);

	return ret;
}

// Log the counters of a sidecar as the status holds them
static void NodeMimicLogCounters(NODE_MIMIC_SIDECAR *sc) {
	NODE_MIMIC_STATUS st;

	Lock(sc->Lock);
	{
		Copy(&st, &sc->St, sizeof(st));
	}
	Unlock(sc->Lock);

	NodeLog(sc->Mimic->Node, "Mimic %s sidecar counters: %I64u accepted, %I64u probes, %I64u streams, %I64u dropped", NodeMimicRoleName(sc->Role),
	        st.Accepted, st.Probes, st.Streams, st.Dropped);
}

// One message of the sidecar; NODE_MIMIC_RUN_REFUSED when it refused its settings, NODE_MIMIC_RUN_STOPPED (go on)
// otherwise
static UINT NodeMimicOnMessage(NODE_MIMIC_SIDECAR *sc, NODE_MIMIC_PROC *p, char *line, NODE_MIMIC_MESSAGE *m) {
	NODE *n = sc->Mimic->Node;
	char *role = NodeMimicRoleName(sc->Role);

	if (NodeMimicParseMessage(line, m) == false) {
		NodeLog(n, "Mimic %s sidecar: a message that is not a JSON object with a type", role);
		return NODE_MIMIC_RUN_STOPPED;
	}

	NodeMimicBlank(m->Error);
	NodeMimicBlank(m->Version);

	if (StrCmp(m->Type, "ready") == 0) {
		Lock(sc->Lock);
		{
			sc->Ready = true;
			sc->ProcessId = p->ProcessId;
			sc->St.Running = true;
			sc->St.ProcessId = p->ProcessId;
			StrCpy(sc->St.Version, sizeof(sc->St.Version), m->Version);
			StrCpy(sc->St.Listen, sizeof(sc->St.Listen), m->Listen);
			StrCpy(sc->St.Error, sizeof(sc->St.Error), "");
		}
		Unlock(sc->Lock);

		SetEvent(sc->ReadyEvent);
		NodeLog(n, "Mimic %s sidecar ready: %s (protocol %u)%s%s", role, m->Version, m->Protocol, IsEmptyStr(m->Listen) ? "" : ", REALITY listener on ", m->Listen);
	} else if (StrCmp(m->Type, "stats") == 0) {
		Lock(sc->Lock);
		{
			sc->St.Accepted = sc->BaseAccepted + m->Accepted;
			sc->St.Probes = sc->BaseProbes + m->Probes;
			sc->St.Streams = sc->BaseStreams + m->Streams;
			sc->St.Dropped = sc->BaseDropped + m->Dropped;
		}
		Unlock(sc->Lock);
	} else if (StrCmp(m->Type, "accepted") == 0 || StrCmp(m->Type, "probe") == 0) {
		// Counted by the sidecar, which the stats tell; a probe is never logged on its own
	} else if (StrCmp(m->Type, "error") == 0) {
		bool ready;

		Lock(sc->Lock);
		{
			sc->St.NumErrors++;
			ready = sc->Ready;
			if (ready == false)
				Format(sc->St.Error, sizeof(sc->St.Error), "the sidecar refused the settings: %s", m->Error);
		}
		Unlock(sc->Lock);

		// An error before ready is the answer to start: the sidecar refused the settings and ends
		if (ready == false) {
			NodeLog(n, "Mimic %s sidecar refused the %s setting, the role stays unavailable: %s", role,
			        sc->Role == NODE_MIMIC_ROLE_SERVER ? NODE_SETTING_MIMIC_SERVER : NODE_SETTING_MIMIC_CLIENT, m->Error);
			return NODE_MIMIC_RUN_REFUSED;
		}

		NodeLog(n, "Mimic %s sidecar error%s%s: %s", role, IsEmptyStr(m->Peer) ? "" : " for ", m->Peer, m->Error);
	} else {
		NodeLog(n, "Mimic %s sidecar: a message of the unknown type \"%s\" ignored", role, m->Type);
	}

	return NODE_MIMIC_RUN_STOPPED;
}

// Run one process of the sidecar: start it, send the start message, then read what it tells and ask for its counters
// until it ends or the node stops it. Gives NODE_MIMIC_RUN_*.
static UINT NodeMimicRun(NODE_MIMIC_SIDECAR *sc, NODE_MIMIC_PROC *p, char *line) {
	NODE *n = sc->Mimic->Node;
	char *role = NodeMimicRoleName(sc->Role);
	char error[MAX_SIZE];
	UCHAR buf[NODE_MIMIC_READ_SIZE];
	OVERLAPPED ov;
	UINT line_size = 0;
	UINT start_size = 0;
	UINT ret = NODE_MIMIC_RUN_ENDED;
	static const char stats[] = "{\"type\":\"stats\"}\n";

	char *start = NodeMimicStartMessage(sc, &start_size, error, sizeof(error));
	if (start == NULL) {
		Lock(sc->Lock);
		{
			Format(sc->St.Error, sizeof(sc->St.Error), "the setting cannot go to the sidecar: %s", error);
		}
		Unlock(sc->Lock);

		NodeLog(n, "Mimic %s sidecar not started, the role stays unavailable: %s", role, error);
		return NODE_MIMIC_RUN_REFUSED;
	}

	HANDLE read_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE write_event = CreateEventW(NULL, TRUE, FALSE, NULL);
	NODE_MIMIC_MESSAGE *m = ZeroMalloc(sizeof(NODE_MIMIC_MESSAGE));

	if (read_event == NULL || write_event == NULL || NodeMimicLaunch(sc, p) == false) {
		ret = NODE_MIMIC_RUN_ENDED;
	} else {
		Lock(sc->Lock);
		{
			sc->Generation++;
			sc->St.NumStarts++;
			sc->St.ProcessId = p->ProcessId;
		}
		Unlock(sc->Lock);

		NodeLog(n, "Mimic %s sidecar %S mimic started: process %u", role, n->MimicSidecar, p->ProcessId);

		bool sent = NodeMimicWrite(p->Pipe, write_event, start, start_size);
		if (sent == false)
			NodeLog(n, "Mimic %s sidecar: the settings did not reach it", role);

		UINT64 next_log = Tick64() + NODE_MIMIC_LOG_STATS;
		UINT64 logged[4] = {0, 0, 0, 0};

		// The stop event first: WaitForMultipleObjects reports the lowest signalled index
		HANDLE events[3] = {sc->StopEvent, read_event, p->Process};

		while (sent) {
			DWORD got = 0;

			Zero(&ov, sizeof(ov));
			ov.hEvent = read_event;
			ResetEvent(read_event);

			if (ReadFile(p->Pipe, buf, sizeof(buf), NULL, &ov) == FALSE && GetLastError() != ERROR_IO_PENDING)
				break;

			DWORD w;
			while ((w = WaitForMultipleObjects(3, events, FALSE, NODE_MIMIC_STATS)) == WAIT_TIMEOUT) {
				bool ready;
				UINT64 now[4];

				Lock(sc->Lock);
				{
					ready = sc->Ready;
					now[0] = sc->St.Accepted;
					now[1] = sc->St.Probes;
					now[2] = sc->St.Streams;
					now[3] = sc->St.Dropped;
				}
				Unlock(sc->Lock);

				if (ready)
					NodeMimicWrite(p->Pipe, write_event, stats, sizeof(stats) - 1);

				if (Tick64() >= next_log && Cmp(now, logged, sizeof(now)) != 0) {
					NodeMimicLogCounters(sc);
					Copy(logged, now, sizeof(now));
					next_log = Tick64() + NODE_MIMIC_LOG_STATS;
				}
			}

			if (w != WAIT_OBJECT_0 + 1) {
				CancelIoEx(p->Pipe, &ov);
				GetOverlappedResult(p->Pipe, &ov, &got, TRUE);
				if (w == WAIT_OBJECT_0)
					ret = NODE_MIMIC_RUN_STOPPED;
				break;
			}

			if (GetOverlappedResult(p->Pipe, &ov, &got, FALSE) == FALSE)
				break;

			bool too_long = false;
			bool refused = false;

			for (DWORD i = 0; i < got && too_long == false && refused == false; i++) {
				if (buf[i] != '\n') {
					if (line_size >= NODE_MIMIC_MAX_LINE)
						too_long = true;
					else
						line[line_size++] = (char)buf[i];
					continue;
				}

				line[line_size] = 0;
				if (line_size != 0)
					refused = (NodeMimicOnMessage(sc, p, line, m) == NODE_MIMIC_RUN_REFUSED);
				line_size = 0;
			}

			if (refused) {
				ret = NODE_MIMIC_RUN_REFUSED;
				break;
			}

			if (too_long) {
				NodeLog(n, "Mimic %s sidecar: a message longer than %u bytes, the node ends the sidecar", role, (UINT)NODE_MIMIC_MAX_LINE);
				break;
			}
		}
	}

	Zero(line, NODE_MIMIC_MAX_LINE + 1);
	Zero(start, start_size);
	Free(start);
	Free(m);
	if (read_event != NULL)
		CloseHandle(read_event);
	if (write_event != NULL)
		CloseHandle(write_event);

	return ret;
}

// End a process of the sidecar: close the pipe, which ends the session of a sidecar that still runs, wait for it to
// exit or end its job, and keep its counters. Logs how it ended and gives its exit code.
static DWORD NodeMimicEnd(NODE_MIMIC_SIDECAR *sc, NODE_MIMIC_PROC *p) {
	DWORD code = 0;
	bool exited = true;

	if (p->Pipe != INVALID_HANDLE_VALUE)
		CloseHandle(p->Pipe);
	p->Pipe = INVALID_HANDLE_VALUE;

	if (p->Process != NULL) {
		exited = (WaitForSingleObject(p->Process, NODE_MIMIC_EXIT_WAIT) == WAIT_OBJECT_0);
		if (exited == false && p->Job != NULL) {
			TerminateJobObject(p->Job, 1);
			WaitForSingleObject(p->Process, NODE_MIMIC_EXIT_WAIT);
		}
		GetExitCodeProcess(p->Process, &code);
		CloseHandle(p->Process);
	}

	// Closing the job ends the sidecar if it still runs (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if (p->Job != NULL)
		CloseHandle(p->Job);

	Lock(sc->Lock);
	{
		sc->Ready = false;
		sc->ProcessId = 0;
		sc->St.Running = false;
		sc->St.ProcessId = 0;
		sc->BaseAccepted = sc->St.Accepted;
		sc->BaseProbes = sc->St.Probes;
		sc->BaseStreams = sc->St.Streams;
		sc->BaseDropped = sc->St.Dropped;
	}
	Unlock(sc->Lock);

	if (p->ProcessId != 0) {
		if (exited)
			NodeLog(sc->Mimic->Node, "Mimic %s sidecar %u exited with code %u", NodeMimicRoleName(sc->Role), p->ProcessId, (UINT)code);
		else
			NodeLog(sc->Mimic->Node, "Mimic %s sidecar %u did not exit within %u ms and was ended", NodeMimicRoleName(sc->Role), p->ProcessId, (UINT)NODE_MIMIC_EXIT_WAIT);
		NodeMimicLogCounters(sc);
	}

	Zero(p, sizeof(NODE_MIMIC_PROC));
	p->Pipe = INVALID_HANDLE_VALUE;

	return code;
}

// The supervisor of a sidecar: it runs the sidecar, and starts it again after the delay when it ends by itself, until
// the node stops it or the sidecar refuses its settings
static DWORD WINAPI NodeMimicSupervisor(void *param) {
	NODE_MIMIC_SIDECAR *sc = (NODE_MIMIC_SIDECAR *)param;
	NODE *n = sc->Mimic->Node;
	char *role = NodeMimicRoleName(sc->Role);
	NODE_MIMIC_PROC p;
	UINT delay = NODE_MIMIC_RESTART_FIRST;
	char *line = ZeroMalloc(NODE_MIMIC_MAX_LINE + 1);

	Zero(&p, sizeof(p));
	p.Pipe = INVALID_HANDLE_VALUE;

	while (true) {
		UINT64 started = Tick64();
		UINT ret = NodeMimicRun(sc, &p, line);
		DWORD code = NodeMimicEnd(sc, &p);

		if (ret == NODE_MIMIC_RUN_STOPPED)
			break;

		if (ret == NODE_MIMIC_RUN_REFUSED) {
			Lock(sc->Lock);
			{
				sc->Refused = true;
			}
			Unlock(sc->Lock);

			SetEvent(sc->ReadyEvent);
			break;
		}

		// A sidecar that ran a long time starts again after the first delay
		if (Tick64() - started >= NODE_MIMIC_RESTART_MAX)
			delay = NODE_MIMIC_RESTART_FIRST;

		NodeLog(n, "Mimic %s sidecar ended by itself (exit code %u): started again in %u ms", role, (UINT)code, delay);

		if (WaitForSingleObject(sc->StopEvent, delay) != WAIT_TIMEOUT)
			break;

		delay = MIN(delay * 2, NODE_MIMIC_RESTART_MAX);

		Lock(sc->Lock);
		{
			sc->St.NumRestarts++;
		}
		Unlock(sc->Lock);
	}

	Free(line);

	return 0;
}

// Start the supervisor of a sidecar, which runs it until NodeMimicStopSidecar; false when it cannot run
static bool NodeMimicLaunchSupervisor(NODE_MIMIC_SIDECAR *sc) {
	DWORD thread_id = 0;

	if (sc->Supervisor != NULL)
		return true;

	ResetEvent(sc->StopEvent);
	ResetEvent(sc->ReadyEvent);

	Lock(sc->Lock);
	{
		sc->Refused = false;
	}
	Unlock(sc->Lock);

	sc->Supervisor = CreateThread(NULL, 0, NodeMimicSupervisor, sc, 0, &thread_id);
	if (sc->Supervisor == NULL) {
		NodeLog(sc->Mimic->Node, "Mimic %s sidecar not started: no supervisor thread (error %u)", NodeMimicRoleName(sc->Role), (UINT)GetLastError());
		return false;
	}

	return true;
}

// Start the sidecar of a role and wait until it sent ready or refused its settings
bool NodeMimicStartSidecar(NODE_MIMIC_SIDECAR *sc) {
	if (NodeMimicLaunchSupervisor(sc) == false)
		return false;

	WaitForSingleObject(sc->ReadyEvent, NODE_MIMIC_READY_WAIT);

	return NodeMimicSidecarReady(sc, NULL, NULL);
}

// Stop the sidecar of a role: closing its pipe ends its session, so it closes its listener and its streams and exits
void NodeMimicStopSidecar(NODE_MIMIC_SIDECAR *sc) {
	if (sc->Supervisor == NULL)
		return;

	SetEvent(sc->StopEvent);
	WaitForSingleObject(sc->Supervisor, INFINITE);
	CloseHandle(sc->Supervisor);
	sc->Supervisor = NULL;

	NodeLog(sc->Mimic->Node, "Mimic %s sidecar stopped", NodeMimicRoleName(sc->Role));
}

bool NodeMimicSidecarReady(NODE_MIMIC_SIDECAR *sc, UINT *pid, UINT *generation) {
	bool ret;

	Lock(sc->Lock);
	{
		ret = sc->Ready;
		if (pid != NULL)
			*pid = sc->ProcessId;
		if (generation != NULL)
			*generation = sc->Generation;
	}
	Unlock(sc->Lock);

	return ret;
}

// Free the sidecars of a node, whose supervisors stopped
static void NodeMimicFree(NODE_MIMIC *m) {
	for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++) {
		NODE_MIMIC_SIDECAR *sc = &m->Sidecars[i];

		if (sc->Settings != NULL) {
			Zero(sc->Settings, StrLen(sc->Settings));
			Free(sc->Settings);
		}
		if (sc->StopEvent != NULL)
			CloseHandle(sc->StopEvent);
		if (sc->ReadyEvent != NULL)
			CloseHandle(sc->ReadyEvent);
		DeleteLock(sc->Lock);
	}

	DeleteLock(m->ListenerLock);
	Free(m);
}

// The executable of the sidecar: ranz.exe next to the executable of the node, until a test names another; and the keys that
// the control stream reports about the node, the public key of its mimic server (NodeMimicState.c; CORE-P2-7, #424)
void NodeMimicInit(NODE *n) {
	GetExeDirW(n->MimicSidecar, sizeof(n->MimicSidecar));
	ConbinePathW(n->MimicSidecar, sizeof(n->MimicSidecar), n->MimicSidecar, NODE_BGP_EXE_NAME);
	n->MimicKeys = ControlNewKeys();
}

NODE_MIMIC *NodeMimicNew(NODE *n) {
	wchar_t log_names[NODE_MIMIC_NUM_ROLES][MAX_PATH] = {L"ranz-mimic-server.log", L"ranz-mimic-client.log"};
	wchar_t log_dir[MAX_PATH];

	NODE_MIMIC *m = ZeroMalloc(sizeof(NODE_MIMIC));
	m->Node = n;
	m->ListenerLock = NewLock();
	InitializeSRWLock(&m->ServeLock);

	ConbinePathW(log_dir, sizeof(log_dir), n->DataDir, NODE_LOG_DIR_NAME);

	for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++) {
		NODE_MIMIC_SIDECAR *sc = &m->Sidecars[i];

		sc->Mimic = m;
		sc->Role = i;
		sc->Lock = NewLock();
		sc->StopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
		sc->ReadyEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
		ConbinePathW(sc->LogPath, sizeof(sc->LogPath), log_dir, log_names[i]);
	}

	NodeMimicTransportInit(m);

	return m;
}

// Read the settings of the roles and start the sidecar of the client role. The caller holds the node lock. A node
// without the settings has no mimic transport and says nothing of it; a node without ranz.exe next to it has none
// either, and says why. The key of a mimic server that the settings hold goes to the Controller after each Hello
// (NodeMimicState.c; CORE-P2-7, #424), so that a node reports the same key after a restart.
void NodeMimicStart(NODE *n) {
	char *names[NODE_MIMIC_NUM_ROLES] = {NODE_SETTING_MIMIC_SERVER, NODE_SETTING_MIMIC_CLIENT};
	UINT num = 0;

	if (n->Mimic != NULL || n->Store == NULL)
		return;

	NODE_MIMIC *m = NodeMimicNew(n);

	for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++) {
		NODE_MIMIC_SIDECAR *sc = &m->Sidecars[i];
		char *value = ZeroMalloc(NODE_MIMIC_MAX_SETTING + 2);

		if (CsGetSetting(n->Store, names[i], value, NODE_MIMIC_MAX_SETTING + 2) && IsEmptyStr(value) == false) {
			sc->St.Configured = true;
			num++;

			if (StrLen(value) > NODE_MIMIC_MAX_SETTING) {
				Format(sc->St.Error, sizeof(sc->St.Error), "the %s setting is longer than %u bytes", names[i], (UINT)NODE_MIMIC_MAX_SETTING);
				NodeLog(n, "Mimic %s role unavailable: %s", NodeMimicRoleName(i), sc->St.Error);
			} else {
				sc->Settings = CopyStr(value);
				if (i == NODE_MIMIC_ROLE_SERVER)
					NodeMimicReportKey(n, value);
			}
		}

		Zero(value, NODE_MIMIC_MAX_SETTING + 2);
		Free(value);
	}

	if (num == 0) {
		NodeMimicFree(m);
		return;
	}

	// The overlay takes the streams of the mimic server without the node lock (NodeMimicAcceptServed)
	InterlockedExchangePointer((PVOID volatile *)&n->Mimic, m);

	if (IsFileExistsW(n->MimicSidecar) == false) {
		for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++) {
			NODE_MIMIC_SIDECAR *sc = &m->Sidecars[i];

			if (sc->St.Configured)
				Format(sc->St.Error, sizeof(sc->St.Error), "ranz.exe, which holds the sidecar, is not installed at %S", n->MimicSidecar);

			if (sc->Settings != NULL) {
				Zero(sc->Settings, StrLen(sc->Settings));
				Free(sc->Settings);
				sc->Settings = NULL;
			}
		}

		NodeLog(n, "Mimic transport unavailable: ranz.exe, which holds the sidecar, is not installed at %S", n->MimicSidecar);
		return;
	}

	NODE_MIMIC_SIDECAR *client = &m->Sidecars[NODE_MIMIC_ROLE_CLIENT];

	if (client->Settings != NULL) {
		// The client role listens on a data pipe of its own, which the node names
		NodeMimicPipeName(client->DataPipe, sizeof(client->DataPipe), L"client");
		NodeMimicLaunchSupervisor(client);
	}

	NodeLog(n, "Mimic transport: the server role %s, the client role %s", m->Sidecars[NODE_MIMIC_ROLE_SERVER].Settings != NULL ? "starts when it listens" : "has no settings",
	        client->Settings != NULL ? "starts" : "has no settings");
}

// Stop the sidecars and free the transport, whose listener and streams the caller closed before. The caller holds the
// node lock.
void NodeMimicStop(NODE *n) {
	NODE_MIMIC *m = n->Mimic;
	if (m == NULL)
		return;

	// The listener that the node opened for the server role of its state closes first (NodeMimicState.c; CORE-P2-7, #424)
	NodeMimicUnserve(m);

	bool listening;

	Lock(m->ListenerLock);
	{
		listening = (m->Listener != NULL);
	}
	Unlock(m->ListenerLock);

	for (UINT i = 0; i < NODE_MIMIC_NUM_ROLES; i++)
		NodeMimicStopSidecar(&m->Sidecars[i]);

	// A listener that is still open holds the transport: it is freed with the node's memory only when it is closed
	if (listening) {
		NodeLog(n, "Mimic transport: its listener was not closed before the node stopped");
		return;
	}

	InterlockedExchangePointer((PVOID volatile *)&n->Mimic, NULL);
	NodeMimicFree(m);
}

// The mimic transport of the node: NULL while the node does not run, its configuration has no mimic setting, or ranz.exe
// is not next to it. A role whose sidecar does not run fails its dial or its listen.
TRANSPORT *NodeMimicTransport(NODE *n) {
	TRANSPORT *ret = NULL;
	if (n == NULL)
		return NULL;

	Lock(n->Lock);
	{
		NODE_MIMIC *m = n->Mimic;

		if (m != NULL && (m->Sidecars[NODE_MIMIC_ROLE_SERVER].Settings != NULL || m->Sidecars[NODE_MIMIC_ROLE_CLIENT].Settings != NULL))
			ret = &m->Transport;
	}
	Unlock(n->Lock);

	return ret;
}

// The state of the sidecar of a role (NODE_MIMIC_ROLE_*)
void NodeMimicGetStatus(NODE *n, UINT role, NODE_MIMIC_STATUS *st) {
	if (st == NULL)
		return;

	Zero(st, sizeof(NODE_MIMIC_STATUS));

	if (n == NULL || role >= NODE_MIMIC_NUM_ROLES)
		return;

	Lock(n->Lock);
	{
		NODE_MIMIC *m = n->Mimic;

		if (m != NULL) {
			NODE_MIMIC_SIDECAR *sc = &m->Sidecars[role];

			Lock(sc->Lock);
			{
				Copy(st, &sc->St, sizeof(NODE_MIMIC_STATUS));
			}
			Unlock(sc->Lock);
		}
	}
	Unlock(n->Lock);
}
