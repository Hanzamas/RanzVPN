// NodeL2Npcap.c
// The Npcap backend of the L2 adapter (NodeL2.h; CORE-S3-3, #73), and what holds the NIC of a bridge in promiscuous mode
// for the XDP backend (NodeL2NpcapHold). Npcap is optional and never bundled (ADR-0018 decision 3): ranz.exe carries no
// file of it, so no Npcap OEM licence is needed, and the node uses it only where the operator installed it. The backend
// loads Npcap's wpcap.dll by its full path from System32\Npcap, the folder that the Npcap installer gives its DLLs, as
// the Npcap developer guide asks of a program that links Npcap explicitly; where that file is missing the backend does
// not bind, and a bridge goes on to its next backend. In the ranzvpnserver service the load fails while the
// signed-images mitigation of ADR-0039 is on, as Npcap's publisher, not Microsoft, signs its DLLs; the node log says so.
// The code follows the documented API of libpcap and WinPcap, which Npcap keeps (pcap_open with its open flags,
// pcap_next_ex, pcap_sendpacket, pcap_getevent, pcap_setfilter), declared here as the node takes it by GetProcAddress:
// - Capture: a handle opened with PCAP_OPENFLAG_PROMISCUOUS, so the NIC takes the frames of every MAC address;
//   PCAP_OPENFLAG_NOCAPTURE_LOCAL, which WinPcap documents for "applications like bridges, that should ignore the traffic
//   they just sent"; and PCAP_OPENFLAG_MAX_RESPONSIVENESS, so the driver hands each frame over at once. Its drain thread
//   waits on the event of the handle and takes the frames with pcap_next_ex, which gives them in place, into the capture
//   ring of the adapter: it takes no lock and allocates nothing (#72, risk R1). Npcap is a filter driver, so the frames
//   that the host sends are on the segment it sees, as they are for SeLow.
// - Inject: a second handle sends the owner's frames with pcap_sendpacket, on the injector thread, so a send never waits
//   behind a read of the drain thread on the same handle. Its BPF filter takes no frame, so it keeps none.
// - The promiscuous mode for the XDP backend: one more handle opened promiscuous, whose filter takes no frame either, so
//   Npcap copies nothing while XDP carries the frames; it is kept until the XDP backend lets go of the bridge.

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "NodeL2.h"

// The folder of Npcap's DLLs below System32, and its pcap library
#define NODE_L2_NPCAP_DLL L"\\Npcap\\wpcap.dll"
// The flags of pcap_open (pcap/pcap.h of libpcap, which Npcap ships in its SDK)
#define NODE_L2_PCAP_PROMISCUOUS        0x01
#define NODE_L2_PCAP_NOCAPTURE_LOCAL    0x08
#define NODE_L2_PCAP_MAX_RESPONSIVENESS 0x10
// Bytes of the error text of a pcap call (PCAP_ERRBUF_SIZE)
#define NODE_L2_PCAP_ERRBUF 256
// Bytes of a frame that the capture handle keeps at most: more than any frame of the adapter (NODE_L2_MAX_FRAME), so
// that a longer one arrives whole and the capture ring counts it as one that it refused
#define NODE_L2_PCAP_SNAPLEN 65536
// ms that pcap_next_ex waits for a frame, and that the drain thread waits on the event of the handle at a time, so that
// it sees its halt
#define NODE_L2_PCAP_TIMEOUT 1
#define NODE_L2_NPCAP_WAIT   50
// Frames that the drain thread takes in a row before it wakes the adapter queue
#define NODE_L2_NPCAP_BATCH 256
// The BPF instruction "ret #0" (BPF_RET | BPF_K, k 0): a filter of it takes no frame
#define NODE_L2_BPF_REJECT 0x06

// The header of a captured frame (struct pcap_pkthdr): its time as a struct timeval of Winsock, two longs, then the
// bytes captured and the bytes of the frame
typedef struct NODE_L2_PCAP_HEADER {
	long Seconds;
	long Microseconds;
	UINT Captured;
	UINT Size;
} NODE_L2_PCAP_HEADER;

// A BPF instruction and a program of them (struct bpf_insn, struct bpf_program)
typedef struct NODE_L2_BPF_INSN {
	USHORT Code;
	UCHAR Jt;
	UCHAR Jf;
	UINT K;
} NODE_L2_BPF_INSN;

typedef struct NODE_L2_BPF_PROGRAM {
	UINT Length;
	NODE_L2_BPF_INSN *Instructions;
} NODE_L2_BPF_PROGRAM;

// The functions of wpcap.dll that the node takes by name; a pcap_t is opaque
typedef void *(NODE_L2_PCAP_OPEN_FUNC)(const char *source, int snaplen, int flags, int read_timeout, void *auth, char *errbuf);
typedef void(NODE_L2_PCAP_CLOSE_FUNC)(void *p);
typedef int(NODE_L2_PCAP_NEXT_EX_FUNC)(void *p, NODE_L2_PCAP_HEADER **header, const UCHAR **data);
typedef int(NODE_L2_PCAP_SENDPACKET_FUNC)(void *p, const UCHAR *data, int size);
typedef HANDLE(NODE_L2_PCAP_GETEVENT_FUNC)(void *p);
typedef int(NODE_L2_PCAP_SETFILTER_FUNC)(void *p, NODE_L2_BPF_PROGRAM *program);
typedef char *(NODE_L2_PCAP_GETERR_FUNC)(void *p);

// wpcap.dll and its functions, loaded once per process and kept until the process ends
typedef struct NODE_L2_NPCAP_API {
	HMODULE Module;
	NODE_L2_PCAP_OPEN_FUNC *Open;
	NODE_L2_PCAP_CLOSE_FUNC *Close;
	NODE_L2_PCAP_NEXT_EX_FUNC *NextEx;
	NODE_L2_PCAP_SENDPACKET_FUNC *SendPacket;
	NODE_L2_PCAP_GETEVENT_FUNC *GetEvent;
	NODE_L2_PCAP_SETFILTER_FUNC *SetFilter;
	NODE_L2_PCAP_GETERR_FUNC *GetErr;
} NODE_L2_NPCAP_API;

static INIT_ONCE node_l2_npcap_once = INIT_ONCE_STATIC_INIT;
static NODE_L2_NPCAP_API node_l2_npcap;
static bool node_l2_npcap_loaded = false;
static char node_l2_npcap_error[MAX_SIZE];

// The state of the backend on one adapter (NODE_L2.BackendState)
typedef struct NODE_L2_NPCAP {
	NODE_L2 *Adapter;
	// The capture handle, its event, which the handle owns, and the send handle
	void *Capture;
	HANDLE Event;
	void *Send;
	// The drain thread, and its halt; Broken once a read failed (the adapter went, or Npcap let go of it)
	HANDLE Thread;
	volatile LONG Halt;
	volatile LONG Broken;
} NODE_L2_NPCAP;

// Load wpcap.dll from System32\Npcap, and Packet.dll beside it, which it imports, and take its functions
static BOOL CALLBACK NodeL2NpcapLoad(PINIT_ONCE once, void *param, void **context) {
	wchar_t path[MAX_PATH];
	UINT len = (UINT)GetSystemDirectoryW(path, MAX_PATH);

	if (len == 0 || len >= MAX_PATH - 32) {
		Format(node_l2_npcap_error, sizeof(node_l2_npcap_error), "the system directory cannot be read (error %u)", (UINT)GetLastError());
		return TRUE;
	}
	UniStrCat(path, sizeof(path), NODE_L2_NPCAP_DLL);

	if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
		Format(node_l2_npcap_error, sizeof(node_l2_npcap_error), "Npcap is not installed: there is no %S", path);
		return TRUE;
	}

	HMODULE m = LoadLibraryExW(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (m == NULL) {
		UINT err = (UINT)GetLastError();

		Format(node_l2_npcap_error, sizeof(node_l2_npcap_error), "%S of Npcap did not load (error %u)%s", path, err,
		       err == ERROR_INVALID_IMAGE_HASH ? ": this process takes images that Microsoft signed only (the signed-images mitigation of ADR-0039)" : "");
		return TRUE;
	}

	node_l2_npcap.Open = (NODE_L2_PCAP_OPEN_FUNC *)(void *)GetProcAddress(m, "pcap_open");
	node_l2_npcap.Close = (NODE_L2_PCAP_CLOSE_FUNC *)(void *)GetProcAddress(m, "pcap_close");
	node_l2_npcap.NextEx = (NODE_L2_PCAP_NEXT_EX_FUNC *)(void *)GetProcAddress(m, "pcap_next_ex");
	node_l2_npcap.SendPacket = (NODE_L2_PCAP_SENDPACKET_FUNC *)(void *)GetProcAddress(m, "pcap_sendpacket");
	node_l2_npcap.GetEvent = (NODE_L2_PCAP_GETEVENT_FUNC *)(void *)GetProcAddress(m, "pcap_getevent");
	node_l2_npcap.SetFilter = (NODE_L2_PCAP_SETFILTER_FUNC *)(void *)GetProcAddress(m, "pcap_setfilter");
	node_l2_npcap.GetErr = (NODE_L2_PCAP_GETERR_FUNC *)(void *)GetProcAddress(m, "pcap_geterr");

	if (node_l2_npcap.Open == NULL || node_l2_npcap.Close == NULL || node_l2_npcap.NextEx == NULL || node_l2_npcap.SendPacket == NULL ||
	    node_l2_npcap.GetEvent == NULL || node_l2_npcap.SetFilter == NULL || node_l2_npcap.GetErr == NULL) {
		Format(node_l2_npcap_error, sizeof(node_l2_npcap_error), "%S of Npcap lacks a function of the pcap API that the node calls", path);
		Zero(&node_l2_npcap, sizeof(node_l2_npcap));
		FreeLibrary(m);
		return TRUE;
	}

	node_l2_npcap.Module = m;
	node_l2_npcap_loaded = true;

	return TRUE;
}

// Whether Npcap is on this host and its pcap API loaded; error (when not NULL) gets why not
bool NodeL2NpcapPresent(char *error, UINT error_size) {
	InitOnceExecuteOnce(&node_l2_npcap_once, NodeL2NpcapLoad, NULL, NULL);

	StrCpy(error, error_size, node_l2_npcap_loaded ? "" : node_l2_npcap_error);

	return node_l2_npcap_loaded;
}

// Open a handle of Npcap on the NIC of the adapter, its device \Device\NPF_{GUID}, with the open flags flags; with
// reject, a filter that takes no frame. NULL, with why in error, when it cannot.
static void *NodeL2NpcapHandle(NODE_L2 *a, int flags, bool reject, char *error, UINT error_size) {
	char device[MAX_SIZE];
	char errbuf[NODE_L2_PCAP_ERRBUF];
	NODE_L2_BPF_INSN none;
	NODE_L2_BPF_PROGRAM program;
	const GUID *g = &a->Guid;

	Format(device, sizeof(device), "\\Device\\NPF_{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0],
	       (UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);

	Zero(errbuf, sizeof(errbuf));
	void *p = node_l2_npcap.Open(device, NODE_L2_PCAP_SNAPLEN, flags, NODE_L2_PCAP_TIMEOUT, NULL, errbuf);
	if (p == NULL) {
		errbuf[sizeof(errbuf) - 1] = 0;
		Format(error, error_size, "Npcap cannot open %s: %s", device, errbuf);
		return NULL;
	}

	if (reject) {
		Zero(&none, sizeof(none));
		none.Code = NODE_L2_BPF_REJECT;
		program.Length = 1;
		program.Instructions = &none;
		if (node_l2_npcap.SetFilter(p, &program) != 0) {
			Format(error, error_size, "Npcap takes no filter on %s: %s", device, node_l2_npcap.GetErr(p));
			node_l2_npcap.Close(p);
			return NULL;
		}
	}

	return p;
}

// The drain thread: once the event of the capture handle is set, the frames that it holds, each straight from the
// buffer of pcap into the capture ring of the adapter. A frame that the handle cut short is longer than any that the
// adapter carries, and counted as such. A read that fails marks the binding broken, which the health check sees.
static DWORD WINAPI NodeL2NpcapDrain(void *param) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)param;

	while (ReadAcquire(&s->Halt) == 0) {
		UINT num = 0;

		WaitForSingleObject(s->Event, NODE_L2_NPCAP_WAIT);

		while (num < NODE_L2_NPCAP_BATCH && ReadAcquire(&s->Halt) == 0) {
			NODE_L2_PCAP_HEADER *header = NULL;
			const UCHAR *data = NULL;
			int ret = node_l2_npcap.NextEx(s->Capture, &header, &data);

			if (ret != 1) {
				if (ret < 0)
					InterlockedExchange(&s->Broken, 1);
				break;
			}

			if (header->Captured < header->Size)
				InterlockedIncrement64(&s->Adapter->Oversize);
			else
				NodeL2Capture(s->Adapter, data, header->Captured);
			num++;
		}

		if (num != 0)
			NodeL2CaptureDone(s->Adapter);
		else if (ReadAcquire(&s->Broken) != 0)
			Sleep(NODE_L2_NPCAP_WAIT);
	}

	return 0;
}

// Hand a batch to the segment, on the injector thread: each frame through pcap_sendpacket. Returns how many Npcap took.
static UINT NodeL2NpcapInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)a->BackendState;
	UINT taken = 0;

	if (s == NULL)
		return 0;

	for (UINT i = 0; i < num; i++)
		if (node_l2_npcap.SendPacket(s->Send, frames[i], (int)sizes[i]) == 0)
			taken++;

	return taken;
}

// Whether the binding works: no read of the capture handle failed
static bool NodeL2NpcapHealthy(NODE_L2 *a) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)a->BackendState;

	return (s != NULL && ReadAcquire(&s->Broken) == 0);
}

// Free the state of the backend once no thread runs on it
static void NodeL2NpcapRelease(NODE_L2_NPCAP *s) {
	if (s->Capture != NULL)
		node_l2_npcap.Close(s->Capture);
	if (s->Send != NULL)
		node_l2_npcap.Close(s->Send);

	Free(s);
}

// Stop: the drain thread ends within timeout ms, then the handles close. pcap_sendpacket returns once Npcap sent the
// frame, so nothing that was injected is outstanding. A drain thread that does not end in time keeps the state.
static bool NodeL2NpcapDetach(NODE_L2 *a, UINT timeout) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)a->BackendState;

	if (s == NULL)
		return true;

	a->BackendState = NULL;

	InterlockedExchange(&s->Halt, 1);
	if (WaitForSingleObject(s->Thread, timeout) != WAIT_OBJECT_0)
		return false;
	CloseHandle(s->Thread);

	NodeL2NpcapRelease(s);

	return true;
}

// Bind to the NIC: the capture handle, promiscuous and blind to its own frames, the send handle, then the drain thread
static bool NodeL2NpcapAttach(NODE_L2 *a, char *error, UINT error_size) {
	if (NodeL2NpcapPresent(error, error_size) == false)
		return false;

	NODE_L2_NPCAP *s = ZeroMalloc(sizeof(NODE_L2_NPCAP));
	s->Adapter = a;
	s->Capture = NodeL2NpcapHandle(a, NODE_L2_PCAP_PROMISCUOUS | NODE_L2_PCAP_NOCAPTURE_LOCAL | NODE_L2_PCAP_MAX_RESPONSIVENESS, false, error, error_size);
	if (s->Capture != NULL)
		s->Send = NodeL2NpcapHandle(a, 0, true, error, error_size);
	if (s->Capture == NULL || s->Send == NULL) {
		NodeL2NpcapRelease(s);
		return false;
	}

	s->Event = node_l2_npcap.GetEvent(s->Capture);
	if (s->Event == NULL) {
		Format(error, error_size, "Npcap gives no event for its capture handle");
		NodeL2NpcapRelease(s);
		return false;
	}

	s->Thread = CreateThread(NULL, 0, NodeL2NpcapDrain, s, 0, NULL);
	if (s->Thread == NULL) {
		Format(error, error_size, "the drain thread could not start (error %u)", (UINT)GetLastError());
		NodeL2NpcapRelease(s);
		return false;
	}

	SetThreadPriority(s->Thread, THREAD_PRIORITY_HIGHEST);

	// Npcap hands over the frames of the NIC on one handle, whatever queue they came in on
	InterlockedExchange(&a->DriverQueues, 1);
	a->BackendState = s;

	return true;
}

static const NODE_L2_BACKEND node_l2_npcap_backend = {"npcap", NodeL2NpcapAttach, NodeL2NpcapInject, NodeL2NpcapHealthy, NodeL2NpcapDetach};

// The Npcap backend
const NODE_L2_BACKEND *NodeL2NpcapBackend() {
	return &node_l2_npcap_backend;
}

// Hold the NIC of the bridge a in promiscuous mode for the XDP backend (NODE_L2_HOLD_PROC): into *hold, a handle of Npcap
// opened promiscuous, whose filter takes no frame. False, with why in error, where Npcap is not installed or cannot open
// the NIC.
bool NodeL2NpcapHold(NODE_L2 *a, void **hold, char *error, UINT error_size) {
	if (a == NULL || hold == NULL || NodeL2NpcapPresent(error, error_size) == false)
		return false;

	*hold = NodeL2NpcapHandle(a, NODE_L2_PCAP_PROMISCUOUS, true, error, error_size);

	return (*hold != NULL);
}

// Let go of the promiscuous mode that NodeL2NpcapHold holds (NODE_L2_LET_GO_PROC)
void NodeL2NpcapLetGo(void *hold) {
	if (hold != NULL && node_l2_npcap_loaded)
		node_l2_npcap.Close(hold);
}
