// NodeL2Npcap.c
// The Npcap backend of the L2 adapter (NodeL2.h; CORE-S3-3, #73), and what holds the NIC of a bridge in promiscuous mode
// for the XDP backend (NodeL2NpcapHold). Npcap is optional and never bundled (ADR-0018 decision 3): ranz.exe carries no
// file of it, so no Npcap OEM licence is needed, and the node uses it only where the operator installed it. The backend
// loads Npcap's wpcap.dll from System32\Npcap, the folder that the Npcap installer gives its DLLs, which the Npcap
// developer guide asks a program that links Npcap explicitly to load it from: by its full path, with
// LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR so that Packet.dll beside it loads too, instead of the SetDllDirectory of the guide,
// which would change the DLL search of the whole process. Where that file is missing the backend does not bind, and a
// bridge goes on to its next backend. In the ranzvpnserver service the load fails while the signed-images mitigation of
// ADR-0039 is on, as Npcap's publisher, not Microsoft, signs its DLLs; the node log says so.
// The code follows the documented API of libpcap and WinPcap, which Npcap keeps (pcap_open with its open flags,
// pcap_next_ex, pcap_sendpacket, pcap_getevent, pcap_setfilter), which the node takes by GetProcAddress into the table
// of NodeL2.h (NODE_L2_PCAP_API):
// - One handle captures and injects, opened with PCAP_OPENFLAG_PROMISCUOUS, so the NIC takes the frames of every MAC
//   address; PCAP_OPENFLAG_NOCAPTURE_LOCAL, which WinPcap documents for "applications like bridges, that should ignore
//   the traffic they just sent"; and PCAP_OPENFLAG_MAX_RESPONSIVENESS, so the driver hands each frame over at once. The
//   flag leaves out only what the same handle sent: the Npcap driver taps each frame that pcap_sendpacket sends for
//   every other handle on the adapter (NPF_Write and NPF_DoTap, packetWin7/npf/npf of nmap/npcap), so a bridge that sent
//   on a second handle would capture each frame that it put onto the segment and hand it back to its owner. UserBridge,
//   the bridge that the Npcap developer guide gives as its example (hsluoyz/UserBridge), opens each adapter so, once,
//   and reads and sends on that handle from two threads, as this backend does.
// - Capture: the drain thread waits on the event of the handle and takes the frames with pcap_next_ex, which gives them
//   in place, into the capture ring of the adapter: it takes no lock and allocates nothing (#72, risk R1). Npcap is a
//   filter driver, so the frames that the host sends are on the segment it sees, as they are for SeLow.
// - Inject: the injector thread sends the owner's frames on the same handle with pcap_sendpacket. Packet.dll waits for
//   the frames of a read on the event and then reads what the driver holds without waiting (PacketReceivePacket), so a
//   send waits at most for the copy of a read on the synchronous handle.
// - The promiscuous mode for the XDP backend: one more handle opened promiscuous, whose filter takes no frame, so Npcap
//   copies nothing while XDP carries the frames; it is kept until the XDP backend lets go of the bridge.
// - A test gives a stand-in of the pcap API in place of wpcap.dll (NodeL2NpcapStandIn): no runner may carry Npcap, whose
//   free licence allows five installations and has no silent install. Each handle keeps the API that opened it.

#include "Node.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include "NodeL2.h"

// The folder of Npcap's DLLs below System32, and its pcap library
#define NODE_L2_NPCAP_DLL L"\\Npcap\\wpcap.dll"
// Bytes of the error text of a pcap call (PCAP_ERRBUF_SIZE)
#define NODE_L2_PCAP_ERRBUF 256
// Bytes of a frame that the handle of the backend keeps at most: more than any frame of the adapter (NODE_L2_MAX_FRAME),
// so that a longer one arrives whole and the capture ring counts it as one that it refused
#define NODE_L2_PCAP_SNAPLEN 65536
// ms that pcap_next_ex waits for a frame, and that the drain thread waits on the event of the handle at a time, so that
// it sees its halt
#define NODE_L2_PCAP_TIMEOUT 1
#define NODE_L2_NPCAP_WAIT   50
// Frames that the drain thread takes in a row before it wakes the adapter queue
#define NODE_L2_NPCAP_BATCH 256

// The functions of the wpcap.dll of an installed Npcap, loaded once per process and kept until the process ends
static INIT_ONCE node_l2_npcap_once = INIT_ONCE_STATIC_INIT;
static NODE_L2_PCAP_API node_l2_npcap;
static bool node_l2_npcap_loaded = false;
static char node_l2_npcap_error[MAX_SIZE];
// The stand-in of a test, used in place of wpcap.dll while it is set (NodeL2NpcapStandIn)
static const NODE_L2_PCAP_API *node_l2_npcap_standin = NULL;

// The state of the backend on one adapter (NODE_L2.BackendState)
typedef struct NODE_L2_NPCAP {
	NODE_L2 *Adapter;
	// The pcap API that opened the handle, the handle that captures and sends, and its event, which the handle owns
	const NODE_L2_PCAP_API *Api;
	void *Handle;
	HANDLE Event;
	// The drain thread, and its halt; Broken once a read failed (the adapter went, or Npcap let go of it)
	HANDLE Thread;
	volatile LONG Halt;
	volatile LONG Broken;
} NODE_L2_NPCAP;

// What holds the NIC of a bridge in promiscuous mode for the XDP backend (NodeL2NpcapHold): a handle, and the pcap API
// that opened it
typedef struct NODE_L2_NPCAP_HOLD {
	const NODE_L2_PCAP_API *Api;
	void *Handle;
} NODE_L2_NPCAP_HOLD;

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

	node_l2_npcap.Open = (NODE_L2_PCAP_OPEN_PROC *)(void *)GetProcAddress(m, "pcap_open");
	node_l2_npcap.Close = (NODE_L2_PCAP_CLOSE_PROC *)(void *)GetProcAddress(m, "pcap_close");
	node_l2_npcap.NextEx = (NODE_L2_PCAP_NEXT_EX_PROC *)(void *)GetProcAddress(m, "pcap_next_ex");
	node_l2_npcap.SendPacket = (NODE_L2_PCAP_SENDPACKET_PROC *)(void *)GetProcAddress(m, "pcap_sendpacket");
	node_l2_npcap.GetEvent = (NODE_L2_PCAP_GETEVENT_PROC *)(void *)GetProcAddress(m, "pcap_getevent");
	node_l2_npcap.SetFilter = (NODE_L2_PCAP_SETFILTER_PROC *)(void *)GetProcAddress(m, "pcap_setfilter");
	node_l2_npcap.GetErr = (NODE_L2_PCAP_GETERR_PROC *)(void *)GetProcAddress(m, "pcap_geterr");

	if (node_l2_npcap.Open == NULL || node_l2_npcap.Close == NULL || node_l2_npcap.NextEx == NULL || node_l2_npcap.SendPacket == NULL ||
	    node_l2_npcap.GetEvent == NULL || node_l2_npcap.SetFilter == NULL || node_l2_npcap.GetErr == NULL) {
		Format(node_l2_npcap_error, sizeof(node_l2_npcap_error), "%S of Npcap lacks a function of the pcap API that the node calls", path);
		Zero(&node_l2_npcap, sizeof(node_l2_npcap));
		FreeLibrary(m);
		return TRUE;
	}

	node_l2_npcap_loaded = true;

	return TRUE;
}

// The pcap API in use: the stand-in of a test while one is set, else the wpcap.dll of an installed Npcap once it loaded;
// NULL, with why in error (when not NULL), for none
static const NODE_L2_PCAP_API *NodeL2NpcapApi(char *error, UINT error_size) {
	InitOnceExecuteOnce(&node_l2_npcap_once, NodeL2NpcapLoad, NULL, NULL);

	const NODE_L2_PCAP_API *api = node_l2_npcap_standin;
	if (api == NULL && node_l2_npcap_loaded)
		api = &node_l2_npcap;

	StrCpy(error, error_size, api != NULL ? "" : node_l2_npcap_error);

	return api;
}

// Whether Npcap is on this host and its pcap API loaded, or a test gave a stand-in of it; error (when not NULL) gets why
// not
bool NodeL2NpcapPresent(char *error, UINT error_size) {
	return (NodeL2NpcapApi(error, error_size) != NULL);
}

// Give the backend the stand-in of a test in place of the pcap API of wpcap.dll, as no runner may carry Npcap; NULL takes
// it away again, which leaves the wpcap.dll of an installed Npcap. Only while no bridge is on Npcap and nothing holds a
// NIC through it.
void NodeL2NpcapStandIn(const NODE_L2_PCAP_API *api) {
	InitOnceExecuteOnce(&node_l2_npcap_once, NodeL2NpcapLoad, NULL, NULL);

	node_l2_npcap_standin = api;
}

// Open a handle of the pcap API api on the NIC of the adapter, its device \Device\NPF_{GUID}, with the open flags flags;
// with reject, a filter that takes no frame. NULL, with why in error, when it cannot.
static void *NodeL2NpcapHandle(const NODE_L2_PCAP_API *api, NODE_L2 *a, int flags, bool reject, char *error, UINT error_size) {
	char device[MAX_SIZE];
	char errbuf[NODE_L2_PCAP_ERRBUF];
	NODE_L2_BPF_INSN none;
	NODE_L2_BPF_PROGRAM program;
	const GUID *g = &a->Guid;

	Format(device, sizeof(device), "\\Device\\NPF_{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}", (UINT)g->Data1, (UINT)g->Data2, (UINT)g->Data3, (UINT)g->Data4[0],
	       (UINT)g->Data4[1], (UINT)g->Data4[2], (UINT)g->Data4[3], (UINT)g->Data4[4], (UINT)g->Data4[5], (UINT)g->Data4[6], (UINT)g->Data4[7]);

	Zero(errbuf, sizeof(errbuf));
	void *p = api->Open(device, NODE_L2_PCAP_SNAPLEN, flags, NODE_L2_PCAP_TIMEOUT, NULL, errbuf);
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
		if (api->SetFilter(p, &program) != 0) {
			Format(error, error_size, "Npcap takes no filter on %s: %s", device, api->GetErr(p));
			api->Close(p);
			return NULL;
		}
	}

	return p;
}

// The drain thread: once the event of the handle is set, the frames that it holds, each straight from the buffer of
// pcap into the capture ring of the adapter. A frame that the handle cut short is longer than any that the adapter
// carries, and counted as such. A read that fails marks the binding broken, which the health check sees.
static DWORD WINAPI NodeL2NpcapDrain(void *param) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)param;

	while (ReadAcquire(&s->Halt) == 0) {
		UINT num = 0;

		WaitForSingleObject(s->Event, NODE_L2_NPCAP_WAIT);

		while (num < NODE_L2_NPCAP_BATCH && ReadAcquire(&s->Halt) == 0) {
			NODE_L2_PCAP_HEADER *header = NULL;
			const UCHAR *data = NULL;
			int ret = s->Api->NextEx(s->Handle, &header, &data);

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

// Hand a batch to the segment, on the injector thread: each frame through pcap_sendpacket on the handle that captures,
// which leaves it out of its capture. Returns how many Npcap took.
static UINT NodeL2NpcapInject(NODE_L2 *a, const UCHAR **frames, const UINT *sizes, UINT num) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)a->BackendState;
	UINT taken = 0;

	if (s == NULL)
		return 0;

	for (UINT i = 0; i < num; i++)
		if (s->Api->SendPacket(s->Handle, frames[i], (int)sizes[i]) == 0)
			taken++;

	return taken;
}

// Whether the binding works: no read of the handle failed
static bool NodeL2NpcapHealthy(NODE_L2 *a) {
	NODE_L2_NPCAP *s = (NODE_L2_NPCAP *)a->BackendState;

	return (s != NULL && ReadAcquire(&s->Broken) == 0);
}

// Free the state of the backend once no thread runs on it
static void NodeL2NpcapRelease(NODE_L2_NPCAP *s) {
	if (s->Handle != NULL)
		s->Api->Close(s->Handle);

	Free(s);
}

// Stop: the drain thread ends within timeout ms, then the handle closes. pcap_sendpacket returns once Npcap sent the
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

// Bind to the NIC: the handle, promiscuous and blind to the frames that it sends itself, then the drain thread
static bool NodeL2NpcapAttach(NODE_L2 *a, char *error, UINT error_size) {
	const NODE_L2_PCAP_API *api = NodeL2NpcapApi(error, error_size);
	if (api == NULL)
		return false;

	NODE_L2_NPCAP *s = ZeroMalloc(sizeof(NODE_L2_NPCAP));
	s->Adapter = a;
	s->Api = api;
	s->Handle = NodeL2NpcapHandle(api, a, NODE_L2_PCAP_PROMISCUOUS | NODE_L2_PCAP_NOCAPTURE_LOCAL | NODE_L2_PCAP_MAX_RESPONSIVENESS, false, error, error_size);
	if (s->Handle == NULL) {
		NodeL2NpcapRelease(s);
		return false;
	}

	s->Event = api->GetEvent(s->Handle);
	if (s->Event == NULL) {
		Format(error, error_size, "Npcap gives no event for its handle");
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
// opened promiscuous, whose filter takes no frame, with the pcap API that opened it. False, with why in error, where
// Npcap is not installed or cannot open the NIC.
bool NodeL2NpcapHold(NODE_L2 *a, void **hold, char *error, UINT error_size) {
	if (a == NULL || hold == NULL)
		return false;

	*hold = NULL;
	const NODE_L2_PCAP_API *api = NodeL2NpcapApi(error, error_size);
	if (api == NULL)
		return false;

	void *p = NodeL2NpcapHandle(api, a, NODE_L2_PCAP_PROMISCUOUS, true, error, error_size);
	if (p == NULL)
		return false;

	NODE_L2_NPCAP_HOLD *h = ZeroMalloc(sizeof(NODE_L2_NPCAP_HOLD));
	h->Api = api;
	h->Handle = p;
	*hold = h;

	return true;
}

// Let go of the promiscuous mode that NodeL2NpcapHold holds (NODE_L2_LET_GO_PROC)
void NodeL2NpcapLetGo(void *hold) {
	NODE_L2_NPCAP_HOLD *h = (NODE_L2_NPCAP_HOLD *)hold;

	if (h == NULL)
		return;

	h->Api->Close(h->Handle);
	Free(h);
}
