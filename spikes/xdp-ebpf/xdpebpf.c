//
// XDP eBPF spike (ADR-0018): can the supported eBPF path (eBPF for Windows +
// the XDP eBPF hook + an XSKMAP redirect program) replace the deprecated
// XDP_RULE program for TX inspect on a Microsoft KM-TEST Loopback Adapter?
//
//   1. EBPF_LOAD         load ranz_xsk.sys (native eBPF), find xsk_map/stats.
//   2. EBPF_TX_INSPECT   AF_XDP RX socket on {L2, TX, INSPECT} in xsk_map,
//                        program attached with bpf_xdp_attach(); does the
//                        socket get the frames the OS sends?
//   3. EBPF_RX_INSPECT   same program, socket on {L2, RX, INSPECT}; does the
//                        hook see OS-sent frames (KM-TEST looping them back)
//                        or frames injected with {L2, RX, INJECT}?
//   4. RULE_TX_INSPECT   deprecated XDP_RULE redirect on {L2, TX, INSPECT}
//                        while the eBPF program stays attached (coexistence).
//   5. RX_INJECT         AF_XDP TX socket on {L2, RX, INJECT}, no program,
//                        eBPF detached (as in spikes/xdp-loopback).
//
// Built from samples/xskfwd (eBPF loader) and the xdp-loopback spike.
// Spike code, never merged.
//
// Usage: xdpebpf.exe <IfIndex> <LocalIPv4> <PeerIPv4> <Seconds> <ranz_xsk.sys>
//

#include <xdpapi.h>
#include <afxdp_helper.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma warning(push)
#pragma warning(disable : 4201) // nonstandard extension used: nameless struct/union
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#pragma warning(pop)
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK 2048
#define NCHUNK 1024 // power of two; equal to the ring sizes
#define RING 1024
#define BATCH 64
#define TX_PORT 5555 // OS -> peer, captured by TX inspect
#define RX_PORT 5556 // injected peer -> OS, received by a UDP socket

static const UCHAR PeerMac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

static UINT32 IfIndex;
static IN_ADDR LocalIp;
static IN_ADDR PeerIp;
static UCHAR LocalMac[6];
static DWORD Seconds;
static volatile LONG Stop;
static volatile LONG64 Sent;
static volatile LONG64 Received;
static SOCKET RecvSock = INVALID_SOCKET;
static LARGE_INTEGER Freq;

static struct bpf_object *Obj;
static int ProgFd = -1;
static int XskMapFd = -1;
static int StatsFd = -1;
static BOOL Attached;

typedef struct _XSKC {
    HANDLE Sock;
    UCHAR *Umem;
    XSK_RING Rx;
    XSK_RING Fill;
    XSK_RING Tx;
    XSK_RING Comp;
} XSKC;

typedef struct _TXCOUNT {
    UINT64 Frames;
    UINT64 Udp;
    UINT64 Arp;
    UINT64 Other;
    UINT64 FromUs;
} TXCOUNT;

static void Log(const char *Fmt, ...)
{
    va_list Ap;
    va_start(Ap, Fmt);
    vprintf(Fmt, Ap);
    va_end(Ap);
    fflush(stdout);
}

static double Now(void)
{
    LARGE_INTEGER T;
    QueryPerformanceCounter(&T);
    return (double)T.QuadPart / (double)Freq.QuadPart;
}

static BOOL GetMac(void)
{
    ULONG Len = 0;
    IP_ADAPTER_ADDRESSES *All, *P;

    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &Len);
    All = malloc(Len);
    if (All == NULL || GetAdaptersAddresses(AF_UNSPEC, 0, NULL, All, &Len) != NO_ERROR) {
        free(All);
        return FALSE;
    }
    for (P = All; P != NULL; P = P->Next) {
        if (P->IfIndex == IfIndex && P->PhysicalAddressLength == 6) {
            memcpy(LocalMac, P->PhysicalAddress, 6);
            Log("adapter: %ls (%ls) oper=%d\n", P->FriendlyName, P->Description, P->OperStatus);
            free(All);
            return TRUE;
        }
    }
    free(All);
    return FALSE;
}

#define CHK(What) \
    if (FAILED(Hr)) { Log("ERR %s: 0x%08lx\n", What, (unsigned long)Hr); return Hr; }

static HRESULT XskOpen(XSKC *X, BOOL Rx, XDP_HOOK_ID Hook)
{
    HRESULT Hr;
    XSK_UMEM_REG Umem = {0};
    UINT32 Ring = RING;
    XSK_RING_INFO_SET Info;
    UINT32 Len = sizeof(Info);

    X->Umem = VirtualAlloc(NULL, CHUNK * NCHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (X->Umem == NULL) {
        Log("ERR VirtualAlloc\n");
        return E_OUTOFMEMORY;
    }

    Hr = XskCreate(&X->Sock);
    CHK("XskCreate");

    Umem.TotalSize = CHUNK * NCHUNK;
    Umem.ChunkSize = CHUNK;
    Umem.Address = X->Umem;
    Hr = XskSetSockopt(X->Sock, XSK_SOCKOPT_UMEM_REG, &Umem, sizeof(Umem));
    CHK("XSK_SOCKOPT_UMEM_REG");

    Hr = XskSetSockopt(
        X->Sock, Rx ? XSK_SOCKOPT_RX_HOOK_ID : XSK_SOCKOPT_TX_HOOK_ID, &Hook, sizeof(Hook));
    CHK(Rx ? "XSK_SOCKOPT_RX_HOOK_ID" : "XSK_SOCKOPT_TX_HOOK_ID");

    Hr = XskBind(X->Sock, IfIndex, 0, (Rx ? XSK_BIND_FLAG_RX : XSK_BIND_FLAG_TX) | XSK_BIND_FLAG_GENERIC);
    CHK("XskBind");

    if (Rx) {
        Hr = XskSetSockopt(X->Sock, XSK_SOCKOPT_RX_RING_SIZE, &Ring, sizeof(Ring));
        CHK("XSK_SOCKOPT_RX_RING_SIZE");
        Hr = XskSetSockopt(X->Sock, XSK_SOCKOPT_RX_FILL_RING_SIZE, &Ring, sizeof(Ring));
        CHK("XSK_SOCKOPT_RX_FILL_RING_SIZE");
    } else {
        Hr = XskSetSockopt(X->Sock, XSK_SOCKOPT_TX_RING_SIZE, &Ring, sizeof(Ring));
        CHK("XSK_SOCKOPT_TX_RING_SIZE");
        Hr = XskSetSockopt(X->Sock, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &Ring, sizeof(Ring));
        CHK("XSK_SOCKOPT_TX_COMPLETION_RING_SIZE");
    }

    Hr = XskActivate(X->Sock, XSK_ACTIVATE_FLAG_NONE);
    CHK("XskActivate");

    Hr = XskGetSockopt(X->Sock, XSK_SOCKOPT_RING_INFO, &Info, &Len);
    CHK("XSK_SOCKOPT_RING_INFO");

    if (Rx) {
        UINT32 Idx, N, i;
        XskRingInitialize(&X->Rx, &Info.Rx);
        XskRingInitialize(&X->Fill, &Info.Fill);
        N = XskRingProducerReserve(&X->Fill, RING, &Idx);
        for (i = 0; i < N; i++) {
            *(UINT64 *)XskRingGetElement(&X->Fill, Idx + i) = (UINT64)i * CHUNK;
        }
        XskRingProducerSubmit(&X->Fill, N);
    } else {
        XskRingInitialize(&X->Tx, &Info.Tx);
        XskRingInitialize(&X->Comp, &Info.Completion);
    }
    return S_OK;
}

static void XskClose(XSKC *X)
{
    if (X->Sock != NULL) {
        CloseHandle(X->Sock);
        X->Sock = NULL;
    }
    if (X->Umem != NULL) {
        VirtualFree(X->Umem, 0, MEM_RELEASE);
        X->Umem = NULL;
    }
}

static void Hex(const char *Tag, const UCHAR *F, UINT32 Len)
{
    UINT32 i;
    Log("%s len=%u:", Tag, Len);
    for (i = 0; i < Len && i < 48; i++) {
        Log(" %02x", F[i]);
    }
    Log("\n");
}

//
// eBPF helpers
//

static void ReadStats(UINT64 S[4])
{
    UINT32 K;
    for (K = 0; K < 4; K++) {
        UINT64 V = 0;
        if (StatsFd >= 0 && bpf_map_lookup_elem(StatsFd, &K, &V) == 0) {
            S[K] = V;
        } else {
            S[K] = 0;
        }
    }
}

static void LogStatsDelta(const char *Tag, const UINT64 A[4], const UINT64 B[4])
{
    Log("%s ebpf_hook_seen: all=%llu udp%d=%llu udp%d=%llu arp=%llu\n", Tag,
        B[0] - A[0], TX_PORT, B[1] - A[1], RX_PORT, B[2] - A[2], B[3] - A[3]);
}

static int MapPut(HANDLE Sock)
{
    UINT64 Key = 0;
    int Rc = bpf_map_update_elem(XskMapFd, &Key, &Sock, 0);
    Log("bpf_map_update_elem(xsk_map[0]=%p) rc=%d errno=%d\n", Sock, Rc, Rc ? errno : 0);
    return Rc;
}

static void MapDel(void)
{
    UINT64 Key = 0;
    int Rc = bpf_map_delete_elem(XskMapFd, &Key);
    Log("bpf_map_delete_elem(xsk_map[0]) rc=%d errno=%d\n", Rc, Rc ? errno : 0);
}

static int TestEbpfLoad(const char *Path)
{
    struct bpf_program *Prog;
    int Rc;
    UINT32 ProgId = 0;

    Log("== EBPF_LOAD: %s\n", Path);
    Obj = bpf_object__open(Path);
    if (Obj == NULL) {
        Log("ERR bpf_object__open errno=%d\n", errno);
        Log("RESULT EBPF_LOAD FAIL reason=open errno=%d\n", errno);
        return 1;
    }
    Rc = bpf_object__load(Obj);
    if (Rc != 0) {
        Log("ERR bpf_object__load rc=%d errno=%d\n", Rc, errno);
        Log("RESULT EBPF_LOAD FAIL reason=load rc=%d errno=%d\n", Rc, errno);
        return 1;
    }
    Prog = bpf_object__find_program_by_name(Obj, "ranz_xsk");
    ProgFd = Prog ? bpf_program__fd(Prog) : -1;
    XskMapFd = bpf_object__find_map_fd_by_name(Obj, "xsk_map");
    StatsFd = bpf_object__find_map_fd_by_name(Obj, "stats");
    Log("prog_fd=%d xsk_map_fd=%d stats_fd=%d\n", ProgFd, XskMapFd, StatsFd);
    if (ProgFd < 0 || XskMapFd < 0 || StatsFd < 0) {
        Log("RESULT EBPF_LOAD FAIL reason=missing-prog-or-map\n");
        return 1;
    }
    Log("RESULT EBPF_LOAD PASS (native ranz_xsk.sys verified and loaded)\n");

    Rc = bpf_xdp_query_id((int)IfIndex, 0, &ProgId);
    Log("bpf_xdp_query_id before attach rc=%d id=%u\n", Rc, ProgId);
    return 0;
}

static int EbpfAttach(void)
{
    int Rc;
    UINT32 ProgId = 0;

    Rc = bpf_xdp_attach((int)IfIndex, ProgFd, 0, NULL);
    Log("bpf_xdp_attach(IfIndex=%u) rc=%d errno=%d\n", IfIndex, Rc, Rc ? errno : 0);
    if (Rc == 0) {
        Attached = TRUE;
        Rc = bpf_xdp_query_id((int)IfIndex, 0, &ProgId);
        Log("bpf_xdp_query_id after attach rc=%d id=%u\n", Rc, ProgId);
        return 0;
    }
    return 1;
}

static void EbpfDetach(void)
{
    if (Attached) {
        int Rc = bpf_xdp_detach((int)IfIndex, 0, NULL);
        Log("bpf_xdp_detach rc=%d errno=%d\n", Rc, Rc ? errno : 0);
        Attached = FALSE;
    }
}

//
// OS-sent traffic and capture
//

static DWORD WINAPI SenderThread(void *Ctx)
{
    SOCKET S = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKADDR_IN Src = {0}, Dst = {0};
    char Buf[64] = "RANZ-XDP-SPIKE-TX";
    BOOL Flood = (BOOL)(ULONG_PTR)Ctx;

    Src.sin_family = AF_INET;
    Src.sin_addr = LocalIp;
    Dst.sin_family = AF_INET;
    Dst.sin_addr = PeerIp;
    Dst.sin_port = htons(TX_PORT);
    if (bind(S, (SOCKADDR *)&Src, sizeof(Src)) != 0) {
        Log("ERR sender bind: %d\n", WSAGetLastError());
    }
    do {
        if (sendto(S, Buf, sizeof(Buf), 0, (SOCKADDR *)&Dst, sizeof(Dst)) > 0) {
            InterlockedIncrement64(&Sent);
        }
        if (!Flood) {
            Sleep(100);
        }
    } while (!Stop);
    closesocket(S);
    return 0;
}

static BOOL Classify(const UCHAR *F, UINT32 Len, TXCOUNT *C)
{
    BOOL Udp = FALSE;
    C->Frames++;
    if (Len >= 14 && memcmp(F + 6, LocalMac, 6) == 0) {
        C->FromUs++;
    }
    if (Len >= 14 + 20 + 8 && F[12] == 0x08 && F[13] == 0x00 && F[14 + 9] == 17) {
        UINT32 Ihl = (F[14] & 0x0f) * 4;
        if (Len >= 14 + Ihl + 4 && ((F[14 + Ihl + 2] << 8) | F[14 + Ihl + 3]) == TX_PORT) {
            C->Udp++;
            Udp = TRUE;
        } else {
            C->Other++;
        }
    } else if (Len >= 14 && F[12] == 0x08 && F[13] == 0x06) {
        C->Arp++;
    } else {
        C->Other++;
    }
    return Udp;
}

static UINT64 DrainRx(XSKC *X, TXCOUNT *C, UINT32 *Dumped, const char *Tag)
{
    UINT32 Idx, FIdx, N, i;
    UINT64 Bases[BATCH];
    XSK_NOTIFY_RESULT_FLAGS Nr;

    N = XskRingConsumerReserve(&X->Rx, BATCH, &Idx);
    if (N == 0) {
        return 0;
    }
    for (i = 0; i < N; i++) {
        XSK_BUFFER_DESCRIPTOR *D = XskRingGetElement(&X->Rx, Idx + i);
        UCHAR *F = X->Umem + D->Address.BaseAddress + D->Address.Offset;
        BOOL Udp = Classify(F, D->Length, C);
        if (*Dumped < 4 || (Udp && C->Udp == 1)) {
            Hex(Tag, F, D->Length);
            (*Dumped)++;
        }
        Bases[i] = D->Address.BaseAddress;
    }
    XskRingConsumerRelease(&X->Rx, N);
    if (XskRingProducerReserve(&X->Fill, N, &FIdx) == N) {
        for (i = 0; i < N; i++) {
            *(UINT64 *)XskRingGetElement(&X->Fill, FIdx + i) = Bases[i];
        }
        XskRingProducerSubmit(&X->Fill, N);
    }
    if (XskRingProducerNeedPoke(&X->Fill)) {
        XskNotifySocket(X->Sock, XSK_NOTIFY_FLAG_POKE_RX, 0, &Nr);
    }
    return N;
}

//
// Phase 1: 10 datagrams per second for 3 s. Phase 2: flood for Seconds while
// busy-polling. Returns the UDP-to-TX_PORT frames per second seen in phase 2.
//
static double Capture(XSKC *X, const char *Tag, TXCOUNT *C1, TXCOUNT *C2, LONG64 *Sent1)
{
    HANDLE Th;
    double T0, T1, End;
    UINT64 Spin = 0;
    UINT32 Dumped = 0;
    XSK_STATISTICS Stats = {0};
    UINT32 StatsLen = sizeof(Stats);

    Stop = 0;
    Sent = 0;
    Th = CreateThread(NULL, 0, SenderThread, (void *)(ULONG_PTR)FALSE, 0, NULL);
    End = Now() + 3.0;
    while (Now() < End) {
        if (DrainRx(X, C1, &Dumped, Tag) == 0) {
            Sleep(1);
        }
    }
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);
    Sleep(100);
    while (DrainRx(X, C1, &Dumped, Tag) != 0) {
    }
    *Sent1 = Sent;
    Log("%s phase1: sent=%lld frames=%llu udp%d=%llu arp=%llu other=%llu fromAdapterMac=%llu\n",
        Tag, Sent, C1->Frames, TX_PORT, C1->Udp, C1->Arp, C1->Other, C1->FromUs);

    Stop = 0;
    Sent = 0;
    Th = CreateThread(NULL, 0, SenderThread, (void *)(ULONG_PTR)TRUE, 0, NULL);
    T0 = Now();
    End = T0 + Seconds;
    for (;;) {
        DrainRx(X, C2, &Dumped, Tag);
        if ((++Spin & 0xff) == 0 && Now() >= End) {
            break;
        }
    }
    T1 = Now();
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);
    while (DrainRx(X, C2, &Dumped, Tag) != 0) {
    }
    XskGetSockopt(X->Sock, XSK_SOCKOPT_STATISTICS, &Stats, &StatsLen);
    Log("%s phase2: secs=%.2f sent=%lld frames=%llu udp%d=%llu rxDropped=%llu rxInvalid=%llu\n",
        Tag, T1 - T0, Sent, C2->Frames, TX_PORT, C2->Udp, Stats.RxDropped, Stats.RxInvalidDescriptors);
    Log("PPS %s udp_seen=%.0f sendto=%.0f\n", Tag, C2->Udp / (T1 - T0), Sent / (T1 - T0));
    return C2->Udp / (T1 - T0);
}

//
// RX inject
//

static UINT16 Csum(const UCHAR *P, int N)
{
    UINT32 S = 0;
    for (; N > 1; N -= 2, P += 2) {
        S += (P[0] << 8) | P[1];
    }
    if (N) {
        S += P[0] << 8;
    }
    while (S >> 16) {
        S = (S & 0xffff) + (S >> 16);
    }
    return (UINT16)~S;
}

static UINT32 BuildFrame(UCHAR *F)
{
    const UINT32 Pay = 32;
    const UINT32 IpLen = 20 + 8 + Pay;
    UCHAR *Ip = F + 14;
    UCHAR *Udp = Ip + 20;
    UINT16 C;

    memset(F, 0, 14 + IpLen);
    memcpy(F, LocalMac, 6);
    memcpy(F + 6, PeerMac, 6);
    F[12] = 0x08;
    F[13] = 0x00;
    Ip[0] = 0x45;
    Ip[2] = (UCHAR)(IpLen >> 8);
    Ip[3] = (UCHAR)IpLen;
    Ip[8] = 64;
    Ip[9] = 17;
    memcpy(Ip + 12, &PeerIp, 4);
    memcpy(Ip + 16, &LocalIp, 4);
    C = Csum(Ip, 20);
    Ip[10] = (UCHAR)(C >> 8);
    Ip[11] = (UCHAR)C;
    Udp[0] = (UCHAR)(40000 >> 8);
    Udp[1] = (UCHAR)40000;
    Udp[2] = (UCHAR)(RX_PORT >> 8);
    Udp[3] = (UCHAR)RX_PORT;
    Udp[4] = (UCHAR)((8 + Pay) >> 8);
    Udp[5] = (UCHAR)(8 + Pay);
    memcpy(Udp + 8, "RANZ-XDP-SPIKE-RX", 17); // UDP checksum 0 = none (IPv4)
    return 14 + IpLen;
}

static DWORD WINAPI RecvThread(void *Ctx)
{
    char Buf[2048];
    UNREFERENCED_PARAMETER(Ctx);
    while (!Stop) {
        if (recv(RecvSock, Buf, sizeof(Buf), 0) > 0) {
            InterlockedIncrement64(&Received);
        }
    }
    return 0;
}

static UINT32 Inject(XSKC *X, UINT32 Max, UINT32 Len, UINT64 *Submitted)
{
    UINT32 Idx, N, i;
    XSK_NOTIFY_RESULT_FLAGS Nr;

    N = XskRingProducerReserve(&X->Tx, Max, &Idx);
    for (i = 0; i < N; i++) {
        XSK_BUFFER_DESCRIPTOR *D = XskRingGetElement(&X->Tx, Idx + i);
        D->Address.AddressAndOffset = ((*Submitted + i) % NCHUNK) * CHUNK;
        D->Length = Len;
    }
    if (N > 0) {
        XskRingProducerSubmit(&X->Tx, N);
        *Submitted += N;
        if (XskRingProducerNeedPoke(&X->Tx)) {
            XskNotifySocket(X->Sock, XSK_NOTIFY_FLAG_POKE_TX, 0, &Nr);
        }
    }
    return N;
}

static UINT32 Complete(XSKC *X)
{
    UINT32 Idx, N;
    N = XskRingConsumerReserve(&X->Comp, RING, &Idx);
    if (N > 0) {
        XskRingConsumerRelease(&X->Comp, N);
    }
    return N;
}

//
// Injects 5 frames (and, if Flood, keeps the TX ring full for Seconds) and
// counts what a UDP socket on LocalIp:RX_PORT receives. Observe, if non-NULL,
// is an RX XSK drained in parallel (eBPF redirect target).
//
static int RxInject(const char *Tag, BOOL Flood, XSKC *Observe, LONG64 *SingleOut)
{
    XSKC X = {0};
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INJECT};
    SOCKADDR_IN A = {0};
    int RcvBuf = 16 << 20;
    DWORD Timeout = 200;
    HANDLE Th;
    UINT32 Len, i, Dumped = 0;
    UINT64 Submitted = 0, Completed = 0, Spin = 0;
    LONG64 Single, FloodRx;
    double T0, T1, End;
    XSK_NOTIFY_RESULT_FLAGS Nr;
    TXCOUNT Seen = {0};

    Log("== %s: hook {L2, RX, INJECT}, generic, queue 0\n", Tag);
    *SingleOut = 0;

    RecvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    A.sin_family = AF_INET;
    A.sin_addr = LocalIp;
    A.sin_port = htons(RX_PORT);
    if (bind(RecvSock, (SOCKADDR *)&A, sizeof(A)) != 0) {
        Log("ERR recv bind: %d\n", WSAGetLastError());
        Log("RESULT %s FAIL reason=udp-bind\n", Tag);
        closesocket(RecvSock);
        return 1;
    }
    setsockopt(RecvSock, SOL_SOCKET, SO_RCVBUF, (char *)&RcvBuf, sizeof(RcvBuf));
    setsockopt(RecvSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));

    if (FAILED(XskOpen(&X, FALSE, Hook))) {
        Log("RESULT %s FAIL reason=xsk-setup\n", Tag);
        XskClose(&X);
        closesocket(RecvSock);
        return 1;
    }

    Len = BuildFrame(X.Umem);
    for (i = 1; i < NCHUNK; i++) {
        memcpy(X.Umem + (SIZE_T)i * CHUNK, X.Umem, Len);
    }
    Hex("rx-inject frame", X.Umem, Len);

    Stop = 0;
    Received = 0;
    Th = CreateThread(NULL, 0, RecvThread, NULL, 0, NULL);

    for (i = 0; i < 5; i++) {
        Inject(&X, 1, Len, &Submitted);
        XskNotifySocket(X.Sock, XSK_NOTIFY_FLAG_POKE_TX, 0, &Nr);
        Sleep(200);
        Completed += Complete(&X);
        if (Observe != NULL) {
            while (DrainRx(Observe, &Seen, &Dumped, "ebpf-rx-inspect frame (during inject)") != 0) {
            }
        }
    }
    Sleep(500);
    Completed += Complete(&X);
    if (Observe != NULL) {
        while (DrainRx(Observe, &Seen, &Dumped, "ebpf-rx-inspect frame (during inject)") != 0) {
        }
    }
    Single = Received;
    *SingleOut = Single;
    Log("%s phase1: injected=%llu completed=%llu udp_received=%lld xsk_seen=%llu\n",
        Tag, Submitted, Completed, Single, Seen.Frames);

    FloodRx = 0;
    if (Flood) {
        Received = 0;
        Submitted = Completed = 0;
        T0 = Now();
        End = T0 + Seconds;
        for (;;) {
            UINT64 Free = RING - (Submitted - Completed);
            if (Free > 0) {
                Inject(&X, (UINT32)(Free < BATCH ? Free : BATCH), Len, &Submitted);
            }
            Completed += Complete(&X);
            if ((++Spin & 0xff) == 0 && Now() >= End) {
                break;
            }
        }
        T1 = Now();
        Sleep(500);
        Completed += Complete(&X);
        FloodRx = Received;
        Log("%s phase2: secs=%.2f submitted=%llu completed=%llu udp_received=%lld\n",
            Tag, T1 - T0, Submitted, Completed, FloodRx);
        Log("PPS %s injected=%.0f delivered_to_socket=%.0f\n",
            Tag, Completed / (T1 - T0), FloodRx / (T1 - T0));
    }
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);

    if (Single > 0) {
        Log("RESULT %s PASS udp_received=%lld of 5\n", Tag, Single);
    } else if (FloodRx > 0) {
        Log("RESULT %s PASS-FLOOD-ONLY udp_received=%lld\n", Tag, FloodRx);
    } else {
        Log("RESULT %s FAIL reason=no-delivery completed=%llu xsk_seen=%llu\n", Tag, Completed, Seen.Frames);
    }

    XskClose(&X);
    closesocket(RecvSock);
    return (Single > 0 || FloodRx > 0) ? 0 : 1;
}

//
// Tests
//

static int TestEbpfTxInspect(void)
{
    XSKC X = {0};
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
    TXCOUNT C1 = {0}, C2 = {0};
    UINT64 S0[4], S1[4];
    LONG64 Sent1;
    int MapRc;

    Log("== EBPF_TX_INSPECT: XSK on {L2, TX, INSPECT}, eBPF program via bpf_xdp_attach\n");
    if (FAILED(XskOpen(&X, TRUE, Hook))) {
        Log("RESULT EBPF_TX_INSPECT FAIL reason=xsk-setup\n");
        XskClose(&X);
        return 1;
    }
    MapRc = MapPut(X.Sock);
    if (EbpfAttach() != 0) {
        Log("RESULT EBPF_ATTACH FAIL errno=%d\n", errno);
        Log("RESULT EBPF_TX_INSPECT FAIL reason=attach\n");
        XskClose(&X);
        return 1;
    }
    Log("RESULT EBPF_ATTACH PASS (bpf_xdp_attach on the KM-TEST adapter)\n");

    ReadStats(S0);
    Capture(&X, "EBPF_TX_INSPECT", &C1, &C2, &Sent1);
    ReadStats(S1);
    LogStatsDelta("EBPF_TX_INSPECT", S0, S1);

    if (C1.Udp + C2.Udp > 0) {
        Log("RESULT EBPF_TX_INSPECT PASS udp_frames=%llu (OS-sent UDP reached the XSK via eBPF)\n",
            C1.Udp + C2.Udp);
    } else {
        Log("RESULT EBPF_TX_INSPECT FAIL reason=no-frames map_update_rc=%d os_sent=%lld xsk_frames=%llu "
            "ebpf_hook_seen_udp%d=%llu (the XDP eBPF hook is {L2, RX, INSPECT} only; "
            "nothing runs the program on the TX path)\n",
            MapRc, Sent1, C1.Frames + C2.Frames, TX_PORT, S1[1] - S0[1]);
    }
    if (MapRc == 0) {
        MapDel();
    }
    XskClose(&X);
    return (C1.Udp + C2.Udp > 0) ? 0 : 1;
}

static int TestEbpfRxInspect(void)
{
    XSKC X = {0};
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INSPECT};
    TXCOUNT C1 = {0}, C2 = {0};
    UINT64 S0[4], S1[4], S2[4];
    LONG64 Sent1, Inj;
    double Pps;

    Log("== EBPF_RX_INSPECT: XSK on {L2, RX, INSPECT} (the eBPF hook), same program\n");
    if (FAILED(XskOpen(&X, TRUE, Hook))) {
        Log("RESULT EBPF_RX_INSPECT FAIL reason=xsk-setup\n");
        XskClose(&X);
        return 1;
    }
    MapPut(X.Sock);

    ReadStats(S0);
    Pps = Capture(&X, "EBPF_RX_INSPECT", &C1, &C2, &Sent1);
    ReadStats(S1);
    LogStatsDelta("EBPF_RX_INSPECT(os-sent)", S0, S1);
    if (C1.Udp + C2.Udp > 0) {
        Log("RESULT EBPF_RX_INSPECT_SEES_OS_TX YES udp_frames=%llu pps=%.0f (KM-TEST loops sends back to RX)\n",
            C1.Udp + C2.Udp, Pps);
    } else {
        Log("RESULT EBPF_RX_INSPECT_SEES_OS_TX NO xsk_udp=0 ebpf_hook_seen_udp%d=%llu "
            "(KM-TEST does not loop sends back to its RX path)\n", TX_PORT, S1[1] - S0[1]);
    }

    //
    // Does the RX-inspect program see frames injected with {L2, RX, INJECT}?
    // If it did, a redirect-all program would steal them from TCPIP.
    //
    RxInject("RX_INJECT_WITH_EBPF", FALSE, &X, &Inj);
    ReadStats(S2);
    LogStatsDelta("EBPF_RX_INSPECT(injected)", S1, S2);
    Log("RESULT EBPF_SEES_RX_INJECT %s ebpf_hook_seen_udp%d=%llu udp_socket_got=%lld of 5\n",
        (S2[2] - S1[2]) > 0 ? "YES" : "NO", RX_PORT, S2[2] - S1[2], Inj);

    MapDel();
    XskClose(&X);
    return 0;
}

static int TestRuleTxInspect(const char *Tag)
{
    HRESULT Hr;
    XSKC X = {0};
    HANDLE Prog = NULL;
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
    XDP_RULE Rule = {0};
    TXCOUNT C1 = {0}, C2 = {0};
    UINT64 S0[4], S1[4];
    LONG64 Sent1;

    Log("== %s: deprecated XDP_RULE redirect on {L2, TX, INSPECT}, eBPF attached=%d\n", Tag, Attached);
    if (FAILED(XskOpen(&X, TRUE, Hook))) {
        Log("RESULT %s FAIL reason=xsk-setup\n", Tag);
        XskClose(&X);
        return 1;
    }
    Rule.Match = XDP_MATCH_ALL;
    Rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    Rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    Rule.Redirect.Target = X.Sock;
    Hr = XdpCreateProgram(IfIndex, &Hook, 0, XDP_CREATE_PROGRAM_FLAG_GENERIC, &Rule, 1, &Prog);
    if (FAILED(Hr)) {
        Log("RESULT %s FAIL reason=program-attach hr=0x%08lx\n", Tag, (unsigned long)Hr);
        XskClose(&X);
        return 1;
    }
    ReadStats(S0);
    Capture(&X, Tag, &C1, &C2, &Sent1);
    ReadStats(S1);
    if (StatsFd >= 0) {
        LogStatsDelta(Tag, S0, S1);
    }
    if (C1.Udp > 0) {
        Log("RESULT %s PASS udp_frames=%llu of %lld sent (phase 1)\n", Tag, C1.Udp, Sent1);
    } else {
        Log("RESULT %s FAIL reason=no-frames frames=%llu\n", Tag, C1.Frames);
    }
    CloseHandle(Prog);
    XskClose(&X);
    return C1.Udp > 0 ? 0 : 1;
}

int __cdecl main(int argc, char **argv)
{
    WSADATA Wsa;
    int Rc = 0;
    LONG64 Dummy;

    if (argc < 6) {
        Log("usage: xdpebpf.exe <IfIndex> <LocalIPv4> <PeerIPv4> <Seconds> <ranz_xsk.sys>\n");
        return 2;
    }
    QueryPerformanceFrequency(&Freq);
    WSAStartup(MAKEWORD(2, 2), &Wsa);

    IfIndex = (UINT32)atoi(argv[1]);
    inet_pton(AF_INET, argv[2], &LocalIp);
    inet_pton(AF_INET, argv[3], &PeerIp);
    Seconds = (DWORD)atoi(argv[4]);

    if (!GetMac()) {
        Log("RESULT SETUP FAIL reason=no-adapter IfIndex=%u\n", IfIndex);
        return 2;
    }
    Log("IfIndex=%u mac=%02x-%02x-%02x-%02x-%02x-%02x local=%s peer=%s secs=%lu\n",
        IfIndex, LocalMac[0], LocalMac[1], LocalMac[2], LocalMac[3], LocalMac[4], LocalMac[5],
        argv[2], argv[3], Seconds);

    if (TestEbpfLoad(argv[5]) == 0) {
        Rc |= TestEbpfTxInspect();
        if (Attached) {
            Rc |= TestEbpfRxInspect() << 1;
            Rc |= TestRuleTxInspect("RULE_TX_INSPECT_WITH_EBPF") << 2;
        }
        EbpfDetach();
    } else {
        Rc |= 1;
        Rc |= TestRuleTxInspect("RULE_TX_INSPECT") << 2;
    }
    Rc |= RxInject("RX_INJECT", TRUE, NULL, &Dummy) << 3;

    if (Obj != NULL) {
        bpf_object__close(Obj);
    }
    WSACleanup();
    return Rc;
}
