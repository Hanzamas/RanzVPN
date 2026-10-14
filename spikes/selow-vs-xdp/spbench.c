//
// SeLow vs XDP benchmark on one Microsoft KM-TEST Loopback Adapter.
// Spike code (branch spike/selow-vs-xdp), never merged.
//
//   tx  The OS sends IPv4/UDP out of the adapter. A Winsock load generator
//       (N threads, plain send() or UDP Segmentation Offload) produces the
//       traffic, and one backend thread reads the frames in user mode:
//         xdp    AF_XDP RX socket on hook {L2, TX, INSPECT} + redirect-all
//         selow  SeLow adapter device, ReadFile of SL exchange buffers
//   rx  One backend thread writes IPv4/UDP frames (dst MAC = adapter MAC)
//       that the OS stack must receive. UDP sockets on the adapter IP count
//       what TCPIP delivers:
//         xdp    AF_XDP TX socket on hook {L2, RX, INJECT}
//         selow  SeLow adapter device, WriteFile of SL exchange buffers
//   list  Print the adapters SeLow has bound (selow only).
//
// Both backends get a 4096-frame buffer: XSK rings of 4096, and SeLow's
// fixed SL_MAX_PACKET_QUEUED (receive) and pending-send limit of 4096.
//
// Usage:
//   spbench -b xdp|selow -d tx|rx|list -i IfIndex [-l FrameLen] [-s Secs]
//           [-g sendto|uso] [-t Threads (0 = one per logical CPU)] [-p]
//           [-r Receivers] [-w WarmupMs] [-a LocalIPv4] [-e PeerIPv4]
//
// Prints one "BENCH k=v ..." line per measurement, or "BENCH_FAIL ...".
//

#include <xdpapi.h>
#include <afxdp_helper.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SeLowCommon.h"

#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif

#define TX_PORT 5555 // OS -> peer, captured by the backend
#define RX_PORT 5556 // injected peer -> OS, received by UDP sockets
#define CHUNK 2048
#define RING 4096 // XSK ring size, power of two
#define NCHUNK RING
#define BATCH 256
#define MAX_GEN 64
#define MAX_CAP 8
#define USO_MAX_BYTES 65000
#define USO_MAX_SEGS 256
#define HDR 42 // Ethernet 14 + IPv4 20 + UDP 8

static const UCHAR PeerMac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};

typedef struct DECLSPEC_ALIGN(64) _TSTAT {
    volatile LONG64 Calls;
    volatile LONG64 Dgrams;
    volatile LONG64 Bytes;
    volatile LONG64 Other;
    volatile LONG64 Dups;
    volatile LONG64 Errors;
    HANDLE Thread;
    int Index;
    int Segs;
    int Uso;
    int LastErr;
} TSTAT;

typedef struct _LOCAL {
    LONG64 Dgrams;
    LONG64 Bytes;
    LONG64 Other;
    LONG64 Dups;
} LOCAL;

typedef struct _XSKC {
    HANDLE Sock;
    UCHAR *Umem;
    XSK_RING Rx;
    XSK_RING Fill;
    XSK_RING Tx;
    XSK_RING Comp;
} XSKC;

typedef struct _SNAP {
    double T;
    ULONGLONG SysBusy, SysAll, Proc, GenCpu, CapCpu;
    LONG64 GenCalls, GenDgrams, GenErrors, CapDgrams, CapBytes, CapOther, CapDups;
} SNAP;

static TSTAT Gen[MAX_GEN];
static TSTAT Cap[MAX_CAP];
static int NGen, NCap;

static UINT32 IfIndex;
static IN_ADDR LocalIp, PeerIp;
static UCHAR LocalMac[6];
static UINT32 FrameLen = 64;
static UINT32 Payload;
static DWORD Seconds = 5, WarmupMs = 500;
static int Threads = 1, Receivers = 2, Pin = 0, NCpu = 1;
static const char *Backend = "xdp", *Dir = "tx", *GenMode = "sendto";
static volatile LONG Stop;
static LARGE_INTEGER Freq;
static SOCKET RecvSock[MAX_CAP];
static UCHAR Template[MAX_CAP][CHUNK];

static HANDLE SlBasic = INVALID_HANDLE_VALUE;
static HANDLE SlFile = INVALID_HANDLE_VALUE;
static HANDLE SlEvent;
static UCHAR *SlGet, *SlPut;

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

static void Fail(const char *Reason)
{
    Log("BENCH_FAIL backend=%s dir=%s len=%u gen=%s threads=%d reason=%s\n",
        Backend, Dir, FrameLen, GenMode, Threads, Reason);
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
            free(All);
            return TRUE;
        }
    }
    free(All);
    return FALSE;
}

//
// CPU accounting: system-wide busy time, this process, and per thread.
//

static ULONGLONG Ft(const FILETIME *F)
{
    return ((ULONGLONG)F->dwHighDateTime << 32) | F->dwLowDateTime;
}

static ULONGLONG ThreadCpu(HANDLE H)
{
    FILETIME C, E, K, U;
    if (H == NULL || !GetThreadTimes(H, &C, &E, &K, &U)) {
        return 0;
    }
    return Ft(&K) + Ft(&U);
}

static void Snap(SNAP *S)
{
    FILETIME I, K, U, C, E;
    int i;

    memset(S, 0, sizeof(*S));
    GetSystemTimes(&I, &K, &U);
    S->SysAll = Ft(&K) + Ft(&U); // kernel time includes idle time
    S->SysBusy = S->SysAll - Ft(&I);
    if (GetProcessTimes(GetCurrentProcess(), &C, &E, &K, &U)) {
        S->Proc = Ft(&K) + Ft(&U);
    }
    for (i = 0; i < NGen; i++) {
        S->GenCpu += ThreadCpu(Gen[i].Thread);
        S->GenCalls += Gen[i].Calls;
        S->GenDgrams += Gen[i].Dgrams;
        S->GenErrors += Gen[i].Errors;
    }
    for (i = 0; i < NCap; i++) {
        S->CapCpu += ThreadCpu(Cap[i].Thread);
        S->CapDgrams += Cap[i].Dgrams;
        S->CapBytes += Cap[i].Bytes;
        S->CapOther += Cap[i].Other;
        S->CapDups += Cap[i].Dups;
    }
    S->T = Now();
}

static void Measure(SNAP *A, SNAP *B)
{
    Sleep(WarmupMs);
    Snap(A);
    Sleep(Seconds * 1000);
    Snap(B);
}

static void Report(const SNAP *A, const SNAP *B, const char *Mode, int NThreads, const char *Extra)
{
    double Dt = B->T - A->T;
    double W = Dt * 1e7;
    double GenPps = (double)(B->GenDgrams - A->GenDgrams) / Dt;
    double GenCps = (double)(B->GenCalls - A->GenCalls) / Dt;
    double Pps = (double)(B->CapDgrams - A->CapDgrams) / Dt;
    double Mbps = (double)(B->CapBytes - A->CapBytes) * 8.0 / Dt / 1e6;
    double OtherPs = (double)(B->CapOther - A->CapOther) / Dt;
    double Sys = (double)(B->SysBusy - A->SysBusy) / W;
    double SysAll = (double)(B->SysAll - A->SysAll);
    double SysPct = SysAll > 0 ? 100.0 * (double)(B->SysBusy - A->SysBusy) / SysAll : 0;
    double GenC = (double)(B->GenCpu - A->GenCpu) / W;
    double CapC = (double)(B->CapCpu - A->CapCpu) / W;
    double ProcC = (double)(B->Proc - A->Proc) / W;
    double Loss = GenPps > 0 ? 100.0 * (1.0 - Pps / GenPps) : 0;
    double Cpm = Pps > 0 ? Sys / (Pps / 1e6) : 0;

    Log("BENCH backend=%s dir=%s len=%u gen=%s threads=%d pin=%d secs=%.2f "
        "gen_calls_ps=%.0f gen_pps=%.0f pps=%.0f mbps=%.1f loss_pct=%.2f other_ps=%.0f "
        "dups=%lld gen_errors=%lld cpu_sys=%.2f cpu_sys_pct=%.1f cpu_gen=%.2f cpu_cap=%.2f "
        "cpu_proc=%.2f cores_per_mpps=%.2f ncpu=%d %s\n",
        Backend, Dir, FrameLen, Mode, NThreads, Pin, Dt,
        GenCps, GenPps, Pps, Mbps, Loss, OtherPs,
        B->CapDups, B->GenErrors - A->GenErrors, Sys, SysPct, GenC, CapC,
        ProcC, Cpm, NCpu, Extra);
}

static DWORD WINAPI Watchdog(void *Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    Sleep(WarmupMs + Seconds * 1000 + 30000);
    Fail("watchdog");
    ExitProcess(9);
}

//
// Frames
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

// IPv4/UDP frame of FrameLen bytes (no FCS), peer -> local, to DstPort.
// The payload starts with an 8-byte sequence number. UDP checksum 0 (none).
static void BuildFrame(UCHAR *F, UINT16 DstPort)
{
    UINT32 IpLen = FrameLen - 14;
    UCHAR *Ip = F + 14;
    UCHAR *Udp = Ip + 20;
    UINT16 C;

    memset(F, 0, FrameLen);
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
    Udp[0] = 0x9c; // source port 40000
    Udp[1] = 0x40;
    Udp[2] = (UCHAR)(DstPort >> 8);
    Udp[3] = (UCHAR)DstPort;
    Udp[4] = (UCHAR)((IpLen - 20) >> 8);
    Udp[5] = (UCHAR)(IpLen - 20);
}

static void SetSeq(UCHAR *F, UINT64 Seq)
{
    memcpy(F + HDR, &Seq, 8);
}

// TX capture: count the generator's UDP frames, detect duplicates and
// reordering per sender thread (sequence = n << 6 | thread, n from 1).
static void CountTx(const UCHAR *F, UINT32 Len, LOCAL *L, UINT64 *Last)
{
    if (Len >= HDR + 8 && F[12] == 0x08 && F[13] == 0x00 && F[14] == 0x45 && F[23] == 17 &&
        F[36] == (TX_PORT >> 8) && F[37] == (TX_PORT & 0xff)) {
        UINT64 Seq, N;
        UINT32 T;
        memcpy(&Seq, F + HDR, 8);
        T = (UINT32)(Seq & 63);
        N = Seq >> 6;
        if (N <= Last[T]) {
            L->Dups++;
        } else {
            Last[T] = N;
        }
        L->Dgrams++;
        L->Bytes += Len;
    } else {
        L->Other++;
    }
}

static void Publish(TSTAT *S, const LOCAL *L)
{
    S->Dgrams = L->Dgrams;
    S->Bytes = L->Bytes;
    S->Other = L->Other;
    S->Dups = L->Dups;
}

//
// XDP backend
//

#define CHK(What) \
    if (FAILED(Hr)) { Log("ERR %s: 0x%08lx\n", What, (unsigned long)Hr); return Hr; }

static HRESULT XskOpenOnce(XSKC *X, BOOL Rx, XDP_HOOK_ID Hook)
{
    HRESULT Hr;
    XSK_UMEM_REG Umem = {0};
    UINT32 Ring = RING;
    XSK_RING_INFO_SET Info;
    UINT32 Len = sizeof(Info);

    if (X->Umem == NULL) {
        X->Umem = VirtualAlloc(NULL, (SIZE_T)CHUNK * NCHUNK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (X->Umem == NULL) {
            Log("ERR VirtualAlloc\n");
            return E_OUTOFMEMORY;
        }
    }

    Hr = XskCreate(&X->Sock);
    CHK("XskCreate");

    Umem.TotalSize = (UINT64)CHUNK * NCHUNK;
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
        XskRingInitialize(&X->Rx, &Info.Rx);
        XskRingInitialize(&X->Fill, &Info.Fill);
    } else {
        XskRingInitialize(&X->Tx, &Info.Tx);
        XskRingInitialize(&X->Comp, &Info.Completion);
    }
    return S_OK;
}

// Retries for up to 10 s: the ms_xdp binding may just have been re-enabled.
static HRESULT XskOpen(XSKC *X, BOOL Rx, XDP_HOOK_ID Hook)
{
    HRESULT Hr = E_FAIL;
    int Try;
    for (Try = 0; Try < 20; Try++) {
        Hr = XskOpenOnce(X, Rx, Hook);
        if (SUCCEEDED(Hr)) {
            return Hr;
        }
        if (X->Sock != NULL) {
            CloseHandle(X->Sock);
            X->Sock = NULL;
        }
        Sleep(500);
    }
    return Hr;
}

static void XskClose(XSKC *X)
{
    if (X->Sock != NULL) {
        CloseHandle(X->Sock);
    }
    if (X->Umem != NULL) {
        VirtualFree(X->Umem, 0, MEM_RELEASE);
    }
}

static DWORD WINAPI XdpCapThread(void *Ctx)
{
    XSKC *X = Ctx;
    TSTAT *S = &Cap[0];
    LOCAL L = {0};
    UINT64 Last[64] = {0};
    UINT64 Bases[BATCH];

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    while (!Stop) {
        UINT32 Idx, FIdx, N, i;
        XSK_NOTIFY_RESULT_FLAGS Nr;

        N = XskRingConsumerReserve(&X->Rx, BATCH, &Idx);
        if (N == 0) {
            XSK_NOTIFY_FLAGS F = XSK_NOTIFY_FLAG_WAIT_RX;
            if (XskRingProducerNeedPoke(&X->Fill)) {
                F = (XSK_NOTIFY_FLAGS)(F | XSK_NOTIFY_FLAG_POKE_RX);
            }
            XskNotifySocket(X->Sock, F, 10, &Nr);
            S->Calls++;
            continue;
        }
        for (i = 0; i < N; i++) {
            XSK_BUFFER_DESCRIPTOR *D = XskRingGetElement(&X->Rx, Idx + i);
            CountTx(X->Umem + D->Address.BaseAddress + D->Address.Offset, D->Length, &L, Last);
            Bases[i] = D->Address.BaseAddress;
        }
        XskRingConsumerRelease(&X->Rx, N);
        if (XskRingProducerReserve(&X->Fill, N, &FIdx) == N) {
            for (i = 0; i < N; i++) {
                *(UINT64 *)XskRingGetElement(&X->Fill, FIdx + i) = Bases[i];
            }
            XskRingProducerSubmit(&X->Fill, N);
        } else {
            S->Errors++;
        }
        if (XskRingProducerNeedPoke(&X->Fill)) {
            XskNotifySocket(X->Sock, XSK_NOTIFY_FLAG_POKE_RX, 0, &Nr);
        }
        Publish(S, &L);
    }
    Publish(S, &L);
    return 0;
}

static int XdpTxOpen(XSKC *X, HANDLE *Prog)
{
    HRESULT Hr;
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
    XDP_RULE Rule = {0};
    UINT32 Idx, N, i;

    if (FAILED(XskOpen(X, TRUE, Hook))) {
        Fail("xsk-setup");
        return 1;
    }
    N = XskRingProducerReserve(&X->Fill, RING, &Idx);
    for (i = 0; i < N; i++) {
        *(UINT64 *)XskRingGetElement(&X->Fill, Idx + i) = (UINT64)i * CHUNK;
    }
    XskRingProducerSubmit(&X->Fill, N);

    Rule.Match = XDP_MATCH_ALL;
    Rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    Rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    Rule.Redirect.Target = X->Sock;
    Hr = XdpCreateProgram(IfIndex, &Hook, 0, XDP_CREATE_PROGRAM_FLAG_GENERIC, &Rule, 1, Prog);
    if (FAILED(Hr)) {
        Log("ERR XdpCreateProgram(TX inspect): 0x%08lx\n", (unsigned long)Hr);
        Fail("program-attach");
        return 1;
    }
    return 0;
}

static DWORD WINAPI XdpInjectThread(void *Ctx)
{
    XSKC *X = Ctx;
    TSTAT *S = &Gen[0];
    UINT64 Submitted = 0, Completed = 0;

    while (!Stop) {
        UINT32 Free = RING - (UINT32)(Submitted - Completed);
        UINT32 Idx, N = 0, C, i;
        XSK_NOTIFY_RESULT_FLAGS Nr;

        if (Free > 0) {
            N = XskRingProducerReserve(&X->Tx, Free < BATCH ? Free : BATCH, &Idx);
            for (i = 0; i < N; i++) {
                XSK_BUFFER_DESCRIPTOR *D = XskRingGetElement(&X->Tx, Idx + i);
                UINT64 K = Submitted + i;
                UINT64 Off = (K % NCHUNK) * CHUNK;
                SetSeq(X->Umem + Off, K + 1);
                D->Address.AddressAndOffset = Off;
                D->Length = FrameLen;
            }
            if (N > 0) {
                XskRingProducerSubmit(&X->Tx, N);
                Submitted += N;
                S->Calls++;
                if (XskRingProducerNeedPoke(&X->Tx)) {
                    XskNotifySocket(X->Sock, XSK_NOTIFY_FLAG_POKE_TX, 0, &Nr);
                }
            }
        }
        C = XskRingConsumerReserve(&X->Comp, RING, &Idx);
        if (C > 0) {
            XskRingConsumerRelease(&X->Comp, C);
            Completed += C;
            S->Dgrams = (LONG64)Completed;
        }
        if (N == 0 && C == 0) {
            XSK_NOTIFY_FLAGS F = XSK_NOTIFY_FLAG_WAIT_TX;
            if (XskRingProducerNeedPoke(&X->Tx)) {
                F = (XSK_NOTIFY_FLAGS)(F | XSK_NOTIFY_FLAG_POKE_TX);
            }
            XskNotifySocket(X->Sock, F, 10, &Nr);
        }
    }
    return 0;
}

//
// SeLow backend (same device protocol as src/Cedar/SeLowUser.c)
//

static int SelowOpen(BOOL ListOnly)
{
    SL_ADAPTER_INFO_LIST *L;
    WCHAR Id[SL_ADAPTER_ID_LEN + 1] = {0};
    WCHAR Path[MAX_PATH];
    SL_IOCTL_EVENT_NAME En;
    DWORD Got;
    double End = Now() + 30.0;
    DWORD LastErr = 0;
    BOOL Printed = FALSE;
    UINT32 i;

    L = VirtualAlloc(NULL, sizeof(*L), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (L == NULL) {
        Fail("alloc");
        return 1;
    }
    for (;;) {
        if (SlBasic == INVALID_HANDLE_VALUE) {
            SlBasic = CreateFileA(SL_BASIC_DEVICE_FILENAME_WIN32, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (SlBasic == INVALID_HANDLE_VALUE && GetLastError() != LastErr) {
                LastErr = GetLastError();
                Log("selow: open %s failed: %lu\n", SL_BASIC_DEVICE_FILENAME_WIN32, LastErr);
            }
        }
        if (SlBasic != INVALID_HANDLE_VALUE) {
            memset(L, 0, sizeof(*L));
            Got = 0;
            if (ReadFile(SlBasic, L, sizeof(*L), &Got, NULL) && L->Signature == SL_SIGNATURE) {
                for (i = 0; i < L->NumAdapters && i < SL_MAX_ADAPTER_INFO_LIST_ENTRY; i++) {
                    if (memcmp(L->Adapters[i].MacAddress, LocalMac, 6) == 0) {
                        memcpy(Id, L->Adapters[i].AdapterId, sizeof(L->Adapters[i].AdapterId));
                    }
                }
                if (ListOnly || Id[0] != 0 || !Printed) {
                    Log("selow: driver SL_VER=%u (header %u) enum=%u adapters=%u\n",
                        L->SeLowVersion, SL_VER, L->EnumCompleted, L->NumAdapters);
                    for (i = 0; i < L->NumAdapters && i < SL_MAX_ADAPTER_INFO_LIST_ENTRY; i++) {
                        const UCHAR *M = L->Adapters[i].MacAddress;
                        Log("selow: adapter %u id=%.64ls mac=%02x-%02x-%02x-%02x-%02x-%02x mtu=%u vlanhw=%u name=%.255s\n",
                            i, L->Adapters[i].AdapterId, M[0], M[1], M[2], M[3], M[4], M[5],
                            L->Adapters[i].MtuSize, L->Adapters[i].SupportsVLanHw, L->Adapters[i].FriendlyName);
                    }
                    Printed = TRUE;
                }
            } else {
                Log("selow: adapter list read failed: %lu sig=0x%08x\n", GetLastError(), L->Signature);
            }
        }
        if (Id[0] != 0 || Now() > End) {
            break;
        }
        Sleep(500);
    }
    VirtualFree(L, 0, MEM_RELEASE);
    if (Id[0] == 0) {
        Fail(SlBasic == INVALID_HANDLE_VALUE ? "selow-no-device" : "selow-adapter-not-bound");
        return 1;
    }
    Log("selow: KM-TEST adapter is %ls\n", Id);
    if (ListOnly) {
        return 0;
    }

    _snwprintf(Path, MAX_PATH, L"\\\\.\\%ls", Id);
    End = Now() + 15.0;
    do {
        SlFile = CreateFileW(Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (SlFile == INVALID_HANDLE_VALUE) {
            LastErr = GetLastError();
            Sleep(500);
        }
    } while (SlFile == INVALID_HANDLE_VALUE && Now() < End);
    if (SlFile == INVALID_HANDLE_VALUE) {
        Log("selow: open %ls failed: %lu\n", Path, LastErr);
        Fail("selow-adapter-open");
        return 1;
    }
    memset(&En, 0, sizeof(En));
    if (!DeviceIoControl(SlFile, SL_IOCTL_GET_EVENT_NAME, &En, sizeof(En), &En, sizeof(En), &Got, NULL)) {
        Log("selow: SL_IOCTL_GET_EVENT_NAME failed: %lu\n", GetLastError());
        Fail("selow-ioctl");
        return 1;
    }
    En.EventNameWin32[SL_EVENT_NAME_SIZE - 1] = 0;
    SlEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, En.EventNameWin32);
    if (SlEvent == NULL) {
        Log("selow: OpenEvent(%s) failed: %lu\n", En.EventNameWin32, GetLastError());
        Fail("selow-event");
        return 1;
    }
    SlGet = VirtualAlloc(NULL, SL_EXCHANGE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    SlPut = VirtualAlloc(NULL, SL_EXCHANGE_BUFFER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (SlGet == NULL || SlPut == NULL) {
        Fail("alloc");
        return 1;
    }
    Log("selow: opened %ls event=%s exchange=%u bytes\n", Path, En.EventNameWin32, (UINT32)SL_EXCHANGE_BUFFER_SIZE);
    return 0;
}

static void SelowClose(void)
{
    if (SlEvent != NULL) {
        CloseHandle(SlEvent);
    }
    if (SlFile != INVALID_HANDLE_VALUE) {
        CloseHandle(SlFile);
    }
    if (SlBasic != INVALID_HANDLE_VALUE) {
        CloseHandle(SlBasic);
    }
}

static DWORD WINAPI SelowCapThread(void *Ctx)
{
    TSTAT *S = &Cap[0];
    LOCAL L = {0};
    UINT64 Last[64] = {0};
    UNREFERENCED_PARAMETER(Ctx);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    while (!Stop) {
        DWORD Got = 0;
        UINT32 N, i;

        if (!ReadFile(SlFile, SlGet, SL_EXCHANGE_BUFFER_SIZE, &Got, NULL)) {
            S->Errors++;
            S->LastErr = (int)GetLastError();
            Sleep(10);
            continue;
        }
        S->Calls++;
        N = SL_NUM_PACKET(SlGet);
        if (N > SL_MAX_PACKET_EXCHANGE) {
            N = 0;
        }
        for (i = 0; i < N; i++) {
            UINT32 Sz = SL_SIZE_OF_PACKET(SlGet, i);
            if (Sz <= SL_EX_SIZEOF_ONE_PACKET) {
                CountTx((UCHAR *)SL_ADDR_OF_PACKET(SlGet, i), Sz, &L, Last);
            }
        }
        Publish(S, &L);
        if (N == 0) {
            WaitForSingleObject(SlEvent, 10);
        }
    }
    Publish(S, &L);
    return 0;
}

static DWORD WINAPI SelowInjectThread(void *Ctx)
{
    TSTAT *S = &Gen[0];
    UINT64 K = 0;
    UINT32 i;
    UNREFERENCED_PARAMETER(Ctx);

    while (!Stop) {
        DWORD W = 0;
        for (i = 0; i < SL_MAX_PACKET_EXCHANGE; i++) {
            SetSeq((UCHAR *)SL_ADDR_OF_PACKET(SlPut, i), K + i + 1);
        }
        SL_NUM_PACKET(SlPut) = SL_MAX_PACKET_EXCHANGE;
        if (WriteFile(SlFile, SlPut, SL_EXCHANGE_BUFFER_SIZE, &W, NULL) && W == SL_EXCHANGE_BUFFER_SIZE) {
            K += SL_MAX_PACKET_EXCHANGE;
            S->Calls++;
            S->Dgrams = (LONG64)K;
        } else {
            S->Errors++;
            S->LastErr = (int)GetLastError();
            if (S->Errors > 1000) {
                break;
            }
            Sleep(1);
        }
    }
    return 0;
}

//
// Load generator (tx): Winsock UDP from the adapter IP to the peer.
//

static DWORD WINAPI SendThread(void *Ctx)
{
    TSTAT *S = Ctx;
    SOCKET Sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKADDR_IN Src = {0}, Dst = {0};
    int SndBuf = 4 << 20;
    UCHAR *Buf;
    UINT64 N = 1;
    int Segs = 1, k;

    if (Pin) {
        SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1 << (S->Index % NCpu));
    }
    Src.sin_family = AF_INET;
    Src.sin_addr = LocalIp;
    Dst.sin_family = AF_INET;
    Dst.sin_addr = PeerIp;
    Dst.sin_port = htons(TX_PORT);
    if (bind(Sk, (SOCKADDR *)&Src, sizeof(Src)) != 0 || connect(Sk, (SOCKADDR *)&Dst, sizeof(Dst)) != 0) {
        S->LastErr = WSAGetLastError();
        S->Errors++;
        closesocket(Sk);
        return 1;
    }
    setsockopt(Sk, SOL_SOCKET, SO_SNDBUF, (char *)&SndBuf, sizeof(SndBuf));

    if (!strcmp(GenMode, "uso")) {
        DWORD M = Payload;
        if (setsockopt(Sk, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char *)&M, sizeof(M)) == 0) {
            S->Uso = 1;
            Segs = USO_MAX_BYTES / (int)Payload;
            if (Segs > USO_MAX_SEGS) {
                Segs = USO_MAX_SEGS;
            }
        } else {
            S->LastErr = WSAGetLastError();
        }
    }
    Buf = calloc((size_t)USO_MAX_SEGS, Payload);
    if (Buf == NULL) {
        closesocket(Sk);
        return 1;
    }

    while (!Stop) {
        int R;
        for (k = 0; k < Segs; k++) {
            UINT64 Seq = ((N + k) << 6) | (UINT64)S->Index;
            memcpy(Buf + (size_t)k * Payload, &Seq, 8);
        }
        R = send(Sk, (char *)Buf, Segs * (int)Payload, 0);
        if (R > 0) {
            N += Segs;
            S->Calls++;
            S->Dgrams += Segs;
        } else {
            int E = WSAGetLastError();
            S->Errors++;
            S->LastErr = E;
            if (S->Uso && Segs > 1 && (E == WSAEMSGSIZE || E == WSAEINVAL)) {
                Segs /= 2;
            }
        }
    }
    S->Segs = Segs;
    free(Buf);
    closesocket(Sk);
    return 0;
}

//
// UDP sink (rx): one socket and one thread per destination port.
//

static DWORD WINAPI RecvThread(void *Ctx)
{
    TSTAT *S = Ctx;
    char Buf[2048];
    UINT64 Last = 0;
    LOCAL L = {0};

    while (!Stop) {
        int R = recv(RecvSock[S->Index], Buf, sizeof(Buf), 0);
        if (R >= 8) {
            UINT64 Seq;
            memcpy(&Seq, Buf, 8);
            if (Seq <= Last) {
                L.Dups++;
            } else {
                Last = Seq;
            }
            L.Dgrams++;
            L.Bytes += R + HDR;
            Publish(S, &L);
        } else if (R > 0) {
            L.Other++;
        }
    }
    Publish(S, &L);
    return 0;
}

//
// Tests
//

static void JoinAll(void)
{
    int i;
    Stop = 1;
    for (i = 0; i < NGen; i++) {
        WaitForSingleObject(Gen[i].Thread, 5000);
    }
    for (i = 0; i < NCap; i++) {
        WaitForSingleObject(Cap[i].Thread, 5000);
    }
}

static int RunTx(void)
{
    XSKC X = {0};
    HANDLE Prog = NULL;
    SNAP A, B;
    char Extra[512];
    const char *Mode = GenMode;
    int i, AllUso = 1;
    size_t Used;

    if (!strcmp(Backend, "xdp")) {
        if (XdpTxOpen(&X, &Prog) != 0) {
            XskClose(&X);
            return 1;
        }
        Cap[0].Thread = CreateThread(NULL, 0, XdpCapThread, &X, 0, NULL);
    } else {
        Cap[0].Thread = CreateThread(NULL, 0, SelowCapThread, NULL, 0, NULL);
    }
    NCap = 1;
    Sleep(100);

    for (i = 0; i < Threads; i++) {
        Gen[i].Index = i;
        Gen[i].Thread = CreateThread(NULL, 0, SendThread, &Gen[i], 0, NULL);
    }
    NGen = Threads;

    Measure(&A, &B);
    JoinAll();

    for (i = 0; i < NGen; i++) {
        AllUso &= Gen[i].Uso;
    }
    if (!strcmp(GenMode, "uso") && !AllUso) {
        Mode = "sendto-fallback";
    }
    Used = (size_t)_snprintf(Extra, sizeof(Extra), "segs=%d gen_err=%d cap_calls=%lld cap_errors=%lld",
        Gen[0].Segs, Gen[0].LastErr, Cap[0].Calls, Cap[0].Errors);
    if (Prog != NULL) {
        XSK_STATISTICS St = {0};
        UINT32 StLen = sizeof(St);
        XskGetSockopt(X.Sock, XSK_SOCKOPT_STATISTICS, &St, &StLen);
        _snprintf(Extra + Used, sizeof(Extra) - Used, " xdp_rx_dropped=%llu xdp_rx_truncated=%llu",
            St.RxDropped, St.RxTruncated);
        CloseHandle(Prog);
    }
    Extra[sizeof(Extra) - 1] = 0;
    Report(&A, &B, Mode, Threads, Extra);
    XskClose(&X);
    return B.CapDgrams > 0 ? 0 : 1;
}

static int RunRx(void)
{
    XSKC X = {0};
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INJECT};
    SNAP A, B;
    char Extra[256];
    int i;

    for (i = 0; i < Receivers; i++) {
        SOCKADDR_IN Addr = {0};
        int Rcv = 16 << 20;
        DWORD To = 100;
        RecvSock[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        Addr.sin_family = AF_INET;
        Addr.sin_addr = LocalIp;
        Addr.sin_port = htons((u_short)(RX_PORT + i));
        if (bind(RecvSock[i], (SOCKADDR *)&Addr, sizeof(Addr)) != 0) {
            Log("ERR recv bind port %d: %d\n", RX_PORT + i, WSAGetLastError());
            Fail("udp-bind");
            return 1;
        }
        setsockopt(RecvSock[i], SOL_SOCKET, SO_RCVBUF, (char *)&Rcv, sizeof(Rcv));
        setsockopt(RecvSock[i], SOL_SOCKET, SO_RCVTIMEO, (char *)&To, sizeof(To));
        BuildFrame(Template[i], (UINT16)(RX_PORT + i));
    }
    for (i = 0; i < Receivers; i++) {
        Cap[i].Index = i;
        Cap[i].Thread = CreateThread(NULL, 0, RecvThread, &Cap[i], 0, NULL);
    }
    NCap = Receivers;

    if (!strcmp(Backend, "xdp")) {
        if (FAILED(XskOpen(&X, FALSE, Hook))) {
            Fail("xsk-setup");
            JoinAll();
            XskClose(&X);
            return 1;
        }
        // Chunk c always carries frames for port RX_PORT + c % Receivers.
        for (i = 0; i < NCHUNK; i++) {
            memcpy(X.Umem + (SIZE_T)i * CHUNK, Template[i % Receivers], FrameLen);
        }
        Gen[0].Thread = CreateThread(NULL, 0, XdpInjectThread, &X, 0, NULL);
    } else {
        // Slot i of every exchange buffer carries port RX_PORT + i % Receivers.
        memset(SlPut, 0, SL_EXCHANGE_BUFFER_SIZE);
        for (i = 0; i < SL_MAX_PACKET_EXCHANGE; i++) {
            memcpy((UCHAR *)SL_ADDR_OF_PACKET(SlPut, i), Template[i % Receivers], FrameLen);
            SL_SIZE_OF_PACKET(SlPut, i) = FrameLen;
        }
        Gen[0].Thread = CreateThread(NULL, 0, SelowInjectThread, NULL, 0, NULL);
    }
    NGen = 1;

    Measure(&A, &B);
    JoinAll();

    _snprintf(Extra, sizeof(Extra), "receivers=%d gen_err=%d", Receivers, Gen[0].LastErr);
    Extra[sizeof(Extra) - 1] = 0;
    Report(&A, &B, "inject", 1, Extra);
    for (i = 0; i < Receivers; i++) {
        closesocket(RecvSock[i]);
    }
    XskClose(&X);
    return B.CapDgrams > 0 ? 0 : 1;
}

static void Usage(void)
{
    Log("usage: spbench -b xdp|selow -d tx|rx|list -i IfIndex [-l FrameLen] [-s Secs]\n"
        "               [-g sendto|uso] [-t Threads] [-p] [-r Receivers] [-w WarmupMs]\n"
        "               [-a LocalIPv4] [-e PeerIPv4]\n");
}

int __cdecl main(int argc, char **argv)
{
    WSADATA Wsa;
    const char *Local = "10.99.0.1", *Peer = "10.99.0.2";
    int i, Rc;

    for (i = 1; i < argc; i++) {
        const char *A = argv[i];
        const char *V = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(A, "-p")) {
            Pin = 1;
            continue;
        }
        if (V == NULL) {
            Usage();
            return 2;
        }
        if (!strcmp(A, "-b")) {
            Backend = V;
        } else if (!strcmp(A, "-d")) {
            Dir = V;
        } else if (!strcmp(A, "-i")) {
            IfIndex = (UINT32)atoi(V);
        } else if (!strcmp(A, "-l")) {
            FrameLen = (UINT32)atoi(V);
        } else if (!strcmp(A, "-s")) {
            Seconds = (DWORD)atoi(V);
        } else if (!strcmp(A, "-g")) {
            GenMode = V;
        } else if (!strcmp(A, "-t")) {
            Threads = atoi(V);
        } else if (!strcmp(A, "-r")) {
            Receivers = atoi(V);
        } else if (!strcmp(A, "-w")) {
            WarmupMs = (DWORD)atoi(V);
        } else if (!strcmp(A, "-a")) {
            Local = V;
        } else if (!strcmp(A, "-e")) {
            Peer = V;
        } else {
            Usage();
            return 2;
        }
        i++;
    }

    QueryPerformanceFrequency(&Freq);
    WSAStartup(MAKEWORD(2, 2), &Wsa);
    NCpu = (int)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (NCpu < 1 || NCpu > 64) {
        NCpu = NCpu < 1 ? 1 : 64;
    }
    if (Threads <= 0) {
        Threads = NCpu;
    }
    if (Threads > MAX_GEN) {
        Threads = MAX_GEN;
    }
    if (Receivers != 1 && Receivers != 2 && Receivers != 4 && Receivers != 8) {
        Receivers = 2;
    }
    if (FrameLen < HDR + 8 || FrameLen > 1514) {
        Usage();
        return 2;
    }
    Payload = FrameLen - HDR;
    inet_pton(AF_INET, Local, &LocalIp);
    inet_pton(AF_INET, Peer, &PeerIp);

    if (!GetMac()) {
        Fail("no-adapter");
        return 2;
    }
    Log("spbench backend=%s dir=%s IfIndex=%u mac=%02x-%02x-%02x-%02x-%02x-%02x len=%u payload=%u gen=%s threads=%d pin=%d ncpu=%d secs=%lu\n",
        Backend, Dir, IfIndex, LocalMac[0], LocalMac[1], LocalMac[2], LocalMac[3], LocalMac[4], LocalMac[5],
        FrameLen, Payload, GenMode, Threads, Pin, NCpu, Seconds);
    CloseHandle(CreateThread(NULL, 0, Watchdog, NULL, 0, NULL));

    if (!strcmp(Backend, "selow")) {
        if (SelowOpen(!strcmp(Dir, "list")) != 0) {
            return 3;
        }
        if (!strcmp(Dir, "list")) {
            SelowClose();
            return 0;
        }
    } else if (strcmp(Backend, "xdp") != 0) {
        Usage();
        return 2;
    }

    if (!strcmp(Dir, "tx")) {
        Rc = RunTx();
    } else if (!strcmp(Dir, "rx")) {
        Rc = RunRx();
    } else {
        Usage();
        Rc = 2;
    }
    SelowClose();
    WSACleanup();
    return Rc;
}
