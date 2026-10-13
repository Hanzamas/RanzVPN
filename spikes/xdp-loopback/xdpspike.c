//
// XDP spike (ADR-0018): can XDP for Windows, in generic mode, turn a
// Microsoft KM-TEST Loopback Adapter into a TAP-like L2 device?
//
//   (a) TX inspect: an AF_XDP RX socket on hook {L2, TX, INSPECT} with a
//       redirect-all program sees the frames TCPIP sends out of the adapter.
//   (b) RX inject: an AF_XDP TX socket on hook {L2, RX, INJECT} hands frames
//       up to TCPIP as if they were received on the adapter; a UDP socket
//       bound to the adapter IP must get them.
//
// Built from the xskfwd samples (samples/xskfwd, samples/deprecated/xskfwd)
// of microsoft/xdp-for-windows release/1.4. Spike code, never merged.
//
// Usage: xdpspike.exe <IfIndex> <LocalIPv4> <PeerIPv4> <Seconds> [tx|rx|all]
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

typedef struct _XSKC {
    HANDLE Sock;
    UCHAR *Umem;
    XSK_RING Rx;
    XSK_RING Fill;
    XSK_RING Tx;
    XSK_RING Comp;
} XSKC;

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
        XskRingInitialize(&X->Rx, &Info.Rx);
        XskRingInitialize(&X->Fill, &Info.Fill);
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
    }
    if (X->Umem != NULL) {
        VirtualFree(X->Umem, 0, MEM_RELEASE);
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
// (a) TX inspect
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

typedef struct _TXCOUNT {
    UINT64 Frames;
    UINT64 Udp;
    UINT64 Arp;
    UINT64 Other;
    UINT64 FromUs;
} TXCOUNT;

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

static UINT64 DrainRx(XSKC *X, TXCOUNT *C, UINT32 *Dumped)
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
            Hex("tx-inspect frame", F, D->Length);
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

static int TestTxInspect(void)
{
    HRESULT Hr;
    XSKC X = {0};
    HANDLE Prog = NULL;
    HANDLE Th;
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_TX, XDP_HOOK_INSPECT};
    XDP_RULE Rule = {0};
    UINT32 Idx, N, i, Dumped = 0;
    TXCOUNT C1 = {0}, C2 = {0};
    XSK_STATISTICS Stats = {0};
    UINT32 StatsLen = sizeof(Stats);
    double T0, T1, End;
    UINT64 Spin = 0;

    Log("== TX inspect: hook {L2, TX, INSPECT}, generic, queue 0\n");
    if (FAILED(XskOpen(&X, TRUE, Hook))) {
        Log("RESULT TX_INSPECT FAIL reason=xsk-setup\n");
        XskClose(&X);
        return 1;
    }

    N = XskRingProducerReserve(&X.Fill, RING, &Idx);
    for (i = 0; i < N; i++) {
        *(UINT64 *)XskRingGetElement(&X.Fill, Idx + i) = (UINT64)i * CHUNK;
    }
    XskRingProducerSubmit(&X.Fill, N);

    Rule.Match = XDP_MATCH_ALL;
    Rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    Rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    Rule.Redirect.Target = X.Sock;
    Hr = XdpCreateProgram(IfIndex, &Hook, 0, XDP_CREATE_PROGRAM_FLAG_GENERIC, &Rule, 1, &Prog);
    if (FAILED(Hr)) {
        Log("ERR XdpCreateProgram(TX inspect): 0x%08lx\n", (unsigned long)Hr);
        Log("RESULT TX_INSPECT FAIL reason=program-attach hr=0x%08lx\n", (unsigned long)Hr);
        XskClose(&X);
        return 1;
    }

    //
    // Phase 1: functional. A slow sender (10 datagrams per second) for 3 s.
    //
    Stop = 0;
    Sent = 0;
    Th = CreateThread(NULL, 0, SenderThread, (void *)(ULONG_PTR)FALSE, 0, NULL);
    End = Now() + 3.0;
    while (Now() < End) {
        if (DrainRx(&X, &C1, &Dumped) == 0) {
            Sleep(1);
        }
    }
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);
    Log("phase1: sent=%lld frames=%llu udp%d=%llu arp=%llu other=%llu fromAdapterMac=%llu\n",
        Sent, C1.Frames, TX_PORT, C1.Udp, C1.Arp, C1.Other, C1.FromUs);

    //
    // Phase 2: throughput. Flood sendto() for Seconds while busy-polling.
    //
    Stop = 0;
    Sent = 0;
    Th = CreateThread(NULL, 0, SenderThread, (void *)(ULONG_PTR)TRUE, 0, NULL);
    T0 = Now();
    End = T0 + Seconds;
    for (;;) {
        DrainRx(&X, &C2, &Dumped);
        if ((++Spin & 0xff) == 0 && Now() >= End) {
            break;
        }
    }
    T1 = Now();
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);
    while (DrainRx(&X, &C2, &Dumped) != 0) {
    }

    XskGetSockopt(X.Sock, XSK_SOCKOPT_STATISTICS, &Stats, &StatsLen);
    Log("phase2: secs=%.2f sent=%lld frames=%llu udp%d=%llu rxDropped=%llu rxTruncated=%llu\n",
        T1 - T0, Sent, C2.Frames, TX_PORT, C2.Udp, Stats.RxDropped, Stats.RxTruncated);
    Log("PPS TX_INSPECT udp_seen=%.0f sendto=%.0f\n",
        C2.Udp / (T1 - T0), Sent / (T1 - T0));

    if (C1.Udp > 0) {
        Log("RESULT TX_INSPECT PASS udp_frames=%llu (OS-sent UDP seen by XSK)\n", C1.Udp);
    } else if (C1.Frames > 0) {
        Log("RESULT TX_INSPECT PASS-PARTIAL frames=%llu (OS frames seen, but not the test UDP)\n", C1.Frames);
    } else {
        Log("RESULT TX_INSPECT FAIL reason=no-frames (program attached, XSK saw nothing)\n");
    }

    CloseHandle(Prog);
    XskClose(&X);
    return C1.Frames > 0 ? 0 : 1;
}

//
// (b) RX inject
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

static int TestRxInject(void)
{
    XSKC X = {0};
    XDP_HOOK_ID Hook = {XDP_HOOK_L2, XDP_HOOK_RX, XDP_HOOK_INJECT};
    SOCKADDR_IN A = {0};
    int RcvBuf = 16 << 20;
    DWORD Timeout = 200;
    HANDLE Th;
    UINT32 Len, i;
    UINT64 Submitted = 0, Completed = 0;
    LONG64 Single, Flood;
    double T0, T1, End;
    XSK_NOTIFY_RESULT_FLAGS Nr;
    UINT64 Spin = 0;

    Log("== RX inject: hook {L2, RX, INJECT}, generic, queue 0\n");

    RecvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    A.sin_family = AF_INET;
    A.sin_addr = LocalIp;
    A.sin_port = htons(RX_PORT);
    if (bind(RecvSock, (SOCKADDR *)&A, sizeof(A)) != 0) {
        Log("ERR recv bind: %d\n", WSAGetLastError());
        Log("RESULT RX_INJECT FAIL reason=udp-bind\n");
        return 1;
    }
    setsockopt(RecvSock, SOL_SOCKET, SO_RCVBUF, (char *)&RcvBuf, sizeof(RcvBuf));
    setsockopt(RecvSock, SOL_SOCKET, SO_RCVTIMEO, (char *)&Timeout, sizeof(Timeout));

    if (FAILED(XskOpen(&X, FALSE, Hook))) {
        Log("RESULT RX_INJECT FAIL reason=xsk-setup\n");
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

    //
    // Phase 1: functional. Inject 5 frames, one every 200 ms.
    //
    for (i = 0; i < 5; i++) {
        Inject(&X, 1, Len, &Submitted);
        XskNotifySocket(X.Sock, XSK_NOTIFY_FLAG_POKE_TX, 0, &Nr);
        Sleep(200);
        Completed += Complete(&X);
    }
    Sleep(500);
    Completed += Complete(&X);
    Single = Received;
    Log("phase1: injected=%llu completed=%llu udp_received=%lld\n", Submitted, Completed, Single);

    //
    // Phase 2: throughput. Keep the TX ring full for Seconds.
    //
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
    Stop = 1;
    WaitForSingleObject(Th, INFINITE);
    CloseHandle(Th);
    Flood = Received;

    Log("phase2: secs=%.2f submitted=%llu completed=%llu udp_received=%lld\n",
        T1 - T0, Submitted, Completed, Flood);
    Log("PPS RX_INJECT injected=%.0f delivered_to_socket=%.0f\n",
        Completed / (T1 - T0), Flood / (T1 - T0));

    if (Single > 0) {
        Log("RESULT RX_INJECT PASS udp_received=%lld of 5 (injected frames reached a UDP socket on the adapter IP)\n", Single);
    } else if (Flood > 0) {
        Log("RESULT RX_INJECT PASS-FLOOD-ONLY udp_received=%lld\n", Flood);
    } else {
        Log("RESULT RX_INJECT FAIL reason=no-delivery completed=%llu (XSK took the frames, TCPIP did not deliver)\n",
            Completed);
    }

    XskClose(&X);
    closesocket(RecvSock);
    return (Single > 0 || Flood > 0) ? 0 : 1;
}

int __cdecl main(int argc, char **argv)
{
    WSADATA Wsa;
    const char *Mode = argc > 5 ? argv[5] : "all";
    int Rc = 0;

    if (argc < 5) {
        Log("usage: xdpspike.exe <IfIndex> <LocalIPv4> <PeerIPv4> <Seconds> [tx|rx|all]\n");
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

    if (!_stricmp(Mode, "tx") || !_stricmp(Mode, "all")) {
        Rc |= TestTxInspect();
    }
    if (!_stricmp(Mode, "rx") || !_stricmp(Mode, "all")) {
        Rc |= TestRxInject() << 1;
    }
    WSACleanup();
    return Rc;
}
