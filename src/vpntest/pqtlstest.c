// pqtlstest.c
// Named post-quantum key exchange test of vpntest ("pqtls" command, CORE-P2-5 #382)
//
// The key exchange of the QUIC and TLS-443 paths between two Nodes, as the stack reports it in the connection information
// of each session (TransportGroup): Schannel in the cipher information of its context, msquic in the handshake information
// of its connection. node-s is a Node of the new core in this process, whose overlay takes its states from the test
// (NodeOverlayApply), with a Listener: the front door on a TCP port and QUIC on a UDP port that the system picks, never 443,
// with a certificate of the LocalMachine\My store. node-c is a client of the new protocol in this process, with the TLS and
// QUIC transports that a Node dials the endpoints of its peers with: it dials node-s over TLS-443 and over QUIC and opens a
// Noise session, which the overlay of node-s takes as the session of its peer. node-c reads the group of each session from
// its stream, node-s from its overlay (NodeOverlayGetSessions), and the ServerHello on the wire of TLS-443 must carry it too.
// node-c's ClientHello shows what the host asks for: the test reads it on a TCP listener of its own, which closes the
// connection once it has it. The steps:
// - the names of the groups, and which of them are quantum-resistant (TransportGroupName, TransportGroupPostQuantum);
// - the host: the Windows build, whether CNG has ML-KEM, and the TLS group list in force (TransportTlsHybrid);
// - switched on: no ECC Curve Order policy, and the machine's list with x25519_mlkem768 first, as the TLS transport of a Node
//   writes it (TransportTlsSetGroups). The host asks for the hybrid where CNG has ML-KEM, a Node reports the Capability
//   pq_tls (NodeCapsProc), node-c's ClientHello offers X25519MLKEM768 first with its key share, and the QUIC and the TLS-443
//   session negotiate it, read on both ends; where CNG has no ML-KEM, as switched off below;
// - switched off: an ECC Curve Order policy whose list names the classical groups only, which wins over the list that a
//   Node sets, so the TLS transports of node-s and node-c leave both lists as they are, and the machine's list without the
//   hybrid. Schannel takes a change of the machine's list at once, and a change of a policy only when Windows starts, which
//   a runner cannot do within its job: the two lists together are what Schannel holds on a host with that policy once
//   Windows started. The host does not ask for the hybrid, a Node does not report pq_tls, node-c's ClientHello offers no
//   group with ML-KEM and X25519 first with its key share, and the same sessions come up with one classical group of those
//   that node-c offers, not quantum-resistant: the one that the server of the host picks, which is not always the first
//   that the client offers (secp384r1 on the x64 runner, Windows Server 2025, with no ECC Curve Order policy set: its
//   Schannel server picked it of the X25519, secp256r1 and secp384r1 that node-c offered with a key share each).
// The listeners of node-s start again in each step, so that their credentials take the list of the step. The test puts the
// two lists back as it found them, also when its watchdog ends it.
//
// "vpntest pqtls probe" changes nothing: it runs one session over TLS-443 and one over QUIC between two transports of this
// process under the list in force, transports that set no list, and prints the group of each end as "PQTLS PROBE <path>
// ..." lines, which .github/scripts/pq-doctor.ps1 reads before and after it runs what ranz doctor says to run.
// Print "PQTLS TEST OK" only when every check passes. Needs administrator rights: the LocalMachine\My store, the key storage
// provider of the machine and the TLS group lists of the machine.

#include "testlist.h"

#include "Cedar/ConfigStore.h"
#include "Cedar/Node.h"
#include "Cedar/NodeCaps.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Tick64.h"

#include "Core/Control.h"
#include "Core/Crypto.h"
#include "Core/Transport.h"

#include <WS2tcpip.h>

#include <stdio.h>

#define	PQTLSTEST_WATCHDOG		240000		// The test process is aborted after this (ms)
#define	PQTLSTEST_BOUND			20000		// A bounded wait on observable state (ms)
#define	PQTLSTEST_POLL			20			// Poll interval of observable state (ms)
#define	PQTLSTEST_TIMEOUT		15000		// A Noise handshake, or an accept, within this time (ms)
#define	PQTLSTEST_VRF			1			// The VRF of the test
#define	PQTLSTEST_NODE			"node-s"	// The node that listens
#define	PQTLSTEST_PEER			"node-c"	// Its peer, which dials it
#define	PQTLSTEST_CN			L"CN=localhost"	// The subject of the certificate
#define	PQTLSTEST_SAN			L"localhost"	// ... and its subject alternative name
#define	PQTLSTEST_LISTEN		"127.0.0.1:0"	// The listeners of the probe: test ports of the loopback interface, never 443
#define	PQTLSTEST_MAX_SESSIONS	4			// The sessions of node-s that the test reads at most
#define	PQTLSTEST_MAX_GROUPS	32			// The groups of node-c's ClientHello that the test keeps
#define	PQTLSTEST_HELLO_SIZE	16384		// Bytes of the record of node-c's ClientHello that the test reads at most
// What the test reads of node-c's ClientHello (RFC 8446 sections 4.1.2, 4.2.7 and 4.2.8)
#define	PQTLSTEST_RECORD_HEADER	5			// A TLS record: its type, version and length, then its bytes
#define	PQTLSTEST_HANDSHAKE		22			// A handshake record
#define	PQTLSTEST_CLIENT_HELLO	1			// The ClientHello message
#define	PQTLSTEST_RANDOM_SIZE	32			// The random of a ClientHello
#define	PQTLSTEST_EXT_GROUPS	0x000A		// The extension supported_groups
#define	PQTLSTEST_EXT_KEY_SHARE	0x0033		// The extension key_share
// The TLS group lists: the machine's, which a Node writes, and the one of an ECC Curve Order policy, which wins over it
#define	PQTLSTEST_LIST_KEY		L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002"
#define	PQTLSTEST_POLICY_KEY	L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
#define	PQTLSTEST_VALUE			L"EccCurves"
#define	PQTLSTEST_LIST_SIZE		2048		// Characters of a group list

// The list of the policy that switches the hybrid off: the classical groups only, X25519 first, as a REG_MULTI_SZ
static const wchar_t pqtlstest_classical[] = L"curve25519\0NistP256\0NistP384\0";

// A value of a group list as the test found it, to put it back
typedef struct PQTLSTEST_SAVED
{
	bool Had;							// The value was there ...
	DWORD Type;							// ... of this type ...
	DWORD Size;							// ... and this size in bytes
	BYTE Data[PQTLSTEST_LIST_SIZE * sizeof(wchar_t)];
} PQTLSTEST_SAVED;

// The two lists before the test, which the watchdog puts back too once both were saved
static PQTLSTEST_SAVED pqtlstest_machine;
static PQTLSTEST_SAVED pqtlstest_policy;
static volatile LONG pqtlstest_saved = 0;

// The state of the test
typedef struct PQTLSTEST_CTX
{
	UINT NumChecks;
	UINT NumFailed;
	wchar_t Dir[MAX_PATH];				// The data directory of node-s
	NODE *Node;							// node-s
	PEER_KEY Key;						// Its static key
	UCHAR PeerScalar[PEER_KEY_SIZE];	// The static key of node-c
	UCHAR PeerPublic[PEER_KEY_SIZE];	// ... and its public half
	UINT64 Generation;					// The Generation of the last state applied
} PQTLSTEST_CTX;

// How one session went
typedef struct PQTLSTEST_SESSION
{
	bool Up;							// node-c's Noise session came up, and the overlay of node-s took it
	UINT Client;						// The group that the stack of node-c reported for its stream
	UINT Server;						// ... and the one that the stack of node-s reported for its session
	TRANSPORT_TLS_INFO Tls;				// TLS-443: what node-c's handshake gave, the group of the ServerHello among it
} PQTLSTEST_SESSION;

// What node-c's ClientHello offers: the groups of its supported_groups in their order, and the groups of its key shares
typedef struct PQTLSTEST_HELLO
{
	bool Read;							// The test read and parsed it
	UINT NumGroups;
	UINT Groups[PQTLSTEST_MAX_GROUPS];
	UINT NumShares;
	UINT Shares[PQTLSTEST_MAX_GROUPS];
} PQTLSTEST_HELLO;

// A reader of the bytes of node-c's ClientHello: Pos stays at most Size, and a read past Size fails
typedef struct PQTLSTEST_READER
{
	UCHAR *Data;
	UINT Size;
	UINT Pos;
} PQTLSTEST_READER;

// node-c's dial of the listener of the test that reads its ClientHello, on a thread of its own
typedef struct PQTLSTEST_DIAL
{
	TRANSPORT *Transport;				// node-c's TLS transport
	char Address[MAX_SIZE];				// The listener of the test
} PQTLSTEST_DIAL;

static bool PqTlsTestCheck(PQTLSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PqTlsTestCheck(PQTLSTEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
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

//
// The group lists
//

// Save the value of a list of key as it is
static void PqTlsTestSave(wchar_t *key, PQTLSTEST_SAVED *v)
{
	Zero(v, sizeof(PQTLSTEST_SAVED));
	v->Size = sizeof(v->Data);
	v->Had = (RegGetValueW(HKEY_LOCAL_MACHINE, key, PQTLSTEST_VALUE, RRF_RT_ANY | RRF_NOEXPAND, &v->Type, v->Data, &v->Size) == ERROR_SUCCESS);
}

// Write the value of a list of key, of type and size bytes; false when it cannot be written
static bool PqTlsTestWrite(wchar_t *key, DWORD type, const void *data, DWORD size)
{
	HKEY k = NULL;
	LSTATUS r = RegCreateKeyExW(HKEY_LOCAL_MACHINE, key, 0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL);

	if (r == ERROR_SUCCESS)
	{
		r = RegSetValueExW(k, PQTLSTEST_VALUE, 0, type, (const BYTE *)data, size);
		RegCloseKey(k);
	}

	return (r == ERROR_SUCCESS);
}

// Take the value of a list of key away; true when it is not there any more
static bool PqTlsTestDelete(wchar_t *key)
{
	LSTATUS r = RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key, PQTLSTEST_VALUE);

	return (r == ERROR_SUCCESS || r == ERROR_FILE_NOT_FOUND);
}

// Put a saved value back: write it, or take it away where it was not there
static bool PqTlsTestPutBack(wchar_t *key, PQTLSTEST_SAVED *v)
{
	if (v->Had == false)
	{
		return PqTlsTestDelete(key);
	}

	return PqTlsTestWrite(key, v->Type, v->Data, v->Size);
}

// Put both lists back as the test found them
static bool PqTlsTestRestore()
{
	bool policy = PqTlsTestPutBack(PQTLSTEST_POLICY_KEY, &pqtlstest_policy);
	bool machine = PqTlsTestPutBack(PQTLSTEST_LIST_KEY, &pqtlstest_machine);

	return (policy && machine);
}

// The watchdog: a test that hangs ends the process, with the lists of the machine put back
static DWORD WINAPI PqTlsTestWatchdog(LPVOID param)
{
	if (WaitForSingleObject((HANDLE)param, PQTLSTEST_WATCHDOG) == WAIT_TIMEOUT)
	{
		if (InterlockedCompareExchange(&pqtlstest_saved, 0, 0) != 0)
		{
			PqTlsTestRestore();
		}
		Print("PQTLS TEST FAILED (the watchdog ended it after %u ms)\n", PQTLSTEST_WATCHDOG);
		fflush(stdout);
		ExitProcess(1);
	}

	return 0;
}

// The host: its Windows build, ML-KEM in CNG and the group list in force, and whether it asks for the hybrid
static void PqTlsTestHost(TRANSPORT_TLS_HYBRID *h)
{
	wchar_t build[64];
	DWORD ubr = 0, ubr_size = sizeof(ubr), build_size = sizeof(build);
	char *list[] = {"the default of Windows", "the machine's", "an ECC Curve Order policy's"};

	UniStrCpy(build, sizeof(build), L"?");
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"CurrentBuild", RRF_RT_REG_SZ, NULL, build, &build_size);
	RegGetValueW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR", RRF_RT_REG_DWORD, NULL, &ubr, &ubr_size);

	TransportTlsHybrid(h);
	Print("  [GROUP] Windows build %S.%u; ML-KEM in CNG: %s; the list in force is %s: %s; the host asks for X25519MLKEM768: %s\n", build, (UINT)ubr,
		h->MlKem ? "yes" : "no", list[h->List <= TRANSPORT_TLS_LIST_POLICY ? h->List : 0], h->Text, h->Asks ? "yes" : "no");
}

//
// The names
//

// The names of the groups, and which of them are quantum-resistant
static void PqTlsTestNames(PQTLSTEST_CTX *ctx)
{
	Print("[the names of the groups, and the quantum-resistant ones]\n");

	PqTlsTestCheck(ctx, StrCmp(TransportGroupName(CRYPTO_GROUP_X25519MLKEM768), "X25519MLKEM768") == 0 && StrCmp(TransportGroupName(CRYPTO_GROUP_X25519), "X25519") == 0 &&
		StrCmp(TransportGroupName(0x0017), "secp256r1") == 0 && StrCmp(TransportGroupName(0x11EB), "SecP256r1MLKEM768") == 0 && StrCmp(TransportGroupName(0), "none") == 0 &&
		StrCmp(TransportGroupName(0x1234), "unknown") == 0,
		"  0x11EC is X25519MLKEM768, 0x001D X25519, 0x0017 secp256r1, 0x11EB SecP256r1MLKEM768, 0 none, another unknown", "0x11EC is %s, 0x001D %s, 0 %s",
		TransportGroupName(CRYPTO_GROUP_X25519MLKEM768), TransportGroupName(CRYPTO_GROUP_X25519), TransportGroupName(0));
	PqTlsTestCheck(ctx, TransportGroupPostQuantum(CRYPTO_GROUP_X25519MLKEM768) && TransportGroupPostQuantum(0x11EB) && TransportGroupPostQuantum(0x11ED) &&
		TransportGroupPostQuantum(0x0201) && TransportGroupPostQuantum(CRYPTO_GROUP_X25519) == false && TransportGroupPostQuantum(0x0017) == false &&
		TransportGroupPostQuantum(0x0018) == false && TransportGroupPostQuantum(0) == false,
		"  the groups with ML-KEM are quantum-resistant, X25519 and the NIST curves are not, and neither is no group", "they are not told apart");
}

//
// node-c's ClientHello
//

// A big-endian value of n bytes (1 to 3) into *value; false when fewer are left
static bool PqTlsTestGet(PQTLSTEST_READER *r, UINT n, UINT *value)
{
	UINT v = 0;

	if (n > r->Size - r->Pos)
	{
		return false;
	}

	for (UINT i = 0;i < n;i++)
	{
		v = (v << 8) | r->Data[r->Pos + i];
	}
	r->Pos += n;
	*value = v;

	return true;
}

// A vector whose length takes len_size bytes into sub, and r past it; false when it does not fit
static bool PqTlsTestVector(PQTLSTEST_READER *r, UINT len_size, PQTLSTEST_READER *sub)
{
	UINT len = 0;

	if (PqTlsTestGet(r, len_size, &len) == false || len > r->Size - r->Pos)
	{
		return false;
	}

	sub->Data = r->Data + r->Pos;
	sub->Size = len;
	sub->Pos = 0;
	r->Pos += len;

	return true;
}

// A GREASE value of RFC 8701, which a client may offer among its groups and which no server picks
static bool PqTlsTestGrease(UINT group)
{
	return ((group & 0x0F0F) == 0x0A0A && (group >> 8) == (group & 0xFF));
}

// The groups of a record that holds a whole ClientHello: those of its supported_groups in their order, and those of its
// key shares, GREASE left out; false for anything else
static bool PqTlsTestParseHello(UCHAR *data, UINT size, PQTLSTEST_HELLO *h)
{
	PQTLSTEST_READER r = {data, size, 0};
	PQTLSTEST_READER record, hello, skip, ext;
	UINT type = 0, version = 0;

	Zero(h, sizeof(PQTLSTEST_HELLO));

	// The handshake record and its ClientHello, then its version, random, session id, cipher suites and compression methods
	if (PqTlsTestGet(&r, 1, &type) == false || type != PQTLSTEST_HANDSHAKE || PqTlsTestGet(&r, 2, &version) == false || PqTlsTestVector(&r, 2, &record) == false ||
		PqTlsTestGet(&record, 1, &type) == false || type != PQTLSTEST_CLIENT_HELLO || PqTlsTestVector(&record, 3, &hello) == false ||
		PqTlsTestGet(&hello, 2, &version) == false || hello.Size - hello.Pos < PQTLSTEST_RANDOM_SIZE)
	{
		return false;
	}
	hello.Pos += PQTLSTEST_RANDOM_SIZE;
	if (PqTlsTestVector(&hello, 1, &skip) == false || PqTlsTestVector(&hello, 2, &skip) == false || PqTlsTestVector(&hello, 1, &skip) == false ||
		PqTlsTestVector(&hello, 2, &ext) == false)
	{
		return false;
	}

	// The extensions: the groups of supported_groups, and the group of each key share, whose key the test steps over
	while (ext.Pos < ext.Size)
	{
		PQTLSTEST_READER e, list, key;
		UINT ext_type = 0, group = 0;

		if (PqTlsTestGet(&ext, 2, &ext_type) == false || PqTlsTestVector(&ext, 2, &e) == false)
		{
			return false;
		}
		if (ext_type != PQTLSTEST_EXT_GROUPS && ext_type != PQTLSTEST_EXT_KEY_SHARE)
		{
			continue;
		}
		if (PqTlsTestVector(&e, 2, &list) == false)
		{
			return false;
		}
		while (list.Pos < list.Size)
		{
			if (PqTlsTestGet(&list, 2, &group) == false || (ext_type == PQTLSTEST_EXT_KEY_SHARE && PqTlsTestVector(&list, 2, &key) == false))
			{
				return false;
			}
			if (PqTlsTestGrease(group))
			{
				continue;
			}
			if (ext_type == PQTLSTEST_EXT_GROUPS && h->NumGroups < PQTLSTEST_MAX_GROUPS)
			{
				h->Groups[h->NumGroups++] = group;
			}
			else if (ext_type == PQTLSTEST_EXT_KEY_SHARE && h->NumShares < PQTLSTEST_MAX_GROUPS)
			{
				h->Shares[h->NumShares++] = group;
			}
		}
	}

	h->Read = (h->NumGroups != 0);

	return h->Read;
}

// node-c dials the listener of the test, which closes the connection once it read the ClientHello: the handshake fails
static DWORD WINAPI PqTlsTestDialThread(LPVOID param)
{
	PQTLSTEST_DIAL *d = (PQTLSTEST_DIAL *)param;

	TransportClose(TransportDial(d->Transport, d->Address, NULL));

	return 0;
}

// Whether s has something to read, or a connection to accept, within PQTLSTEST_TIMEOUT
static bool PqTlsTestReadable(SOCKET s)
{
	WSAPOLLFD p;

	Zero(&p, sizeof(p));
	p.fd = s;
	p.events = POLLRDNORM;

	return (WSAPoll(&p, 1, PQTLSTEST_TIMEOUT) > 0);
}

// What node-c's TLS transport t offers in its ClientHello: it dials a TCP listener of the test on the loopback interface,
// which reads the record of the ClientHello, in the segments that the transport splits it into, and closes the connection
static void PqTlsTestClientHello(TRANSPORT *t, PQTLSTEST_HELLO *h)
{
	struct sockaddr_in sa;
	int sa_size = sizeof(sa);
	PQTLSTEST_DIAL d;
	UINT got = 0, want = PQTLSTEST_RECORD_HEADER;

	Zero(h, sizeof(PQTLSTEST_HELLO));
	if (t == NULL)
	{
		return;
	}

	SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (l == INVALID_SOCKET)
	{
		return;
	}
	Zero(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(l, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(l, 1) != 0 || getsockname(l, (struct sockaddr *)&sa, &sa_size) != 0)
	{
		closesocket(l);
		return;
	}

	Zero(&d, sizeof(d));
	d.Transport = t;
	Format(d.Address, sizeof(d.Address), "127.0.0.1:%u", (UINT)ntohs(sa.sin_port));
	HANDLE thread = CreateThread(NULL, 0, PqTlsTestDialThread, &d, 0, NULL);

	// The record header, then the rest of the record
	UCHAR *buf = ZeroMalloc(PQTLSTEST_HELLO_SIZE);
	SOCKET s = (thread != NULL && PqTlsTestReadable(l) ? accept(l, NULL, NULL) : INVALID_SOCKET);
	while (s != INVALID_SOCKET && got < want && PqTlsTestReadable(s))
	{
		int n = recv(s, (char *)(buf + got), (int)(want - got), 0);

		if (n <= 0)
		{
			break;
		}
		got += (UINT)n;
		if (got == PQTLSTEST_RECORD_HEADER)
		{
			want = PQTLSTEST_RECORD_HEADER + (((UINT)buf[3] << 8) | buf[4]);
			if (want > PQTLSTEST_HELLO_SIZE)
			{
				break;
			}
		}
	}
	if (s != INVALID_SOCKET)
	{
		closesocket(s);
	}
	closesocket(l);

	if (thread != NULL)
	{
		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
	}

	if (got == want && got > PQTLSTEST_RECORD_HEADER)
	{
		PqTlsTestParseHello(buf, got, h);
	}
	Free(buf);
}

// The groups as text into str: "X25519MLKEM768 (0x11EC), X25519 (0x001D)", or "none"
static void PqTlsTestGroupText(char *str, UINT size, UINT *groups, UINT num)
{
	char one[MAX_SIZE];

	StrCpy(str, size, num == 0 ? "none" : "");
	for (UINT i = 0;i < num;i++)
	{
		Format(one, sizeof(one), "%s%s (0x%04X)", i == 0 ? "" : ", ", TransportGroupName(groups[i]), groups[i]);
		StrCat(str, size, one);
	}
}

// Whether one of the groups is quantum-resistant
static bool PqTlsTestAnyPostQuantum(UINT *groups, UINT num)
{
	for (UINT i = 0;i < num;i++)
	{
		if (TransportGroupPostQuantum(groups[i]))
		{
			return true;
		}
	}

	return false;
}

//
// The sessions between node-c and node-s
//

// Apply a state of node-s to its overlay, as the control stream does: its address in VRF 1, node-c as its peer, and the
// Listener l, NULL for none
static bool PqTlsTestApply(PQTLSTEST_CTX *ctx, CONTROL_LISTENER *l)
{
	CONTROL_STATE st;
	CONTROL_PEER peer;
	UCHAR self[4] = {100, 64, 0, 1};
	UCHAR other[4] = {100, 64, 0, 2};

	Zero(&st, sizeof(st));
	Zero(&peer, sizeof(peer));

	st.Generation = ++ctx->Generation;
	StrCpy(st.Name, sizeof(st.Name), PQTLSTEST_NODE);
	StrCpy(st.Addresses[0].Network, sizeof(st.Addresses[0].Network), "default");
	st.Addresses[0].VrfId = PQTLSTEST_VRF;
	Copy(st.Addresses[0].Address, self, 4);
	st.Addresses[0].AddressSize = 4;
	st.Addresses[0].Length = 10;
	st.NumAddresses = 1;

	StrCpy(peer.Name, sizeof(peer.Name), PQTLSTEST_PEER);
	Copy(peer.Key, ctx->PeerPublic, PEER_KEY_SIZE);
	peer.NumVrfs = 1;
	peer.VrfIds[0] = PQTLSTEST_VRF;
	StrCpy(peer.Addresses[0].Network, sizeof(peer.Addresses[0].Network), "default");
	peer.Addresses[0].VrfId = PQTLSTEST_VRF;
	Copy(peer.Addresses[0].Address, other, 4);
	peer.Addresses[0].AddressSize = 4;
	peer.Addresses[0].Length = 10;
	peer.NumAddresses = 1;
	st.Peers = &peer;
	st.NumPeers = 1;

	st.Listener = l;

	return NodeOverlayApply(ctx->Node, &st);
}

// Whether the overlay of node-s shows the session of node-c up (or down) within PQTLSTEST_BOUND; group, which may be NULL,
// gets the group that node-s reported for it
static bool PqTlsTestPeer(PQTLSTEST_CTX *ctx, bool up, UINT *group)
{
	NODE_OVERLAY_SESSION list[PQTLSTEST_MAX_SESSIONS];

	for (UINT64 end = Tick64() + PQTLSTEST_BOUND;Tick64() < end;SleepThread(PQTLSTEST_POLL))
	{
		UINT num = MIN(NodeOverlayGetSessions(ctx->Node, list, PQTLSTEST_MAX_SESSIONS, NULL, 0), PQTLSTEST_MAX_SESSIONS);

		for (UINT i = 0;i < num;i++)
		{
			if (StrCmp(list[i].Name, PQTLSTEST_PEER) == 0 && list[i].Up == up)
			{
				if (group != NULL)
				{
					*group = list[i].Group;
				}
				return true;
			}
		}
	}

	return false;
}

// node-c: dial port of node-s over the client transport t and open the Noise session with the static key of node-s, which
// the overlay of node-s takes as the session of its peer; the group that each end reported, and for TLS-443 (tls) what
// the handshake gave. The session closes again, and the overlay sees it go.
static void PqTlsTestSession(PQTLSTEST_CTX *ctx, TRANSPORT *t, UINT port, bool tls, PQTLSTEST_SESSION *r)
{
	char address[MAX_SIZE];
	NOISE_SESSION_CONFIG cfg;

	Zero(r, sizeof(PQTLSTEST_SESSION));

	Format(address, sizeof(address), "127.0.0.1:%u", port);
	TRANSPORT_STREAM *s = TransportDial(t, address, NULL);
	if (s == NULL)
	{
		return;
	}

	r->Client = TransportGroup(s);
	if (tls)
	{
		TransportTlsLastHandshake(t, &r->Tls);
	}

	TRANSPORT_NOISE *n = ZeroMalloc(sizeof(TRANSPORT_NOISE));
	Zero(&cfg, sizeof(cfg));
	cfg.Suite = NOISE_SUITE_IK;
	cfg.StaticKey = ctx->PeerScalar;
	cfg.RemoteStatic = ctx->Key.Public;
	if (TransportNoiseConnect(n, s, &cfg, PQTLSTEST_TIMEOUT))
	{
		r->Up = PqTlsTestPeer(ctx, true, &r->Server);
		TransportNoiseClose(n);
		r->Up = PqTlsTestPeer(ctx, false, NULL) && r->Up;
	}
	Free(n);
}

// The checks of one session over the path what: it comes up, and both ends report one group. Where the host asks for the
// hybrid, X25519MLKEM768, which node-c offers first. Where it does not, a classical group of those that node-c's ClientHello
// offers, hello, the one that the server picks: node-c offers X25519 first with its key share, but the server of a host may
// prefer another of the groups that both have, as the Schannel server of Windows Server 2025 prefers secp384r1
static void PqTlsTestSessionChecks(PQTLSTEST_CTX *ctx, char *what, PQTLSTEST_SESSION *r, bool asks, PQTLSTEST_HELLO *hello, bool tls)
{
	char tmp[MAX_SIZE];
	bool offered = (hello->Read == false);

	Print("  [GROUP] %s: node-c %s (0x%04X), node-s %s (0x%04X)", what, TransportGroupName(r->Client), r->Client, TransportGroupName(r->Server), r->Server);
	if (tls)
	{
		Print(", the ServerHello 0x%04X%s", r->Tls.Group, r->Tls.Retried ? " after a HelloRetryRequest" : "");
	}
	Print("\n");

	Format(tmp, sizeof(tmp), "  %s: node-c's Noise session comes up, and the overlay of node-s takes it as the session of its peer", what);
	PqTlsTestCheck(ctx, r->Up, tmp, "it did not");
	if (asks)
	{
		Format(tmp, sizeof(tmp), "  %s: the stacks of node-c and node-s report X25519MLKEM768 (0x11EC), quantum-resistant", what);
		PqTlsTestCheck(ctx, r->Client == CRYPTO_GROUP_X25519MLKEM768 && r->Server == CRYPTO_GROUP_X25519MLKEM768, tmp, "node-c 0x%04X, node-s 0x%04X", r->Client, r->Server);
	}
	else
	{
		for (UINT i = 0;i < hello->NumGroups;i++)
		{
			offered = offered || hello->Groups[i] == r->Client;
		}
		Format(tmp, sizeof(tmp), "  %s: the stacks of node-c and node-s report one classical group that node-c offers, not quantum-resistant", what);
		PqTlsTestCheck(ctx, r->Client != 0 && r->Client == r->Server && offered && TransportGroupPostQuantum(r->Client) == false, tmp, "node-c 0x%04X, node-s 0x%04X",
			r->Client, r->Server);
	}
	if (tls)
	{
		Format(tmp, sizeof(tmp), "  %s: the ServerHello on the wire carries the group that Schannel reports", what);
		PqTlsTestCheck(ctx, r->Client != 0 && r->Tls.Group == r->Client && r->Tls.StackGroup == r->Client, tmp, "the ServerHello 0x%04X, Schannel 0x%04X, node-c 0x%04X",
			r->Tls.Group, r->Tls.StackGroup, r->Client);
	}
}

// One step, the hybrid switched on or off: the lists as the step leaves them, the Capability of a node, node-c's ClientHello,
// and a session over TLS-443 and one over QUIC between node-c and node-s on listeners that start under those lists
static void PqTlsTestStep(PQTLSTEST_CTX *ctx, char *thumbprint, bool on)
{
	TRANSPORT_TLS_HYBRID h;
	PQTLSTEST_HELLO hello;
	CONTROL_CAPS caps;
	CONTROL_LISTENER l;
	NODE_LISTENER_STATUS st;
	TRANSPORT_TLS_CONFIG tls_cfg;
	TRANSPORT_QUIC_CONFIG quic_cfg;
	PQTLSTEST_SESSION r;
	char offered[MAX_SIZE * 2];
	char shares[MAX_SIZE * 2];

	if (on)
	{
		Print("[switched on: no ECC Curve Order policy, and the machine's list with x25519_mlkem768 first, as a Node writes it]\n");
		bool deleted = PqTlsTestDelete(PQTLSTEST_POLICY_KEY);
		UINT set = TransportTlsSetGroups();
		PqTlsTestCheck(ctx, deleted && set == TRANSPORT_TLS_GROUPS_SET, "  no policy decides the list, and the TLS transport of a Node sets the machine's", "policy taken off %u, set %u",
			(UINT)deleted, set);
	}
	else
	{
		// The policy first, so that no TLS transport of a Node puts the hybrid back into the machine's list
		Print("[switched off: an ECC Curve Order policy that names the classical groups only, and the machine's list without the hybrid, which Schannel takes at once]\n");
		bool written = PqTlsTestWrite(PQTLSTEST_POLICY_KEY, REG_MULTI_SZ, pqtlstest_classical, sizeof(pqtlstest_classical)) &&
			PqTlsTestWrite(PQTLSTEST_LIST_KEY, REG_MULTI_SZ, pqtlstest_classical, sizeof(pqtlstest_classical));
		UINT set = TransportTlsSetGroups();
		PqTlsTestCheck(ctx, written && set == TRANSPORT_TLS_GROUPS_POLICY, "  the policy wins: the TLS transport of a Node leaves both lists as they are",
			"written %u, set %u", (UINT)written, set);
	}

	PqTlsTestHost(&h);
	if (on)
	{
		PqTlsTestCheck(ctx, h.List == TRANSPORT_TLS_LIST_MACHINE && h.First == h.MlKem && h.Asks == h.MlKem,
			h.MlKem ? "  the host asks for X25519MLKEM768: CNG has ML-KEM, and the machine's list names it first" : "  the host does not ask for X25519MLKEM768: CNG has no ML-KEM",
			"list %u, first %u, asks %u, ML-KEM %u", h.List, (UINT)h.First, (UINT)h.Asks, (UINT)h.MlKem);
	}
	else
	{
		PqTlsTestCheck(ctx, h.List == TRANSPORT_TLS_LIST_POLICY && h.Listed == false && h.Asks == false,
			"  the host does not ask for X25519MLKEM768: the list of the policy does not name it", "list %u, listed %u, asks %u", h.List, (UINT)h.Listed, (UINT)h.Asks);
	}

	Zero(&caps, sizeof(caps));
	NodeCapsProc(NULL, &caps);
	PqTlsTestCheck(ctx, caps.PqTls == h.Asks, h.Asks ? "  a Node reports the Capability pq_tls in its Hello" : "  a Node does not report the Capability pq_tls in its Hello",
		"it reports %u", (UINT)caps.PqTls);

	// What the host asks for: the groups of node-c's ClientHello, with the TLS transport that a Node dials the endpoints of
	// its peers with
	TransportTlsDefaultConfig(&tls_cfg, thumbprint, false);
	TRANSPORT *tls = TransportTlsClientNew(&tls_cfg);
	PqTlsTestClientHello(tls, &hello);
	PqTlsTestGroupText(offered, sizeof(offered), hello.Groups, hello.NumGroups);
	PqTlsTestGroupText(shares, sizeof(shares), hello.Shares, hello.NumShares);
	Print("  [GROUP] node-c's ClientHello offers %s, with the key shares of %s\n", offered, shares);
	if (PqTlsTestCheck(ctx, hello.Read, "  the test reads the groups that node-c's ClientHello offers", "the transport %s, and no ClientHello came", tls != NULL ? "started" : "did not start"))
	{
		if (h.Asks)
		{
			bool shared = false;
			for (UINT i = 0;i < hello.NumShares;i++)
			{
				shared = shared || hello.Shares[i] == CRYPTO_GROUP_X25519MLKEM768;
			}
			PqTlsTestCheck(ctx, hello.Groups[0] == CRYPTO_GROUP_X25519MLKEM768 && shared, "  node-c's ClientHello offers X25519MLKEM768 first, with its key share",
				"it offers %s, with the key shares of %s", offered, shares);
		}
		else
		{
			// The fallback that the Node asks for: X25519, first in its list and in the list of the step
			bool x25519 = false;
			for (UINT i = 0;i < hello.NumShares;i++)
			{
				x25519 = x25519 || hello.Shares[i] == CRYPTO_GROUP_X25519;
			}
			PqTlsTestCheck(ctx, PqTlsTestAnyPostQuantum(hello.Groups, hello.NumGroups) == false && PqTlsTestAnyPostQuantum(hello.Shares, hello.NumShares) == false,
				"  node-c's ClientHello offers no group with ML-KEM", "it offers %s, with the key shares of %s", offered, shares);
			PqTlsTestCheck(ctx, hello.Groups[0] == CRYPTO_GROUP_X25519 && x25519, "  node-c's ClientHello offers X25519 first, with its key share",
				"it offers %s, with the key shares of %s", offered, shares);
		}
	}

	// The Listener of node-s, whose front door and QUIC start now, under the lists of the step
	Zero(&l, sizeof(l));
	StrCpy(l.Name, sizeof(l.Name), "edge");
	l.Source = CONTROL_CERT_KSP;
	StrCpy(l.Thumbprint, sizeof(l.Thumbprint), thumbprint);
	bool applied = PqTlsTestApply(ctx, &l);
	NodeListenerGetStatus(ctx->Node, &st);
	if (PqTlsTestCheck(ctx, applied && st.Running && st.Port != 0, "  the front door of node-s listens with the certificate of the store", "applied %u, running %u, port %u, error %s",
		(UINT)applied, (UINT)st.Running, st.Port, st.Error))
	{
		// TLS-443, with the transport of node-c that sent the ClientHello
		Zero(&r, sizeof(r));
		if (tls != NULL)
		{
			PqTlsTestSession(ctx, tls, st.Port, true, &r);
		}
		PqTlsTestSessionChecks(ctx, "TLS-443", &r, h.Asks, &hello, true);

		// QUIC, where msquic.dll is next to vpntest
		if (TransportQuicAvailable() && st.QuicPort != 0)
		{
			TransportQuicDefaultConfig(&quic_cfg, thumbprint, false);
			TRANSPORT *quic = TransportQuicClientNew(&quic_cfg);
			Zero(&r, sizeof(r));
			if (quic != NULL)
			{
				PqTlsTestSession(ctx, quic, st.QuicPort, false, &r);
			}
			PqTlsTestSessionChecks(ctx, "QUIC", &r, h.Asks, &hello, false);
			TransportQuicFree(quic);
		}
		else
		{
			Print("  msquic.dll is not next to vpntest: QUIC is not checked\n");
		}
	}
	TransportTlsFree(tls);

	// No Listener: the listeners stop, and the next step starts them again
	PqTlsTestApply(ctx, NULL);
}

// Delete the files of a directory, then the directory
static void PqTlsTestDeleteDir(wchar_t *dir)
{
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		DIRENT *e = d->File[i];
		wchar_t path[MAX_PATH];

		ConbinePathW(path, sizeof(path), dir, e->FileNameW);
		if (e->Folder)
		{
			PqTlsTestDeleteDir(path);
		}
		else
		{
			FileDeleteW(path);
		}
	}

	FreeDir(d);
	DeleteDirW(dir);
}

// The steps on node-s: the hybrid switched on, then off
static void PqTlsTestNode(PQTLSTEST_CTX *ctx)
{
	TRANSPORT *loopback = TransportLoopbackNew("loopback", 0, false);
	NODE_OVERLAY_CONFIG cfg;
	UCHAR scalar[PEER_KEY_SIZE];
	wchar_t tmp[MAX_PATH];
	wchar_t path[MAX_PATH];
	char thumbprint[MAX_SIZE];

	StrCpy(thumbprint, sizeof(thumbprint), "");

	// The keys of node-s and node-c
	bool ok = (loopback != NULL);
	for (UINT i = 0;i < PEER_KEY_SIZE;i++)
	{
		scalar[i] = (UCHAR)(0x35 + i);
		ctx->PeerScalar[i] = (UCHAR)(0x75 + i);
	}
	ok = ok && PeerKeyFromScalar(&ctx->Key, scalar) && CryptoX25519PublicKey(ctx->PeerPublic, ctx->PeerScalar);
	Zero(scalar, sizeof(scalar));

	// The certificate of the Listener: a self-signed ECDSA P-256 certificate of the LocalMachine\My store, its key in the KSP
	PCCERT_CONTEXT cert = (ok ? CryptoCertCreateSelfSigned(PQTLSTEST_CN, PQTLSTEST_SAN, NULL, 30, CRYPTO_MACHINE) : NULL);
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, CRYPTO_MACHINE));
	PqTlsTestCheck(ctx, have, "a certificate of the LocalMachine\\My store with its key in the key storage provider of the machine", "the certificate could not be made");

	if (have)
	{
		// node-s, with the overlay that applies the states of the test
		UniFormat(tmp, sizeof(tmp), L"pqtlstest_%u", Rand32());
		ConbinePathW(ctx->Dir, sizeof(ctx->Dir), MsGetMyTempDirW(), tmp);
		MakeDirExW(ctx->Dir);
		ConbinePathW(path, sizeof(path), ctx->Dir, CS_FILE_NAME);
		CONFIG_STORE *s = CsOpen(path);
		if (s != NULL)
		{
			CsSetSetting(s, NODE_SETTING_ROLES, "none");
			CsSetSetting(s, NODE_SETTING_WORKERS, "1");
			CsClose(s);
		}

		ctx->Node = NewNode(ctx->Dir);
		NodeStart(ctx->Node);

		Zero(&cfg, sizeof(cfg));
		cfg.Data = loopback;
		cfg.Key = &ctx->Key;
		if (PqTlsTestCheck(ctx, NodeOverlayStart(ctx->Node, &cfg), "the overlay of node-s runs without a control stream", "NodeOverlayStart failed"))
		{
			PqTlsTestStep(ctx, thumbprint, true);
			PqTlsTestStep(ctx, thumbprint, false);
			NodeOverlayStop(ctx->Node);
		}

		NodeStop(ctx->Node);
		FreeNode(ctx->Node);
		ctx->Node = NULL;
		PqTlsTestDeleteDir(ctx->Dir);
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, CRYPTO_MACHINE);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
	PeerKeyClose(&ctx->Key);
	Zero(ctx->PeerScalar, sizeof(ctx->PeerScalar));
	TransportLoopbackFree(loopback);
}

//
// The probe
//

// One session between the server and the client transport of a path, under the list in force: the group of each end, and
// whether both came up
static bool PqTlsTestProbePath(TRANSPORT *server, TRANSPORT *client, USHORT (*bound)(TRANSPORT *), UINT *client_group, UINT *server_group)
{
	char address[MAX_SIZE];

	*client_group = 0;
	*server_group = 0;

	TRANSPORT_LISTENER *l = TransportListen(server, PQTLSTEST_LISTEN);
	if (l == NULL)
	{
		return false;
	}

	// The client writes a byte, so that the server has the stream of a QUIC connection to accept as soon as it can
	Format(address, sizeof(address), "127.0.0.1:%u", (UINT)bound(server));
	TRANSPORT_STREAM *c = TransportDial(client, address, NULL);
	TRANSPORT_STREAM *s = (c != NULL && TransportWrite(c, "?", 1) ? TransportAccept(l, PQTLSTEST_TIMEOUT) : NULL);

	*client_group = TransportGroup(c);
	*server_group = TransportGroup(s);
	bool ok = (c != NULL && s != NULL);

	TransportClose(c);
	TransportClose(s);
	TransportCloseListener(l);

	return ok;
}

// The probe: a session over TLS-443 and one over QUIC under the list in force, between transports that set no list, and
// the group of each end, which it prints
static void PqTlsTestProbe(PQTLSTEST_CTX *ctx)
{
	TRANSPORT_TLS_HYBRID h;
	TRANSPORT_TLS_CONFIG tls_server, tls_client;
	TRANSPORT_QUIC_CONFIG quic_cfg;
	char thumbprint[MAX_SIZE];
	UINT c = 0, s = 0;

	Print("[the probe: the groups of a TLS-443 and a QUIC session under the list in force, which it changes nothing of]\n");
	PqTlsTestHost(&h);
	Print("PQTLS PROBE host %s\n", h.Asks ? "asks" : "does-not-ask");

	// A certificate of the current user's store, which the server transports load and the clients pin
	StrCpy(thumbprint, sizeof(thumbprint), "");
	PCCERT_CONTEXT cert = CryptoCertCreateSelfSigned(PQTLSTEST_CN, PQTLSTEST_SAN, NULL, 30, 0);
	bool have = (cert != NULL && CryptoCertThumbprintStr(cert, thumbprint, sizeof(thumbprint)) && CryptoCertAddToStore(cert, NULL, 0));
	if (PqTlsTestCheck(ctx, have, "a certificate of the current user's store with its key in the key storage provider", "the certificate could not be made"))
	{
		// TLS-443: TLS 1.3 on the server, as a Listener has it, and neither transport sets a list
		TransportTlsDefaultConfig(&tls_server, thumbprint, false);
		tls_server.Versions = TRANSPORT_TLS_13;
		tls_server.SetGroups = false;
		TransportTlsDefaultConfig(&tls_client, thumbprint, false);
		tls_client.SetGroups = false;
		TRANSPORT *server = TransportTlsServerNew(&tls_server);
		TRANSPORT *client = TransportTlsClientNew(&tls_client);
		bool up = (server != NULL && client != NULL && PqTlsTestProbePath(server, client, TransportTlsBoundPort, &c, &s));
		Print("PQTLS PROBE tls %s client %s 0x%04X server %s 0x%04X\n", up ? "up" : "down", TransportGroupName(c), c, TransportGroupName(s), s);
		PqTlsTestCheck(ctx, up && c != 0 && c == s, "  a TLS-443 session comes up, and both ends report one group", "up %u, client 0x%04X, server 0x%04X", (UINT)up, c, s);
		TransportTlsFree(client);
		TransportTlsFree(server);

		// QUIC, where msquic.dll is next to vpntest
		if (TransportQuicAvailable())
		{
			TransportQuicDefaultConfig(&quic_cfg, thumbprint, false);
			server = TransportQuicServerNew(&quic_cfg);
			client = TransportQuicClientNew(&quic_cfg);
			up = (server != NULL && client != NULL && PqTlsTestProbePath(server, client, TransportQuicBoundPort, &c, &s));
			Print("PQTLS PROBE quic %s client %s 0x%04X server %s 0x%04X\n", up ? "up" : "down", TransportGroupName(c), c, TransportGroupName(s), s);
			PqTlsTestCheck(ctx, up && c != 0 && c == s, "  a QUIC session comes up, and both ends report one group", "up %u, client 0x%04X, server 0x%04X", (UINT)up, c, s);
			TransportQuicFree(client);
			TransportQuicFree(server);
		}
		else
		{
			Print("PQTLS PROBE quic none (msquic.dll is not next to vpntest)\n");
		}
	}

	if (cert != NULL)
	{
		CryptoCertRemoveFromStore(thumbprint, NULL, 0);
		CryptoCertDeleteKey(cert);
		CryptoCertFree(cert);
	}
}

RANZ_TEST_TAGS("pqtls", pqtls_test, "core", "The post-quantum key exchange of QUIC and TLS-443 (CORE-P2-5): with the hybrid switched on, a Node offers X25519MLKEM768 first and reports pq_tls, and the sessions of two Nodes negotiate it as both stacks report it where CNG has ML-KEM; switched off, a Node offers X25519 first, the sessions come up with a classical group, and no pq_tls; \"pqtls probe\" prints the groups under the list in force (administrator rights).");
void pqtls_test(UINT num, char **arg)
{
	PQTLSTEST_CTX *ctx = ZeroMalloc(sizeof(PQTLSTEST_CTX));
	HANDLE done = CreateEventW(NULL, TRUE, FALSE, NULL);
	HANDLE watchdog = (done != NULL ? CreateThread(NULL, 0, PqTlsTestWatchdog, done, 0, NULL) : NULL);
	bool probe = (num >= 1 && StrCmpi(arg[0], "probe") == 0);

	Print("Post-quantum key exchange test: the group that the QUIC and the TLS-443 session of two Nodes negotiate, with the hybrid switched on and off\n");

	if (PqTlsTestCheck(ctx, CryptoInit(), "the crypto module of the new core runs on CNG", "CryptoInit failed"))
	{
		if (probe)
		{
			PqTlsTestProbe(ctx);
		}
		else
		{
			// The two lists as the test found them, which it puts back at the end, or its watchdog does
			PqTlsTestSave(PQTLSTEST_LIST_KEY, &pqtlstest_machine);
			PqTlsTestSave(PQTLSTEST_POLICY_KEY, &pqtlstest_policy);
			InterlockedExchange(&pqtlstest_saved, 1);

			PqTlsTestNames(ctx);
			PqTlsTestNode(ctx);

			Print("[the lists of the machine as the test found them]\n");
			PqTlsTestCheck(ctx, PqTlsTestRestore(), "  the policy and the machine's list are back", "they could not be put back");
			InterlockedExchange(&pqtlstest_saved, 0);
		}
	}

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
		Print("PQTLS TEST OK\n");
	}
	else
	{
		Print("PQTLS TEST FAILED (%u of %u checks failed)\n", ctx->NumFailed, ctx->NumChecks);
	}

	Free(ctx);
}
