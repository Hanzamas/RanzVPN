// TransportGroup.c
// The key exchange of the outer session of the QUIC and TLS-443 paths (CORE-P2-5, #382; Core/Transport.h): the names of the
// TLS groups, which of them are quantum-resistant, and whether the host asks for X25519MLKEM768 on both paths
// (TransportTlsHybrid), the Capability pq_tls of a node. The group of a stream itself is what its transport read from its
// stack once the handshake completed (TlsStreamGroup of TransportTls.c, QuicStreamGroup of TransportQuic.c), which
// TransportGroup (Transport.c) gives.
//
// The list in force is read as Schannel reads it: the value EccCurves of an ECC Curve Order policy where it is set, else
// the one of the machine, which TransportTlsSetGroups writes, else the default of Windows (TransportTls.c names the three).
// Schannel takes a change of the machine's list at once, and a policy that changed since Windows started when it starts
// again, so the policy is read as it will hold.

#include "Core/Transport.h"

#include <string.h>
#include <wchar.h>

// The machine's Schannel group list and the ECC Curve Order policy that wins over it, as TransportTls.c names them
#define GROUP_LIST_KEY   L"SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002"
#define GROUP_POLICY_KEY L"SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
#define GROUP_LIST_VALUE L"EccCurves"
#define GROUP_LIST_SIZE  2048               // Characters of a group list
#define GROUP_NAME_SIZE  128                // Bytes of one group name in UTF-8, with its NUL
#define GROUP_HYBRID     L"x25519_mlkem768" // X25519MLKEM768 by its Schannel name

// The TLS NamedGroups of the IANA registry that Windows has, besides CRYPTO_GROUP_X25519 and CRYPTO_GROUP_X25519MLKEM768
#define GROUP_SECP256R1          0x0017
#define GROUP_SECP384R1          0x0018
#define GROUP_SECP521R1          0x0019
#define GROUP_MLKEM512           0x0200
#define GROUP_MLKEM768           0x0201
#define GROUP_MLKEM1024          0x0202
#define GROUP_SECP256R1MLKEM768  0x11EB
#define GROUP_SECP384R1MLKEM1024 0x11ED

// The default list of Windows 11 24H2 and Windows Server 2025 where the machine has none of its own, as a REG_MULTI_SZ:
// the list of TransportTls.c, which names no hybrid
static const wchar_t group_default_list[] = L"curve25519\0NistP256\0NistP384\0";

const char *TransportGroupName(UINT group) {
	switch (group) {
	case 0:
		return "none";
	case CRYPTO_GROUP_X25519:
		return "X25519";
	case CRYPTO_GROUP_X25519MLKEM768:
		return "X25519MLKEM768";
	case GROUP_SECP256R1:
		return "secp256r1";
	case GROUP_SECP384R1:
		return "secp384r1";
	case GROUP_SECP521R1:
		return "secp521r1";
	case GROUP_MLKEM512:
		return "MLKEM512";
	case GROUP_MLKEM768:
		return "MLKEM768";
	case GROUP_MLKEM1024:
		return "MLKEM1024";
	case GROUP_SECP256R1MLKEM768:
		return "SecP256r1MLKEM768";
	case GROUP_SECP384R1MLKEM1024:
		return "SecP384r1MLKEM1024";
	default:
		return "unknown";
	}
}

bool TransportGroupPostQuantum(UINT group) {
	switch (group) {
	case CRYPTO_GROUP_X25519MLKEM768:
	case GROUP_SECP256R1MLKEM768:
	case GROUP_SECP384R1MLKEM1024:
	case GROUP_MLKEM512:
	case GROUP_MLKEM768:
	case GROUP_MLKEM1024:
		return true;
	default:
		return false;
	}
}

// The list of the value EccCurves of key into list, GROUP_LIST_SIZE characters, which stays zeroed beyond what the value
// holds, so that its last two characters stay NUL and a list without its last NUL still ends: true when the value is there
// and is a list
static bool GroupListOf(const wchar_t *key, wchar_t *list) {
	DWORD size = (GROUP_LIST_SIZE - 2) * sizeof(wchar_t);

	ZeroMemory(list, GROUP_LIST_SIZE * sizeof(wchar_t));
	return (RegGetValueW(HKEY_LOCAL_MACHINE, key, GROUP_LIST_VALUE, RRF_RT_REG_MULTI_SZ, NULL, list, &size) == ERROR_SUCCESS);
}

// Add the group of len characters to the text of h, after ", " when it holds one already, as much of it as fits
static void GroupAddText(TRANSPORT_TLS_HYBRID *h, const wchar_t *group, UINT len) {
	char name[GROUP_NAME_SIZE];
	int n = WideCharToMultiByte(CP_UTF8, 0, group, (int)len, name, sizeof(name) - 1, NULL, NULL);

	if (n <= 0)
		return;
	name[n] = 0;

	if (h->Text[0] != 0)
		strncat_s(h->Text, sizeof(h->Text), ", ", _TRUNCATE);
	strncat_s(h->Text, sizeof(h->Text), name, _TRUNCATE);
}

void TransportTlsHybrid(TRANSPORT_TLS_HYBRID *h) {
	DWORD policy_size = 0;

	if (h == NULL)
		return;

	ZeroMemory(h, sizeof(TRANSPORT_TLS_HYBRID));
	h->MlKem = CryptoMlKemAvailable();

	wchar_t *list = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, GROUP_LIST_SIZE * sizeof(wchar_t));
	if (list == NULL)
		return;

	// A policy wins wherever its value is, whatever it holds, as TransportTlsSetGroups takes it; then the machine's own
	// list; then the default of Windows
	if (RegGetValueW(HKEY_LOCAL_MACHINE, GROUP_POLICY_KEY, GROUP_LIST_VALUE, RRF_RT_ANY, NULL, NULL, &policy_size) == ERROR_SUCCESS) {
		h->List = TRANSPORT_TLS_LIST_POLICY;
		(void)GroupListOf(GROUP_POLICY_KEY, list);
	} else if (GroupListOf(GROUP_LIST_KEY, list)) {
		h->List = TRANSPORT_TLS_LIST_MACHINE;
	} else {
		h->List = TRANSPORT_TLS_LIST_DEFAULT;
		CopyMemory(list, group_default_list, sizeof(group_default_list));
	}

	// Each group of the list, read within the buffer, whose last two characters stay NUL: its length is counted within what
	// is left of the buffer, as TransportTlsSetGroups counts it, so that the next group starts inside the buffer too
	for (UINT i = 0; i < GROUP_LIST_SIZE - 1 && list[i] != 0;) {
		UINT len = 0;

		while (len < GROUP_LIST_SIZE - 1 - i && list[i + len] != 0)
			len++;
		if (CompareStringOrdinal(list + i, (int)len, GROUP_HYBRID, -1, TRUE) == CSTR_EQUAL) {
			h->Listed = true;
			if (i == 0)
				h->First = true;
		}
		GroupAddText(h, list + i, len);
		i += len + 1;
	}

	// Schannel offers the groups of the list in its order, the hybrid only where CNG has ML-KEM: a host asks for the hybrid
	// when it is first
	h->Asks = (h->MlKem && h->First);

	HeapFree(GetProcessHeap(), 0, list);
}
