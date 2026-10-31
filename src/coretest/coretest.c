// coretest.c
// Test program of the new core: the known-answer and certificate tests of the crypto module
// (src/Core; CORE-F1, #61), the tests of the session module, its handshake, session and tunnel
// (CORE-F2, #62), the tests of the peer module on the NAT simulator of natsim.c (CORE-S5-2,
// #78), and of its ICE and port mapping on the loopback interfaces with the home gateway of
// homegw.c (CORE-S5-3, #79), in a program that links these modules and nothing of the slim fork,
// so that it also shows that they need no OpenSSL and no liboqs.
//
// Usage: coretest <test> | coretest all. Each named test prints "<TEST> TEST OK" or
// "<TEST> TEST FAILED" (.github/scripts/coretest.ps1 looks for the first) and the exit code is
// 0 when every test that ran passed.

#include "coretest.h"

#include <stdarg.h>
#include <string.h>

// Failed checks of the running test
static UINT coretest_fails = 0;

bool coretest_check(bool passed, const char *what) {
	if (passed) {
		printf("  [PASS] %s\n", what);
	} else {
		printf("  [FAIL] %s\n", what);
		coretest_fails++;
	}

	return passed;
}

void coretest_info(const char *format, ...) {
	va_list args;

	printf("  [INFO] ");
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
	printf("\n");
}

// Print a byte string in hex
static void coretest_print_hex(const char *label, const UCHAR *data, UINT size) {
	printf("         %s ", label);
	for (UINT i = 0; i < size; i++)
		printf("%02x", data[i]);
	printf("\n");
}

static int coretest_hex_digit(char c) {
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

UINT coretest_unhex(UCHAR *dst, UINT size, const char *hex) {
	UINT n = 0;

	while (n < size && hex[0] != 0 && hex[1] != 0) {
		int hi = coretest_hex_digit(hex[0]);
		int lo = coretest_hex_digit(hex[1]);
		if (hi < 0 || lo < 0)
			break;
		dst[n++] = (UCHAR)(hi * 16 + lo);
		hex += 2;
	}

	return n;
}

bool coretest_check_hex(const void *got, UINT size, const char *expect_hex, const char *what) {
	UCHAR *expect = (UCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
	bool same = false;

	if (expect != NULL) {
		same = strlen(expect_hex) == 2 * (size_t)size && coretest_unhex(expect, size, expect_hex) == size && memcmp(got, expect, size) == 0;
		if (same == false) {
			coretest_print_hex("got     ", (const UCHAR *)got, size);
			printf("         expected %s\n", expect_hex);
		}
		HeapFree(GetProcessHeap(), 0, expect);
	}

	return coretest_check(same, what);
}

bool coretest_elevated() {
	HANDLE token = NULL;
	TOKEN_ELEVATION elevation;
	DWORD size = 0;
	bool elevated = false;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
			elevated = elevation.TokenIsElevated != 0;
		CloseHandle(token);
	}

	return elevated;
}

UINT coretest_scope() {
	return coretest_elevated() ? CRYPTO_MACHINE : 0;
}

const char *coretest_scope_name() {
	return coretest_elevated() ? "machine key set and LocalMachine store (elevated, as the service)" : "current user's key set and store (not elevated)";
}

// The Windows version and the processor, from RtlGetVersion (GetVersionEx answers what the
// manifest declares)
static void coretest_print_system() {
	typedef LONG(WINAPI * RTL_GET_VERSION)(OSVERSIONINFOW *);
	OSVERSIONINFOW v;
	SYSTEM_INFO si;

	ZeroMemory(&v, sizeof(v));
	v.dwOSVersionInfoSize = sizeof(v);
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	RTL_GET_VERSION get_version = ntdll != NULL ? (RTL_GET_VERSION)(void *)GetProcAddress(ntdll, "RtlGetVersion") : NULL;
	if (get_version != NULL)
		get_version(&v);

	GetNativeSystemInfo(&si);
	const char *arch = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? "x64"
	                   : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "arm64"
	                                                                               : "other";

	printf("Windows %lu.%lu build %lu, %s\n", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber, arch);
}

typedef void(TEST_PROC)();

typedef struct TEST_LIST {
	char *command_str;
	TEST_PROC *proc;
	char *help;
} TEST_LIST;

static TEST_LIST test_list[] = {
    {"rand", rand_test, "System random generator: sizes, distinct outputs, the share of zero bytes in 1 MiB."},
    {"sha256", sha256_test, "SHA-256 against the FIPS 180-2 vectors, in one call and over parts."},
    {"hmac", hmac_test, "HMAC-SHA256 against the RFC 4231 test cases."},
    {"hkdf", hkdf_test, "HKDF-SHA256 against RFC 5869 A.1 to A.3, Expand alone, an empty IKM, the output limit."},
    {"aesgcm", aesgcm_test, "AES-128-GCM and AES-256-GCM against the GCM specification test cases; tag, AAD and nonce tampering."},
    {"x25519", x25519_test, "X25519 against RFC 7748 5.2 and 6.1, the iterated test, clamping, masking, reduction, low-order points."},
    {"identity", identity_test, "Node identity key in the software KSP: RFC 7748 6.1 through NCrypt, open, create, delete."},
    {"mlkem", mlkem_test, "ML-KEM-768 and the X25519MLKEM768 hybrid where the OS has it; omitted, without failing, where not."},
    {"cryptorefusal", cryptorefusal_test, "Refusals of the crypto module: missing arguments, released state, an ML-KEM key out of range, a key of another curve; outputs zeroed, keys released."},
    {"selfsign", selfsign_test, "Self-signed ECDSA P-256 certificate on a CNG key: signature, algorithms, extensions, key in the KSP."},
    {"pfx", pfx_test, "PFX of OpenSSL 3 defaults (PBES2, AES-256-CBC, SHA-256 MAC) into the KSP; wrong password and no PFX refused."},
    {"certstore", certstore_test, "Certificate store: add, find by thumbprint, remove; malformed thumbprints refused."},
    {"schannel", schannel_test, "Schannel TLS 1.3 in memory with the server key in the KSP: store certificate and PFX, data both ways."},
    {"noise", noise_test, "Noise_IK_25519_AESGCM_SHA256 against the cacophony vector, static keys as scalars and in the KSP; rekey; the rules."},
    {"noisehfs", noisehfs_test, "Noise_IKhfs_25519+MLKEM768_AESGCM_SHA256 where the OS has ML-KEM: both sides, sizes, a changed e1 or ekem1."},
    {"noisesession", noisesession_test, "Noise session: golden transcripts, channel binding, Login, keepalive, dead timeout, rekey on a schedule."},
    {"noisetunnel", noisetunnel_test, "Tunnel: flows over N = 1 and N = 4 connections, a lost connection's flows move, independent rekey; the flow hash of a frame."},
    {"noiseinterop", noiseinterop_test, "Interop with flynn/noise (ranz-noisepeer): both roles, rekey, handshake hash; another prologue or key fails."},
    {"envelope", envelope_test, "Signal and bind envelopes (Noise_K_25519_AESGCM_SHA256) against their known answers, in memory and in the KSP; every altered bit refused."},
    {"relay", relay_test, "Two nodes behind symmetric NATs come up through a relay in one round trip and their traffic flows at once; the direct path is blocked."},
    {"relaypolicy", relaypolicy_test, "Forged, altered, replayed and redirected signals and binds refused; the relay's VRF policy and rate; one ingress for direct and relayed; relay restart."},
    {"iceupgrade", iceupgrade_test, "A home gateway grants a public port through libplum; a relayed pair moves to the direct path that ICE validates with no datagram missing, and back when it fails."},
    {"icesymmetric", icesymmetric_test, "A pair behind two symmetric NATs: every ICE check fails and the pair stays on the relay, with its traffic flowing throughout."},
    {"punch", punch_test, "Symmetric-NAT traversal: two sequential NATs meet by port prediction, a cone and a random NAT by birthday punching, two random NATs take no punch and stay on the relay, and the attempts of a pair whose path is cut keep to the budget and the rate and stop for the backoff."},
    {"peersession", peersession_test, "Peer sessions: no inner byte in the clear on any link, relayed or direct; altered, replayed and misdirected records refused; one session from two handshakes; rekey and timeout without loss."},
    {"frontdoor", frontdoor_test, "Front door, the node and its owners as processes: TLS of the new protocol stays in the node, other ALPN or SNI and a signature reach their owner processes through WSADuplicateSocketW; a handed connection outlives the node."},
    {"quicexporter", quicexporter_test, "QUIC exporter: only the pinned msquic minor is read; another minor, a table without the entry and a connection without an exporter are refused, each side logged once."},
    {"fallback", fallback_test, "Fallback after a handshake: a server that refuses the handshake over QUIC is reached over TLS-443 at the next dial; QUIC comes back after its hold."},
    {"iceanswer", iceanswer_test, "An ICE session of an offer whose answer is lost fails after about 40 s while the pair stays on the relay; ICE runs again for the pair and moves it to the direct path."},
    {"iceinput", iceinput_test, "A STUN message to the ICE socket is read once, whatever the number of ICE sessions, and goes to the session that its username fragment or its transaction names; the others are dropped."},
};

#define NUM_TESTS (sizeof(test_list) / sizeof(test_list[0]))

// Run one test and print its marker; true when it passed
static bool coretest_run(TEST_LIST *t) {
	char upper[64];
	UINT i;

	for (i = 0; t->command_str[i] != 0 && i < sizeof(upper) - 1; i++)
		upper[i] = (char)((t->command_str[i] >= 'a' && t->command_str[i] <= 'z') ? t->command_str[i] - 'a' + 'A' : t->command_str[i]);
	upper[i] = 0;

	printf("%s: %s\n", t->command_str, t->help);
	coretest_fails = 0;
	t->proc();
	printf("%s TEST %s\n\n", upper, coretest_fails == 0 ? "OK" : "FAILED");
	fflush(stdout);

	return coretest_fails == 0;
}

int main(int argc, char *argv[]) {
	UINT failed = 0;
	bool found = false;

	// A node or an owner process of the front door test, which prints only what the test reads
	if (argc >= 2 && _stricmp(argv[1], CORETEST_FRONTDOOR_CHILD) == 0)
		return frontdoor_child(argc, argv);

	printf("coretest: tests of the Ranz VPN new core\n");
	coretest_print_system();

	if (argc < 2) {
		printf("Usage: coretest <test> | coretest all\n\n");
		for (UINT i = 0; i < NUM_TESTS; i++)
			printf(" '%s' : %s\n", test_list[i].command_str, test_list[i].help);
		return 2;
	}

	if (CryptoInit() == false)
		printf("CryptoInit(): the CNG curve25519 provider is missing\n");
	printf("ML-KEM in CNG: %s\n\n", CryptoMlKemAvailable() ? "yes" : "no");

	for (UINT i = 0; i < NUM_TESTS; i++) {
		if (_stricmp(argv[1], "all") == 0 || _stricmp(argv[1], test_list[i].command_str) == 0) {
			found = true;
			if (coretest_run(&test_list[i]) == false)
				failed++;
		}
	}

	if (found == false) {
		printf("Invalid test: %s\n", argv[1]);
		return 2;
	}

	return failed == 0 ? 0 : 1;
}
