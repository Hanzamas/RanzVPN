// interop.c
// The interop check of the session module (src/Core/Noise.h; CORE-F2, #62) against an
// established Noise implementation: flynn/noise (github.com/flynn/noise v1.1.0, the library of the
// controller's control stream) in ranz-noisepeer (controller/cmd/ranz-noisepeer). The test starts
// the peer for each case and runs the peer's script over its standard input and output: the
// Noise_IK_25519_AESGCM_SHA256 handshake with payloads, transport messages both ways with a rekey
// of all four cipher states in the middle, and the handshake hashes. The module is the initiator
// once and the responder once (with its static key in the key storage provider, as on a node);
// a prologue that differs, as a channel binding to another TLS session gives, and a wrong pinned
// key fail on both sides.
//
// The peer is ranz-noisepeer.exe next to coretest.exe, or the file that RANZ_NOISE_PEER names.
// Build it with: go build -o build/ranz-noisepeer.exe ./cmd/ranz-noisepeer (in controller/).

#include "coretest.h"

#include "Core/Noise.h"

#include <string.h>

#define INTEROP_TIMEOUT  20000 // A read from the peer, or its exit, within this time (ms)
#define INTEROP_MESSAGES 4     // The peer's -messages
#define INTEROP_REKEY    2     // The peer's -rekey: both ends rekey before this round

// The peer's process and the two pipes to it
typedef struct INTEROP_PEER {
	HANDLE Process;
	HANDLE In;  // The peer's standard input, written here
	HANDLE Out; // The peer's standard output, read here
} INTEROP_PEER;

// The path of ranz-noisepeer.exe: RANZ_NOISE_PEER, or the directory of coretest.exe
static bool interop_peer_path(wchar_t *path, UINT size) {
	DWORD n = GetEnvironmentVariableW(L"RANZ_NOISE_PEER", path, size);

	if (n == 0 || n >= size) {
		n = GetModuleFileNameW(NULL, path, size);
		if (n == 0 || n >= size)
			return false;
		wchar_t *slash = wcsrchr(path, L'\\');
		if (slash == NULL || (UINT)(slash - path) + 20 >= size)
			return false;
		wcscpy_s(slash + 1, size - (UINT)(slash + 1 - path), L"ranz-noisepeer.exe");
	}

	return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static void interop_hex(char *dst, const UCHAR *src, UINT size) {
	static const char hex[] = "0123456789abcdef";

	for (UINT i = 0; i < size; i++) {
		dst[2 * i] = hex[src[i] >> 4];
		dst[2 * i + 1] = hex[src[i] & 0x0F];
	}
	dst[2 * size] = 0;
}

// Start the peer as initiator or responder with its static scalar, the responder's public key
// (initiator only) and the prologue
static bool interop_start(INTEROP_PEER *p, const wchar_t *exe, bool initiator, const UCHAR *static_key, const UCHAR *remote, const UCHAR *prologue, UINT prologue_size) {
	char static_hex[2 * NOISE_KEY_SIZE + 1], remote_hex[2 * NOISE_KEY_SIZE + 1], prologue_hex[2 * NOISE_MAX_PROLOGUE + 1];
	wchar_t cmd[1024];
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE child_in = NULL, child_out = NULL, child_err = NULL;
	bool ok = false;

	ZeroMemory(p, sizeof(INTEROP_PEER));
	if (prologue_size > NOISE_MAX_PROLOGUE)
		return false;
	interop_hex(static_hex, static_key, NOISE_KEY_SIZE);
	interop_hex(remote_hex, remote != NULL ? remote : static_key, NOISE_KEY_SIZE);
	interop_hex(prologue_hex, prologue, prologue_size);
	_snwprintf_s(cmd, sizeof(cmd) / sizeof(wchar_t), _TRUNCATE, L"\"%s\" -initiator=%S -static=%S%S%S -prologue=%S -messages=%u -rekey=%u", exe,
	             initiator ? "true" : "false", static_hex, initiator ? " -remote=" : "", initiator ? remote_hex : "", prologue_hex, INTEROP_MESSAGES, INTEROP_REKEY);

	// The ends of the pipes that the peer gets are inherited, the ones kept here are not; its
	// standard error goes to this program's output, so its messages are in the log
	ZeroMemory(&sa, sizeof(sa));
	sa.nLength = sizeof(sa);
	sa.bInheritHandle = TRUE;
	if (CreatePipe(&child_in, &p->In, &sa, 0) == false || CreatePipe(&p->Out, &child_out, &sa, 0) == false ||
	    SetHandleInformation(p->In, HANDLE_FLAG_INHERIT, 0) == false || SetHandleInformation(p->Out, HANDLE_FLAG_INHERIT, 0) == false ||
	    DuplicateHandle(GetCurrentProcess(), GetStdHandle(STD_OUTPUT_HANDLE), GetCurrentProcess(), &child_err, 0, TRUE, DUPLICATE_SAME_ACCESS) == false)
		goto END;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = child_in;
	si.hStdOutput = child_out;
	si.hStdError = child_err;
	ZeroMemory(&pi, sizeof(pi));
	fflush(stdout);
	if (CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) == false) {
		coretest_info("CreateProcess of the peer: error %lu", GetLastError());
		goto END;
	}

	CloseHandle(pi.hThread);
	p->Process = pi.hProcess;
	ok = true;

END:
	if (child_in != NULL)
		CloseHandle(child_in);
	if (child_out != NULL)
		CloseHandle(child_out);
	if (child_err != NULL)
		CloseHandle(child_err);
	if (ok == false) {
		if (p->In != NULL)
			CloseHandle(p->In);
		if (p->Out != NULL)
			CloseHandle(p->Out);
		ZeroMemory(p, sizeof(INTEROP_PEER));
	}

	return ok;
}

// Read exactly size bytes from the peer, within INTEROP_TIMEOUT; false when it ended first
static bool interop_read_bytes(INTEROP_PEER *p, UCHAR *buf, UINT size) {
	UINT64 end = GetTickCount64() + INTEROP_TIMEOUT;
	UINT got = 0;

	while (got < size) {
		DWORD avail = 0;
		DWORD n = 0;

		// A peer that exited leaves a broken pipe once its output is read
		if (PeekNamedPipe(p->Out, NULL, 0, NULL, &avail, NULL) == false)
			return false;
		if (avail == 0) {
			if (GetTickCount64() >= end)
				return false;
			Sleep(1);
			continue;
		}
		if (ReadFile(p->Out, buf + got, avail < size - got ? avail : size - got, &n, NULL) == false || n == 0)
			return false;
		got += n;
	}

	return true;
}

// One message from the peer: a 4-byte big-endian length, then the message
static bool interop_read(INTEROP_PEER *p, UCHAR *msg, UINT max, UINT *size) {
	UCHAR hdr[4];

	*size = 0;
	if (interop_read_bytes(p, hdr, 4) == false)
		return false;

	UINT n = ((UINT)hdr[0] << 24) | ((UINT)hdr[1] << 16) | ((UINT)hdr[2] << 8) | hdr[3];
	if (n > max || (n != 0 && interop_read_bytes(p, msg, n) == false))
		return false;

	*size = n;
	return true;
}

static bool interop_write(INTEROP_PEER *p, const UCHAR *msg, UINT size) {
	UCHAR hdr[4] = {(UCHAR)(size >> 24), (UCHAR)(size >> 16), (UCHAR)(size >> 8), (UCHAR)size};
	DWORD n = 0;

	if (WriteFile(p->In, hdr, 4, &n, NULL) == false || n != 4)
		return false;

	return size == 0 || (WriteFile(p->In, msg, size, &n, NULL) && n == size);
}

// Close the peer's input and wait for its exit code; a peer that hangs is ended
static DWORD interop_finish(INTEROP_PEER *p) {
	DWORD code = 0xFFFFFFFF;

	if (p->In != NULL)
		CloseHandle(p->In);
	if (p->Process != NULL) {
		if (WaitForSingleObject(p->Process, INTEROP_TIMEOUT) != WAIT_OBJECT_0) {
			coretest_info("the peer did not exit within %u ms: ended", INTEROP_TIMEOUT);
			TerminateProcess(p->Process, 0xFFFFFFFF);
			WaitForSingleObject(p->Process, INTEROP_TIMEOUT);
		}
		GetExitCodeProcess(p->Process, &code);
		CloseHandle(p->Process);
	}
	if (p->Out != NULL)
		CloseHandle(p->Out);
	ZeroMemory(p, sizeof(INTEROP_PEER));

	return code;
}

static bool interop_send(INTEROP_PEER *p, NOISE_CIPHER *c, const void *data, UINT size) {
	UCHAR msg[256];

	return size + NOISE_TAG_SIZE <= sizeof(msg) && NoiseCipherEncrypt(c, NULL, 0, data, size, msg) && interop_write(p, msg, size + NOISE_TAG_SIZE);
}

static bool interop_expect(INTEROP_PEER *p, NOISE_CIPHER *c, const void *want, UINT want_size) {
	UCHAR msg[256], out[256];
	UINT size = 0;

	return interop_read(p, msg, sizeof(msg), &size) && size == want_size + NOISE_TAG_SIZE && NoiseCipherDecrypt(c, NULL, 0, msg, size, out) &&
	       memcmp(out, want, want_size) == 0;
}

// This module's side of the peer's script on hs; true when every message checked out
static bool interop_script(INTEROP_PEER *p, NOISE_HANDSHAKE *hs) {
	UCHAR msg[512], out[512];
	UINT size = 0, out_size = 0;
	NOISE_CIPHER send, recv;
	char ping[16], pong[16];
	bool ok;

	if (hs->Initiator)
		ok = NoiseHandshakeWrite(hs, "ranz interop 1", 14, msg, sizeof(msg), &size) && interop_write(p, msg, size) && interop_read(p, msg, sizeof(msg), &size) &&
		     NoiseHandshakeRead(hs, msg, size, out, sizeof(out), &out_size) && out_size == 14 && memcmp(out, "ranz interop 2", 14) == 0;
	else
		ok = interop_read(p, msg, sizeof(msg), &size) && NoiseHandshakeRead(hs, msg, size, out, sizeof(out), &out_size) && out_size == 14 &&
		     memcmp(out, "ranz interop 1", 14) == 0 && NoiseHandshakeWrite(hs, "ranz interop 2", 14, msg, sizeof(msg), &size) && interop_write(p, msg, size);
	if (ok == false || NoiseHandshakeSplit(hs, &send, &recv) == false)
		return false;

	for (UINT i = 0; ok && i < INTEROP_MESSAGES; i++) {
		if (i == INTEROP_REKEY)
			ok = NoiseCipherRekey(&send) && NoiseCipherRekey(&recv);
		_snprintf_s(ping, sizeof(ping), _TRUNCATE, "ping %u", i);
		_snprintf_s(pong, sizeof(pong), _TRUNCATE, "pong %u", i);
		if (hs->Initiator)
			ok = ok && interop_send(p, &send, ping, (UINT)strlen(ping)) && interop_expect(p, &recv, pong, (UINT)strlen(pong));
		else
			ok = ok && interop_expect(p, &recv, ping, (UINT)strlen(ping)) && interop_send(p, &send, pong, (UINT)strlen(pong));
	}

	// The handshake hashes, the channel binding of the session, are the same
	if (hs->Initiator)
		ok = ok && interop_send(p, &send, hs->H, NOISE_KEY_SIZE) && interop_expect(p, &recv, hs->H, NOISE_KEY_SIZE);
	else
		ok = ok && interop_expect(p, &recv, hs->H, NOISE_KEY_SIZE) && interop_send(p, &send, hs->H, NOISE_KEY_SIZE);

	NoiseCipherFree(&send);
	NoiseCipherFree(&recv);
	return ok;
}

// One case: the peer started with its keys and prologue, this module's side on hs; what each side
// made of it
static void interop_case(const wchar_t *exe, bool peer_initiator, const UCHAR *peer_static, const UCHAR *peer_remote, const UCHAR *peer_prologue, UINT peer_prologue_size,
                         NOISE_HANDSHAKE *hs, bool expect_ok, const char *what) {
	INTEROP_PEER p;

	if (interop_start(&p, exe, peer_initiator, peer_static, peer_remote, peer_prologue, peer_prologue_size) == false) {
		coretest_check(false, what);
		return;
	}

	bool ours = interop_script(&p, hs);
	DWORD code = interop_finish(&p);

	coretest_info("this module: %s; flynn/noise: exit code %lu", ours ? "script passed" : "script failed", code);
	if (expect_ok)
		coretest_check(ours && code == 0, what);
	else
		coretest_check(ours == false && code != 0, what);
}

void noiseinterop_test() {
	wchar_t exe[MAX_PATH], name[64];
	UCHAR client[NOISE_KEY_SIZE], client_pub[NOISE_KEY_SIZE], server[NOISE_KEY_SIZE], server_pub[NOISE_KEY_SIZE], other[NOISE_KEY_SIZE], other_pub[NOISE_KEY_SIZE];
	UCHAR binding[NOISE_EXPORTER_SIZE], prologue[NOISE_MAX_PROLOGUE], prologue2[NOISE_MAX_PROLOGUE];
	NOISE_HANDSHAKE hs;
	CRYPTO_IDENTITY id;

	if (coretest_check(interop_peer_path(exe, MAX_PATH), "ranz-noisepeer.exe (flynn/noise) found next to coretest.exe or in RANZ_NOISE_PEER") == false) {
		coretest_info("build it in controller/: go build -o ../build/ranz-noisepeer.exe ./cmd/ranz-noisepeer");
		return;
	}
	coretest_info("peer: %ls", exe);

	// The two nodes, and a prologue as a session bound to a TLS exporter has it
	CryptoX25519GenerateKey(client, client_pub);
	CryptoX25519GenerateKey(server, server_pub);
	CryptoX25519GenerateKey(other, other_pub);
	CryptoRandom(binding, sizeof(binding));
	UINT prologue_size = NoisePrologue(prologue, sizeof(prologue), NOISE_BINDING_EXPORTER, binding, sizeof(binding));
	binding[0] ^= 0x01;
	UINT prologue2_size = NoisePrologue(prologue2, sizeof(prologue2), NOISE_BINDING_EXPORTER, binding, sizeof(binding));

	printf("  this module the initiator, flynn/noise the responder:\n");
	if (NoiseHandshakeInit(&hs, NOISE_SUITE_IK, true, prologue, prologue_size, client, NULL, server_pub))
		interop_case(exe, false, server, NULL, prologue, prologue_size, &hs, true, "handshake, payloads, transport both ways with a rekey, same handshake hash");
	NoiseHandshakeFree(&hs);

	printf("  flynn/noise the initiator, this module the responder with its static key in the key storage provider:\n");
	_snwprintf_s(name, sizeof(name) / sizeof(wchar_t), _TRUNCATE, L"Ranz-coretest-interop-%lu", GetCurrentProcessId());
	if (coretest_check(CryptoIdentityCreate(&id, name, coretest_scope()) && CryptoIdentityPublicKey(&id, server_pub), "a node identity key in the provider")) {
		if (NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue, prologue_size, NULL, &id, NULL)) {
			interop_case(exe, true, client, server_pub, prologue, prologue_size, &hs, true, "handshake, payloads, transport both ways with a rekey, same handshake hash");
			coretest_check(memcmp(hs.RemoteStatic, client_pub, NOISE_KEY_SIZE) == 0, "the module learnt flynn/noise's static key");
		}
		NoiseHandshakeFree(&hs);

		printf("  a prologue that differs (another TLS session), flynn/noise the initiator:\n");
		if (NoiseHandshakeInit(&hs, NOISE_SUITE_IK, false, prologue2, prologue2_size, NULL, &id, NULL))
			interop_case(exe, true, client, server_pub, prologue, prologue_size, &hs, false, "both sides fail");
		NoiseHandshakeFree(&hs);
		CryptoIdentityDelete(&id);
	}

	CryptoX25519PublicKey(server_pub, server);
	printf("  a prologue that differs, this module the initiator:\n");
	if (NoiseHandshakeInit(&hs, NOISE_SUITE_IK, true, prologue, prologue_size, client, NULL, server_pub))
		interop_case(exe, false, server, NULL, prologue2, prologue2_size, &hs, false, "both sides fail");
	NoiseHandshakeFree(&hs);

	printf("  this module pins another responder key:\n");
	if (NoiseHandshakeInit(&hs, NOISE_SUITE_IK, true, prologue, prologue_size, client, NULL, other_pub))
		interop_case(exe, false, server, NULL, prologue, prologue_size, &hs, false, "both sides fail");
	NoiseHandshakeFree(&hs);

	SecureZeroMemory(client, sizeof(client));
	SecureZeroMemory(server, sizeof(server));
	SecureZeroMemory(other, sizeof(other));
}
