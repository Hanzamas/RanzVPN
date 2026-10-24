// TransportDecoy.c
// The own-decoy reverse proxy of the TLS transport (CORE-S2-2, #70): the Trojan posture. After the
// TLS handshake a server reads the first application bytes of a stream (TransportTls.c). A client
// that opens a valid Ranz session sends the first Noise handshake frame there; a prober that sends
// anything else, or a handshake message that does not authenticate, is reverse-proxied to a website
// the operator runs on the loopback interface, so it meets an ordinary HTTPS site byte for byte over
// the same TLS session it opened. The module tells a prober from a valid client by the first
// handshake message: its shape (TransportDecoyIsHandshake, the structural test the session layer
// makes), then the Noise message read with the server's static key and the channel binding of the
// stream (TransportDecoyAuthenticate), which only a client that knows the server's key can write. It
// carries bytes between the prober and the backend over a TCP connection of its own on the Windows
// TCP stack (TransportDecoyProxy). It keeps no
// Schannel state: the TLS transport gives it the stream's own read and write (TRANSPORT_DECOY_IO),
// which encrypt and decrypt the prober's side. Winsock is started by the TLS transport that calls
// it; the module starts none of its own.

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/Transport.h"

#include <stdlib.h>
#include <string.h>

#define DECOY_CONNECT 5000  // A connection to the backend completes within this time (ms)
#define DECOY_POLL    50    // How often the proxy looks at each side and at cancel while it waits (ms)
#define DECOY_BUFFER  16384 // Bytes the proxy carries at a time in each direction

bool TransportDecoyIsHandshake(const UCHAR *first, UINT size) {
	UINT length;

	if (first == NULL || size < TRANSPORT_FRAME_HEADER + 2)
		return false;

	// The frame header is the record's length (big-endian), as the session layer reads it
	length = ((UINT)first[0] << 24) | ((UINT)first[1] << 16) | ((UINT)first[2] << 8) | first[3];
	if (length < 2 || length > NOISE_MAX_RECORD || (UINT64)TRANSPORT_FRAME_HEADER + length > size)
		return false;

	// The record: a handshake record of a suite the node runs (NoiseSessionAccept makes the same test)
	const UCHAR *record = first + TRANSPORT_FRAME_HEADER;
	return (record[0] == NOISE_RECORD_HANDSHAKE && NoiseSuiteAvailable(record[1]));
}

bool TransportDecoyAuthenticate(const UCHAR *first, UINT size, const UCHAR *key, CRYPTO_IDENTITY *identity, UINT binding_type,
                                const UCHAR *binding, UINT binding_size) {
	UCHAR prologue[NOISE_MAX_PROLOGUE];
	NOISE_HANDSHAKE hs;
	UINT payload_size = 0;

	if (TransportDecoyIsHandshake(first, size) == false)
		return false;

	// The prologue the session layer gives the responder over this stream (NoiseSessionAccept)
	UINT prologue_size = NoisePrologue(prologue, sizeof(prologue), binding_type, binding, binding_size);
	if (prologue_size == 0)
		return false;

	// The responder reads the first message, as NoiseSessionAccept does: the handshake payload is empty
	UINT record_size = ((UINT)first[0] << 24) | ((UINT)first[1] << 16) | ((UINT)first[2] << 8) | first[3];
	const UCHAR *record = first + TRANSPORT_FRAME_HEADER;
	ZeroMemory(&hs, sizeof(hs));
	bool ok = (NoiseHandshakeInit(&hs, record[1], false, prologue, prologue_size, key, identity, NULL) &&
	           NoiseHandshakeRead(&hs, record + 2, record_size - 2, NULL, 0, &payload_size));

	NoiseHandshakeFree(&hs);
	SecureZeroMemory(prologue, sizeof(prologue));

	return ok;
}

// Split "host:port" at the last colon into host (max bytes, with its NUL; the brackets of "[v6]:port"
// taken off) and port (port_max bytes, with its NUL). false for anything else.
static bool DecoySplitAddress(const char *address, char *host, UINT max, char *port, UINT port_max) {
	const char *colon = strrchr(address, ':');
	const char *h = address;
	UINT len, digits;

	if (colon == NULL)
		return false;

	len = (UINT)(colon - address);
	if (len >= 2 && address[0] == '[' && colon[-1] == ']') {
		h = address + 1;
		len -= 2;
	}

	digits = (UINT)strlen(colon + 1);
	if (len == 0 || len >= max || digits == 0 || digits >= port_max)
		return false;

	memcpy(host, h, len);
	host[len] = 0;
	memcpy(port, colon + 1, digits + 1);

	return true;
}

// Wait until a connect completes: true when it did, false when it failed, cancel was set or end
// passed. A connect that failed shows in SO_ERROR while the socket is not writable.
static bool DecoyConnectWait(SOCKET s, HANDLE cancel, UINT64 end) {
	while (true) {
		WSAPOLLFD p;
		int error = 0, error_size = sizeof(error);

		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			return false;
		if (GetTickCount64() >= end)
			return false;

		ZeroMemory(&p, sizeof(p));
		p.fd = s;
		p.events = POLLWRNORM;
		int r = WSAPoll(&p, 1, DECOY_POLL);
		if (r < 0 || (r > 0 && (p.revents & (POLLERR | POLLHUP)) != 0))
			return false;
		if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &error_size) != 0 || error != 0)
			return false;
		if (r > 0)
			return true;
	}
}

// A TCP connection to one address of the backend, connected without blocking so that cancel is seen
static SOCKET DecoyConnectOne(const struct addrinfo *a, HANDLE cancel, UINT64 end) {
	u_long nonblocking = 1;
	SOCKET s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);

	if (s == INVALID_SOCKET)
		return INVALID_SOCKET;

	bool ok = (ioctlsocket(s, FIONBIO, &nonblocking) == 0);
	if (ok && connect(s, a->ai_addr, (int)a->ai_addrlen) != 0)
		ok = (WSAGetLastError() == WSAEWOULDBLOCK && DecoyConnectWait(s, cancel, end));

	if (ok == false) {
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// A TCP connection to the backend that address names; INVALID_SOCKET when none of its addresses
// answers, cancel was set or the address is malformed
static SOCKET DecoyConnect(const char *address, HANDLE cancel) {
	char host[TRANSPORT_ADDRESS_SIZE];
	char port[8];
	struct addrinfo hints, *res = NULL;
	SOCKET s = INVALID_SOCKET;
	UINT64 end = GetTickCount64() + DECOY_CONNECT;

	if (DecoySplitAddress(address, host, sizeof(host), port, sizeof(port)) == false)
		return INVALID_SOCKET;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(host, port, &hints, &res) != 0)
		return INVALID_SOCKET;

	for (const struct addrinfo *a = res; a != NULL && s == INVALID_SOCKET; a = a->ai_next)
		s = DecoyConnectOne(a, cancel, end);
	freeaddrinfo(res);

	return s;
}

// Send size bytes on the backend socket; false when it failed
static bool DecoySend(SOCKET s, const UCHAR *buf, UINT size) {
	while (size != 0) {
		int n = send(s, (const char *)buf, (int)(size < 65536 ? size : 65536), 0);

		if (n <= 0)
			return false;
		buf += n;
		size -= (UINT)n;
	}

	return true;
}

bool TransportDecoyProxy(const TRANSPORT_DECOY_IO *io, const char *address, const UCHAR *first, UINT size, HANDLE cancel) {
	UCHAR *buffer;
	SOCKET backend;
	bool ok = true;

	if (io == NULL || io->Read == NULL || io->Write == NULL || address == NULL)
		return false;

	backend = DecoyConnect(address, cancel);
	if (backend == INVALID_SOCKET)
		return false;

	buffer = (UCHAR *)HeapAlloc(GetProcessHeap(), 0, DECOY_BUFFER);
	if (buffer == NULL) {
		closesocket(backend);
		return false;
	}

	// What the prober already sent goes to the backend first
	if (size != 0 && first != NULL)
		ok = DecoySend(backend, first, size);

	// Then bytes both ways until either side ends or cancel is set
	while (ok) {
		WSAPOLLFD p;
		int r;

		if (cancel != NULL && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0)
			break;

		// The backend's bytes to the prober, which its TLS session encrypts
		ZeroMemory(&p, sizeof(p));
		p.fd = backend;
		p.events = POLLRDNORM;
		r = WSAPoll(&p, 1, DECOY_POLL);
		if (r < 0)
			break;
		if (r > 0) {
			int n = recv(backend, (char *)buffer, DECOY_BUFFER, 0);
			if (n <= 0)
				break;
			if (io->Write(io->Stream, buffer, (UINT)n) == false)
				break;
		}

		// The prober's bytes to the backend
		UINT got = io->Read(io->Stream, buffer, DECOY_BUFFER, DECOY_POLL);
		if (got == 0)
			break;
		if (got != TRANSPORT_LATER && DecoySend(backend, buffer, got) == false)
			break;
	}

	SecureZeroMemory(buffer, DECOY_BUFFER);
	HeapFree(GetProcessHeap(), 0, buffer);
	closesocket(backend);

	return true;
}
