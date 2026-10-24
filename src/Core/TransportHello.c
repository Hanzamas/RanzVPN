// TransportHello.c
// The ClientHello posture of the TLS transport (CORE-S2-2, #70): where the server name lies in the
// ClientHello that Schannel writes as a client's first token, so that a client that splits its
// ClientHello into two TCP segments (SplitClientHello, TransportTls.c) cuts it in the middle of the
// name. A DPI engine that matches an SNI keyword in one segment then finds no segment that holds the
// whole name. The bytes are the client's own, but the walk is bounded at every step all the same,
// and fuzz_transport drives it with any bytes.

#include "Core/Transport.h"

#define HELLO_CONTENT_HANDSHAKE 22     // The content type of a handshake record (RFC 8446 section 5.1)
#define HELLO_CLIENT_HELLO      1      // The handshake type of a ClientHello (section 4)
#define HELLO_FIXED             34     // legacy_version (2) and random (32) at the start of a ClientHello
#define HELLO_EXT_SERVER_NAME   0x0000 // The extension server_name (RFC 6066 section 3)
#define HELLO_NAME_HOST         0      // The name type host_name of a ServerNameList entry

// A position in the bytes of a ClientHello: At never passes Limit
typedef struct HELLO_CURSOR {
	const UCHAR *Bytes;
	UINT Limit;
	UINT At;
} HELLO_CURSOR;

// Take a big-endian number of width bytes (1 to 3) into *value; false when fewer are left
static bool HelloNumber(HELLO_CURSOR *c, UINT width, UINT *value) {
	UINT v = 0;

	if (width > c->Limit - c->At)
		return false;
	for (UINT i = 0; i < width; i++)
		v = (v << 8) | c->Bytes[c->At + i];

	c->At += width;
	*value = v;
	return true;
}

// Take a length of width bytes into *length and keep the walk within the bytes it counts (Limit):
// false when fewer are left
static bool HelloEnter(HELLO_CURSOR *c, UINT width, UINT *length) {
	if (HelloNumber(c, width, length) == false || *length > c->Limit - c->At)
		return false;

	c->Limit = c->At + *length;
	return true;
}

// Step over a vector whose length takes width bytes; false when it does not fit
static bool HelloSkip(HELLO_CURSOR *c, UINT width) {
	UINT length = 0;

	if (HelloNumber(c, width, &length) == false || length > c->Limit - c->At)
		return false;

	c->At += length;
	return true;
}

bool TransportTlsHelloName(const UCHAR *hello, UINT size, UINT *offset, UINT *length) {
	HELLO_CURSOR c;
	UINT type = 0, version = 0, body = 0;

	if (offset != NULL)
		*offset = 0;
	if (length != NULL)
		*length = 0;
	if (hello == NULL || offset == NULL || length == NULL)
		return false;

	c.Bytes = hello;
	c.Limit = size;
	c.At = 0;

	// The record: a handshake record and its version, then the ClientHello within the record
	if (HelloNumber(&c, 1, &type) == false || type != HELLO_CONTENT_HANDSHAKE || HelloNumber(&c, 2, &version) == false ||
	    HelloEnter(&c, 2, &body) == false)
		return false;
	if (HelloNumber(&c, 1, &type) == false || type != HELLO_CLIENT_HELLO || HelloEnter(&c, 3, &body) == false)
		return false;

	// The fixed fields, legacy_session_id, cipher_suites and legacy_compression_methods, then the
	// extensions
	if (HELLO_FIXED > c.Limit - c.At)
		return false;
	c.At += HELLO_FIXED;
	if (HelloSkip(&c, 1) == false || HelloSkip(&c, 2) == false || HelloSkip(&c, 1) == false || HelloEnter(&c, 2, &body) == false)
		return false;

	while (c.At < c.Limit) {
		UINT ext = 0, ext_size = 0;

		if (HelloNumber(&c, 2, &ext) == false)
			return false;
		if (ext != HELLO_EXT_SERVER_NAME) {
			if (HelloSkip(&c, 2) == false)
				return false;
			continue;
		}

		// server_name: the ServerNameList within the extension, its first entry a host_name
		UINT list = 0, name_type = 0, name_size = 0;
		if (HelloEnter(&c, 2, &ext_size) == false || HelloEnter(&c, 2, &list) == false || HelloNumber(&c, 1, &name_type) == false ||
		    name_type != HELLO_NAME_HOST || HelloNumber(&c, 2, &name_size) == false || name_size == 0 || name_size > c.Limit - c.At)
			return false;

		*offset = c.At;
		*length = name_size;
		return true;
	}

	return false;
}
