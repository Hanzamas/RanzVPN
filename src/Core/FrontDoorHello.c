// FrontDoorHello.c
// The first bytes of a connection at the front door (SDN-29, #205; ADR-0035): the ClientHello of a TLS connection with
// its server name and ALPN protocols, the owner that the owner table gives the connection, and the handoff message that
// an owner process reads from its pipe. Functions on bytes alone, which the fuzz target fuzz_frontdoor drives.
//
// The ClientHello (RFC 8446 section 4.1.2) comes in handshake records (section 5.1), which may cut it anywhere: the
// parser puts the message together from the records that carry it, up to FRONT_DOOR_MAX_HELLO bytes, and reads the
// extensions server_name (RFC 6066 section 3) and application_layer_protocol_negotiation (RFC 7301 section 3.1).

#include "Core/FrontDoor.h"

#include <string.h>

// What the parser reads of TLS
#define FD_RECORD_HEADER   5     // A record: its type, its legacy version and its length
#define FD_RECORD_MAX      16384 // The largest plaintext of a record (RFC 8446 section 5.1)
#define FD_HANDSHAKE       22    // A handshake record
#define FD_VERSION_MAJOR   3     // The first byte of the legacy version of every TLS record
#define FD_CLIENT_HELLO    1     // The ClientHello message
#define FD_MESSAGE_HEADER  4     // A handshake message: its type and its 3-byte length
#define FD_RANDOM          32    // The random of a ClientHello
#define FD_MAX_SESSION_ID  32    // The longest legacy_session_id
#define FD_EXT_SERVER_NAME 0     // The extension server_name
#define FD_EXT_ALPN        16    // The extension application_layer_protocol_negotiation
#define FD_HOST_NAME       0     // The name type host_name of server_name

// A reader of bytes: Pos stays at most Size, and a read past Size fails
typedef struct FRONT_DOOR_READER {
	const UCHAR *Data; // The bytes
	UINT Size;         // ... their number
	UINT Pos;          // The next byte to read
} FRONT_DOOR_READER;

static bool FrontDoorGet8(FRONT_DOOR_READER *r, UINT *v) {
	if (r->Size - r->Pos < 1)
		return false;

	*v = r->Data[r->Pos];
	r->Pos++;
	return true;
}

static bool FrontDoorGet16(FRONT_DOOR_READER *r, UINT *v) {
	if (r->Size - r->Pos < 2)
		return false;

	*v = ((UINT)r->Data[r->Pos] << 8) | r->Data[r->Pos + 1];
	r->Pos += 2;
	return true;
}

// The next size bytes as a reader of their own
static bool FrontDoorSub(FRONT_DOOR_READER *r, UINT size, FRONT_DOOR_READER *sub) {
	if (r->Size - r->Pos < size)
		return false;

	sub->Data = r->Data + r->Pos;
	sub->Size = size;
	sub->Pos = 0;
	r->Pos += size;
	return true;
}

// A vector of the ClientHello whose length takes len_size bytes (1 or 2), as a reader of its own, of min to max bytes
static bool FrontDoorVector(FRONT_DOOR_READER *r, UINT len_size, UINT min, UINT max, FRONT_DOOR_READER *sub) {
	UINT len = 0;

	if ((len_size == 1 ? FrontDoorGet8(r, &len) : FrontDoorGet16(r, &len)) == false || len < min || len > max)
		return false;

	return FrontDoorSub(r, len, sub);
}

// server_name: the list of names, of which the host_name is kept. A list must hold one name at least and no two of one
// type (RFC 6066 section 3).
static bool FrontDoorServerName(FRONT_DOOR_READER *ext, FRONT_DOOR_HELLO *hello) {
	FRONT_DOOR_READER list, name;

	if (FrontDoorVector(ext, 2, 1, 0xFFFF, &list) == false || ext->Pos != ext->Size)
		return false;

	while (list.Pos < list.Size) {
		UINT type = 0;

		if (FrontDoorGet8(&list, &type) == false || FrontDoorVector(&list, 2, 1, 0xFFFF, &name) == false)
			return false;
		if (type != FD_HOST_NAME)
			continue;
		if (hello->ServerName != NULL || name.Size > FRONT_DOOR_MAX_NAME)
			return false;

		hello->ServerName = name.Data;
		hello->ServerNameSize = name.Size;
	}

	return true;
}

// application_layer_protocol_negotiation: the protocols offered, none of them empty (RFC 7301 section 3.1)
static bool FrontDoorAlpn(FRONT_DOOR_READER *ext, FRONT_DOOR_HELLO *hello) {
	FRONT_DOOR_READER list, name;

	if (FrontDoorVector(ext, 2, 2, 0xFFFF, &list) == false || ext->Pos != ext->Size)
		return false;

	while (list.Pos < list.Size) {
		if (FrontDoorVector(&list, 1, 1, FRONT_DOOR_MAX_PROTOCOL, &name) == false)
			return false;

		if (hello->NumProtocols < FRONT_DOOR_MAX_PROTOCOLS) {
			hello->Protocols[hello->NumProtocols] = name.Data;
			hello->ProtocolSizes[hello->NumProtocols] = name.Size;
		}
		hello->NumProtocols++;
	}

	return true;
}

// The body of a whole ClientHello message in hello->Message: its fields, then its extensions, of which server_name and
// ALPN are read; none may come twice. A ClientHello of TLS 1.2 may have no extensions at all.
static bool FrontDoorClientHello(FRONT_DOOR_HELLO *hello) {
	FRONT_DOOR_READER r, skip, extensions, ext;
	bool server_name = false, alpn = false;
	UINT version = 0;

	r.Data = hello->Message + FD_MESSAGE_HEADER;
	r.Size = hello->MessageSize - FD_MESSAGE_HEADER;
	r.Pos = 0;

	// legacy_version, random, legacy_session_id, cipher_suites (two bytes each), legacy_compression_methods
	if (FrontDoorGet16(&r, &version) == false || FrontDoorSub(&r, FD_RANDOM, &skip) == false || FrontDoorVector(&r, 1, 0, FD_MAX_SESSION_ID, &skip) == false ||
	    FrontDoorVector(&r, 2, 2, 0xFFFE, &skip) == false || (skip.Size % 2) != 0 || FrontDoorVector(&r, 1, 1, 0xFF, &skip) == false)
		return false;
	if (r.Pos == r.Size)
		return true;

	if (FrontDoorVector(&r, 2, 0, 0xFFFF, &extensions) == false || r.Pos != r.Size)
		return false;

	while (extensions.Pos < extensions.Size) {
		UINT type = 0;

		if (FrontDoorGet16(&extensions, &type) == false || FrontDoorVector(&extensions, 2, 0, 0xFFFF, &ext) == false)
			return false;

		if (type == FD_EXT_SERVER_NAME) {
			if (server_name || FrontDoorServerName(&ext, hello) == false)
				return false;
			server_name = true;
		} else if (type == FD_EXT_ALPN) {
			if (alpn || FrontDoorAlpn(&ext, hello) == false)
				return false;
			alpn = true;
		}
	}

	return true;
}

UINT FrontDoorParseHello(const UCHAR *data, UINT size, FRONT_DOOR_HELLO *hello) {
	UINT pos = 0, have = 0, need = 0;

	if (hello == NULL || (data == NULL && size != 0))
		return FRONT_DOOR_HELLO_NONE;

	hello->MessageSize = 0;
	hello->RecordsSize = 0;
	hello->ServerName = NULL;
	hello->ServerNameSize = 0;
	hello->NumProtocols = 0;

	// The handshake records, whose bytes continue the message until it is whole: need is its size once its header came
	while (true) {
		UINT left = size - pos;

		if (left == 0)
			return FRONT_DOOR_HELLO_MORE;
		if (data[pos] != FD_HANDSHAKE || (left >= 2 && data[pos + 1] != FD_VERSION_MAJOR))
			return FRONT_DOOR_HELLO_NONE;
		if (left < FD_RECORD_HEADER)
			return FRONT_DOOR_HELLO_MORE;

		UINT length = ((UINT)data[pos + 3] << 8) | data[pos + 4];
		if (length == 0 || length > FD_RECORD_MAX)
			return FRONT_DOOR_HELLO_NONE;
		pos += FD_RECORD_HEADER;

		// The bytes of the record that came, up to the end of the message once its header told it
		UINT got = (length < size - pos ? length : size - pos);
		UINT room = (need != 0 ? need : FRONT_DOOR_MAX_HELLO) - have;
		UINT take = (got < room ? got : room);
		memcpy(hello->Message + have, data + pos, take);
		have += take;

		// The header of the message: a ClientHello of FRONT_DOOR_MAX_HELLO bytes at most
		if (need == 0 && have >= FD_MESSAGE_HEADER) {
			if (hello->Message[0] != FD_CLIENT_HELLO)
				return FRONT_DOOR_HELLO_NONE;

			need = FD_MESSAGE_HEADER + (((UINT)hello->Message[1] << 16) | ((UINT)hello->Message[2] << 8) | hello->Message[3]);
			if (need > FRONT_DOOR_MAX_HELLO)
				return FRONT_DOOR_HELLO_NONE;
			if (have > need) {
				take -= have - need;
				have = need;
			}
		}

		if (need != 0 && have == need) {
			hello->MessageSize = need;
			hello->RecordsSize = pos + take;
			return (FrontDoorClientHello(hello) ? FRONT_DOOR_HELLO_DONE : FRONT_DOOR_HELLO_NONE);
		}

		if (got < length)
			return FRONT_DOOR_HELLO_MORE;
		pos += length;
	}
}

// Whether a list of names separated by commas, spaces around each ignored, holds the name of size bytes. A server name
// (host) is compared without the case of ASCII letters, and "*.suffix" holds every name that ends in ".suffix"; an ALPN
// protocol is compared byte for byte.
static bool FrontDoorListHas(const char *list, const UCHAR *name, UINT size, bool host) {
	const char *p = list;

	while (*p != 0) {
		const char *start, *end;

		while (*p == ' ' || *p == '\t')
			p++;
		start = p;
		while (*p != 0 && *p != ',')
			p++;
		end = p;
		if (*p == ',')
			p++;
		while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
			end--;

		UINT len = (UINT)(end - start);
		if (len == 0)
			continue;

		if (host && len >= 2 && start[0] == '*' && start[1] == '.') {
			// "*.example": the name ends in ".example" and has a label in front of it
			UINT suffix = len - 1;
			if (size > suffix && _strnicmp((const char *)name + size - suffix, start + 1, suffix) == 0)
				return true;
		} else if (len == size) {
			if ((host ? _strnicmp((const char *)name, start, len) : memcmp(name, start, len)) == 0)
				return true;
		}
	}

	return false;
}

// Whether a TLS owner takes a connection whose ClientHello names what hello holds
static bool FrontDoorTakesHello(const FRONT_DOOR_OWNER *o, const FRONT_DOOR_HELLO *hello) {
	if (o->Kind != FRONT_DOOR_TLS)
		return false;

	if (o->ServerNames[0] != 0 && (hello->ServerName == NULL || FrontDoorListHas(o->ServerNames, hello->ServerName, hello->ServerNameSize, true) == false))
		return false;

	if (o->Protocols[0] != 0) {
		UINT kept = (hello->NumProtocols < FRONT_DOOR_MAX_PROTOCOLS ? hello->NumProtocols : FRONT_DOOR_MAX_PROTOCOLS);
		bool offered = false;

		for (UINT i = 0; i < kept && offered == false; i++)
			offered = FrontDoorListHas(o->Protocols, hello->Protocols[i], hello->ProtocolSizes[i], false);
		if (offered == false)
			return false;
	}

	return true;
}

// The owner of a TLS connection: the first TLS owner that takes what its ClientHello names
static UINT FrontDoorRouteTls(const FRONT_DOOR_OWNER *owners, UINT num, const UCHAR *data, UINT size, bool last) {
	FRONT_DOOR_HELLO *hello = (FRONT_DOOR_HELLO *)HeapAlloc(GetProcessHeap(), 0, sizeof(FRONT_DOOR_HELLO));
	UINT ret = FRONT_DOOR_NONE;

	if (hello == NULL)
		return FRONT_DOOR_NONE;

	switch (FrontDoorParseHello(data, size, hello)) {
	case FRONT_DOOR_HELLO_DONE:
		for (UINT i = 0; i < num && ret == FRONT_DOOR_NONE; i++)
			if (FrontDoorTakesHello(&owners[i], hello))
				ret = i;
		break;
	case FRONT_DOOR_HELLO_MORE:
		ret = (last ? FRONT_DOOR_NONE : FRONT_DOOR_MORE);
		break;
	default:
		break;
	}

	HeapFree(GetProcessHeap(), 0, hello);

	return ret;
}

UINT FrontDoorRoute(const FRONT_DOOR_OWNER *owners, UINT num, const UCHAR *data, UINT size, bool last) {
	bool pending = false;

	if (owners == NULL || num == 0 || num > FRONT_DOOR_MAX_OWNERS || (data == NULL && size != 0))
		return FRONT_DOOR_NONE;
	if (size == 0)
		return (last ? FRONT_DOOR_NONE : FRONT_DOOR_MORE);

	// The start of a TLS handshake record: TLS
	if (data[0] == FD_HANDSHAKE && (size < 2 || data[1] == FD_VERSION_MAJOR))
		return FrontDoorRouteTls(owners, num, data, size, last);

	// Anything else, by its first bytes: an owner whose longer prefix the bytes so far start may still take it, so a
	// later owner gets it only once that one cannot
	for (UINT i = 0; i < num; i++) {
		const FRONT_DOOR_OWNER *o = &owners[i];

		if (o->Kind != FRONT_DOOR_BYTES || o->PrefixSize == 0 || o->PrefixSize > FRONT_DOOR_PREFIX_SIZE)
			continue;

		UINT n = (size < o->PrefixSize ? size : o->PrefixSize);
		if (memcmp(data, o->Prefix, n) != 0)
			continue;

		if (size >= o->PrefixSize)
			return (pending && last == false ? FRONT_DOOR_MORE : i);
		pending = true;
	}

	return (pending && last == false ? FRONT_DOOR_MORE : FRONT_DOOR_NONE);
}

bool FrontDoorHandoffDecode(const void *data, UINT size, WSAPROTOCOL_INFOW *info) {
	FRONT_DOOR_HANDOFF m;

	if (data == NULL || info == NULL || size != sizeof(FRONT_DOOR_HANDOFF))
		return false;

	memcpy(&m, data, sizeof(m));
	if (m.Magic != FRONT_DOOR_HANDOFF_MAGIC || m.Size != sizeof(FRONT_DOOR_HANDOFF))
		return false;

	// A TCP socket of IPv4 or IPv6: the front door hands over nothing else
	if ((m.Info.iAddressFamily != AF_INET && m.Info.iAddressFamily != AF_INET6) || m.Info.iSocketType != SOCK_STREAM || m.Info.iProtocol != IPPROTO_TCP)
		return false;

	memcpy(info, &m.Info, sizeof(WSAPROTOCOL_INFOW));
	info->szProtocol[WSAPROTOCOL_LEN] = 0;

	return true;
}
