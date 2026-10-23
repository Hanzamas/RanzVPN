// fuzz_frontdoor.c
// libFuzzer target: the front door of the new core (src/Core/FrontDoor*.c, SDN-29 #205), which reads the first bytes
// that any peer sends to TCP 443, and the handoff message that an owner process reads from its pipe. Every input runs
// as:
// - the first bytes of a connection: the ClientHello parser (FrontDoorParseHello), whose names must lie inside the
//   message it put together, within their limits, and the owner table of a node beside its Controller
//   (FrontDoorRoute), on the whole input as the bytes so far and as the last ones, and on its first half, as the front
//   door peeks again while more come; the owner it gives must be one of the table;
// - a handoff message (FrontDoorHandoffDecode), which must give a TCP socket of IPv4 or IPv6 when it gives one.

#include "fuzz_common.h"

#include "Core/FrontDoor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Largest input accepted (run_fuzzers.ps1 -max_len): longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		4096

// The owner table of a node beside its Controller, as in coretest frontdoor
#define	FUZZ_NUM_OWNERS			5
static FRONT_DOOR_OWNER fuzz_owners[FUZZ_NUM_OWNERS];
static bool fuzz_owners_made = false;

// A property of the module that does not hold: libFuzzer saves the input, with no abort message box and no Windows
// Error Reporting (as FuzzRun in fuzz_common.c)
static void FuzzFail(const char *what)
{
	fprintf(stderr, "==RANZ FUZZ== %s\n", what);
	fflush(stderr);
	_set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
	abort();
}

// The owner procedure of the node, which the router never calls
static bool FuzzTake(void *param, SOCKET s)
{
	return false;
}

// Once: the owner table, the Controller by ALPN and by the web UI's server name, a signature, an owner of another
// ALPN, and the node for every other TLS
static void FuzzOwners()
{
	if (fuzz_owners_made)
	{
		return;
	}

	memset(fuzz_owners, 0, sizeof(fuzz_owners));

	fuzz_owners[0].Kind = FRONT_DOOR_TLS;
	strcpy_s(fuzz_owners[0].Protocols, sizeof(fuzz_owners[0].Protocols), "h2, http/1.1");
	wcscpy_s(fuzz_owners[0].Pipe, FRONT_DOOR_PIPE_SIZE, L"\\\\.\\pipe\\controller");

	fuzz_owners[1].Kind = FRONT_DOOR_TLS;
	strcpy_s(fuzz_owners[1].ServerNames, sizeof(fuzz_owners[1].ServerNames), "admin.frontdoor.test, *.admin.frontdoor.test");
	wcscpy_s(fuzz_owners[1].Pipe, FRONT_DOOR_PIPE_SIZE, L"\\\\.\\pipe\\controller");

	fuzz_owners[2].Kind = FRONT_DOOR_BYTES;
	fuzz_owners[2].PrefixSize = 20;
	memcpy(fuzz_owners[2].Prefix, "RANZ-FRONT-DOOR-TEST", 20);
	wcscpy_s(fuzz_owners[2].Pipe, FRONT_DOOR_PIPE_SIZE, L"\\\\.\\pipe\\signature");

	fuzz_owners[3].Kind = FRONT_DOOR_TLS;
	strcpy_s(fuzz_owners[3].Protocols, sizeof(fuzz_owners[3].Protocols), "ranz-absent/1");
	wcscpy_s(fuzz_owners[3].Pipe, FRONT_DOOR_PIPE_SIZE, L"\\\\.\\pipe\\absent");

	fuzz_owners[4].Kind = FRONT_DOOR_TLS;
	fuzz_owners[4].Take = FuzzTake;

	fuzz_owners_made = true;
}

// Whether size bytes at p lie inside the message of hello
static bool FuzzInside(const FRONT_DOOR_HELLO *hello, const UCHAR *p, UINT size)
{
	return p >= hello->Message && size <= hello->MessageSize && (UINT)(p - hello->Message) <= hello->MessageSize - size;
}

// The owner that the table gives the first size bytes of data, which must be one of the table or a decision
static void FuzzRoute(const UCHAR *data, UINT size, bool last)
{
	UINT owner = FrontDoorRoute(fuzz_owners, FUZZ_NUM_OWNERS, data, size, last);

	if (owner != FRONT_DOOR_NONE && owner != FRONT_DOOR_MORE && owner >= FUZZ_NUM_OWNERS)
	{
		FuzzFail("FrontDoorRoute gave an owner that the table does not have");
	}
	if (last && owner == FRONT_DOOR_MORE)
	{
		FuzzFail("FrontDoorRoute waits for more bytes after the last ones");
	}
}

// One input: the first bytes of a connection, and a handoff message
static void FuzzFrontDoor(const uint8_t *data, size_t size)
{
	FRONT_DOOR_HELLO *hello;
	WSAPROTOCOL_INFOW info;

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports any read past
	// the end of the input
	UCHAR *copy = malloc(size);
	hello = malloc(sizeof(FRONT_DOOR_HELLO));
	if (copy == NULL || hello == NULL)
	{
		free(copy);
		free(hello);
		return;
	}
	memcpy(copy, data, size);

	if (FrontDoorParseHello(copy, (UINT)size, hello) == FRONT_DOOR_HELLO_DONE)
	{
		UINT kept = (hello->NumProtocols < FRONT_DOOR_MAX_PROTOCOLS ? hello->NumProtocols : FRONT_DOOR_MAX_PROTOCOLS);

		if (hello->MessageSize > FRONT_DOOR_MAX_HELLO || hello->RecordsSize > size)
		{
			FuzzFail("FrontDoorParseHello gave a message larger than its limit or than the input");
		}
		if (hello->ServerName != NULL && (hello->ServerNameSize == 0 || hello->ServerNameSize > FRONT_DOOR_MAX_NAME ||
			FuzzInside(hello, hello->ServerName, hello->ServerNameSize) == false))
		{
			FuzzFail("FrontDoorParseHello gave a server name outside the message or its limits");
		}
		for (UINT i = 0;i < kept;i++)
		{
			if (hello->ProtocolSizes[i] == 0 || hello->ProtocolSizes[i] > FRONT_DOOR_MAX_PROTOCOL ||
				FuzzInside(hello, hello->Protocols[i], hello->ProtocolSizes[i]) == false)
			{
				FuzzFail("FrontDoorParseHello gave an ALPN protocol outside the message or its limits");
			}
		}
	}

	FuzzOwners();
	FuzzRoute(copy, (UINT)size, false);
	FuzzRoute(copy, (UINT)size, true);
	FuzzRoute(copy, (UINT)size / 2, false);

	if (FrontDoorHandoffDecode(copy, (UINT)size, &info) && ((info.iAddressFamily != AF_INET && info.iAddressFamily != AF_INET6) ||
		info.iSocketType != SOCK_STREAM || info.iProtocol != IPPROTO_TCP))
	{
		FuzzFail("FrontDoorHandoffDecode gave a socket that is not one of TCP over IPv4 or IPv6");
	}

	free(hello);
	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzFrontDoor, data, size);

	return 0;
}
