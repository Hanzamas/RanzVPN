// fuzz_stun.c
// libFuzzer target: the STUN client parsers of Mayaqua/Stun.c. Every input runs as a received UDP
// datagram through StunParseBindingResponse(), the parser StunGetMappedAddress() runs on every
// datagram from the STUN server, and as the configured server text through StunParseServerStr().
// The transaction ID passed is the one in the input, so that the attribute parser is reached; with
// a fixed ID only inputs that carry that ID would get past the header.
//
// fuzz-max-len: 2048

#include "fuzz_common.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Stun.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted, STUN_RECV_BUFFER_SIZE: the largest datagram StunGetMappedAddress() reads;
// longer inputs are skipped
#define	FUZZ_MAX_INPUT_SIZE		STUN_RECV_BUFFER_SIZE

// Offset of the transaction ID in a STUN header (RFC 5389 section 6)
#define	FUZZ_STUN_TID_OFFSET	8

// The input as a datagram from the STUN server
static void FuzzStunResponse(const uint8_t *data, size_t size)
{
	UCHAR transaction_id[STUN_TRANSACTION_ID_SIZE];
	IP ip;
	UINT port;

	Zero(transaction_id, sizeof(transaction_id));
	if (size >= FUZZ_STUN_TID_OFFSET + STUN_TRANSACTION_ID_SIZE)
	{
		memcpy(transaction_id, data + FUZZ_STUN_TID_OFFSET, STUN_TRANSACTION_ID_SIZE);
	}

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports
	// any read past the end of the datagram
	UCHAR *datagram = malloc(size);
	if (datagram == NULL)
	{
		return;
	}
	memcpy(datagram, data, size);

	StunParseBindingResponse(datagram, (UINT)size, transaction_id, &ip, &port);

	free(datagram);
}

// The input as server text, up to its first zero byte, into the host buffer StunGetMappedAddress()
// passes
static void FuzzStunServerStr(const uint8_t *data, size_t size)
{
	char host[MAX_HOST_NAME_LEN + 1];
	UINT port;

	// malloc() rather than Malloc(): the text and its terminator fill the block exactly, so
	// AddressSanitizer reports any read past the terminator
	char *str = malloc(size + 1);
	if (str == NULL)
	{
		return;
	}
	memcpy(str, data, size);
	str[size] = 0;

	StunParseServerStr(str, host, sizeof(host), &port);

	free(str);
}

// One input: a datagram and server text
static void FuzzStun(const uint8_t *data, size_t size)
{
	// TEMPORARY, taken out again (CI-FLAKE-7, #605): the 1000th input of a process writes one byte past a block of 4 bytes. The seed
	// replay runs fewer inputs and passes; the step "Fuzz (60 s per target)" of the job fuzz-asan must fail on the AddressSanitizer
	// report, name this target, and keep its crash file and log
	static UINT planted_inputs = 0;

	if (++planted_inputs == 1000)
	{
		volatile char *block = malloc(4);

		if (block != NULL)
		{
			block[4] = 1;
			free((void *)block);
		}
	}

	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	FuzzStunResponse(data, size);
	FuzzStunServerStr(data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzStun, data, size);

	return 0;
}
