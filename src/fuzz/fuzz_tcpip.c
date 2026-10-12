// fuzz_tcpip.c
// libFuzzer target: Ethernet frame parsing (ParsePacketEx4), the parser the virtual hub runs
// on every frame it receives (StorePacket() in Cedar/Hub.c)

#include "fuzz_common.h"

#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include <string.h>

// Largest frame accepted, MAX_PACKET_SIZE in Cedar/Cedar.h; longer inputs are skipped
#define	FUZZ_MAX_FRAME_SIZE		1600

// One Ethernet frame input
static void FuzzTcpIp(const uint8_t *data, size_t size)
{
	UCHAR *frame;
	PKT *p;

	if (size == 0 || size > FUZZ_MAX_FRAME_SIZE)
	{
		return;
	}

	// ParsePacketEx4() may rewrite IP checksums in place, so it parses a writable copy.
	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer
	// reports any read past the end of the frame.
	frame = malloc(size);
	if (frame == NULL)
	{
		return;
	}
	memcpy(frame, data, size);

	// The hub's arguments for a HUB_OPTION left at its defaults: IP parsing on, VLAN TPID 0
	// (0x8100), BPDU bridge ID as MAC address, HTTP parsing on, checksum correction on
	p = ParsePacketEx4(frame, (UINT)size, false, 0, true, false, true);
	FreePacket(p);

	free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzTcpIp, data, size);

	return 0;
}
