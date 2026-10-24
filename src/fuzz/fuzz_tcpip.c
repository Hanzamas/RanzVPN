// fuzz_tcpip.c
// libFuzzer target: Ethernet frame parsing (ParsePacketEx4), the parser the virtual hub runs
// on every frame it receives (StorePacket() in Cedar/Hub.c), and the MSS clamp of a SYN
// (AdjustTcpMssL2) the hub runs on the frames it hands to a session
//
// fuzz-max-len: 1600

#include "fuzz_common.h"

#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include <string.h>

// Largest frame accepted, MAX_PACKET_SIZE in Cedar/Cedar.h; longer inputs are skipped
#define	FUZZ_MAX_FRAME_SIZE		1600

// VLAN TPID of a hub with VlanTypeId set to 802.1ad: frames tagged with it are VLAN frames too
#define	FUZZ_TPID_8021AD		0x88A8

// MSS the clamp is to, below the 1460 of an Ethernet SYN so that the clamp rewrites it
#define	FUZZ_TARGET_MSS			1300

// One Ethernet frame input
static void FuzzTcpIp(const uint8_t *data, size_t size)
{
	if (size == 0 || size > FUZZ_MAX_FRAME_SIZE)
	{
		return;
	}

	// ParsePacketEx4() may rewrite IP checksums in place, so it parses a writable copy.
	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer
	// reports any read past the end of the frame.
	UCHAR *frame = malloc(size);
	if (frame == NULL)
	{
		return;
	}
	memcpy(frame, data, size);

	// The hub's arguments for a HUB_OPTION left at its defaults: IP parsing on, VLAN TPID 0
	// (0x8100), BPDU bridge ID as MAC address, HTTP parsing on, checksum correction on
	PKT *p = ParsePacketEx4(frame, (UINT)size, false, 0, true, false, true);
	FreePacket(p);

	// The same on a hub with VlanTypeId 0x88A8
	p = ParsePacketEx4(frame, (UINT)size, false, FUZZ_TPID_8021AD, true, false, true);
	FreePacket(p);

	// The MSS clamp of StorePacketToHubPa(), with the default and the 802.1ad TPID. It may rewrite
	// the MSS option and the TCP checksum, so it runs after the parsers
	AdjustTcpMssL2(frame, (UINT)size, FUZZ_TARGET_MSS, 0);
	AdjustTcpMssL2(frame, (UINT)size, FUZZ_TARGET_MSS, FUZZ_TPID_8021AD);

	free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzTcpIp, data, size);

	return 0;
}
