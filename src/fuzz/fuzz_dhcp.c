// fuzz_dhcp.c
// libFuzzer target: the DHCP reply rewrite of the virtual hub. StorePacket() in Cedar/Hub.c runs
// DhcpModifyIPv4() on a DHCP reply to a local client: it parses the frame and rebuilds the DHCP
// payload with DhcpModify(), which reads the options with ParseDhcpOptions(). Every input runs as an
// Ethernet frame (DhcpModifyIPv4), as a DHCP payload (DhcpModify) and as DHCP options
// (ParseDhcpOptions). DhcpParseClasslessRouteData() is not driven on its own: FND-52 deletes it.

#include "fuzz_common.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/TcpIp.h"

#include <stdlib.h>
#include <string.h>

// Largest frame accepted, MAX_PACKET_SIZE in Cedar/Cedar.h; longer inputs are skipped
#define	FUZZ_MAX_FRAME_SIZE		1600

// Copy of the input in a malloc() block of exactly 'size' bytes, so that AddressSanitizer reports
// any read past the end of the input. NULL when out of memory
static UCHAR *FuzzDhcpCopy(const uint8_t *data, size_t size)
{
	UCHAR *copy = malloc(size);

	if (copy != NULL)
	{
		memcpy(copy, data, size);
	}

	return copy;
}

// One input: a frame, a DHCP payload and DHCP options
static void FuzzDhcp(const uint8_t *data, size_t size)
{
	DHCP_MODIFY_OPTION m;

	if (size == 0 || size > FUZZ_MAX_FRAME_SIZE)
	{
		return;
	}

	// The option StorePacket() passes: the gateway, DNS, WINS and domain name options of an OFFER or
	// an ACK go
	Zero(&m, sizeof(m));
	m.RemoveDefaultGatewayOnReply = true;

	// An Ethernet frame, as StorePacket() passes it
	UCHAR *copy = FuzzDhcpCopy(data, size);
	if (copy == NULL)
	{
		return;
	}
	FreeBuf(DhcpModifyIPv4(&m, copy, (UINT)size));
	free(copy);

	// The DHCP payload of a UDP datagram, as DhcpModifyIPv4() passes it
	copy = FuzzDhcpCopy(data, size);
	if (copy == NULL)
	{
		return;
	}
	FreeBuf(DhcpModify(&m, copy, (UINT)size));
	free(copy);

	// The options behind the magic cookie, as DhcpModify() passes them
	copy = FuzzDhcpCopy(data, size);
	if (copy == NULL)
	{
		return;
	}
	FreeDhcpOptions(ParseDhcpOptions(copy, (UINT)size));
	free(copy);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzDhcp, data, size);

	return 0;
}
