// fuzz_net.c
// libFuzzer target: network-input parsers of Mayaqua/Network.c, without a frame around the input.
// Every input runs as a TCP payload through GetSniNameFromSslPacket(), which the frame parser runs
// on a TCP payload to port 443 (ParseHttpsAccessLog() in TcpIp.c; fuzz_tcpip reaches it only
// through a whole frame), and as text through the address and mask parsers of the admin RPC and
// the command line (StrToIP, StrToIP6, ParseIpAndMask46, ParseIpAndMask4, ParseIpAndMask6,
// ParseIpAndSubnetMask4). Every address parsed is formatted again with IPToStr() or IPToStr32().

#include "fuzz_common.h"

#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"

#include <stdlib.h>
#include <string.h>

// Largest input accepted; longer inputs are skipped. Above MAX_PACKET_SIZE (1600, Cedar/Cedar.h),
// the largest frame and so the largest TCP payload, and above MAX_SIZE (512), the longest address
// text the command line and the admin RPC pass
#define	FUZZ_MAX_INPUT_SIZE		4096

// Server name buffer shorter than any real name, so that the truncating copy is reached
#define	FUZZ_SHORT_SNI_SIZE		8

// The input as a TCP payload: the buffer of ParseHttpsAccessLog() and a short one
static void FuzzNetSni(const uint8_t *data, size_t size)
{
	char sni[MAX_PATH];
	char short_sni[FUZZ_SHORT_SNI_SIZE];

	// malloc() rather than Malloc(): the copy is exactly 'size' bytes, so AddressSanitizer reports
	// any read past the end of the payload
	UCHAR *payload = malloc(size);
	if (payload == NULL)
	{
		return;
	}
	memcpy(payload, data, size);

	GetSniNameFromSslPacket(payload, (UINT)size, sni, sizeof(sni));
	GetSniNameFromSslPacket(payload, (UINT)size, short_sni, sizeof(short_sni));

	free(payload);
}

// The input as address text, up to its first zero byte
static void FuzzNetAddress(const uint8_t *data, size_t size)
{
	char out[MAX_SIZE];
	IP ip;
	IP mask;
	UINT ip32;
	UINT mask32;

	// malloc() rather than Malloc(): the text and its terminator fill the block exactly, so
	// AddressSanitizer reports any read past the terminator
	char *str = malloc(size + 1);
	if (str == NULL)
	{
		return;
	}
	memcpy(str, data, size);
	str[size] = 0;

	if (StrToIP(&ip, str))
	{
		IPToStr(out, sizeof(out), &ip);
	}

	if (StrToIP6(&ip, str))
	{
		IPToStr(out, sizeof(out), &ip);
	}

	if (ParseIpAndMask46(str, &ip, &mask))
	{
		IPToStr(out, sizeof(out), &ip);
		IPToStr(out, sizeof(out), &mask);
	}

	if (ParseIpAndMask4(str, &ip32, &mask32))
	{
		IPToStr32(out, sizeof(out), ip32);
		IPToStr32(out, sizeof(out), mask32);
	}

	if (ParseIpAndMask6(str, &ip, &mask))
	{
		IPToStr(out, sizeof(out), &ip);
		IPToStr(out, sizeof(out), &mask);
	}

	if (ParseIpAndSubnetMask4(str, &ip32, &mask32))
	{
		IPToStr32(out, sizeof(out), ip32);
		IPToStr32(out, sizeof(out), mask32);
	}

	free(str);
}

// One input: a TCP payload and address text
static void FuzzNet(const uint8_t *data, size_t size)
{
	if (size == 0 || size > FUZZ_MAX_INPUT_SIZE)
	{
		return;
	}

	FuzzNetSni(data, size);
	FuzzNetAddress(data, size);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FuzzRun(FuzzNet, data, size);

	return 0;
}
