// IpAddr.c
// IP address value types: parse, print, compare and mask IPv4 and IPv6 addresses

#include "IpAddr.h"

#include "Memory.h"
#include "Str.h"

#include <mstcpip.h>

bool IsStrIPv6Address(char *str)
{
	IP ip;
	if (str == NULL)
	{
		return false;
	}

	if (StrToIP6(&ip, str) == false)
	{
		return false;
	}

	return true;
}

// Subnet mask of 'size' bytes with a prefix of 'len' bits: one bits from the most significant bit
// of the first byte, then zero bits. A length beyond the mask gives all one bits
static void PrefixLenToMask(UCHAR *mask, UINT size, UINT len)
{
	UINT i;

	for (i = 0; i < size; i++)
	{
		if (len >= 8)
		{
			mask[i] = 0xFF;
			len -= 8;
		}
		else
		{
			// 0 to 7 leading one bits; every byte after this one is zero
			mask[i] = (UCHAR)(0xFF00 >> len);
			len = 0;
		}
	}
}

// Prefix length of a subnet mask of 'size' bytes: the number of its leading one bits. INFINITE when
// a one bit follows a zero bit (not a subnet mask)
static UINT MaskToPrefixLen(const UCHAR *mask, UINT size)
{
	UINT len = 0;
	UINT i = 0;
	UCHAR rest;

	while (i < size && mask[i] == 0xFF)
	{
		len += 8;
		i++;
	}

	if (i == size)
	{
		return len;
	}

	// The first byte with a zero bit: its leading one bits count, the bits behind them must be zero
	rest = mask[i];
	while ((rest & 0x80) != 0)
	{
		len++;
		rest = (UCHAR)(rest << 1);
	}

	if (rest != 0)
	{
		return INFINITE;
	}

	// Every byte behind it must be zero
	for (i++; i < size; i++)
	{
		if (mask[i] != 0)
		{
			return INFINITE;
		}
	}

	return len;
}

// Prefix length of an IPv6 subnet mask; 0 for an IPv4 address or a mask that is not contiguous
UINT SubnetMaskToInt6(const IP *a)
{
	UINT len;
	if (IsIP6(a) == false)
	{
		return 0;
	}

	len = MaskToPrefixLen(a->address, sizeof(a->address));

	return (len == INFINITE ? 0 : len);
}
static UINT SubnetMaskToInt4(const IP *a)
{
	UINT len;
	if (IsIP4(a) == false)
	{
		return 0;
	}

	len = MaskToPrefixLen(IPV4(a->address), IPV4_SIZE);

	return (len == INFINITE ? 0 : len);
}
static UINT SubnetMaskToInt(const IP *a)
{
	if (IsIP6(a))
	{
		return SubnetMaskToInt6(a);
	}
	else
	{
		return SubnetMaskToInt4(a);
	}
}

static bool IsSubnetMask6(const IP *a)
{
	if (IsIP6(a) == false)
	{
		return false;
	}

	return (MaskToPrefixLen(a->address, sizeof(a->address)) != INFINITE);
}

void IntToSubnetMask6(IP *ip, UINT i)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	PrefixLenToMask(ip->address, sizeof(ip->address), i);
}

void IntToSubnetMask4(IP *ip, UINT i)
{
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	PrefixLenToMask(IPV4(ip->address), IPV4_SIZE, i);
}

static bool IsSubnetMask(const IP *ip)
{
	if (IsIP6(ip))
	{
		return IsSubnetMask6(ip);
	}
	else
	{
		return IsSubnetMask4(ip);
	}
}
bool IsSubnetMask4(const IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return false;
	}

	return (MaskToPrefixLen(IPV4(ip->address), IPV4_SIZE) != INFINITE);
}

static bool ParseIpAndSubnetMask46(char *src, IP *ip, IP *mask)
{
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsSubnetMask4(mask);
	}
	else
	{
		return IsSubnetMask6(mask);
	}
}
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip2, mask2;
	if (src == NULL)
	{
		return false;
	}

	if (ParseIpAndSubnetMask46(src, &ip2, &mask2) == false)
	{
		return false;
	}

	if (IsIP4(&ip2) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip2);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&mask2);
	}

	return true;
}

void MaskToStrEx(char *str, UINT size, const IP *mask, bool always_full_address)
{
	if (str == NULL || mask == NULL)
	{
		return;
	}

	if (always_full_address == false && IsSubnetMask(mask))
	{
		ToStr(str, SubnetMaskToInt(mask));
	}
	else
	{
		IPToStr(str, size, mask);
	}
}
