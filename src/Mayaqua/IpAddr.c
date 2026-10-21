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

void GenerateEui64LocalAddress(IP *a, UCHAR *mac)
{
	if (a == NULL || mac == NULL)
	{
		return;
	}

	Zero(a, sizeof(IP));

	UCHAR tmp[8];
	GenerateEui64Address6(tmp, mac);

	a->address[0] = 0xfe;
	a->address[1] = 0x80;

	Copy(&a->address[8], tmp, sizeof(tmp));
}

void GenerateEui64Address6(UCHAR *dst, UCHAR *mac)
{
	if (dst == NULL || mac == NULL)
	{
		return;
	}

	Copy(dst, mac, 3);
	Copy(dst + 5, mac, 3);

	dst[3] = 0xff;
	dst[4] = 0xfe;
	dst[0] = ((~(dst[0] & 0x02)) & 0x02) | (dst[0] & 0xfd);
}

UINT GetIPv6AddrType(const IPV6_ADDR *addr)
{
	IP ip;
	if (addr == NULL)
	{
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(const IP *ip)
{
	UINT ret = 0;
	if (IsIP6(ip) == false)
	{
		return 0;
	}

	if (ip->address[0] == 0xff)
	{
		IP all_node, all_router;

		GetAllNodeMulticaseAddress6(&all_node);

		GetAllRouterMulticastAddress6(&all_router);

		ret |= IPV6_ADDR_MULTICAST;

		if (CmpIpAddr(ip, &all_node) == 0)
		{
			ret |= IPV6_ADDR_ALL_NODE_MULTICAST;
		}
		else if (CmpIpAddr(ip, &all_router) == 0)
		{
			ret |= IPV6_ADDR_ALL_ROUTER_MULTICAST;
		}
		else
		{
			if (ip->address[1] == 0x02 && ip->address[2] == 0 && ip->address[3] == 0 &&
			        ip->address[4] == 0 && ip->address[5] == 0 && ip->address[6] == 0 &&
			        ip->address[7] == 0 && ip->address[8] == 0 && ip->address[9] == 0 &&
			        ip->address[10] == 0 && ip->address[11] == 0x01 && ip->address[12] == 0xff)
			{
				ret |= IPV6_ADDR_SOLICIATION_MULTICAST;
			}
		}
	}
	else
	{
		ret |= IPV6_ADDR_UNICAST;

		if (ip->address[0] == 0xfe && (ip->address[1] & 0xc0) == 0x80)
		{
			ret |= IPV6_ADDR_LOCAL_UNICAST;
		}
		else
		{
			ret |= IPV6_ADDR_GLOBAL_UNICAST;

			if (IsZero(&ip->address, sizeof(ip->address)))
			{
				ret |= IPV6_ADDR_ZERO;
			}
			else
			{
				IP loopback;

				GetLoopbackAddress6(&loopback);

				if (Cmp(ip->address, loopback.address, sizeof(ip->address)) == 0)
				{
					ret |= IPV6_ADDR_LOOPBACK;
				}
			}
		}
	}

	return ret;
}

void GetLoopbackAddress6(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 0x01;
}

void GetAllNodeMulticaseAddress6(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x01;
}

void GetAllRouterMulticastAddress6(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[0] = 0xff;
	ip->address[1] = 0x02;
	ip->address[15] = 0x02;
}

void IPAnd4(IP *dst, const IP *a, const IP *b)
{
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false)
	{
		ZeroIP4(dst);
		return;
	}

	UINTToIP(dst, IPToUINT(a) & IPToUINT(b));
}

void IPAnd6(IP *dst, const IP *a, const IP *b)
{
	Zero(dst, sizeof(IP));

	if (dst == NULL || IsIP6(a) == false || IsIP6(b) == false)
	{
		return;
	}

	for (BYTE i = 0; i < sizeof(dst->address); ++i)
	{
		dst->address[i] = a->address[i] & b->address[i];
	}
}

void IP6AddrToStr(char *str, UINT size, const IPV6_ADDR *addr)
{
	IP ip;
	if (str == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(&ip, addr->Value);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, const IP *ip)
{
	IN6_ADDR addr;
	char tmp[INET6_ADDRSTRLEN];
	ULONG len = sizeof(tmp);
	if (str == NULL || ip == NULL)
	{
		return;
	}

	Copy(&addr, ip->address, sizeof(addr));

	// RFC 5952 text, with "%" and the scope ID when the scope ID is not zero
	if (RtlIpv6AddressToStringExA(&addr, ip->ipv6_scope_id, 0, tmp, &len) != 0)
	{
		tmp[0] = 0;
	}

	StrCpy(str, size, tmp);
}

bool StrToIP6(IP *ip, const char *str)
{
	char tmp[MAX_PATH];
	IN6_ADDR addr;
	ULONG scope_id;
	USHORT port;
	if (str == NULL || ip == NULL)
	{
		return false;
	}

	StrCpy(tmp, sizeof(tmp), str);
	Trim(tmp);

	if (StartWith(tmp, "[") && EndWith(tmp, "]"))
	{
		StrCpy(tmp, sizeof(tmp), &tmp[1]);

		if (StrLen(tmp) >= 1)
		{
			tmp[StrLen(tmp) - 1] = 0;
		}
	}

	// The whole text is the address and an optional decimal "%scope": no brackets and so no port
	if (InStr(tmp, "[") || InStr(tmp, "]"))
	{
		return false;
	}

	if (RtlIpv6StringToAddressExA(tmp, &addr, &scope_id, &port) != 0)
	{
		return false;
	}

	Zero(ip, sizeof(IP));
	Copy(ip->address, &addr, sizeof(ip->address));
	ip->ipv6_scope_id = scope_id;

	return true;
}
