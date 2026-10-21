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
	for (UINT i = 0; i < size; i++)
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

void ZeroIP4(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[10] = 0xff;
	ip->address[11] = 0xff;
}

void GetLocalHostIP6(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	ip->address[15] = 1;
}
void GetLocalHostIP4(IP *ip)
{
	if (ip == NULL)
	{
		return;
	}

	SetIP(ip, 127, 0, 0, 1);
}

static bool IsLocalHostIP6(const IP *ip)
{
	IP local;
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP6(ip) == false)
	{
		return false;
	}

	GetLocalHostIP6(&local);

	if (CmpIpAddr(&local, ip) == 0)
	{
		return true;
	}

	return false;
}
static bool IsLocalHostIP4(const IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}
	if (IsIP4(ip) == false)
	{
		return false;
	}

	if (IPV4(ip->address)[0] == 127)
	{
		return true;
	}

	return false;
}
bool IsLocalHostIP(const IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP4(ip))
	{
		return IsLocalHostIP4(ip);
	}
	else
	{
		return IsLocalHostIP6(ip);
	}
}

void IPv6AddrToIP(IP *ip, const IPV6_ADDR *addr)
{
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(ip, addr->Value);
}

bool IPToIPv6Addr(IPV6_ADDR *addr, const IP *ip)
{
	if (addr == NULL || ip == NULL)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	if (IsIP6(ip) == false)
	{
		Zero(addr, sizeof(IPV6_ADDR));
		return false;
	}

	for (UINT i = 0; i < sizeof(addr->Value); ++i)
	{
		addr->Value[i] = ip->address[i];
	}

	return true;
}

void SetIP6(IP *ip, const UCHAR *value)
{
	if (ip == NULL || value == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		ip->address[i] = value[i];
	}
}

bool IsIP4(const IP *ip)
{
	if (ip == NULL)
	{
		return false;
	}

	if (IsZero(ip->address, 10) == false)
	{
		return false;
	}

	if (ip->address[10] != 0xff || ip->address[11] != 0xff)
	{
		return false;
	}

	return true;
}

void CopyIP(IP *dst, const IP *src)
{
	Copy(dst, src, sizeof(IP));
}

bool IsValidUnicastIPAddress4(const IP *ip)
{
	if (IsIP4(ip) == false)
	{
		return false;
	}

	if (IsZeroIP(ip))
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] >= 224 && ipv4[0] <= 239)
	{
		return false;
	}

	// Not exact: correct parsing needs the netmask.
	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		if (ipv4[i] != 255)
		{
			return true;
		}
	}

	return false;
}

bool IsValidUnicastIPAddress6(const IP *ip)
{
	UINT ipv6Type;

	if (!IsIP6(ip))
	{
		return false;
	}

	if (IsZeroIP(ip))
	{
		return false;
	}

	ipv6Type = GetIPAddrType6(ip);

	if (!(ipv6Type & IPV6_ADDR_LOCAL_UNICAST) &&
	        !(ipv6Type & IPV6_ADDR_GLOBAL_UNICAST))
	{
		return false;
	}

	return true;
}

bool IsZeroIP(const IP *ip)
{
	if (ip == NULL)
	{
		return true;
	}

	if (IsZero(ip->address, sizeof(ip->address)))
	{
		return true;
	}

	if (IsIP4(ip))
	{
		return IsZero(IPV4(ip->address), IPV4_SIZE);
	}

	return false;
}
bool IsZeroIP6Addr(const IPV6_ADDR *addr)
{
	if (addr == NULL)
	{
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
}

UINT IPToUINT(const IP *ip)
{
	if (ip == NULL || IsIP6(ip))
	{
		return 0;
	}

	UINT value;

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		((BYTE *)&value)[i] = IPV4(ip->address)[i];
	}

	return value;
}

void UINTToIP(IP *ip, UINT value)
{
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		IPV4(ip->address)[i] = ((BYTE *)&value)[i];
	}
}

void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4)
{
	if (ip == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	ip->address[12] = a1;
	ip->address[13] = a2;
	ip->address[14] = a3;
	ip->address[15] = a4;
}

void IPToStr32(char *str, UINT size, UINT ip)
{
	IP ip_st;
	if (str == NULL)
	{
		return;
	}

	UINTToIP(&ip_st, ip);
	IPToStr(str, size, &ip_st);
}

void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, const UCHAR *ip_6_bytes)
{
	IP ip4;
	IP ip6;
	IP ip;
	if (str == NULL)
	{
		return;
	}

	Zero(&ip, sizeof(ip));

	UINTToIP(&ip4, ip_4_uint);
	SetIP6(&ip6, ip_6_bytes);

	if (IsIP6(&ip4) || (IsZeroIP(&ip4) && (IsZeroIP(&ip6) == false)))
	{
		Copy(&ip, &ip6, sizeof(IP));
	}
	else
	{
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

void IPToStr(char *str, UINT size, const IP *ip)
{
	if (str == NULL || ip == NULL)
	{
		return;
	}

	if (IsIP6(ip))
	{
		IPToStr6(str, size, ip);
	}
	else
	{
		IN_ADDR addr;
		char tmp[INET_ADDRSTRLEN];

		Copy(&addr, IPV4(ip->address), sizeof(addr));
		RtlIpv4AddressToStringA(&addr, tmp);

		StrCpy(str, size, tmp);
	}
}

bool StrToIP(IP *ip, const char *str)
{
	char *tmp;
	PCSTR end;
	IN_ADDR addr;
	bool ok;
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	if (StrToIP6(ip, str))
	{
		return true;
	}

	ZeroIP4(ip);

	// Strict four-part dotted decimal, and nothing after it
	tmp = CopyStr(str);
	Trim(tmp);
	ok = (RtlIpv4StringToAddressA(tmp, TRUE, &end, &addr) == 0 && *end == 0);
	Free(tmp);

	if (ok == false)
	{
		return false;
	}

	Copy(IPV4(ip->address), &addr, IPV4_SIZE);

	return true;
}

void IPToInAddr(struct in_addr *addr, const IP *ip)
{
	if (addr == NULL || IsIP4(ip) == false)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	const BYTE *ipv4 = IPV4(ip->address);
	for (UINT i = 0; i < IPV4_SIZE; ++i)
	{
		((BYTE *)addr)[i] = ipv4[i];
	}
}

void IPToInAddr6(struct in6_addr *addr, const IP *ip)
{
	if (addr == NULL || ip == NULL)
	{
		return;
	}

	Zero(addr, sizeof(struct in6_addr));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		((BYTE *)addr)[i] = ip->address[i];
	}
}

void InAddrToIP(IP *ip, const struct in_addr *addr)
{
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	ZeroIP4(ip);

	BYTE *ipv4 = IPV4(ip->address);

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		ipv4[i] = ((UCHAR *)addr)[i];
	}
}

void InAddrToIP6(IP *ip, const struct in6_addr *addr)
{
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	for (BYTE i = 0; i < sizeof(ip->address); ++i)
	{
		ip->address[i] = ((UCHAR *)addr)[i];
	}
}

bool ParseIpAndMask46(const char *src, IP *ip, IP *mask)
{
	TOKEN_LIST *t;
	char *ipstr;
	char *subnetstr;
	bool ret = false;
	IP ip2;
	IP mask2;
	if (src == NULL || ip == NULL || mask == NULL)
	{
		return false;
	}

	Zero(&ip2, sizeof(IP));
	Zero(&mask2, sizeof(IP));

	t = ParseToken(src, "/");
	if (t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	ipstr = t->Token[0];
	subnetstr = t->Token[1];
	Trim(ipstr);
	Trim(subnetstr);

	if (StrToIP(&ip2, ipstr))
	{
		if (StrToIP(&mask2, subnetstr))
		{
			if (IsIP6(&ip2) && IsIP6(&mask2))
			{
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
			else if (IsIP4(&ip2) && IsIP4(&mask2))
			{
				ret = true;
				Copy(ip, &ip2, sizeof(IP));
				Copy(mask, &mask2, sizeof(IP));
			}
		}
		else
		{
			if (IsNum(subnetstr))
			{
				UINT i = ToInt(subnetstr);
				if (IsIP6(&ip2) && i <= 128)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask6(mask, i);
				}
				else if (i <= 32)
				{
					ret = true;
					Copy(ip, &ip2, sizeof(IP));
					IntToSubnetMask4(mask, i);
				}
			}
		}
	}

	FreeToken(t);

	return ret;
}
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask)
{
	IP ip_ip, ip_mask;
	if (ParseIpAndMask46(src, &ip_ip, &ip_mask) == false)
	{
		return false;
	}

	if (IsIP4(&ip_ip) == false)
	{
		return false;
	}

	if (ip != NULL)
	{
		*ip = IPToUINT(&ip_ip);
	}

	if (mask != NULL)
	{
		*mask = IPToUINT(&ip_mask);
	}

	return true;
}
bool ParseIpAndMask6(const char *src, IP *ip, IP *mask)
{
	if (ParseIpAndMask46(src, ip, mask) == false)
	{
		return false;
	}

	if (IsIP6(ip) == false)
	{
		return false;
	}

	return true;
}

void MaskToStr(char *str, UINT size, const IP *mask)
{
	MaskToStrEx(str, size, mask, false);
}
void MaskToStr32(char *str, UINT size, UINT mask)
{
	MaskToStr32Ex(str, size, mask, false);
}
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address)
{
	IP ip;

	UINTToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
static void Mask6AddrToStrEx(char *str, UINT size, const IPV6_ADDR *mask, bool always_full_address)
{
	IP ip;

	if (str == NULL || mask == NULL)
	{
		StrCpy(str, size, "");
		return;
	}

	IPv6AddrToIP(&ip, mask);

	MaskToStrEx(str, size, &ip, always_full_address);
}
void Mask6AddrToStr(char *str, UINT size, const IPV6_ADDR *mask)
{
	Mask6AddrToStrEx(str, size, mask, false);
}

void FreeHostIPAddressList(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	for (UINT i = 0; i < LIST_NUM(o); i++)
	{
		IP *ip = LIST_DATA(o, i);

		Free(ip);
	}

	ReleaseList(o);
}

void AddHostIPAddressToList(LIST *o, const IP *ip)
{
	const IP *r = NULL;
	if (o == NULL || ip == NULL)
	{
		return;
	}

	if (o->cmp != NULL)
	{
		r = Search(o, ip);
	}
	else
	{
		for (UINT i = 0; i < LIST_NUM(o); i++)
		{
			IP *a = LIST_DATA(o, i);

			if (CmpIpAddr(ip, a) == 0)
			{
				r = ip;
				break;
			}
		}
	}

	if (r != NULL)
	{
		return;
	}

	Insert(o, Clone(ip, sizeof(IP)));
}

LIST *CloneIPAddressList(const LIST *o)
{
	LIST *ret;
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(o->cmp);

	for (UINT i = 0; i < LIST_NUM(o); i++)
	{
		IP *ip = LIST_DATA(o, i);

		if (ip != NULL)
		{
			ip = Clone(ip, sizeof(IP));

			Add(ret, ip);
		}
	}

	return ret;
}
