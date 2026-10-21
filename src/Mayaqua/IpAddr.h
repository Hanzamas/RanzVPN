// IpAddr.h
// Header of IpAddr.c: the IP address value types and their pure functions

#ifndef	IPADDR_H
#define	IPADDR_H

#include "MayaType.h"

struct IP
{
	BYTE address[16];   // IP address (RFC 3493 format used for IPv4)
	UINT ipv6_scope_id;
};

#define	IPV4(address)				(&address[12])
#define	IPV4_SIZE					(4)

#define	CmpIpAddr(ip1, ip2)			(Cmp((ip1)->address, (ip2)->address, sizeof((ip1)->address)))

#define	IsIP6(ip)					(ip && IsIP4(ip) == false)

struct IPV6_ADDR
{
	UCHAR Value[16];
};

#define IPV6_ADDR_UNICAST						1
#define IPV6_ADDR_LOCAL_UNICAST					2
#define IPV6_ADDR_GLOBAL_UNICAST				4
#define IPV6_ADDR_MULTICAST						8
#define IPV6_ADDR_ALL_NODE_MULTICAST			16
#define IPV6_ADDR_ALL_ROUTER_MULTICAST			32
#define IPV6_ADDR_SOLICIATION_MULTICAST			64
#define	IPV6_ADDR_ZERO							128
#define	IPV6_ADDR_LOOPBACK						256

bool IsStrIPv6Address(char *str);
UINT SubnetMaskToInt6(const IP *a);
void GenerateEui64LocalAddress(IP *a, UCHAR *mac);
void GenerateEui64Address6(UCHAR *dst, UCHAR *mac);
UINT GetIPv6AddrType(const IPV6_ADDR *addr);
UINT GetIPAddrType6(const IP *ip);
void GetLoopbackAddress6(IP *ip);
void GetAllNodeMulticaseAddress6(IP *ip);
void GetAllRouterMulticastAddress6(IP *ip);
void IPAnd4(IP *dst, const IP *a, const IP *b);
void IPAnd6(IP *dst, const IP *a, const IP *b);
void IntToSubnetMask6(IP *ip, UINT i);
void IP6AddrToStr(char *str, UINT size, const IPV6_ADDR *addr);
void IPToStr6(char *str, UINT size, const IP *ip);
bool StrToIP6(IP *ip, const char *str);
void ZeroIP4(IP *ip);
void GetLocalHostIP6(IP *ip);
void GetLocalHostIP4(IP *ip);
bool IsLocalHostIP(const IP *ip);
void IPv6AddrToIP(IP *ip, const IPV6_ADDR *addr);
bool IPToIPv6Addr(IPV6_ADDR *addr, const IP *ip);
void SetIP6(IP *ip, const UCHAR *value);
bool IsIP4(const IP *ip);
void CopyIP(IP *dst, const IP *src);
bool IsValidUnicastIPAddress4(const IP *ip);
bool IsValidUnicastIPAddress6(const IP *ip);
bool IsZeroIP(const IP *ip);
bool IsZeroIP6Addr(const IPV6_ADDR *addr);
void IntToSubnetMask4(IP *ip, UINT i);
bool IsSubnetMask4(const IP *ip);
UINT IPToUINT(const IP *ip);
void UINTToIP(IP *ip, UINT value);
void SetIP(IP *ip, UCHAR a1, UCHAR a2, UCHAR a3, UCHAR a4);
void IPToStr32(char *str, UINT size, UINT ip);
void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, const UCHAR *ip_6_bytes);
void IPToStr(char *str, UINT size, const IP *ip);
bool StrToIP(IP *ip, const char *str);
void IPToInAddr(struct in_addr *addr, const IP *ip);
void IPToInAddr6(struct in6_addr *addr, const IP *ip);
void InAddrToIP(IP *ip, const struct in_addr *addr);
void InAddrToIP6(IP *ip, const struct in6_addr *addr);
bool ParseIpAndSubnetMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask46(const char *src, IP *ip, IP *mask);
bool ParseIpAndMask4(char *src, UINT *ip, UINT *mask);
bool ParseIpAndMask6(const char *src, IP *ip, IP *mask);
void MaskToStr(char *str, UINT size, const IP *mask);
void MaskToStrEx(char *str, UINT size, const IP *mask, bool always_full_address);
void MaskToStr32(char *str, UINT size, UINT mask);
void MaskToStr32Ex(char *str, UINT size, UINT mask, bool always_full_address);
void Mask6AddrToStr(char *str, UINT size, const IPV6_ADDR *mask);
void FreeHostIPAddressList(LIST *o);
void AddHostIPAddressToList(LIST *o, const IP *ip);
LIST *CloneIPAddressList(const LIST *o);

#endif
