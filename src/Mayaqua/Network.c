// Network.c
// Network communication module

#include "Network.h"

#include "Cfg.h"
#include "DNS.h"
#include "FileIO.h"
#include "HTTP.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Object.h"
#include "Pack.h"
#include "Str.h"
#include "TcpIp.h"
#include "Tick64.h"

#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <iphlpapi.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <MSWSock.h>
#include <wincrypt.h>
#include <IcmpAPI.h>

static LOCK *machine_name_lock = NULL;
static COUNTER *num_tcp_connections = NULL;
static LIST *WaitThreadList = NULL;
static UCHAR machine_ip_process_hash[SHA1_SIZE];
static LOCK *machine_ip_process_hash_lock = NULL;
static LOCK *current_global_ip_lock = NULL;
static bool current_global_ip_set = false;
static IP current_glocal_ipv4 = {0};
static IP current_glocal_ipv6 = {0};
static LOCK *host_ip_address_list_cache_lock = NULL;
static UINT64 host_ip_address_list_cache_last = 0;
static LIST *host_ip_address_cache = NULL;
static bool disable_gethostname_by_accept = false;


static LIST *ip_clients = NULL;
static bool ip_clients_full_logged = false;	// EvictOldestIpClient has logged that ip_clients is full

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;


static DH_CTX *dh_param = NULL;

// Decoded copy of the Windows ROOT store, for the client's peer verification
#define	SSL_ROOT_CERTS_REFRESH_SPAN		(10 * 60 * 1000ULL)
static STACK_OF(X509) *ssl_root_certs = NULL;
static UINT64 ssl_root_certs_tick = 0;

typedef struct PRIVATE_IP_SUBNET
{
	UINT Ip, Mask, Ip2;
} PRIVATE_IP_SUBNET;

static LIST *g_private_ip_list = NULL;


static LIST *g_dyn_value_list = NULL;


static void InitDynList()
{
	g_dyn_value_list = NewList(NULL);
}

static void FreeDynList()
{
	UINT i;
	if (g_dyn_value_list == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(g_dyn_value_list); i++)
	{
		DYN_VALUE *d = LIST_DATA(g_dyn_value_list, i);

		Free(d);
	}

	ReleaseList(g_dyn_value_list);

	g_dyn_value_list = NULL;
}

int GetCurrentTimezone()
{
	int ret = 0;

	ret = GetCurrentTimezoneWin32();

	return ret;
}

// Offset of local time from UTC in minutes (positive east of UTC), for the time zone
// information and the zone ID that GetTimeZoneInformation returned. The biases of
// TIME_ZONE_INFORMATION are UTC minus local time: the offset is the zone bias plus the
// daylight or standard bias in effect, with the sign turned around
int GetTimezoneInfoOffsetWin32(TIME_ZONE_INFORMATION *info, UINT zone_id)
{
	LONG bias;
	if (info == NULL)
	{
		return 0;
	}

	bias = info->Bias;

	if (zone_id == TIME_ZONE_ID_DAYLIGHT)
	{
		bias += info->DaylightBias;
	}
	else if (zone_id == TIME_ZONE_ID_STANDARD)
	{
		bias += info->StandardBias;
	}

	return -(int)bias;
}

// Current offset of local time from UTC in minutes (positive east of UTC), daylight saving
// time included when it is in effect; 0 when the time zone cannot be read
int GetCurrentTimezoneWin32()
{
	TIME_ZONE_INFORMATION info;
	DWORD zone_id;
	Zero(&info, sizeof(info));

	zone_id = GetTimeZoneInformation(&info);
	if (zone_id == TIME_ZONE_ID_INVALID)
	{
		return 0;
	}

	return GetTimezoneInfoOffsetWin32(&info, zone_id);
}

bool IsMacAddressLocalFast(void *addr)
{
	bool ret = false;
	if (addr == NULL)
	{
		return false;
	}

	Lock(local_mac_list_lock);
	{
		if (local_mac_list == NULL)
		{
			RefreshLocalMacAddressList();
		}

		ret = IsMacAddressLocalInner(local_mac_list, addr);
	}
	Unlock(local_mac_list_lock);

	return ret;
}

void RefreshLocalMacAddressList()
{
	Lock(local_mac_list_lock);
	{
		if (local_mac_list != NULL)
		{
			FreeNicList(local_mac_list);
		}

		local_mac_list = GetNicList();
	}
	Unlock(local_mac_list_lock);
}

bool IsMacAddressLocalInner(LIST *o, void *addr)
{
	bool ret = false;
	UINT i;
	if (o == NULL || addr == NULL)
	{
		return false;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		if (Cmp(e->MacAddress, addr, 6) == 0)
		{
			ret = true;
			break;
		}
	}

	return ret;
}

LIST *GetNicList()
{
	LIST *o = NULL;

	o = Win32GetNicList();

	if (o != NULL)
	{
		return o;
	}


	return NewListFast(NULL);
}

LIST *Win32GetNicList()
{
	UINT i;
	LIST *o = NewListFast(NULL);
	MS_ADAPTER_LIST *al = MsCreateAdapterList();

	if (al == NULL)
	{
		return NULL;
	}

	for (i = 0; i < al->Num; i++)
	{
		MS_ADAPTER *a = al->Adapters[i];

		if (a->Type == 6 && a->AddressSize == 6)
		{
			// Skip interfaces whose state is unknown: the device is not plugged in.
			if (a->MediaConnectState == MediaConnectStateUnknown)
			{
				continue;
			}

			NIC_ENTRY *e = ZeroMalloc(sizeof(NIC_ENTRY));

			StrCpy(e->IfName, sizeof(e->IfName), a->Title);
			Copy(e->MacAddress, a->Address, 6);

			Add(o, e);
		}
	}

	MsFreeAdapterList(al);

	return o;
}

void FreeNicList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		NIC_ENTRY *e = LIST_DATA(o, i);

		Free(e);
	}

	ReleaseList(o);
}

void ParseNtUsername(char *src_username, char *dst_username, UINT dst_username_size, char *dst_domain, UINT dst_domain_size, bool do_not_parse_atmark)
{
	char tmp_username[MAX_SIZE];
	char tmp_domain[MAX_SIZE];
	TOKEN_LIST *t;

	if (src_username != dst_username)
	{
		ClearStr(dst_username, dst_username_size);
	}

	ClearStr(dst_domain, dst_domain_size);
	if (src_username == NULL || dst_username == NULL || dst_domain == NULL)
	{
		return;
	}

	StrCpy(tmp_username, sizeof(tmp_username), src_username);
	ClearStr(tmp_domain, sizeof(tmp_domain));

	if (do_not_parse_atmark == false)
	{
		t = ParseTokenWithNullStr(tmp_username, "@");
		if (t->NumTokens >= 1)
		{
			StrCpy(tmp_username, sizeof(tmp_username), t->Token[0]);
		}
		if (t->NumTokens >= 2)
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[1]);
		}
		FreeToken(t);
	}

	t = ParseTokenWithNullStr(tmp_username, "\\");
	if (t->NumTokens >= 2)
	{
		if (IsEmptyStr(tmp_domain))
		{
			StrCpy(tmp_domain, sizeof(tmp_domain), t->Token[0]);
		}

		StrCpy(tmp_username, sizeof(tmp_username), t->Token[1]);
	}
	FreeToken(t);

	StrCpy(dst_username, dst_username_size, tmp_username);
	StrCpy(dst_domain, dst_domain_size, tmp_domain);
}

void GetCurrentMachineIpProcessHash(void *hash)
{
	if (hash == NULL)
	{
		return;
	}

	Lock(machine_ip_process_hash_lock);
	{
		if (IsZero(machine_ip_process_hash, SHA1_SIZE))
		{
			GetCurrentMachineIpProcessHashInternal(machine_ip_process_hash);
		}

		Copy(hash, machine_ip_process_hash, SHA1_SIZE);
	}
	Unlock(machine_ip_process_hash_lock);
}
void GetCurrentMachineIpProcessHashInternal(void *hash)
{
	BUF *b;
	LIST *ip_list;
	char machine_name[MAX_SIZE];
	wchar_t exe_path[MAX_PATH];
	char *product_id = NULL;
	if (hash == NULL)
	{
		return;
	}

	product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductId");
	if (product_id == NULL)
	{
		product_id = MsRegReadStr(REG_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductId");
	}

	b = NewBuf();

	GetMachineHostName(machine_name, sizeof(machine_name));
	Trim(machine_name);
	StrUpper(machine_name);

	GetExeNameW(exe_path, sizeof(exe_path));
	UniTrim(exe_path);
	UniStrUpper(exe_path);

	WriteBuf(b, machine_name, StrSize(machine_name));
	WriteBuf(b, exe_path, UniStrSize(exe_path));
	WriteBuf(b, product_id, StrSize(product_id));

	ip_list = GetHostIPAddressList();
	if (ip_list != NULL)
	{
		UINT i;
		for (i = 0; i < LIST_NUM(ip_list); i++)
		{
			IP *ip = LIST_DATA(ip_list, i);

			WriteBuf(b, ip, sizeof(IP));
		}
	}
	FreeHostIPAddressList(ip_list);

	Sha1(hash, b->Buf, b->Size);

	FreeBuf(b);

	Free(product_id);
}


typedef struct WIN32_ACCEPT_CHECK_DATA
{
	bool Rejected;
} WIN32_ACCEPT_CHECK_DATA;

static int CALLBACK Win32AcceptCheckCallback(LPWSABUF lpCallerId, LPWSABUF lpCallerData, LPQOS pQos,
                                      LPQOS lpGQOS, LPWSABUF lpCalleeId, LPWSABUF lpCalleeData,
                                      GROUP FAR *g, DWORD_PTR dwCallbackData)
{
	return CF_ACCEPT;
}

static SOCKET Win32Accept(SOCK *sock, SOCKET s, struct sockaddr *addr, int *addrlen)
{
	SOCKET ret;
	WIN32_ACCEPT_CHECK_DATA d;
	UINT err;
	int initial_addrlen = *addrlen;
	UINT num_error = 0;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	if (sock == NULL || s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (sock->hAcceptEvent == NULL)
	{
		sock->hAcceptEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

		WSAEventSelect(s, sock->hAcceptEvent, FD_ACCEPT | FD_CLOSE);
	}

L_LOOP:

	if (sock->CancelAccept)
	{
		return INVALID_SOCKET;
	}

	Zero(&d, sizeof(d));

	*addrlen = initial_addrlen;
	Zero(addr, initial_addrlen);
	ret = WSAAccept(s, addr, addrlen, Win32AcceptCheckCallback, (DWORD_PTR)&d);

	if (ret == INVALID_SOCKET)
	{
		err = WSAGetLastError();

		if (err == WSAEWOULDBLOCK)
		{
			UINT wait_ret = WaitForSingleObject(sock->hAcceptEvent, 1234);

			if (wait_ret == WAIT_OBJECT_0 || wait_ret == WAIT_TIMEOUT)
			{
				goto L_LOOP;
			}

			Debug("!!! WaitForSingleObject Error. ret=%u GetLastError=%u\n", wait_ret, (UINT)GetLastError());
		}

		num_error++;

		Debug("!!! WSAAccept Error: %u  rej=%u  num=%u  tick=%I64u\n", err, d.Rejected, num_error, Tick64());

		if (d.Rejected && err == WSAECONNREFUSED)
		{
			goto L_LOOP;
		}

		if (err == WSAETIMEDOUT)
		{
			goto L_LOOP;
		}

		sock->AcceptError = err;
	}
	else
	{
		WSAEventSelect(ret, sock->hAcceptEvent, 0);

		WSAIoctl(ret, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);
	}

	return ret;
}


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
static UINT MaskToPrefixLen(UCHAR *mask, UINT size)
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
UINT SubnetMaskToInt6(IP *a)
{
	UINT len;
	if (IsIP6(a) == false)
	{
		return 0;
	}

	len = MaskToPrefixLen(a->address, sizeof(a->address));

	return (len == INFINITE ? 0 : len);
}
static UINT SubnetMaskToInt4(IP *a)
{
	UINT len;
	if (IsIP4(a) == false)
	{
		return 0;
	}

	len = MaskToPrefixLen(IPV4(a->address), IPV4_SIZE);

	return (len == INFINITE ? 0 : len);
}
static UINT SubnetMaskToInt(IP *a)
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

static bool IsSubnetMask6(IP *a)
{
	if (IsIP6(a) == false)
	{
		return false;
	}

	return (MaskToPrefixLen(a->address, sizeof(a->address)) != INFINITE);
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

UINT GetIPv6AddrType(IPV6_ADDR *addr)
{
	IP ip;
	if (addr == NULL)
	{
		return 0;
	}

	IPv6AddrToIP(&ip, addr);

	return GetIPAddrType6(&ip);
}
UINT GetIPAddrType6(IP *ip)
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

void IPAnd4(IP *dst, IP *a, IP *b)
{
	if (dst == NULL || a == NULL || b == NULL || IsIP4(a) == false || IsIP4(b) == false)
	{
		ZeroIP4(dst);
		return;
	}

	UINTToIP(dst, IPToUINT(a) & IPToUINT(b));
}

void IPAnd6(IP *dst, IP *a, IP *b)
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

void IntToSubnetMask6(IP *ip, UINT i)
{
	if (ip == NULL)
	{
		return;
	}

	Zero(ip, sizeof(IP));

	PrefixLenToMask(ip->address, sizeof(ip->address), i);
}

void IP6AddrToStr(char *str, UINT size, IPV6_ADDR *addr)
{
	if (str == NULL || addr == NULL)
	{
		return;
	}

	IPToStr6Array(str, size, addr->Value);
}
void IPToStr6Array(char *str, UINT size, UCHAR *bytes)
{
	IP ip;
	if (str == NULL || bytes == NULL)
	{
		return;
	}

	SetIP6(&ip, bytes);

	IPToStr6(str, size, &ip);
}
void IPToStr6(char *str, UINT size, IP *ip)
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

bool StrToIP6(IP *ip, char *str)
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
		StrCpyAllowOverlap(tmp, sizeof(tmp), &tmp[1]);

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

static bool IsLocalHostIP6(IP *ip)
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
static bool IsLocalHostIP4(IP *ip)
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
bool IsLocalHostIP(IP *ip)
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

void IPv6AddrToIP(IP *ip, IPV6_ADDR *addr)
{
	if (ip == NULL || addr == NULL)
	{
		return;
	}

	SetIP6(ip, addr->Value);
}

bool IPToIPv6Addr(IPV6_ADDR *addr, IP *ip)
{
	UINT i;
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

	for (i = 0; i < sizeof(addr->Value); ++i)
	{
		addr->Value[i] = ip->address[i];
	}

	return true;
}

void SetIP6(IP *ip, UCHAR *value)
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

bool IsIP4(IP *ip)
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

void CopyIP(IP *dst, IP *src)
{
	Copy(dst, src, sizeof(IP));
}

bool IsValidUnicastIPAddress4(IP *ip)
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

bool IsValidUnicastIPAddress6(IP *ip)
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

UINT GetNumIpClient(IP *ip)
{
	IP_CLIENT *c;
	UINT ret = 0;
	if (ip == NULL)
	{
		return 0;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			ret = c->NumConnections;
		}
	}
	UnlockList(ip_clients);

	return ret;
}

// Map a source address to its per-source rate-limit key: an IPv4 address keeps all 32 bits,
// an IPv6 address keeps only its /64 prefix, since one host can pick any address inside its /64
void GetRateLimitKey(IP *key, IP *ip)
{
	if (key == NULL)
	{
		return;
	}

	Zero(key, sizeof(IP));

	if (ip == NULL)
	{
		return;
	}

	Copy(key->address, ip->address, sizeof(key->address));

	if (IsIP4(ip) == false)
	{
		Zero(&key->address[8], 8);
	}
}

// ip_clients is full: drop the key with the oldest last connection (ip_clients has no
// expired entries, a key leaves when its last connection closes), log the first time
static void EvictOldestIpClient()
{
	IP_CLIENT *oldest = NULL;
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		if (oldest == NULL || c->LastTick < oldest->LastTick)
		{
			oldest = c;
		}
	}

	if (oldest != NULL)
	{
		Delete(ip_clients, oldest);
		Free(oldest);
	}

	if (ip_clients_full_logged == false)
	{
		ip_clients_full_logged = true;
		Debug("ip_clients reached %u source keys, the least recently seen keys are dropped\n", RATE_LIMIT_TABLE_MAX);
	}
}

static void AddIpClient(IP *ip)
{
	IP_CLIENT *c;
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c == NULL)
		{
			if (LIST_NUM(ip_clients) >= RATE_LIMIT_TABLE_MAX)
			{
				EvictOldestIpClient();
			}

			c = ZeroMallocFast(sizeof(IP_CLIENT));
			GetRateLimitKey(&c->IpAddress, ip);
			c->NumConnections = 0;

			Add(ip_clients, c);
		}

		c->NumConnections++;
		c->LastTick = Tick64();
	}
	UnlockList(ip_clients);

}

static void DelIpClient(IP *ip)
{
	IP_CLIENT *c;
	if (ip == NULL)
	{
		return;
	}

	LockList(ip_clients);
	{
		c = SearchIpClient(ip);

		if (c != NULL)
		{
			c->NumConnections--;

			if (c->NumConnections == 0)
			{
				Delete(ip_clients, c);
				Free(c);
			}
		}
	}
	UnlockList(ip_clients);

}

IP_CLIENT *SearchIpClient(IP *ip)
{
	IP_CLIENT t;
	if (ip == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	GetRateLimitKey(&t.IpAddress, ip);

	return Search(ip_clients, &t);
}

static void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
	ip_clients_full_logged = false;
}

static void FreeIpClientList()
{
	UINT i;

	for (i = 0; i < LIST_NUM(ip_clients); i++)
	{
		IP_CLIENT *c = LIST_DATA(ip_clients, i);

		Free(c);
	}

	ReleaseList(ip_clients);
	ip_clients = NULL;
}

int CompareIpClientList(void *p1, void *p2)
{
	IP_CLIENT *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(IP_CLIENT **)p1;
	c2 = *(IP_CLIENT **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}

	return CmpIpAddr(&c1->IpAddress, &c2->IpAddress);
}

bool IsZeroIP(IP *ip)
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
bool IsZeroIP6Addr(IPV6_ADDR *addr)
{
	if (addr == NULL)
	{
		return true;
	}

	return IsZero(addr, sizeof(IPV6_ADDR));
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

static bool IsSubnetMask(IP *ip)
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
bool IsSubnetMask4(IP *ip)
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


static void Win32InitSocketLibrary()
{
	WSADATA data;
	Zero(&data, sizeof(data));
	WSAStartup(MAKEWORD(2, 2), &data);
}

static void Win32Cancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	SetEvent((HANDLE)c->hEvent);
}

static void Win32CleanupCancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	if (c->SpecialFlag == false)
	{
		CloseHandle(c->hEvent);
	}

	Free(c);
}

static CANCEL *Win32NewCancel()
{
	CANCEL *c = ZeroMallocFast(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = false;
	c->hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	return c;
}

static bool Win32WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	if (event == NULL || timeout == 0)
	{
		return false;
	}

	if (WaitForSingleObject((HANDLE)event->hEvent, timeout) == WAIT_OBJECT_0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

static void Win32CleanupSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	CloseHandle((HANDLE)event->hEvent);

	Free(event);
}

static void Win32SetSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	SetEvent((HANDLE)event->hEvent);
}

static SOCK_EVENT *Win32NewSockEvent()
{
	SOCK_EVENT *e = ZeroMallocFast(sizeof(SOCK_EVENT));

	e->ref = NewRef();
	e->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	return e;
}

static void Win32JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	HANDLE hEvent;
	if (sock == NULL || event == NULL || sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode != false || (sock->Type != SOCK_UDP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	hEvent = event->hEvent;

	WSAEventSelect(sock->socket, hEvent, FD_READ | FD_WRITE | FD_CLOSE);

	AddRef(event->ref);
	sock->SockEvent = event;
}

static void Win32InitAsyncSocket(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}
	if (sock->AsyncMode)
	{
		return;
	}
	if (sock->ListenMode || (sock->Type == SOCK_TCP && sock->Connected == false))
	{
		return;
	}

	sock->AsyncMode = true;

	sock->hEvent = (void *)CreateEvent(NULL, FALSE, FALSE, NULL);

	WSAEventSelect(sock->socket, sock->hEvent, FD_READ | FD_WRITE | FD_CLOSE);
}

static void Win32FreeAsyncSocket(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	if (sock->hEvent != NULL)
	{
		CloseHandle((HANDLE)sock->hEvent);
	}
	sock->hEvent = NULL;
	sock->AsyncMode = false;

	if (sock->SockEvent != NULL)
	{
		ReleaseSockEvent(sock->SockEvent);
		sock->SockEvent = NULL;
	}
}

static void Win32Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	HANDLE array[MAXIMUM_WAIT_OBJECTS];
	UINT n, i;
	SOCK *s;
	Zero(array, sizeof(array));
	n = 0;

	if (set != NULL)
	{
		for (i = 0; i < set->NumSocket; i++)
		{
			s = set->Sock[i];
			if (s != NULL)
			{
				Win32InitAsyncSocket(s);
				if (s->hEvent != NULL)
				{
					array[n++] = (HANDLE)s->hEvent;
				}
			}
		}
	}
	if (c1 != NULL && c1->hEvent != NULL)
	{
		array[n++] = c1->hEvent;
	}
	if (c2 != NULL && c2->hEvent != NULL)
	{
		array[n++] = c2->hEvent;
	}

	if (timeout == 0)
	{
		return;
	}

	if (n == 0)
	{
		SleepThread(timeout);
	}
	else
	{
		if (n == 1)
		{
			WaitForSingleObject(array[0], timeout);
		}
		else
		{
			WaitForMultipleObjects(n, array, false, timeout);
		}
	}
}


bool IsIPv6Supported()
{
	SOCKET s;

	s = socket(AF_INET6, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	closesocket(s);

	return true;
}

bool HasIPv6Address()
{
	LIST *o;
	UINT i;
	bool ret = false;

	o = GetHostIPAddressList();

	ret = false;

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (IsIP6(p))
		{
			UINT type = GetIPAddrType6(p);
			if ((type & IPV6_ADDR_GLOBAL_UNICAST) && ((type & IPV6_ADDR_ZERO) == 0) && ((type & IPV6_ADDR_LOOPBACK) == 0))
			{
				ret = true;
				break;
			}

		}
	}

	FreeHostIPAddressList(o);

	return ret;
}

void AddWaitThread(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	AddRef(t->ref);

	LockList(WaitThreadList);
	{
		Add(WaitThreadList, t);
	}
	UnlockList(WaitThreadList);
}

void DelWaitThread(THREAD *t)
{
	if (t == NULL)
	{
		return;
	}

	LockList(WaitThreadList);
	{
		if (Delete(WaitThreadList, t))
		{
			ReleaseThread(t);
		}
	}
	UnlockList(WaitThreadList);
}

static void InitWaitThread()
{
	WaitThreadList = NewList(NULL);
}

static void FreeWaitThread()
{
	UINT i, num;
	THREAD **threads;

	LockList(WaitThreadList);
	{
		num = LIST_NUM(WaitThreadList);
		threads = ToArray(WaitThreadList);
		DeleteAll(WaitThreadList);
	}
	UnlockList(WaitThreadList);

	for (i = 0; i < num; i++)
	{
		THREAD *t = threads[i];
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	Free(threads);

	ReleaseList(WaitThreadList);
	WaitThreadList = NULL;
}

SOCK_EVENT *NewSockEvent()
{
	return Win32NewSockEvent();
}

void SetSockEvent(SOCK_EVENT *event)
{
	Win32SetSockEvent(event);
}

bool WaitSockEvent(SOCK_EVENT *event, UINT timeout)
{
	bool ret = false;
	ret = Win32WaitSockEvent(event, timeout);
	return ret;
}

void ReleaseSockEvent(SOCK_EVENT *event)
{
	if (event == NULL)
	{
		return;
	}

	if (Release(event->ref) == 0)
	{
		Win32CleanupSockEvent(event);
	}
}

void JoinSockToSockEvent(SOCK *sock, SOCK_EVENT *event)
{
	if (sock == NULL || event == NULL)
	{
		return;
	}

	Win32JoinSockToSockEvent(sock, event);
}

CANCEL *NewCancelSpecial(void *hEvent)
{
	CANCEL *c;
	if (hEvent == NULL)
	{
		return NULL;
	}

	c = ZeroMalloc(sizeof(CANCEL));
	c->ref = NewRef();
	c->SpecialFlag = true;

	c->hEvent = (HANDLE)hEvent;

	return c;
}

CANCEL *NewCancel()
{
	CANCEL *c = NULL;
	c = Win32NewCancel();
	return c;
}

void ReleaseCancel(CANCEL *c)
{
	if (c == NULL)
	{
		return;
	}

	if (Release(c->ref) == 0)
	{
		Win32CleanupCancel(c);
	}
}

void Cancel(CANCEL *c)
{
	Win32Cancel(c);
}

// Fill a sockaddr for a UDP socket of the given family and return its length, 0 if the IP is not of that
// family. A NULL or zero IP gives the any-address, which is what bind wants.
static int UdpSockAddr(struct sockaddr_storage *sa, bool ipv6, IP *ip, UINT port)
{
	Zero(sa, sizeof(*sa));

	if (ipv6)
	{
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;

		if (ip != NULL && IsIP6(ip) == false)
		{
			return 0;
		}

		a6->sin6_family = AF_INET6;
		a6->sin6_port = htons((USHORT)port);

		if (ip != NULL && IsZeroIP(ip) == false)
		{
			IPToInAddr6(&a6->sin6_addr, ip);
			a6->sin6_scope_id = ip->ipv6_scope_id;
		}

		return sizeof(*a6);
	}
	else
	{
		struct sockaddr_in *a4 = (struct sockaddr_in *)sa;

		if (ip != NULL && IsIP4(ip) == false)
		{
			return 0;
		}

		a4->sin_family = AF_INET;
		a4->sin_port = htons((USHORT)port);

		if (ip != NULL && IsZeroIP(ip) == false)
		{
			IPToInAddr(&a4->sin_addr, ip);
		}

		return sizeof(*a4);
	}
}

// Read the source IP and port from the sockaddr that recvfrom filled in
static void UdpSockAddrToIP(IP *ip, UINT *port, struct sockaddr_storage *sa, bool ipv6)
{
	if (ipv6)
	{
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;

		InAddrToIP6(ip, &a6->sin6_addr);
		ip->ipv6_scope_id = a6->sin6_scope_id;
		*port = (UINT)ntohs(a6->sin6_port);
	}
	else
	{
		struct sockaddr_in *a4 = (struct sockaddr_in *)sa;

		InAddrToIP(ip, &a4->sin_addr);
		*port = (UINT)ntohs(a4->sin_port);
	}
}

// Whether a datagram to this address needs SO_BROADCAST: the IPv4 limited broadcast, or a multicast address
static bool UdpNeedsBroadcast(bool ipv6, IP *ip)
{
	const BYTE *ipv4;

	if (ipv6)
	{
		return (GetIPAddrType6(ip) & IPV6_ADDR_MULTICAST) != 0;
	}

	ipv4 = IPV4(ip->address);

	return (ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
		(ipv4[0] >= 224 && ipv4[0] <= 239);
}

// The result of a failed recvfrom (send == false) or sendto (send == true): SOCK_LATER when the call would
// block, else 0. An error that only means "the datagram was lost" sets the Ignore flag of that direction.
static UINT UdpIoFailed(SOCK *sock, bool send)
{
	UINT e = (UINT)WSAGetLastError();

	if (e == WSAECONNRESET || e == WSAENETRESET || e == WSAEMSGSIZE || e == WSAENETUNREACH ||
	        e == WSAENOBUFS || e == WSAEHOSTUNREACH || e == WSAEUSERS || e == WSAEADDRNOTAVAIL ||
	        (send && e == WSAEINVAL))
	{
		if (send)
		{
			sock->IgnoreSendErr = true;
		}
		else
		{
			sock->IgnoreRecvErr = true;
		}
	}
	else if (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS)
	{
		return SOCK_LATER;
	}
	else if (send == false)
	{
		Debug("RecvFrom(): recvfrom() failed with error: %u\n", e);
	}

	return 0;
}

UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_storage addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock == NULL)
	{
		return 0;
	}

	sock->IgnoreRecvErr = false;

	if (src_addr == NULL || src_port == NULL || data == NULL || size == 0)
	{
		return 0;
	}

	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}

	ret = recvfrom(sock->socket, data, size, 0, (struct sockaddr *)&addr, &socklen);
	if (ret > 0)
	{
		UdpSockAddrToIP(src_addr, src_port, &addr, sock->IPv6);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}

	return UdpIoFailed(sock, false);
}

UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	struct sockaddr_storage addr;
	int addrlen;
	int ret;

	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || dest_port == 0 || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536)
	{
		return 0;
	}
	if (sock->Type != SOCK_UDP || sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (size == 0)
	{
		return 0;
	}

	addrlen = UdpSockAddr(&addr, sock->IPv6, dest_addr, dest_port);
	if (addrlen == 0)
	{
		return 0;
	}

	if (sock->UdpBroadcast == false && UdpNeedsBroadcast(sock->IPv6, dest_addr))
	{
		UINT yes = 1;

		sock->UdpBroadcast = true;

		(void)setsockopt(sock->socket, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
	}

	ret = sendto(sock->socket, data, size, 0, (struct sockaddr *)&addr, addrlen);
	if (ret != (int)size)
	{
		return UdpIoFailed(sock, true);
	}

	return ret;
}

// Winsock reports an ICMP port or network unreachable, caused by an earlier datagram of a UDP socket, as
// WSAECONNRESET or WSAENETRESET on the next recvfrom() or sendto() of the socket. The error says nothing about
// the datagram at hand and every caller only skips it, so both reports are switched off.
static void DisableUdpReset(SOCKET s)
{
	BOOL off = FALSE;
	DWORD ret_size = 0;

	if (WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), NULL, 0, &ret_size, NULL, NULL) != 0)
	{
		Debug("DisableUdpReset(): SIO_UDP_CONNRESET failed with error: %u\n", WSAGetLastError());
	}

	if (WSAIoctl(s, SIO_UDP_NETRESET, &off, sizeof(off), NULL, 0, &ret_size, NULL, NULL) != 0)
	{
		Debug("DisableUdpReset(): SIO_UDP_NETRESET failed with error: %u\n", WSAGetLastError());
	}
}

SOCK *NewUDP(UINT port)
{
	return NewUDPEx2(port, false, NULL);
}
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_storage addr;
	int addrlen;
	UINT true_flag = 1;

	addrlen = UdpSockAddr(&addr, ipv6, ip, port);
	if (addrlen == 0)
	{
		return NULL;
	}

	s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
	{
		if (port != 0)
		{
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
			{
				UINT false_flag = 0;
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
				if (bind(s, (struct sockaddr *)&addr, addrlen) != 0)
				{
					closesocket(s);
					return NULL;
				}
			}
		}
		else
		{
			closesocket(s);
			return NULL;
		}
	}

	sock = NewSock();

	sock->Type = SOCK_UDP;
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = false;
	sock->IPv6 = ipv6;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	DisableUdpReset(s);

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDPEx3(UINT port, IP *ip)
{
	return NewUDPEx2(port, ip != NULL && IsIP4(ip) == false, ip);
}

void Select(SOCKSET *set, UINT timeout, CANCEL *c1, CANCEL *c2)
{
	Win32Select(set, timeout, c1, c2);
}

void AddSockSet(SOCKSET *set, SOCK *sock)
{
	if (set == NULL || sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_TCP && sock->Connected == false)
	{
		return;
	}

	if (set->NumSocket >= MAX_SOCKSET_NUM)
	{
		return;
	}
	set->Sock[set->NumSocket++] = sock;
}

void InitSockSet(SOCKSET *set)
{
	if (set == NULL)
	{
		return;
	}

	Zero(set, sizeof(SOCKSET));
}

bool RecvAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UINT recv_size, sz, ret;
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}
	if (sock->AsyncMode)
	{
		return false;
	}

	recv_size = 0;

	while (true)
	{
		sz = size - recv_size;
		ret = Recv(sock, (UCHAR *)data + recv_size, sz, secure);
		if (ret == 0)
		{
			return false;
		}
		if (ret == SOCK_LATER)
		{
			// Safe: RecvAll() runs only when AsyncMode is true, and Recv() returns
			// SOCK_LATER only when AsyncMode is false.
			return false;
		}
		recv_size += ret;
		if (recv_size >= size)
		{
			return true;
		}
	}
}

bool SendNow(SOCK *sock, int secure)
{
	bool ret;
	if (sock == NULL || sock->AsyncMode != false)
	{
		return false;
	}
	if (sock->SendBuf->Size == 0)
	{
		return true;
	}

	ret = SendAll(sock, sock->SendBuf->Buf, sock->SendBuf->Size, secure);
	ClearBuf(sock->SendBuf);

	return ret;
}

void SendAdd(SOCK *sock, void *data, UINT size)
{
	if (sock == NULL || data == NULL || size == 0 || sock->AsyncMode != false)
	{
		return;
	}

	WriteBuf(sock->SendBuf, data, size);
}

bool SendAll(SOCK *sock, void *data, UINT size, bool secure)
{
	UCHAR *buf;
	UINT sent_size;
	UINT ret;
	if (sock == NULL || data == NULL)
	{
		return false;
	}
	if (sock->AsyncMode)
	{
		return false;
	}
	if (size == 0)
	{
		return true;
	}

	buf = (UCHAR *)data;
	sent_size = 0;

	while (true)
	{
		ret = Send(sock, buf, size - sent_size, secure);
		if (ret == 0)
		{
			return false;
		}
		sent_size += ret;
		buf += ret;
		if (sent_size >= size)
		{
			return true;
		}
	}
}

// Certificates of the chain_certs folder next to the exe, deduplicated by SHA-1 digest. The cache is scanned
// once and again only after the folder changed (a change notification) or InvalidateChainCertCache() was called
static LOCK *chain_cert_lock = NULL;
static LIST *chain_cert_list = NULL;				// X of the folder, each digest once
static HANDLE chain_cert_notify = INVALID_HANDLE_VALUE;	// Change notification of the folder
static bool chain_cert_valid = false;				// chain_cert_list is current
static UINT chain_cert_scans = 0;					// Scans of the folder so far

// Get the folder of the chain certificates
static void GetChainCertDirW(wchar_t *dirname, UINT size)
{
	wchar_t exedir[MAX_SIZE];

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, size, exedir, L"chain_certs");
}

// Create the folder of the chain certificates (once, at server start)
void PrepareChainCertDir()
{
	wchar_t dirname[MAX_SIZE];

	GetChainCertDirW(dirname, sizeof(dirname));

	MakeDirExW(dirname);
}

// Mark the cached chain certificates as out of date: the next connection scans the folder again
void InvalidateChainCertCache()
{
	if (chain_cert_lock == NULL)
	{
		return;
	}

	Lock(chain_cert_lock);
	{
		chain_cert_valid = false;
	}
	Unlock(chain_cert_lock);
}

// Number of scans of the chain_certs folder so far
UINT GetChainCertScanCount()
{
	UINT ret;

	if (chain_cert_lock == NULL)
	{
		return 0;
	}

	Lock(chain_cert_lock);
	{
		ret = chain_cert_scans;
	}
	Unlock(chain_cert_lock);

	return ret;
}

// Release the cache and the change notification
static void FreeChainCertCache()
{
	if (chain_cert_list != NULL)
	{
		FreeXList(chain_cert_list);
		chain_cert_list = NULL;
	}

	if (chain_cert_notify != INVALID_HANDLE_VALUE)
	{
		FindCloseChangeNotification(chain_cert_notify);
		chain_cert_notify = INVALID_HANDLE_VALUE;
	}

	chain_cert_valid = false;
}

// Read the folder into the cache. chain_cert_lock is held
static void ScanChainCertDir(wchar_t *dirname)
{
	DIRLIST *dir;
	LIST *o;
	LIST *hashes;
	UINT i;

	o = NewListFast(NULL);
	hashes = NewListFast(NULL);

	dir = EnumDirW(dirname);

	if (dir != NULL)
	{
		for (i = 0; i < dir->NumFiles; i++)
		{
			DIRENT *e = dir->File[i];

			if (e->Folder == false)
			{
				wchar_t tmp[MAX_SIZE];
				X *x;

				CombinePathW(tmp, sizeof(tmp), dirname, e->FileNameW);

				x = FileToXW(tmp);

				if (x != NULL)
				{
					UINT j;
					bool exists = false;
					UCHAR hash[SHA1_SIZE];

					GetXDigest(x, hash, true);

					for (j = 0; j < LIST_NUM(hashes); j++)
					{
						UCHAR *hash2 = LIST_DATA(hashes, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0)
						{
							exists = true;
							break;
						}
					}

					if (exists == false)
					{
						Add(hashes, Clone(hash, SHA1_SIZE));
						Add(o, x);
					}
					else
					{
						FreeX(x);
					}
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0; i < LIST_NUM(hashes); i++)
	{
		Free(LIST_DATA(hashes, i));
	}

	ReleaseList(hashes);

	chain_cert_list = o;
	chain_cert_scans++;
}

// Bring the cache up to date: read the folder again when it changed or was invalidated. chain_cert_lock is held
static void RefreshChainCertCache()
{
	if (chain_cert_valid && chain_cert_notify != INVALID_HANDLE_VALUE &&
		WaitForSingleObject(chain_cert_notify, 0) == WAIT_OBJECT_0)
	{
		// The folder changed: arm the notification again before the scan so that a change during it is seen
		if (FindNextChangeNotification(chain_cert_notify) == false)
		{
			FindCloseChangeNotification(chain_cert_notify);
			chain_cert_notify = INVALID_HANDLE_VALUE;
		}

		chain_cert_valid = false;
	}

	if (chain_cert_valid == false)
	{
		wchar_t dirname[MAX_SIZE];

		GetChainCertDirW(dirname, sizeof(dirname));

		if (chain_cert_list != NULL)
		{
			FreeXList(chain_cert_list);
			chain_cert_list = NULL;
		}

		// The notification is opened before the scan so that no change between them is lost
		if (chain_cert_notify == INVALID_HANDLE_VALUE)
		{
			chain_cert_notify = FindFirstChangeNotificationW(dirname, FALSE,
				FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE);
		}

		ScanChainCertDir(dirname);

		// Without a notification (no folder) every call scans
		chain_cert_valid = (chain_cert_notify != INVALID_HANDLE_VALUE);
	}
}

// Generation of the chain certificates: it changes each time the cached list is read again. The cache is brought
// up to date first, so a context built after this call has the certificates of this generation (or newer ones)
UINT GetChainCertGeneration()
{
	UINT ret;

	if (chain_cert_lock == NULL)
	{
		return 0;
	}

	Lock(chain_cert_lock);
	{
		RefreshChainCertCache();

		ret = chain_cert_scans;
	}
	Unlock(chain_cert_lock);

	return ret;
}

// Add the certificates of the chain_certs folder to the chain of ctx. Returns the number added
UINT AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx)
{
	UINT i;
	UINT ret = 0;

	if (ctx == NULL || chain_cert_lock == NULL)
	{
		return 0;
	}

	Lock(chain_cert_lock);
	{
		RefreshChainCertCache();

		for (i = 0; i < LIST_NUM(chain_cert_list); i++)
		{
			if (AddChainSslCert(ctx, LIST_DATA(chain_cert_list, i)))
			{
				ret++;
			}
		}
	}
	Unlock(chain_cert_lock);

	return ret;
}

bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x)
{
	if (ctx == NULL || x == NULL || x->x509 == NULL)
	{
		return false;
	}

	// The context takes over the reference when it succeeds
	if (X509_up_ref(x->x509) != 1)
	{
		return false;
	}

	if (SSL_CTX_add_extra_chain_cert(ctx, x->x509) != 1)
	{
		X509_free(x->x509);
		return false;
	}

	return true;
}

// Drain the OpenSSL error queue of a failed SSL_accept or SSL_connect into the ssl_err code
static void SslHandshakeError(bool server_mode, UINT *ssl_err)
{
	unsigned long err;
	while ((err = ERR_get_error()) != 0)
	{
		Debug("%s error %X: %s\n", server_mode ? "SSL_accept" : "SSL_connect", (UINT)err, ERR_reason_error_string(err));
		if (ERR_GET_LIB(err) != ERR_LIB_SSL)
		{
			continue;
		}
		switch (ERR_GET_REASON(err))
		{
		case SSL_R_UNSUPPORTED_PROTOCOL:
		case SSL_R_VERSION_TOO_LOW:
#if defined(SSL_R_VERSION_TOO_HIGH)
		case SSL_R_VERSION_TOO_HIGH:
#endif
			*ssl_err = 150;
			break;
		// The two reasons the accept and connect mappings disagree on
		case SSL_R_TLSV1_ALERT_PROTOCOL_VERSION:
			*ssl_err = (server_mode ? 152 : 150);
			break;
		case SSL_R_NO_SHARED_CIPHER:
			*ssl_err = (server_mode ? 151 : 152);
			break;
		default:
			*ssl_err = 152;
		}
	}
}

// Add the Windows ROOT store's certificates to a client's verification store
static void AddSslRootCerts(X509_STORE *store)
{
	UINT64 now = Tick64();
	int i;

	if (ssl_root_certs == NULL || now >= ssl_root_certs_tick + SSL_ROOT_CERTS_REFRESH_SPAN)
	{
		STACK_OF(X509) *certs = sk_X509_new_null();

		if (certs != NULL)
		{
			HCERTSTORE hStore = CertOpenSystemStore(0, "ROOT");
			if (hStore != NULL)
			{
				PCCERT_CONTEXT pContext = NULL;
				while ((pContext = CertEnumCertificatesInStore(hStore, pContext)) != NULL)
				{
					// d2i_X509 advances the pointer it is given: decode from a local copy, never the store's own context
					const unsigned char *der = pContext->pbCertEncoded;
					X509 *x509 = d2i_X509(NULL, &der, (long)pContext->cbCertEncoded);
					if (x509 != NULL && sk_X509_push(certs, x509) == 0)
					{
						X509_free(x509);
					}
				}
				CertCloseStore(hStore, 0);
			}

			sk_X509_pop_free(ssl_root_certs, X509_free);
			ssl_root_certs = certs;
			ssl_root_certs_tick = now;
		}
	}

	if (ssl_root_certs != NULL)
	{
		for (i = 0; i < sk_X509_num(ssl_root_certs); i++)
		{
			X509_STORE_add_cert(store, sk_X509_value(ssl_root_certs, i));
		}
	}
}

static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err);

// A server context with every setting that does not depend on the connection applied: version flags, security
// level, certificate chain, certificate and key, cipher list and groups. x and priv may be NULL (no certificate),
// chain NULL takes the certificates of the chain_certs folder, cipher_list NULL keeps the OpenSSL default and
// settings NULL overrides nothing. Connections take the context by reference (ShareSSLCtx, FreeSSLCtx)
struct ssl_ctx_st *NewServerSSLCtx(X *x, K *priv, LIST *chain, char *cipher_list, SSL_ACCEPT_SETTINGS *settings)
{
	SSL_CTX *ctx;
	SSL_ACCEPT_SETTINGS none;
	bool use_cert = (x != NULL && priv != NULL && CheckXandK(x, priv));

	ctx = NewSSLCtx(true);
	if (ctx == NULL)
	{
		return NULL;
	}

	if (settings == NULL)
	{
		Zero(&none, sizeof(none));
		settings = &none;
	}

	if (settings->Tls_Disable1_0)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
	}

	if (settings->Tls_Disable1_1)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
	}

	if (settings->Tls_Disable1_2)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
	}

	if (settings->Tls_Disable1_3)
	{
		SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
	}

	if (chain == NULL)
	{
		AddChainSslCertOnDirectory(ctx);
	}
	else
	{
		UINT i;

		LockList(chain);
		{
			for (i = 0;i < LIST_NUM(chain);i++)
			{
				AddChainSslCert(ctx, LIST_DATA(chain, i));
			}
		}
		UnlockList(chain);
	}

	if (settings->Override_Security_Level)
	{
		SSL_CTX_set_security_level(ctx, settings->Override_Security_Level_Value);
	}

	if (use_cert)
	{
		SSL_CTX_use_certificate(ctx, x->x509);
		SSL_CTX_use_PrivateKey(ctx, priv->pkey);
	}

	if (cipher_list != NULL)
	{
		if (SSL_CTX_set_cipher_list(ctx, cipher_list) == 0)
		{
			SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
		}
	}

	SSL_CTX_set1_groups_list(ctx, PQ_GROUP_LIST);

	// A context that lives for many connections must not resume sessions: a fresh context per connection never did
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

	return ctx;
}

bool StartSSL(SOCK *sock, X *x, K *priv)
{
	return StartSSLEx(sock, x, priv, NULL);
}
bool StartSSLEx(SOCK *sock, X *x, K *priv, char *sni_hostname)
{
	return StartSSLEx3(sock, x, priv, NULL, sni_hostname, NULL, NULL);
}
bool StartSSLEx3(SOCK *sock, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err)
{
	return StartSSLMain(sock, NULL, x, priv, chain, sni_hostname, ssl_option, ssl_err);
}
// Start TLS on an accepted connection with a server context that is shared by many connections (NewServerSSLCtx).
// The caller keeps its own reference of ctx
bool StartSSLServer(SOCK *sock, struct ssl_ctx_st *ctx, UINT *ssl_err)
{
	if (ctx == NULL)
	{
		return false;
	}

	return StartSSLMain(sock, ctx, NULL, NULL, NULL, NULL, NULL, ssl_err);
}
// server_ctx NULL: a context of this call (a client context, or a server one built from x, priv and chain)
static bool StartSSLMain(SOCK *sock, struct ssl_ctx_st *server_ctx, X *x, K *priv, LIST *chain, char *sni_hostname, SSL_VERIFY_OPTION *ssl_option, UINT *ssl_err)
{
	X509 *x509;
	EVP_PKEY *key;
	UINT prev_timeout;
	SSL_CTX *ssl_ctx;
	UINT dummy_err = 0;
	long ssl_verify_err;
	int handshake_ret;

	if (sock == NULL)
	{
		return false;
	}
	if (ssl_err == NULL)
	{
		ssl_err = &dummy_err;
	}
	if (sock->Connected == false || sock->socket == INVALID_SOCKET ||
	        sock->ListenMode != false)
	{
		return false;
	}
	if (x != NULL && priv == NULL)
	{
		return false;
	}
	if (server_ctx != NULL && sock->ServerMode == false)
	{
		return false;
	}

	if (sock->SecureMode)
	{
		return true;
	}

	Lock(sock->ssl_lock);
	if (sock->SecureMode)
	{
		Unlock(sock->ssl_lock);
		return true;
	}

	if (server_ctx != NULL)
	{
		ShareSSLCtx(server_ctx);
		ssl_ctx = server_ctx;
	}
	else if (sock->ServerMode)
	{
		ssl_ctx = NewServerSSLCtx(x, priv, chain, NULL, NULL);
	}
	else
	{
		ssl_ctx = NewSSLCtx(false);
	}
	if (ssl_ctx == NULL)
	{
		goto FAIL;
	}

	if (sock->ServerMode == false)
	{
		if (ssl_option != NULL && ssl_option->VerifyPeer)
		{
			X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
			if (ssl_option->AddDefaultCA)
			{
				AddSslRootCerts(store);
			}

			UINT i;
			for (i = 0; i < LIST_NUM(ssl_option->CaList); ++i)
			{
				X *ca = LIST_DATA(ssl_option->CaList, i);
				X509_STORE_add_cert(store, ca->x509);
			}

			X509_VERIFY_PARAM *vpm = SSL_CTX_get0_param(ssl_ctx);
			X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_PARTIAL_CHAIN);

			// Enable hostname verification (by default CN is only checked if SAN is not available)
			if (ssl_option->VerifyHostname && IsEmptyStr(sni_hostname) == false)
			{
				X509_VERIFY_PARAM_set1_host(vpm, sni_hostname, StrLen(sni_hostname));
			}
		}
	}

	sock->ssl = SSL_new(ssl_ctx);

	if (sock->ssl == NULL)
	{
		goto FAIL;
	}

	SSL_set_fd(sock->ssl, (int)sock->socket);

	if (sock->ServerMode == false)
	{
		if (IsEmptyStr(sni_hostname) == false)
		{
			SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
		}
	}

	if (sock->ServerMode == false)
	{
		// A client: certificate and groups of this connection (a server has them in its context)
		if (x != NULL)
		{
			if (CheckXandK(x, priv))
			{
				x509 = x->x509;
				key = priv->pkey;

				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
		}

		SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);
	}

	if (sock->ServerMode)
	{
		handshake_ret = SSL_accept(sock->ssl);
	}
	else
	{
		prev_timeout = GetTimeout(sock);
		SetTimeout(sock, TIMEOUT_SSL_CONNECT);
		handshake_ret = SSL_connect(sock->ssl);
		SetTimeout(sock, prev_timeout);
	}

	if (handshake_ret <= 0)
	{
		SslHandshakeError(sock->ServerMode, ssl_err);
		goto FAIL;
	}

	if (sock->ServerMode)
	{

		if (true)
		{
			const char *sni_recv_hostname = SSL_get_servername(sock->ssl, TLSEXT_NAMETYPE_host_name);

			if (IsEmptyStr((char *)sni_recv_hostname) == false)
			{
				StrCpy(sock->SniHostname, sizeof(sock->SniHostname), (char *)sni_recv_hostname);
			}
		}

	}

	x509 = SSL_get_peer_certificate(sock->ssl);
	ssl_verify_err = SSL_get_verify_result(sock->ssl);
	sock->SslVersion = SSL_get_version(sock->ssl);

	if (x509 == NULL)
	{
		sock->RemoteX = NULL;
	}
	else
	{
		sock->RemoteX = X509ToX(x509);
		if (sock->RemoteX == NULL)
		{
			// X509ToX leaves a certificate it refuses to the caller: our reference
			FreeX509(x509);
		}
	}

	if (ssl_option != NULL && ssl_option->VerifyPeer)
	{
		// OpenSSL checks no name when none is given: hostname verification without a hostname is a mismatch
		if (ssl_verify_err == X509_V_OK && sock->ServerMode == false && ssl_option->VerifyHostname && IsEmptyStr(sni_hostname))
		{
			ssl_verify_err = X509_V_ERR_HOSTNAME_MISMATCH;
		}

		if (ssl_verify_err != X509_V_OK)
		{
			// Clear any error if matching saved certificate and not expired
			if (ssl_option->SavedCert != NULL && sock->RemoteX != NULL && CheckXDateNow(sock->RemoteX) && CompareX(ssl_option->SavedCert, sock->RemoteX))
			{
				ssl_verify_err = X509_V_OK;
			}
			else
			{
				switch (ssl_verify_err)
				{
				case X509_V_ERR_CERT_HAS_EXPIRED:
					*ssl_err = 106;
					break;
				case X509_V_ERR_HOSTNAME_MISMATCH:
					*ssl_err = 149;
					break;
				default:
					*ssl_err = 85;
				}

				if (ssl_option->PromptOnVerifyFail == false)
				{
					goto FAIL;
				}
			}
		}
	}

	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));

	// The only success point: Recv/Send(secure) and Disconnect see SecureMode with a live ssl and ssl_ctx
	sock->SecureMode = true;

	Unlock(sock->ssl_lock);

	return true;

FAIL:
	// The one failure exit: no SSL object, no context, no lock held, not secure
	if (sock->ssl != NULL)
	{
		SSL_free(sock->ssl);
		sock->ssl = NULL;
	}
	FreeSSLCtx(ssl_ctx);
	sock->SecureMode = false;

	Unlock(sock->ssl_lock);

	return false;
}

// A failed recv, send or SSL call: SOCK_LATER when an async socket only has to wait, else the socket is disconnected
static UINT SockFailResult(SOCK *sock, bool later)
{
	if (later)
	{
		return SOCK_LATER;
	}

	Disconnect(sock);
	return 0;
}

// The SSL_get_error code of a failed SSL_peek, SSL_read or SSL_write: an async socket waits on WANT_READ/WANT_WRITE
static UINT SslFailResult(SOCK *sock, int e)
{
	if (sock->AsyncMode && e == SSL_ERROR_SSL)
	{
		UINT ssl_err_no;
		while ((ssl_err_no = ERR_get_error()) != 0)
		{
			Debug("%s %u SSL_ERROR_SSL on ASYNC socket !!! ssl_err_no = %u: '%s'\n", __FILE__, __LINE__, ssl_err_no, ERR_error_string(ssl_err_no, NULL));
		}
	}

	return SockFailResult(sock, sock->AsyncMode && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE));
}

static UINT SecureRecv(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;

	if (sock->AsyncMode)
	{
		// In async mode, check that at least 1 byte is readable: SSL_read would block otherwise.
		char c;
		Lock(sock->ssl_lock);
		{
			if (sock->Connected == false || sock->ssl == NULL)
			{
				Unlock(sock->ssl_lock);
				return 0;
			}
			ERR_clear_error();
			ret = SSL_peek(sock->ssl, &c, sizeof(c));
			if (ret <= 0)
			{
				e = SSL_get_error(sock->ssl, ret);
			}
		}
		Unlock(sock->ssl_lock);
		// Both 0 and negative values may be retryable: use SSL_get_error().
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		if (ret <= 0 && (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_SSL))
		{
			return SslFailResult(sock, e);
		}
	}

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		ERR_clear_error();
		ret = SSL_read(sock->ssl, data, size);

		if (ret <= 0)
		{
			e = SSL_get_error(sock->ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

static UINT SecureSend(SOCK *sock, void *data, UINT size)
{
	int ret, e = SSL_ERROR_NONE;

	Lock(sock->ssl_lock);
	{
		if (sock->Connected == false || sock->ssl == NULL)
		{
			Unlock(sock->ssl_lock);
			return 0;
		}

		if (sock->AsyncMode)
		{
			SSL_set_mode(sock->ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
		}

		ERR_clear_error();
		ret = SSL_write(sock->ssl, data, size);
		if (ret <= 0)
		{
			e = SSL_get_error(sock->ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SslFailResult(sock, e);
}

UINT Recv(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;

	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	// recv and SSL_read take an int: the same cap as Send
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);

	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureRecv(sock, data, size);
	}

	s = sock->socket;

	ret = recv(s, data, size, 0);

	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

UINT Send(SOCK *sock, void *data, UINT size, bool secure)
{
	SOCKET s;
	int ret;
	if (sock == NULL || data == NULL || size == 0)
	{
		return 0;
	}
	size = MIN(size, MAX_SEND_BUF_MEM_SIZE);
	if (sock->Type != SOCK_TCP || sock->Connected == false || sock->ListenMode != false ||
	        sock->socket == INVALID_SOCKET)
	{
		return 0;
	}
	if (secure != false && sock->SecureMode == false)
	{
		return 0;
	}

	if (secure)
	{
		return SecureSend(sock, data, size);
	}

	s = sock->socket;
	ret = send(s, data, size, 0);
	if (ret > 0)
	{
		return (UINT)ret;
	}

	return SockFailResult(sock, sock->AsyncMode && ret == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK);
}

UINT GetTimeout(SOCK *sock)
{
	if (sock == NULL)
	{
		return INFINITE;
	}
	if (sock->Type != SOCK_TCP)
	{
		return INFINITE;
	}

	return sock->TimeOut;
}

void SetTimeout(SOCK *sock, UINT timeout)
{
	if (sock == NULL)
	{
		return;
	}
	if (sock->Type == SOCK_UDP)
	{
		return;
	}

	if (timeout == INFINITE)
	{
		timeout = TIMEOUT_INFINITE;
	}

	// Same value again, or "no limit" on a socket whose timeouts were never set (the OS default): nothing to change
	if (timeout == sock->TimeOut || (timeout == TIMEOUT_INFINITE && sock->TimeOut == 0))
	{
		sock->TimeOut = timeout;
		return;
	}

	sock->TimeOut = timeout;

	setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(UINT));
	setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(UINT));
}

void DisableGetHostNameWhenAcceptInit()
{
	disable_gethostname_by_accept = true;
}

void AcceptInit(SOCK *s)
{
	AcceptInitEx(s, false);
}
void AcceptInitEx(SOCK *s, bool no_lookup_hostname)
{
	char tmp[MAX_SIZE];
	if (s == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	if (disable_gethostname_by_accept == false && no_lookup_hostname == false)
	{
		if (GetHostName(tmp, sizeof(tmp), &s->RemoteIP) == false ||
		        IsEmptyStr(tmp))
		{
			IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
		}
	}
	else
	{
		IPToStr(tmp, sizeof(tmp), &s->RemoteIP);
	}

	if (s->RemoteHostname != NULL)
	{
		Free(s->RemoteHostname);
	}

	s->RemoteHostname = CopyStr(tmp);
}

// True when a failed accept() of a listening socket may succeed on the next call: the peer reset or aborted the
// connection before it was accepted, or the process ran short of buffers or descriptors. Any other error, and a
// canceled accept (err 0), means that the listening socket must be rebuilt.
bool IsTransientAcceptError(UINT err)
{
	switch (err)
	{
	case WSAECONNRESET:
	case WSAECONNABORTED:
	case WSAENOBUFS:
	case WSAEMFILE:
		return true;

	default:
		return false;
	}
}

SOCK *Accept(SOCK *sock)
{
	SOCK *ret;
	SOCKET s, new_socket;
	int size;
	struct sockaddr_storage addr;
	UINT true_flag = 1;
	bool is_ipv6;
	if (sock == NULL)
	{
		return NULL;
	}
	sock->AcceptError = 0;
	if (sock->ListenMode == false || sock->Type != SOCK_TCP || sock->ServerMode == false)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		return NULL;
	}

	s = sock->socket;
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}
	Zero(&addr, sizeof(addr));
	size = sizeof(addr);

	if (sock->EnableConditionalAccept)
	{
		new_socket = Win32Accept(sock, s, (struct sockaddr *)&addr, &size);
	}
	else
	{
		new_socket = accept(s, (struct sockaddr *)&addr, &size);
		if (new_socket == INVALID_SOCKET)
		{
			sock->AcceptError = WSAGetLastError();
		}
	}

	if (new_socket == INVALID_SOCKET)
	{
		return NULL;
	}
	if (sock->CancelAccept)
	{
		closesocket(new_socket);
		return NULL;
	}

	ret = NewSock();
	ret->socket = new_socket;
	ret->Connected = true;
	ret->AsyncMode = false;
	ret->Type = SOCK_TCP;
	ret->ServerMode = true;
	ret->SecureMode = false;

	(void)setsockopt(ret->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(ret, TIMEOUT_INFINITE);

	QuerySocketInformation(ret);

	// An IPv4 peer of the dual-stack listener arrives as ::ffff:a.b.c.d, which decodes to an IPv4 address
	is_ipv6 = IsIP6(&ret->RemoteIP);

	if (IsLocalHostIP(&ret->RemoteIP) == false)
	{
		ret->IpClientAdded = true;
		AddIpClient(&ret->RemoteIP);
	}

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, is_ipv6) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, is_ipv6);
		}
	}

	StrCpy(ret->UnderlayProtocol, sizeof(ret->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);

	AddProtocolDetailsStr(ret->ProtocolDetails, sizeof(ret->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	return ret;
}

SOCK *Listen(UINT port)
{
	return ListenEx2(port, false, false, NULL, false);
}

// A TCP socket bound to addr. An AF_INET6 socket gets IPV6_V6ONLY from v6only: false makes it dual-stack.
// bind_failed (may be NULL) tells a failed bind(), a port held or reserved, from a family the stack does not support.
static SOCKET ListenBind(struct sockaddr *addr, int addr_size, bool v6only, bool *bind_failed)
{
	SOCKET s = socket(addr->sa_family, SOCK_STREAM, 0);

	if (bind_failed != NULL)
	{
		*bind_failed = false;
	}

	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (addr->sa_family == AF_INET6)
	{
		DWORD flag = (v6only ? 1 : 0);

		if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flag, sizeof(flag)) != 0)
		{
			closesocket(s);
			return INVALID_SOCKET;
		}
	}

	if (bind(s, addr, addr_size) != 0)
	{
		if (bind_failed != NULL)
		{
			*bind_failed = true;
		}

		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// One TCP listen socket per port. Without a ListenIP it is a dual-stack AF_INET6 socket on [::]:port, so IPv4 peers
// arrive as ::ffff:a.b.c.d. AF_INET is used for local_only, an IPv4 ListenIP, ipv4_only or an unsupported IPv6.
SOCK *ListenEx2(UINT port, bool local_only, bool enable_ca, IP *listen_ip, bool ipv4_only)
{
	SOCKET s = INVALID_SOCKET;
	SOCK *sock;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	UINT backlog = SOMAXCONN;
	UINT true_flag = 1;
	bool is_ipv6 = false;
	if (port == 0 || port >= 65536)
	{
		return NULL;
	}

	Zero(&addr4, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons((UINT)port);
	Zero(&addr6, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons((UINT)port);

	if (local_only)
	{
		IP localhost;

		SetIP(&localhost, 127, 0, 0, 1);
		IPToInAddr(&addr4.sin_addr, &localhost);

		enable_ca = false;

		s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false, NULL);
	}
	else if (listen_ip == NULL || IsZeroIP(listen_ip))
	{
		bool held = false;

		if (ipv4_only == false)
		{
			s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), false, &held);
			is_ipv6 = true;
		}

		// IPv6 is off or unsupported: IPv4 listens. A port another process holds or Windows reserves stays a failed
		// bind, so the listener reports it and retries instead of listening on one family only.
		if (s == INVALID_SOCKET && held == false)
		{
			s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false, NULL);
			is_ipv6 = false;
		}
	}
	else if (IsIP4(listen_ip))
	{
		IPToInAddr(&addr4.sin_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false, NULL);
	}
	else if (ipv4_only == false)
	{
		IPToInAddr6(&addr6.sin6_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), true, NULL);
		is_ipv6 = true;
	}

	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	if (enable_ca)
	{
		setsockopt(s, SOL_SOCKET, SO_CONDITIONAL_ACCEPT, (char *)&true_flag, sizeof(true_flag));
		backlog = 1;
	}

	if (listen(s, backlog))
	{
		closesocket(s);
		return NULL;
	}

	sock = NewSock();
	sock->Connected = false;
	sock->AsyncMode = false;
	sock->ServerMode = true;
	sock->Type = SOCK_TCP;
	sock->socket = s;
	sock->ListenMode = true;
	sock->SecureMode = false;
	sock->LocalPort = port;
	sock->IPv6 = is_ipv6;
	sock->EnableConditionalAccept = enable_ca;

	return sock;
}

void Disconnect(SOCK *sock)
{
	SOCKET s;
	if (sock == NULL)
	{
		return;
	}

	if (sock->Type == SOCK_TCP && sock->ListenMode)
	{
		sock->CancelAccept = true;

		if (sock->hAcceptEvent != NULL)
		{
			SetEvent(sock->hAcceptEvent);
		}
	}

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				return;
			}
			s = sock->socket;

			if (sock->Connected)
			{
				shutdown(s, SD_BOTH);
			}

			closesocket(s);

			Lock(sock->ssl_lock);
			{
				if (sock->SecureMode)
				{
					if (sock->ssl != NULL)
					{
						SSL_free(sock->ssl);
						FreeSSLCtx(sock->ssl_ctx);
						sock->ssl = NULL;
						sock->ssl_ctx = NULL;
					}
					sock->Connected = false;
					sock->SecureMode = false;
				}
			}
			Unlock(sock->ssl_lock);

			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;

			if (sock->IpClientAdded)
			{
				DelIpClient(&sock->RemoteIP);
				sock->IpClientAdded = false;
			}
		}
		Unlock(sock->lock);
	}
	else if (sock->Type == SOCK_UDP)
	{
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				return;
			}

			s = sock->socket;

			closesocket(s);

			sock->socket = INVALID_SOCKET;
			sock->Type = 0;
			sock->AsyncMode = false;
			sock->Connected = false;
			sock->ListenMode = false;
			sock->SecureMode = false;
		}
		Unlock(sock->lock);
	}
	Unlock(sock->disconnect_lock);
}

static char *PrintError(int ErrorCode)
{
	char *Message;
	switch (ErrorCode) {
	case WSAEFAULT:
		Message = "Bad address.";
		break;

	case WSAEWOULDBLOCK:
		Message = "Resource temporarily unavailable.";
		break;

	case WSAEINPROGRESS:
		Message = "Operation now in progress.";
		break;

	case WSAEALREADY:
		Message = "Operation already in progress.";
		break;

	case WSAEAFNOSUPPORT:
		Message = "Address family not supported by protocol family.";
		break;

	case WSAEADDRINUSE:
		Message = "Address already in use.";
		break;

	case WSAEADDRNOTAVAIL:
		Message = "Cannot assign requested address.";
		break;

	case WSAEISCONN:
		Message = "Socket is already connected.";
		break;

	case WSAEINVAL:
		Message = "Invalid argument.";
		break;

	default:
		Message = "";
		break;
	}
	return Message;
}

static int connect_timeout(SOCKET s, struct sockaddr *addr, int size, int timeout, bool *cancel_flag)
{
	UINT64 end_time;
	bool ok = false;
	WSAEVENT hEvent;
	UINT zero = 0;
	UINT tmp = 0;
	DWORD ret_size = 0;
	if (s == INVALID_SOCKET || addr == NULL)
	{
		return -1;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}

	hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	// WSAEventSelect puts the socket in non-blocking mode; connect() is issued once and
	// its result arrives as FD_CONNECT, polled in 25 ms slices so the cancel flag is honoured
	WSAEventSelect(s, hEvent, FD_CONNECT);

	end_time = Tick64() + (UINT64)timeout;

	if (connect(s, addr, size) == 0)
	{
		ok = true;
	}
	else if (WSAGetLastError() == WSAEWOULDBLOCK)
	{
		while (*cancel_flag == false && Tick64() < end_time)
		{
			WSANETWORKEVENTS events;

			if (WaitForSingleObject(hEvent, 25) != WAIT_OBJECT_0)
			{
				continue;
			}

			if (WSAEnumNetworkEvents(s, hEvent, &events) != 0)
			{
				break;
			}

			if (events.lNetworkEvents & FD_CONNECT)
			{
				ok = (events.iErrorCode[FD_CONNECT_BIT] == 0);
				break;
			}
		}
	}

	WSAEventSelect(s, hEvent, 0);

	WSAIoctl(s, FIONBIO, &zero, sizeof(zero), &tmp, sizeof(tmp), &ret_size, NULL, NULL);

	CloseHandle(hEvent);

	if (ok)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static void SetSockTos(SOCK *s, int tos)
{
	if (s == NULL)
	{
		return;
	}

	if (s->CurrentTos == tos)
	{
		return;
	}

	(void)setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int));

	s->CurrentTos = tos;
}

void SetSockHighPriority(SOCK *s, bool flag)
{
	if (s == NULL)
	{
		return;
	}

	SetSockTos(s, (flag ? 16 : 0));
}

static int bind_sock(SOCKET sock, IP *ip, UINT port)
{

	if (IsIP4(ip))
	{
		struct sockaddr_in sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		sockaddr_in.sin_family = AF_INET;
		IPToInAddr(&sockaddr_in.sin_addr, ip);
		sockaddr_in.sin_port = htons((USHORT)port);

		UINT true_flag = 1;
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&true_flag, sizeof(true_flag));

		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	}
	else
	{
		struct sockaddr_in6 sockaddr_in;

		Zero(&sockaddr_in, sizeof(sockaddr_in));

		sockaddr_in.sin6_family = AF_INET6;
		IPToInAddr6(&sockaddr_in.sin6_addr, ip);
		sockaddr_in.sin6_scope_id = ip->ipv6_scope_id;
		sockaddr_in.sin6_port = htons((USHORT)port);

		UINT true_flag = 1;
		(void)setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&true_flag, sizeof(true_flag));

		return (bind(sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in)));
	}
}

static SOCKET BindConnectTimeout(bool ipv6, IP *localIP, UINT localport, IP *ip, UINT port, UINT timeout, bool *cancel_flag)
{
	SOCKET s;
	struct sockaddr_in sockaddr4;
	struct sockaddr_in6 sockaddr6;
	struct sockaddr *addr;
	int addr_size;
	IP tmpIP;
	IP *bind_ip = localIP;

	Zero(&sockaddr4, sizeof(sockaddr4));
	Zero(&sockaddr6, sizeof(sockaddr6));

	if (ipv6)
	{
		sockaddr6.sin6_family = AF_INET6;
		sockaddr6.sin6_port = htons((USHORT)port);
		sockaddr6.sin6_scope_id = ip->ipv6_scope_id;
		IPToInAddr6(&sockaddr6.sin6_addr, ip);
		addr = (struct sockaddr *)&sockaddr6;
		addr_size = sizeof(sockaddr6);
	}
	else
	{
		sockaddr4.sin_family = AF_INET;
		sockaddr4.sin_port = htons((USHORT)port);
		IPToInAddr(&sockaddr4.sin_addr, ip);
		addr = (struct sockaddr *)&sockaddr4;
		addr_size = sizeof(sockaddr4);
	}

	s = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	if (bind_ip == BIND_LOCALIP_NULL)
	{
		// A NULL local address is the unspecified address of the target family
		StrToIP(&tmpIP, ipv6 ? "0::0" : "0.0.0.0");
		bind_ip = &tmpIP;
	}

	if ((IsZeroIP(bind_ip) == false) || (localport != 0))
	{
		if (bind_sock(s, bind_ip, localport) != 0)
		{
			int ier = WSAGetLastError();
			Debug("IPv%d bind() failed with error: %d %s\n", ipv6 ? 6 : 4, ier, PrintError(ier));
			closesocket(s);
			return INVALID_SOCKET;
		}
	}

	if (connect_timeout(s, addr, addr_size, timeout, cancel_flag) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

static void BindConnectThread(THREAD *thread, void *param)
{
	UINT i;
	CONNECT_SERIAL_PARAM *p = (CONNECT_SERIAL_PARAM *)param;
	if (thread == NULL || p == NULL)
	{
		return;
	}

	if (p->Delay >= 1)
	{
		WaitEx(NULL, p->Delay, p->NoDelayFlag);
	}

	for (i = 0; i < LIST_NUM(p->IpList); ++i)
	{
		SOCKET s;
		IP *ip = LIST_DATA(p->IpList, i);

		if (IsZeroIp(ip))
		{
			continue;
		}

		if (i > 0 && p->RetryDelay >= 1)
		{
			WaitEx(NULL, p->RetryDelay, p->CancelFlag);
		}

		if (*p->CancelFlag)
		{
			break;
		}

		s = BindConnectTimeout(p->IPv6, p->LocalIP, p->LocalPort, ip, p->Port, p->Timeout, p->CancelFlag);

		if (s != INVALID_SOCKET)
		{
			Copy(p->Ret_Ip, ip, sizeof(IP));

			p->Sock = CreateTCPSock(s, p->IPv6, p->Hostname);
			break;
		}
	}

	p->Ok = (p->Sock == NULL ? false : true);
	p->Finished = true;

	Set(p->FinishEvent);
}

SOCK *CreateTCPSock(SOCKET s, bool is_ipv6, char *hostname_original)
{
	SOCK *sock;
	UINT true_flag = 1;

	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	sock = NewSock();
	sock->socket = s;
	sock->Type = SOCK_TCP;
	sock->ServerMode = false;

	StrCpy(sock->UnderlayProtocol, sizeof(sock->UnderlayProtocol), is_ipv6 ? SOCK_UNDERLAY_NATIVE_V6 : SOCK_UNDERLAY_NATIVE_V4);
	AddProtocolDetailsStr(sock->ProtocolDetails, sizeof(sock->ProtocolDetails), is_ipv6 ? "IPv6" : "IPv4");

	sock->RemoteHostname = CopyStr(hostname_original);

	(void)setsockopt(sock->socket, IPPROTO_TCP, TCP_NODELAY, (char *)&true_flag, sizeof(true_flag));

	SetTimeout(sock, TIMEOUT_INFINITE);

	QuerySocketInformation(sock);

	if (IsZeroIp(&sock->LocalIP) == false && IsLocalHostIP(&sock->LocalIP) == false)
	{
		IP current_ip;

		if (GetCurrentGlobalIP(&current_ip, is_ipv6) == false)
		{
			SetCurrentGlobalIP(&sock->LocalIP, is_ipv6);
		}
	}

	sock->Connected = true;
	sock->AsyncMode = false;
	sock->SecureMode = false;
	sock->IPv6 = is_ipv6;

	return sock;
}

SOCK *Connect(char *hostname, UINT port)
{
	return ConnectEx4(hostname, port, 0, NULL, NULL);
}
SOCK *ConnectEx4(char *hostname, UINT port, UINT timeout, bool *cancel_flag, IP *ret_ip)
{
	return BindConnectEx4(BIND_LOCALIP_NULL, BIND_LOCALPORT_NULL, hostname, port, timeout, cancel_flag, ret_ip);
}

SOCK *BindConnectEx4(IP *localIP, UINT localport, char *hostname, UINT port, UINT timeout, bool *cancel_flag, IP *ret_ip)
{
	bool dummy = false;
	IP dummy_ret_ip;
	LIST *iplists[2] = {NULL, NULL};	// [0] IPv6, [1] IPv4
	CONNECT_SERIAL_PARAM params[2];
	THREAD *threads[2] = {NULL, NULL};
	IP ret_ips[2];
	EVENT *finish_event;
	bool cancel_flag2 = false;
	bool no_delay_flag = false;
	SOCK *ret = NULL;
	UINT i;
	if (hostname == NULL || port == 0 || port >= 65536 || IsEmptyStr(hostname))
	{
		return NULL;
	}
	if (timeout == 0)
	{
		timeout = TIMEOUT_TCP_PORT_CHECK;
	}
	if (cancel_flag == NULL)
	{
		cancel_flag = &dummy;
	}

	Zero(&dummy_ret_ip, sizeof(IP));
	if (ret_ip == NULL)
	{
		ret_ip = &dummy_ret_ip;
	}

	if (IsZeroIp(ret_ip) == false)
	{
		LIST **target = IsIP6(ret_ip) ? &iplists[0] : &iplists[1];

		*target = NewListFast(NULL);
		AddHostIPAddressToList(*target, ret_ip);
	}
	else
	{
		if (DnsResolveEx(&iplists[0], &iplists[1], hostname, 0, cancel_flag) == false)
		{
			return NULL;
		}
	}

	finish_event = NewEvent();

	Zero(params, sizeof(params));
	Zero(ret_ips, sizeof(ret_ips));

	for (i = 0; i < 2; ++i)
	{
		CONNECT_SERIAL_PARAM *p = &params[i];

		if (LIST_NUM(iplists[i]) == 0)
		{
			continue;
		}

		p->IpList = iplists[i];
		p->IPv6 = (i == 0);

		if (localIP == BIND_LOCALIP_NULL)
		{
			p->LocalIP = BIND_LOCALIP_NULL;
		}
		else
		{
			CopyIP(&p->LocalIP_Cache, localIP);
			p->LocalIP = &p->LocalIP_Cache;
		}
		p->LocalPort = localport;

		p->Port = port;
		p->Timeout = timeout;
		StrCpy(p->Hostname, sizeof(p->Hostname), hostname);
		p->CancelFlag = &cancel_flag2;
		p->NoDelayFlag = &no_delay_flag;
		p->FinishEvent = finish_event;
		p->Ret_Ip = &ret_ips[i];
		p->RetryDelay = 250;
		p->Delay = (p->IPv6 ? 0 : 250);		// Delay IPv4 by 250ms to prioritize IPv6 (RFC 6555 recommends 150-250ms, Chrome uses 300ms)
		threads[i] = NewThread(BindConnectThread, p);
	}

	if (threads[0] == NULL || threads[1] == NULL)
	{
		no_delay_flag = true;
	}

	while (true)
	{
		if (*cancel_flag)
		{
			break;
		}

		if ((threads[0] == NULL || params[0].Finished) && (threads[1] == NULL || params[1].Finished))
		{
			break;
		}

		if ((params[0].Finished && params[0].Ok) || (params[1].Finished && params[1].Ok))
		{
			break;
		}

		// This check must be placed last to avoid race condition with cancel flag
		if (no_delay_flag == false && (params[0].Finished || params[1].Finished))
		{
			no_delay_flag = true;
		}

		Wait(finish_event, 25);
	}

	cancel_flag2 = true;
	no_delay_flag = true;

	for (i = 0; i < 2; ++i)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}
	ReleaseEvent(finish_event);
	FreeHostIPAddressList(iplists[0]);
	FreeHostIPAddressList(iplists[1]);

	// IPv6 wins over IPv4 when both connected; the losing socket (or both, on cancel) is closed
	for (i = 0; i < 2; ++i)
	{
		if (*cancel_flag == false && ret == NULL && params[i].Ok)
		{
			ret = params[i].Sock;
			Copy(ret_ip, &ret_ips[i], sizeof(IP));
		}
		else
		{
			Disconnect(params[i].Sock);
			ReleaseSock(params[i].Sock);
		}
	}

	return ret;
}

void AddProtocolDetailsStr(char *dst, UINT dst_size, char *str)
{
	TOKEN_LIST *t1, *t2;
	UINT i, j;
	if (dst == NULL || str == NULL)
	{
		return;
	}

	t1 = ParseTokenWithoutNullStr(dst, " ");
	t2 = ParseTokenWithoutNullStr(str, " ");

	for (i = 0; i < t2->NumTokens; i++)
	{
		bool exists = false;
		for (j = 0; j < t1->NumTokens; j++)
		{
			if (StrCmpi(t1->Token[j], t2->Token[i]) == 0)
			{
				exists = true;
				break;
			}
		}

		if (exists == false)
		{
			StrCat(dst, dst_size, t2->Token[i]);
			StrCat(dst, dst_size, " ");
		}
	}

	FreeToken(t1);
	FreeToken(t2);
}

static void AddProtocolDetailsKeyValueStr(char *dst, UINT dst_size, char *key, char *value)
{
	char tmp[128];
	StrCpy(tmp, sizeof(tmp), key);
	StrCat(tmp, sizeof(tmp), "=");
	StrCat(tmp, sizeof(tmp), value);
	AddProtocolDetailsStr(dst, dst_size, tmp);
}

void AddProtocolDetailsKeyValueInt(char *dst, UINT dst_size, char *key, UINT value)
{
	char tmp[128];
	ToStr(tmp, value);
	AddProtocolDetailsKeyValueStr(dst, dst_size, key, tmp);
}


static bool SetSocketBufferSize(SOCKET s, bool send, UINT size)
{
	int value = (int)size;
	if (s == INVALID_SOCKET)
	{
		return false;
	}

	if (setsockopt(s, SOL_SOCKET, (send ? SO_SNDBUF : SO_RCVBUF), (char *)&value, sizeof(int)) != 0)
	{
		return false;
	}

	return true;
}
static UINT SetSocketBufferSizeWithBestEffort(SOCKET s, bool send, UINT size)
{
	if (s == INVALID_SOCKET)
	{
		return 0;
	}

	while (true)
	{
		if (SetSocketBufferSize(s, send, size))
		{
			return size;
		}

		size = (UINT)((double)size / 1.5);

		if (size <= 32767)
		{
			return 0;
		}
	}
}

void InitUdpSocketBufferSize(SOCKET s)
{
	SetSocketBufferSizeWithBestEffort(s, true, UDP_MAX_BUFFER_SIZE);
	SetSocketBufferSizeWithBestEffort(s, false, UDP_MAX_BUFFER_SIZE);
}

// Decode a socket address by its family. An IPv4-mapped IPv6 address (an IPv4 peer of a dual-stack socket)
// becomes an IPv4 IP.
static void DecodeSockAddr(struct sockaddr_storage *addr, IP *ip, UINT *port)
{
	if (addr->ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;

		*port = (UINT)ntohs(addr6->sin6_port);
		InAddrToIP6(ip, &addr6->sin6_addr);
		ip->ipv6_scope_id = addr6->sin6_scope_id;
	}
	else if (addr->ss_family == AF_INET)
	{
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;

		*port = (UINT)ntohs(addr4->sin_port);
		InAddrToIP(ip, &addr4->sin_addr);
	}
}

void QuerySocketInformation(SOCK *sock)
{
	if (sock == NULL)
	{
		return;
	}

	Lock(sock->lock);
	{
		struct sockaddr_storage sockaddr;
		int size;

		if (sock->Type == SOCK_TCP)
		{
			size = sizeof(sockaddr);
			if (getpeername(sock->socket, (struct sockaddr *)&sockaddr, &size) == 0)
			{
				DecodeSockAddr(&sockaddr, &sock->RemoteIP, &sock->RemotePort);
			}
		}

		size = sizeof(sockaddr);
		if (getsockname(sock->socket, (struct sockaddr *)&sockaddr, &size) == 0)
		{
			DecodeSockAddr(&sockaddr, &sock->LocalIP, &sock->LocalPort);
		}

	}
	Unlock(sock->lock);
}

void ReleaseSock(SOCK *s)
{
	if (s == NULL)
	{
		return;
	}

	if (Release(s->ref) == 0)
	{
		CleanupSock(s);
	}
}

void CleanupSock(SOCK *s)
{
	if (s == NULL)
	{
		return;
	}

	Disconnect(s);

	Win32FreeAsyncSocket(s);

	FreeBuf(s->SendBuf);
	if (s->socket != INVALID_SOCKET)
	{
		closesocket(s->socket);
	}
	Free(s->RemoteHostname);

	if (s->hAcceptEvent != NULL)
	{
		CloseHandle(s->hAcceptEvent);
	}

	if (s->RemoteX != NULL)
	{
		FreeX(s->RemoteX);
		s->RemoteX = NULL;
	}

	if (s->CipherName != NULL)
	{
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	DeleteLock(s->lock);
	DeleteLock(s->ssl_lock);
	DeleteLock(s->disconnect_lock);

	Dec(num_tcp_connections);

	Free(s);
}

SOCK *NewSock()
{
	SOCK *s = ZeroMallocFast(sizeof(SOCK));

	s->ref = NewRef();
	s->lock = NewLock();
	s->SendBuf = NewBuf();
	s->socket = INVALID_SOCKET;
	s->ssl_lock = NewLock();
	s->disconnect_lock = NewLock();

	Inc(num_tcp_connections);

	return s;
}

UINT IPToUINT(IP *ip)
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

void GetMachineHostName(char *name, UINT size)
{
	char tmp[MAX_SIZE];
	UINT i, len;
	if (name == NULL)
	{
		return;
	}

	GetMachineName(tmp, sizeof(tmp));

	len = StrLen(tmp);
	for (i = 0; i < len; i++)
	{
		if (tmp[i] == '.')
		{
			tmp[i] = 0;
		}
	}

	ConvertSafeFileName(name, size, tmp);
}

void GetMachineName(char *name, UINT size)
{
	static char name_cache[MAX_SIZE];
	static bool name_cached = false;
	char tmp[MAX_SIZE];
	if (name == NULL)
	{
		return;
	}

	Lock(machine_name_lock);
	{
		if (name_cached != false)
		{
			StrCpy(name, size, name_cache);
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(tmp, sizeof(tmp));
		if (gethostname(tmp, MAX_SIZE) != 0)
		{
			StrCpy(name, size, "Unknown");
			Unlock(machine_name_lock);
			return;
		}
		ClearStr(name, size);
		StrCpy(name, size, tmp);
		if (IsEmptyStr(name) || StartWith(name, "localhost"))
		{
			ClearStr(name, size);
			MsGetComputerName(name, size);
		}
		StrCpy(name_cache, sizeof(name_cache), name);
		name_cached = true;
	}
	Unlock(machine_name_lock);
}

bool GetHostName(char *hostname, UINT size, IP *ip)
{
	if (hostname == NULL || size == 0 || ip == NULL)
	{
		return false;
	}

	if (DnsResolveReverse(hostname, size, ip, 0, NULL))
	{
		return true;
	}

	if (IsIP4(ip) && GetNetBiosName(hostname, size, ip))
	{
		DnsCacheReverseUpdate(ip, hostname);
		return true;
	}

	return false;
}

#define	NUM_NBT_QUERYS_SEND			3

bool GetNetBiosName(char *name, UINT size, IP *ip)
{
	SOCK *s;
	UINT i, j;
	bool flag = false;
	bool ok = false;
	NBTREQUEST req;
	UCHAR buf[1024];
	USHORT tran_id[NUM_NBT_QUERYS_SEND];
	UINT64 timeout_tick;
	if (name == NULL || ip == NULL)
	{
		return false;
	}

	IPToStr(name, size, ip);

	for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
	{
		tran_id[i] = Rand16();
	}

	s = NewUDP(0);
	if (s == NULL)
	{
		return false;
	}

	for (j = 0; j < NUM_NBT_QUERYS_SEND; j++)
	{
		Zero(&req, sizeof(req));
		req.TransactionId = Endian16(tran_id[j]);
		req.NumQuestions = Endian16(1);
		req.Query[0] = 0x20;
		req.Query[1] = 0x43;
		req.Query[2] = 0x4b;
		for (i = 3; i <= 32; i++)
		{
			req.Query[i] = 0x41;
		}
		req.Query[35] = 0x21;
		req.Query[37] = 0x01;

		if (SendTo(s, ip, 137, &req, sizeof(req)) == 0)
		{
			ReleaseSock(s);
			return false;
		}
	}

	timeout_tick = Tick64() + (UINT64)TIMEOUT_NETBIOS_HOSTNAME;

	while (1)
	{
		UINT ret;
		IP src_ip;
		UINT src_port;
		SOCKSET set;
		if (Tick64() >= timeout_tick)
		{
			break;
		}
		InitSockSet(&set);
		AddSockSet(&set, s);
		Select(&set, 100, NULL, NULL);

		if (flag == false)
		{
			flag = true;
		}
		else
		{
			SleepThread(10);
		}

		ret = RecvFrom(s, &src_ip, &src_port, buf, sizeof(buf));

		if (ret == SOCK_LATER)
		{
			continue;
		}
		else if (ret == 0)
		{
			break;
		}
		else
		{
			// Only a reply from the queried host's NetBIOS port counts; anything else may be spoofed
			if (ret >= sizeof(NBTRESPONSE) && src_port == 137 && CmpIpAddr(&src_ip, ip) == 0)
			{
				NBTRESPONSE *r = (NBTRESPONSE *)buf;
				bool b = false;
				UINT i;
				USHORT id = Endian16(r->TransactionId);
				for (i = 0; i < NUM_NBT_QUERYS_SEND; i++)
				{
					if (id == tran_id[i])
					{
						b = true;
						break;
					}
				}
				if (b)
				{
					if (r->Flags != 0 && r->NumQuestions == 0 && r->AnswerRRs >= 1)
					{
						if (r->Response[0] == 0x20 && r->Response[1] == 0x43 &&
						        r->Response[2] == 0x4b)
						{
							if (r->Response[34] == 0x00 && r->Response[35] == 0x21 &&
							        r->Response[36] == 0x00 && r->Response[37] == 0x01)
							{
								char *a = (char *)(&r->Response[45]);
								if (StrCheckLen(a, 15))
								{
									if (IsEmptyStr(a) == false)
									{
										StrCpy(name, size, a);
										Trim(name);
										ok = true;
									}
									else
									{
										ok = false;
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	ReleaseSock(s);
	return ok;
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

void IPToStr4or6(char *str, UINT size, UINT ip_4_uint, UCHAR *ip_6_bytes)
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

	if (IsIP6(&ip4) || (IsZeroIp(&ip4) && (IsZeroIp(&ip6) == false)))
	{
		Copy(&ip, &ip6, sizeof(IP));
	}
	else
	{
		Copy(&ip, &ip4, sizeof(IP));
	}

	IPToStr(str, size, &ip);
}

void IPToStr(char *str, UINT size, IP *ip)
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

bool StrToIP(IP *ip, char *str)
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

void IPToInAddr(struct in_addr *addr, IP *ip)
{
	UINT i;
	if (addr == NULL || IsIP4(ip) == false)
	{
		return;
	}

	Zero(addr, sizeof(struct in_addr));

	const BYTE *ipv4 = IPV4(ip->address);
	for (i = 0; i < IPV4_SIZE; ++i)
	{
		((BYTE *)addr)[i] = ipv4[i];
	}
}

void IPToInAddr6(struct in6_addr *addr, IP *ip)
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

void InAddrToIP(IP *ip, struct in_addr *addr)
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

void InAddrToIP6(IP *ip, struct in6_addr *addr)
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

static DH *TmpDhCallback(SSL *ssl, int is_export, int keylength)
{
	DH *ret = NULL;

	if (dh_param != NULL)
	{
		ret = dh_param->dh;
	}

	return ret;
}

struct ssl_ctx_st *NewSSLCtx(bool server_mode)
{
	struct ssl_ctx_st *ctx = SSL_CTX_new(server_mode ? TLS_server_method() : TLS_client_method());
	if(ctx == NULL)
	{
		return NULL;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

	if (server_mode)
	{
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

	return ctx;
}

// Take one more reference of ctx: each holder calls FreeSSLCtx once
void ShareSSLCtx(struct ssl_ctx_st *ctx)
{
	if (ctx == NULL)
	{
		return;
	}

	SSL_CTX_up_ref(ctx);
}

void FreeSSLCtx(struct ssl_ctx_st *ctx)
{
	if (ctx == NULL)
	{
		return;
	}

	SSL_CTX_free(ctx);
}

UINT GetOSSecurityLevel()
{
	UINT security_level_new = 0, security_level_set_ssl_version = 0;
	struct ssl_ctx_st *ctx = SSL_CTX_new(TLS_method());

	if (ctx == NULL)
	{
		return security_level_new;
	}


	security_level_new = SSL_CTX_get_security_level(ctx);

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, TLS_server_method());

	FreeSSLCtx(ctx);

	if(security_level_new >= security_level_set_ssl_version)
	{
		return security_level_new;
	}

	return security_level_set_ssl_version;
}

void InitNetwork()
{
	disable_gethostname_by_accept = false;


	InitDynList();


	host_ip_address_list_cache_lock = NewLock();
	host_ip_address_list_cache_last = 0;

	num_tcp_connections = NewCounter();

	InitIpClientList();

	InitWaitThread();

	Win32InitSocketLibrary();

	DnsInit();

	machine_name_lock = NewLock();
	machine_ip_process_hash_lock = NewLock();
	local_mac_list_lock = NewLock();

	current_global_ip_lock = NewLock();
	current_global_ip_set = false;

	chain_cert_lock = NewLock();
}

TOKEN_LIST *GetCipherList()
{
	int i, num;
	SSL *ssl;
	SSL_CTX *ctx;
	const char *name;
	STACK_OF(SSL_CIPHER) *sk;

	TOKEN_LIST *ciphers = ZeroMalloc(sizeof(TOKEN_LIST));

	ctx = NewSSLCtx(true);
	if (ctx == NULL)
	{
		return ciphers;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL)
	{
		FreeSSLCtx(ctx);
		return ciphers;
	}

	// A copy of the list (OpenSSL 1.1.1 or later is required): NULL when no cipher is enabled
	sk = SSL_get1_supported_ciphers(ssl);
	num = (sk != NULL ? sk_SSL_CIPHER_num(sk) : 0);

	if (num > 0)
	{
		ciphers->Token = ZeroMalloc(sizeof(char *) * (UINT)num);
	}

	for (i = 0; i < num; i++)
	{
		const SSL_CIPHER *c = sk_SSL_CIPHER_value(sk, i);
		if (c == NULL)
		{
			continue;
		}

		name = SSL_CIPHER_get_name(c);
		if (IsEmptyStr((char *)name))
		{
			break;
		}

		ciphers->Token[ciphers->NumTokens++] = CopyStr((char *)name);
	}

	sk_SSL_CIPHER_free(sk);
	SSL_free(ssl);
	// SSL_free drops only the SSL's own reference: the context is ours
	FreeSSLCtx(ctx);

	return ciphers;
}

COUNTER *GetNumTcpConnectionsCounter()
{
	return num_tcp_connections;
}

bool GetCurrentGlobalIP(IP *ip, bool ipv6)
{
	bool ret = false;
	if (ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(ip, &current_glocal_ipv4, sizeof(IP));
		}
		else
		{
			Copy(ip, &current_glocal_ipv6, sizeof(IP));
		}

		ret = current_global_ip_set;
	}
	Unlock(current_global_ip_lock);

	return ret;
}

bool IsIPMyHost(IP *ip)
{
	LIST *o;
	UINT i;
	bool ret = false;
	if (ip == NULL)
	{
		return false;
	}

	if (IsZeroIp(ip))
	{
		return false;
	}

	o = GetHostIPAddressList();

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *p = LIST_DATA(o, i);

		if (CmpIpAddr(p, ip) == 0)
		{
			ret = true;
			break;
		}
	}

	FreeHostIPAddressList(o);

	if (ret == false)
	{
		if (IsLocalHostIP(ip))
		{
			ret = true;
		}
	}

	return ret;
}

bool IsIPPrivate(IP *ip)
{
	if (IsIP4(ip) == false)
	{
		return false;
	}

	const BYTE *ipv4 = IPV4(ip->address);

	// RFC 1918 defines 10.0.0.0/8
	if (ipv4[0] == 10)
	{
		return true;
	}

	// RFC 1918 defines 172.16.0.0/12
	if (ipv4[0] == 172)
	{
		if (ipv4[1] >= 16 && ipv4[1] <= 31)
		{
			return true;
		}
	}

	// RFC 1918 defines 192.168.0.0/16
	if (ipv4[0] == 192 && ipv4[1] == 168)
	{
		return true;
	}

	// RFC 3927 defines 169.254.0.0/16
	if (ipv4[0] == 169 && ipv4[1] == 254)
	{
		return true;
	}

	// RFC 6598 defines 100.64.0.0/10
	if (ipv4[0] == 100)
	{
		if (ipv4[1] >= 64 && ipv4[1] <= 127)
		{
			return true;
		}
	}

	if (g_private_ip_list != NULL)
	{
		return IsOnPrivateIPFile(IPToUINT(ip));
	}

	return false;
}

void LoadPrivateIPFile()
{
	BUF *b = ReadDump(PRIVATE_IP_TXT_FILENAME);
	LIST *o;
	if (b == NULL)
	{
		return;
	}

	o = NewList(NULL);

	while (true)
	{
		char *line = CfgReadNextLine(b);
		if (line == NULL)
		{
			break;
		}

		Trim(line);

		if (IsEmptyStr(line) == false)
		{
			UINT ip = 0, mask = 0;

			if (ParseIpAndSubnetMask4(line, &ip, &mask))
			{
				PRIVATE_IP_SUBNET *p = ZeroMalloc(sizeof(PRIVATE_IP_SUBNET));

				p->Ip = ip;
				p->Mask = mask;
				p->Ip2 = ip & mask;

				Add(o, p);
			}
		}

		Free(line);
	}

	g_private_ip_list = o;

	FreeBuf(b);
}

bool IsOnPrivateIPFile(UINT ip)
{
	bool ret = false;

	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			if ((ip & p->Mask) == p->Ip2)
			{
				ret = true;
			}
		}
	}

	return ret;
}

void FreePrivateIPFile()
{
	if (g_private_ip_list != NULL)
	{
		LIST *o = g_private_ip_list;
		UINT i;

		g_private_ip_list = NULL;

		for (i = 0; i < LIST_NUM(o); i++)
		{
			PRIVATE_IP_SUBNET *p = LIST_DATA(o, i);

			Free(p);
		}

		ReleaseList(o);
	}
}

void SetCurrentGlobalIP(IP *ip, bool ipv6)
{
	if (ip == NULL)
	{
		return;
	}

	if (IsZeroIp(ip))
	{
		return;
	}

	Lock(current_global_ip_lock);
	{
		if (ipv6 == false)
		{
			Copy(&current_glocal_ipv4, ip, sizeof(IP));
		}
		else
		{
			Copy(&current_glocal_ipv6, ip, sizeof(IP));
		}

		current_global_ip_set = true;
	}
	Unlock(current_global_ip_lock);
}

void FreeNetwork()
{

	if (dh_param != NULL)
	{
		DhFree(dh_param);
		dh_param = NULL;
	}

	sk_X509_pop_free(ssl_root_certs, X509_free);
	ssl_root_certs = NULL;

	FreeWaitThread();

	FreeChainCertCache();
	DeleteLock(chain_cert_lock);
	chain_cert_lock = NULL;

	DeleteLock(machine_name_lock);
	DeleteLock(machine_ip_process_hash_lock);
	machine_name_lock = machine_ip_process_hash_lock = NULL;

	DnsFree();

	WSACleanup();

	DeleteCounter(num_tcp_connections);
	num_tcp_connections = NULL;

	FreeIpClientList();

	DeleteLock(current_global_ip_lock);
	current_global_ip_lock = NULL;

	if (local_mac_list != NULL)
	{
		FreeNicList(local_mac_list);
		local_mac_list = NULL;
	}

	DeleteLock(local_mac_list_lock);
	local_mac_list_lock = NULL;

	DeleteLock(host_ip_address_list_cache_lock);
	host_ip_address_list_cache_lock = NULL;

	FreeHostIPAddressList(host_ip_address_cache);
	host_ip_address_cache = NULL;

	FreeDynList();
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


bool ParseIpAndMask46(char *src, IP *ip, IP *mask)
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
bool ParseIpAndMask6(char *src, IP *ip, IP *mask)
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


void MaskToStr(char *str, UINT size, IP *mask)
{
	MaskToStrEx(str, size, mask, false);
}
void MaskToStrEx(char *str, UINT size, IP *mask, bool always_full_address)
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
static void Mask6AddrToStrEx(char *str, UINT size, IPV6_ADDR *mask, bool always_full_address)
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
void Mask6AddrToStr(char *str, UINT size, IPV6_ADDR *mask)
{
	Mask6AddrToStrEx(str, size, mask, false);
}

void FreeHostIPAddressList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		IP *ip = LIST_DATA(o, i);

		Free(ip);
	}

	ReleaseList(o);
}

void AddHostIPAddressToList(LIST *o, IP *ip)
{
	IP *r = NULL;
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
		UINT i;
		for (i = 0; i < LIST_NUM(o); i++)
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

static int CmpIpAddressList(void *p1, void *p2)
{
	IP *ip1, *ip2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	ip1 = *(IP **)p1;
	ip2 = *(IP **)p2;
	if (ip1 == NULL || ip2 == NULL)
	{
		return 0;
	}

	// IPv4 < IPv6
	r = COMPARE_RET(IsIP6(ip1), IsIP6(ip2));
	if (r != 0)
	{
		return r;
	}

	// any > specified IP
	if (IsZeroIP(ip1) && IsZeroIP(ip2) == false)
	{
		return 1;
	}
	if (IsZeroIP(ip1) == false && IsZeroIP(ip2))
	{
		return -1;
	}

	// local > others
	if (IsLocalHostIP(ip1) && IsLocalHostIP(ip2) == false)
	{
		return 1;
	}
	if (IsLocalHostIP(ip1) == false && IsLocalHostIP(ip2))
	{
		return -1;
	}

	r = CmpIpAddr(ip1, ip2);
	if (r != 0)
	{
		return r;
	}

	if (IsIP6(ip1))
	{
		r = COMPARE_RET(ip1->ipv6_scope_id, ip2->ipv6_scope_id);
	}
	else
	{
		r = 0;
	}

	return r;
}

LIST *GetHostIPAddressList()
{
	LIST *o = NULL;
	if (host_ip_address_list_cache_lock == NULL)
	{
		return GetHostIPAddressListInternal();
	}

	Lock(host_ip_address_list_cache_lock);
	{
		UINT64 now = Tick64();

		if (host_ip_address_list_cache_last == 0 ||
		        ((host_ip_address_list_cache_last + (UINT64)HOST_IP_ADDRESS_LIST_CACHE) < now) ||
		        host_ip_address_cache == NULL)
		{
			if (host_ip_address_cache != NULL)
			{
				FreeHostIPAddressList(host_ip_address_cache);
			}

			host_ip_address_cache = GetHostIPAddressListInternal();

			host_ip_address_list_cache_last = now;
		}

		o = CloneIPAddressList(host_ip_address_cache);
	}
	Unlock(host_ip_address_list_cache_lock);

	if (o == NULL)
	{
		o = GetHostIPAddressListInternal();
	}

	return o;
}

LIST *CloneIPAddressList(LIST *o)
{
	LIST *ret;
	UINT i;
	if (o == NULL)
	{
		return NULL;
	}

	ret = NewListFast(o->cmp);

	for (i = 0; i < LIST_NUM(o); i++)
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

LIST *GetHostIPAddressListInternal()
{
	char hostname[MAX_SIZE];
	LIST *o;
	IP any6, any4;
	IP local6, local4;
	bool is_v6_supported = IsIPv6Supported();

	GetLocalHostIP4(&local4);
	GetLocalHostIP6(&local6);

	ZeroIP4(&any4);
	Zero(&any6, sizeof(any6));

	Zero(hostname, sizeof(hostname));

	gethostname(hostname, sizeof(hostname));

	o = NewListFast(CmpIpAddressList);

	AddHostIPAddressToList(o, &any4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &any6);
	}

	AddHostIPAddressToList(o, &local4);
	if (is_v6_supported)
	{
		AddHostIPAddressToList(o, &local6);
	}

	if (true)
	{
		struct sockaddr_in in;
		struct in_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin_addr, sizeof(addr));

					InAddrToIP(&ip, &addr);
					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}

	if (is_v6_supported)
	{
		struct sockaddr_in6 in;
		struct in6_addr addr;
		struct addrinfo hint;
		struct addrinfo *info;

		Zero(&hint, sizeof(hint));
		hint.ai_family = AF_INET6;
		hint.ai_socktype = SOCK_DGRAM;
		hint.ai_protocol = IPPROTO_UDP;
		info = NULL;

		if (getaddrinfo(hostname, NULL, &hint, &info) == 0)
		{
			if (info->ai_family == AF_INET6)
			{
				struct addrinfo *current = info;
				while (current != NULL)
				{
					IP ip;

					Copy(&in, current->ai_addr, sizeof(in));
					Copy(&addr, &in.sin6_addr, sizeof(addr));

					InAddrToIP6(&ip, &addr);
					ip.ipv6_scope_id = in.sin6_scope_id;

					AddHostIPAddressToList(o, &ip);

					current = current->ai_next;
				}
			}

			freeaddrinfo(info);
		}
	}

	return o;
}

PACK *PackError(UINT error)
{
	PACK *p;

	p = NewPack();
	PackAddInt(p, "error", error);

	return p;
}

UINT GetErrorFromPack(PACK *p)
{
	if (p == NULL)
	{
		return 0;
	}

	return PackGetInt(p, "error");
}

void CreateDummyValue(PACK *p)
{
	UINT size;
	UCHAR *buf;
	if (p == NULL)
	{
		return;
	}

	size = Rand32() % HTTP_PACK_RAND_SIZE_MAX;
	buf = Malloc(size);
	Rand(buf, size);

	PackAddData(p, "pencore", buf, size);

	Free(buf);
}

char *RecvLine(SOCK *s, UINT max_size)
{
	BUF *b;
	char c;
	char *str;
	if (s == NULL || max_size == 0)
	{
		return NULL;
	}

	b = NewBuf();
	while (true)
	{
		UCHAR *buf;
		if (RecvAll(s, &c, sizeof(c), s->SecureMode) == false)
		{
			FreeBuf(b);
			return NULL;
		}
		WriteBuf(b, &c, sizeof(c));
		buf = (UCHAR *)b->Buf;
		if (b->Size > max_size)
		{
			FreeBuf(b);
			return NULL;
		}
		if (b->Size >= 1)
		{
			if (buf[b->Size - 1] == '\n')
			{
				b->Size--;
				if (b->Size >= 1)
				{
					if (buf[b->Size - 1] == '\r')
					{
						b->Size--;
					}
				}
				str = Malloc(b->Size + 1);
				Copy(str, b->Buf, b->Size);
				str[b->Size] = 0;
				FreeBuf(b);

				return str;
			}
		}
	}
}

// Read cursor over a byte range: a read that does not fit fails and moves nothing
typedef struct PKT_CURSOR
{
	UCHAR *Pos;
	UINT Left;
} PKT_CURSOR;

static void PktCursorInit(PKT_CURSOR *c, UCHAR *buf, UINT size)
{
	c->Pos = buf;
	c->Left = size;
}

// Takes the next size bytes as a cursor of their own; sub NULL skips them
static bool PktCursorTake(PKT_CURSOR *c, UINT size, PKT_CURSOR *sub)
{
	if (size > c->Left)
	{
		return false;
	}

	if (sub != NULL)
	{
		PktCursorInit(sub, c->Pos, size);
	}

	c->Pos += size;
	c->Left -= size;

	return true;
}

static bool PktCursorU8(PKT_CURSOR *c, UCHAR *v)
{
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 1, NULL) == false)
	{
		return false;
	}

	*v = p[0];

	return true;
}

// Big-endian
static bool PktCursorU16(PKT_CURSOR *c, USHORT *v)
{
	UCHAR *p = c->Pos;

	if (PktCursorTake(c, 2, NULL) == false)
	{
		return false;
	}

	*v = (USHORT)((p[0] << 8) | p[1]);

	return true;
}

// Host name from the server_name extension of a TLS ClientHello at the start of a TCP payload, read in
// place. The handshake fields are bounded by the record length (not by the handshake length), each
// extension by the extensions length. The first host_name entry that is not empty up to its first NUL
// ends the search: it is cut to sni_size - 1 bytes, then spaces and tabs at both ends are dropped.
bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size)
{
	PKT_CURSOR rec, hello, exts, data, name;
	USHORT version, record_len, hello_type, hello_len, len16, type;
	UCHAR len8;

	if (packet_buf == NULL || packet_size <= 11 || sni == NULL || sni_size == 0)
	{
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	        packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	        packet_buf[9] >= 0x03))
	{
		return false;
	}

	// Record header: content type 0x16 (checked above), version, length
	PktCursorInit(&rec, packet_buf, packet_size);
	if (PktCursorTake(&rec, 1, NULL) == false || PktCursorU16(&rec, &version) == false ||
	        PktCursorU16(&rec, &record_len) == false || version < 0x0301 ||
	        PktCursorTake(&rec, record_len, &hello) == false)
	{
		return false;
	}

	// Handshake type 1 with the top length byte 0, then a 16-bit length that fits in the record
	if (PktCursorU16(&hello, &hello_type) == false || PktCursorU16(&hello, &hello_len) == false ||
	        hello_type != 0x0100 || hello_len > record_len - 4)
	{
		return false;
	}

	// client_version, random, session_id, cipher_suites, compression_methods, extensions
	if (PktCursorU16(&hello, &version) == false || version < 0x0301 ||
	        PktCursorTake(&hello, 32, NULL) == false ||
	        PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	        PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, NULL) == false ||
	        PktCursorU8(&hello, &len8) == false || PktCursorTake(&hello, len8, NULL) == false ||
	        PktCursorU16(&hello, &len16) == false || PktCursorTake(&hello, len16, &exts) == false)
	{
		return false;
	}

	while (PktCursorU16(&exts, &type) && PktCursorU16(&exts, &len16) && PktCursorTake(&exts, len16, &data))
	{
		UINT n, start, end;

		// server_name: list length (not checked), name type 0 (host_name), name length, name
		if (type != 0x0000 || PktCursorTake(&data, 2, NULL) == false ||
		        PktCursorU8(&data, &len8) == false || len8 != 0 ||
		        PktCursorU16(&data, &len16) == false || PktCursorTake(&data, len16, &name) == false)
		{
			continue;
		}

		n = 0;
		while (n < name.Left && name.Pos[n] != 0)
		{
			n++;
		}

		if (n == 0)
		{
			continue;
		}

		end = MIN(n, sni_size - 1);
		start = 0;
		while (start < end && (name.Pos[start] == ' ' || name.Pos[start] == '\t'))
		{
			start++;
		}
		while (end > start && (name.Pos[end - 1] == ' ' || name.Pos[end - 1] == '\t'))
		{
			end--;
		}

		Copy(sni, name.Pos + start, end - start);
		sni[end - start] = '\0';

		return end != start;
	}

	return false;
}

void SetDhParam(DH_CTX *dh)
{
	if (dh_param)
	{
		DhFree(dh_param);
	}

	dh_param = dh;
}
