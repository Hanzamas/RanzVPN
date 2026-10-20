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
#include <wincrypt.h>
#include <IcmpAPI.h>

static LOCK *machine_name_lock = NULL;
static LOCK *disconnect_function_lock = NULL;
extern LOCK *openssl_lock;
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

static LIST *local_mac_list = NULL;
static LOCK *local_mac_list_lock = NULL;


static DH_CTX *dh_param = NULL;

// Decoded copy of the Windows ROOT store, for the client's peer verification (guarded by openssl_lock)
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

			Debug("!!! WaitForSingleObject Error. ret=%u GetLastError=%u\n", wait_ret, GetLastError());
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

UINT SubnetMaskToInt6(IP *a)
{
	UINT i;
	if (IsIP6(a) == false)
	{
		return 0;
	}

	for (i = 0; i <= 128; i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
}
static UINT SubnetMaskToInt4(IP *a)
{
	UINT i;
	if (IsIP4(a) == false)
	{
		return 0;
	}

	for (i = 0; i <= 32; i++)
	{
		IP tmp;

		IntToSubnetMask4(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return i;
		}
	}

	return 0;
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
	UINT i;
	if (IsIP6(a) == false)
	{
		return false;
	}

	for (i = 0; i <= 128; i++)
	{
		IP tmp;

		IntToSubnetMask6(&tmp, i);

		if (CmpIpAddr(a, &tmp) == 0)
		{
			return true;
		}
	}

	return false;
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
	UINT j = i / 8;
	UINT k = i % 8;
	UINT z;
	IP a;

	Zero(&a, sizeof(IP));

	for (z = 0; z < sizeof(a.address); ++z)
	{
		if (z < j)
		{
			a.address[z] = 0xff;
		}
		else if (z == j)
		{
			a.address[z] = ~(0xff >> k);
		}
	}

	Copy(ip, &a, sizeof(IP));
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
	char tmp[MAX_SIZE];

	IPToStr6Inner(tmp, ip);

	StrCpy(str, size, tmp);
}
void IPToStr6Inner(char *str, IP *ip)
{
	UINT i;
	USHORT values[8];
	UINT zero_started_index;
	UINT max_zero_len;
	UINT max_zero_start;
	IP a;
	if (str == NULL || ip == NULL)
	{
		return;
	}

	Copy(&a, ip, sizeof(IP));

	for (i = 0; i < 8; i++)
	{
		Copy(&values[i], &a.address[i * 2], sizeof(USHORT));
		values[i] = Endian16(values[i]);
	}

	zero_started_index = INFINITE;
	max_zero_len = 0;
	max_zero_start = INFINITE;
	for (i = 0; i < 9; i++)
	{
		USHORT v = (i != 8 ? values[i] : 1);

		if (v == 0)
		{
			if (zero_started_index == INFINITE)
			{
				zero_started_index = i;
			}
		}
		else
		{
			UINT zero_len;

			if (zero_started_index != INFINITE)
			{
				zero_len = i - zero_started_index;
				if (zero_len >= 2)
				{
					if (max_zero_len < zero_len)
					{
						max_zero_start = zero_started_index;
						max_zero_len = zero_len;
					}
				}

				zero_started_index = INFINITE;
			}
		}
	}

	StrCpy(str, 0, "");
	for (i = 0; i < 8; i++)
	{
		char tmp[16];

		ToHex(tmp, values[i]);
		StrLower(tmp);

		if (i == max_zero_start)
		{
			if (i == 0)
			{
				StrCat(str, 0, "::");
			}
			else
			{
				StrCat(str, 0, ":");
			}
			i += max_zero_len - 1;
		}
		else
		{
			StrCat(str, 0, tmp);
			if (i != 7)
			{
				StrCat(str, 0, ":");
			}
		}
	}

	if (ip->ipv6_scope_id != 0)
	{
		char tmp[64];

		StrCat(str, 0, "%");
		ToStr(tmp, ip->ipv6_scope_id);

		StrCat(str, 0, tmp);
	}
}

bool StrToIP6(IP *ip, char *str)
{
	TOKEN_LIST *t;
	char tmp[MAX_PATH];
	IP a;
	UINT i;
	UINT scope_id = 0;
	if (str == NULL || ip == NULL)
	{
		return false;
	}

	Zero(&a, sizeof(a));

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

	i = SearchStrEx(tmp, "%", 0, false);
	if (i != INFINITE)
	{
		char ss[MAX_PATH];

		StrCpy(ss, sizeof(ss), &tmp[i + 1]);

		tmp[i] = 0;

		Trim(tmp);

		Trim(ss);

		scope_id = ToInt(ss);
	}

	t = ParseTokenWithNullStr(tmp, ":");
	if (t->NumTokens >= 3 && t->NumTokens <= 8)
	{
		UINT i, n;
		bool b = true;
		UINT k = 0;

		n = 0;

		for (i = 0; i < t->NumTokens; i++)
		{
			char *str = t->Token[i];

			if (i != 0 && i != (t->NumTokens - 1) && StrLen(str) == 0)
			{
				n++;
				if (n == 1)
				{
					k += 2 * (8 - t->NumTokens + 1);
				}
				else
				{
					b = false;
					break;
				}
			}
			else
			{
				UCHAR chars[2];

				if (CheckIPItemStr6(str) == false)
				{
					b = false;
					break;
				}

				IPItemStrToChars6(chars, str);

				a.address[k++] = chars[0];
				a.address[k++] = chars[1];
			}
		}

		if (n != 0 && n != 1)
		{
			b = false;
		}
		else if (n == 0 && t->NumTokens != 8)
		{
			b = false;
		}

		if (b == false)
		{
			FreeToken(t);
			return false;
		}
	}
	else
	{
		FreeToken(t);
		return false;
	}

	FreeToken(t);

	Copy(ip, &a, sizeof(IP));

	ip->ipv6_scope_id = scope_id;

	return true;
}

void IPItemStrToChars6(UCHAR *chars, char *str)
{
	char tmp[5];
	BUF *b;
	UINT len;
	if (chars == NULL)
	{
		return;
	}

	Zero(tmp, sizeof(tmp));

	len = StrLen(str);
	switch (len)
	{
	case 0:
		tmp[0] = tmp[1] = tmp[2] = tmp[3] = '0';
		break;

	case 1:
		tmp[0] = tmp[1] = tmp[2] = '0';
		tmp[3] = str[0];
		break;

	case 2:
		tmp[0] = tmp[1] = '0';
		tmp[2] = str[0];
		tmp[3] = str[1];
		break;

	case 3:
		tmp[0] = '0';
		tmp[1] = str[0];
		tmp[2] = str[1];
		tmp[3] = str[2];
		break;

	case 4:
		tmp[0] = str[0];
		tmp[1] = str[1];
		tmp[2] = str[2];
		tmp[3] = str[3];
		break;
	}

	b = StrToBin(tmp);

	chars[0] = ((UCHAR *)b->Buf)[0];
	chars[1] = ((UCHAR *)b->Buf)[1];

	FreeBuf(b);
}

bool CheckIPItemStr6(char *str)
{
	UINT i, len;
	if (str == NULL)
	{
		return false;
	}

	len = StrLen(str);
	if (len >= 5)
	{
		return false;
	}

	for (i = 0; i < len; i++)
	{
		char c = str[i];

		if ((c >= 'a' && c <= 'f') ||
		        (c >= 'A' && c <= 'F') ||
		        (c >= '0' && c <= '9'))
		{
		}
		else
		{
			return false;
		}
	}

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
			c = ZeroMallocFast(sizeof(IP_CLIENT));
			Copy(&c->IpAddress, ip, sizeof(IP));
			c->NumConnections = 0;

			Add(ip_clients, c);
		}

		c->NumConnections++;
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
	Copy(&t.IpAddress, ip, sizeof(IP));

	return Search(ip_clients, &t);
}

static void InitIpClientList()
{
	ip_clients = NewList(CompareIpClientList);
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

static UINT IntToSubnetMask32(UINT i)
{
	UINT ret = 0xFFFFFFFF;

	switch (i)
	{
	case 0:
		ret = 0x00000000;
		break;
	case 1:
		ret = 0x80000000;
		break;
	case 2:
		ret = 0xC0000000;
		break;
	case 3:
		ret = 0xE0000000;
		break;
	case 4:
		ret = 0xF0000000;
		break;
	case 5:
		ret = 0xF8000000;
		break;
	case 6:
		ret = 0xFC000000;
		break;
	case 7:
		ret = 0xFE000000;
		break;
	case 8:
		ret = 0xFF000000;
		break;
	case 9:
		ret = 0xFF800000;
		break;
	case 10:
		ret = 0xFFC00000;
		break;
	case 11:
		ret = 0xFFE00000;
		break;
	case 12:
		ret = 0xFFF00000;
		break;
	case 13:
		ret = 0xFFF80000;
		break;
	case 14:
		ret = 0xFFFC0000;
		break;
	case 15:
		ret = 0xFFFE0000;
		break;
	case 16:
		ret = 0xFFFF0000;
		break;
	case 17:
		ret = 0xFFFF8000;
		break;
	case 18:
		ret = 0xFFFFC000;
		break;
	case 19:
		ret = 0xFFFFE000;
		break;
	case 20:
		ret = 0xFFFFF000;
		break;
	case 21:
		ret = 0xFFFFF800;
		break;
	case 22:
		ret = 0xFFFFFC00;
		break;
	case 23:
		ret = 0xFFFFFE00;
		break;
	case 24:
		ret = 0xFFFFFF00;
		break;
	case 25:
		ret = 0xFFFFFF80;
		break;
	case 26:
		ret = 0xFFFFFFC0;
		break;
	case 27:
		ret = 0xFFFFFFE0;
		break;
	case 28:
		ret = 0xFFFFFFF0;
		break;
	case 29:
		ret = 0xFFFFFFF8;
		break;
	case 30:
		ret = 0xFFFFFFFC;
		break;
	case 31:
		ret = 0xFFFFFFFE;
		break;
	case 32:
		ret = 0xFFFFFFFF;
		break;
	}

	if (IsLittleEndian())
	{
		ret = Swap32(ret);
	}

	return ret;
}
void IntToSubnetMask4(IP *ip, UINT i)
{
	UINT m;
	if (ip == NULL)
	{
		return;
	}

	m = IntToSubnetMask32(i);

	UINTToIP(ip, m);
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
	UINT i;
	if (ip == NULL)
	{
		return false;
	}

	if (IsIP6(ip))
	{
		return false;
	}

	i = IPToUINT(ip);

	if (IsLittleEndian())
	{
		i = Swap32(i);
	}

	switch (i)
	{
	case 0x00000000:
	case 0x80000000:
	case 0xC0000000:
	case 0xE0000000:
	case 0xF0000000:
	case 0xF8000000:
	case 0xFC000000:
	case 0xFE000000:
	case 0xFF000000:
	case 0xFF800000:
	case 0xFFC00000:
	case 0xFFE00000:
	case 0xFFF00000:
	case 0xFFF80000:
	case 0xFFFC0000:
	case 0xFFFE0000:
	case 0xFFFF0000:
	case 0xFFFF8000:
	case 0xFFFFC000:
	case 0xFFFFE000:
	case 0xFFFFF000:
	case 0xFFFFF800:
	case 0xFFFFFC00:
	case 0xFFFFFE00:
	case 0xFFFFFF00:
	case 0xFFFFFF80:
	case 0xFFFFFFC0:
	case 0xFFFFFFE0:
	case 0xFFFFFFF0:
	case 0xFFFFFFF8:
	case 0xFFFFFFFC:
	case 0xFFFFFFFE:
	case 0xFFFFFFFF:
		return true;
	}

	return false;
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

UINT RecvFrom(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_in addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock != NULL)
	{
		if (sock->IPv6)
		{
			return RecvFrom6(sock, src_addr, src_port, data, size);
		}

		sock->IgnoreRecvErr = false;
	}
	else
	{
		return 0;
	}

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
		InAddrToIP(src_addr, &addr.sin_addr);
		*src_port = (UINT)ntohs(addr.sin_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}
	else
	{
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
		return 0;
	}
}
UINT RecvFrom6(SOCK *sock, IP *src_addr, UINT *src_port, void *data, UINT size)
{
	struct sockaddr_in6 addr;
	int ret = 0;
	int socklen = sizeof(addr);

	if (sock != NULL)
	{
		sock->IgnoreRecvErr = false;
	}
	else
	{
		return 0;
	}

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
		InAddrToIP6(src_addr, &addr.sin6_addr);
		src_addr->ipv6_scope_id = addr.sin6_scope_id;
		*src_port = (UINT)ntohs(addr.sin6_port);
		if (sock->IsRawSocket)
		{
			*src_port = sock->LocalPort;
		}

		Lock(sock->lock);
		{
			sock->RecvNum++;
			sock->RecvSize += (UINT64)ret;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	}
	else if (ret == 0)
	{
		return SOCK_LATER;
	}
	else
	{
		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEADDRNOTAVAIL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreRecvErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			Debug("RecvFrom(): recvfrom() failed with error: %u\n", WSAGetLastError());
		}
		return 0;
	}
}

UINT SendTo(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size)
{
	return SendToEx(sock, dest_addr, dest_port, data, size, false);
}
UINT SendToEx(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in addr;
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
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

	if (sock->IPv6)
	{
		return SendTo6Ex(sock, dest_addr, dest_port, data, size, broadcast);
	}

	if (IsIP4(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	if (sock->IsRawSocket == false)
	{
		addr.sin_port = htons((USHORT)dest_port);
	}
	IPToInAddr(&addr.sin_addr, dest_addr);

	const BYTE *ipv4 = IPV4(dest_addr->address);
	if ((ipv4[0] == 255 && ipv4[1] == 255 && ipv4[2] == 255 && ipv4[3] == 255) ||
		(ipv4[0] >= 224 && ipv4[0] <= 239) ||
		broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		else
		{
			UINT e = WSAGetLastError();
		}
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}
UINT SendTo6Ex(SOCK *sock, IP *dest_addr, UINT dest_port, void *data, UINT size, bool broadcast)
{
	SOCKET s;
	int ret;
	struct sockaddr_in6 addr;
	UINT type;
	if (sock != NULL)
	{
		sock->IgnoreSendErr = false;
	}
	if (sock == NULL || dest_addr == NULL || (sock->IsRawSocket == false && dest_port == 0) || data == NULL)
	{
		return 0;
	}
	if (dest_port >= 65536 && sock->IsRawSocket == false)
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

	if (IsIP6(dest_addr) == false)
	{
		return 0;
	}

	s = sock->socket;
	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (sock->IsRawSocket == false)
	{
		addr.sin6_port = htons((USHORT)dest_port);
	}
	IPToInAddr6(&addr.sin6_addr, dest_addr);
	addr.sin6_scope_id = dest_addr->ipv6_scope_id;

	type = GetIPAddrType6(dest_addr);

	if ((type & IPV6_ADDR_MULTICAST) || broadcast)
	{
		if (sock->UdpBroadcast == false)
		{
			UINT yes = 1;

			sock->UdpBroadcast = true;

			(void)setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&yes, sizeof(yes));
		}
	}

	ret = sendto(s, data, size, 0, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != (int)size)
	{
		sock->IgnoreSendErr = false;

		if (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAENETRESET || WSAGetLastError() == WSAEMSGSIZE || WSAGetLastError() == WSAENETUNREACH ||
		        WSAGetLastError() == WSAENOBUFS || WSAGetLastError() == WSAEHOSTUNREACH || WSAGetLastError() == WSAEUSERS || WSAGetLastError() == WSAEINVAL || WSAGetLastError() == WSAEADDRNOTAVAIL)
		{
			sock->IgnoreSendErr = true;
		}
		else if (WSAGetLastError() == WSAEWOULDBLOCK || WSAGetLastError() == WSAEINPROGRESS)
		{
			return SOCK_LATER;
		}
		return 0;
	}

	Lock(sock->lock);
	{
		sock->SendSize += (UINT64)size;
		sock->SendNum++;
	}
	Unlock(sock->lock);

	return ret;
}

SOCK *NewUDP(UINT port)
{
	return NewUDPEx2(port, false, NULL);
}
SOCK *NewUDPEx2(UINT port, bool ipv6, IP *ip)
{
	if (ipv6 == false)
	{
		return NewUDP4(port, ip);
	}
	else
	{
		return NewUDP6(port, ip);
	}
}
SOCK *NewUDPEx3(UINT port, IP *ip)
{
	if (ip == NULL)
	{
		return NewUDPEx2(port, false, NULL);
	}

	if (IsIP4(ip))
	{
		return NewUDPEx2(port, false, ip);
	}
	else
	{
		return NewUDPEx2(port, true, ip);
	}
}
SOCK *NewUDP4(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in addr;
	if (ip != NULL && IsIP4(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;

	if (ip == NULL || IsZeroIP(ip))
	{
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		IPToInAddr(&addr.sin_addr, ip);
	}

	if (port == 0 || IS_SPECIAL_PORT(port))
	{
		addr.sin_port = 0;
	}
	else
	{
		addr.sin_port = htons((USHORT)port);
	}

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		if (port != 0)
		{
			UINT true_flag = 1;
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				UINT false_flag = 0;
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef	SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
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
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize((int)s);

	if (IS_SPECIAL_PORT(port))
	{
		UINT no = 0;
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
}
SOCK *NewUDP6(UINT port, IP *ip)
{
	SOCK *sock;
	SOCKET s;
	struct sockaddr_in6 addr;
	if (ip != NULL && IsIP6(ip) == false)
	{
		return NULL;
	}

	if (IS_SPECIAL_PORT(port) == false)
	{
		s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else
	{
		s = socket(AF_INET6, SOCK_RAW, GET_SPECIAL_PORT(port));
	}
	if (s == INVALID_SOCKET)
	{
		return NULL;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	if (port == 0)
	{
		addr.sin6_port = 0;
	}
	else
	{
		addr.sin6_port = htons((USHORT)port);
	}

	if (ip != NULL && IsZeroIP(ip) == false)
	{
		IPToInAddr6(&addr.sin6_addr, ip);
		addr.sin6_scope_id = ip->ipv6_scope_id;
	}

	UINT true_flag = 1;
	UINT false_flag = 0;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
	{
		if (port != 0)
		{
			(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&true_flag, sizeof(true_flag));
			if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
			{
				(void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&false_flag, sizeof(false_flag));
#ifdef	SO_EXCLUSIVEADDRUSE
				(void)setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&true_flag, sizeof(true_flag));
#endif
				if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0)
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
	sock->IPv6 = true;
	if (port != 0)
	{
		sock->ServerMode = true;
	}

	sock->socket = s;

	InitUdpSocketBufferSize(s);

	if (IS_SPECIAL_PORT(port))
	{
		UINT no = 0;
#ifdef	IPV6_HDRINCL
		(void)setsockopt(sock->socket, IPPROTO_IP, IPV6_HDRINCL, (char *)&no, sizeof(no));
#endif
		(void)setsockopt(sock->socket, IPPROTO_IP, IP_HDRINCL, (char *)&no, sizeof(no));

		sock->IsRawSocket = true;
		sock->RawSocketIPProtocol = GET_SPECIAL_PORT(port);
	}

	QuerySocketInformation(sock);

	return sock;
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

void SetWantToUseCipher(SOCK *sock, char *name)
{
	if (sock == NULL || name == NULL)
	{
		return;
	}

	if (sock->WaitToUseCipher)
	{
		Free(sock->WaitToUseCipher);
	}

	sock->WaitToUseCipher = CopyStr(name);
}

static void AddChainSslCertOnDirectory(struct ssl_ctx_st *ctx)
{
	wchar_t dirname[MAX_SIZE];
	wchar_t exedir[MAX_SIZE];
	wchar_t txtname[MAX_SIZE];
	DIRLIST *dir;
	LIST *o;
	UINT i;

	if (ctx == NULL)
	{
		return;
	}

	o = NewListFast(NULL);

	GetExeDirW(exedir, sizeof(exedir));

	CombinePathW(dirname, sizeof(dirname), exedir, L"chain_certs");

	MakeDirExW(dirname);

	CombinePathW(txtname, sizeof(txtname), dirname, L"Readme_Chain_Certs.txt");

	if (IsFileExistsW(txtname) == false)
	{
		FileCopyW(L"|chain_certs.txt", txtname);
	}

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

					for (j = 0; j < LIST_NUM(o); j++)
					{
						UCHAR *hash2 = LIST_DATA(o, j);

						if (Cmp(hash, hash2, SHA1_SIZE) == 0)
						{
							exists = true;
						}
					}

					if (exists == false)
					{
						AddChainSslCert(ctx, x);

						Add(o, Clone(hash, SHA1_SIZE));
					}

					FreeX(x);
				}
			}
		}

		FreeDir(dir);
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		UCHAR *hash = LIST_DATA(o, i);

		Free(hash);
	}

	ReleaseList(o);
}

bool AddChainSslCert(struct ssl_ctx_st *ctx, X *x)
{
	bool ret = false;
	X *x_copy;
	if (ctx == NULL || x == NULL)
	{
		return ret;
	}

	x_copy = CloneX(x);

	if (x_copy != NULL)
	{
		SSL_CTX_add_extra_chain_cert(ctx, x_copy->x509);
		x_copy->do_not_free = true;

		ret = true;

		FreeX(x_copy);
	}

	return ret;
}

// Drain the OpenSSL error queue of a failed SSL_accept or SSL_connect into the ssl_err code (call under openssl_lock)
static void SslHandshakeError(bool server_mode, UINT *ssl_err)
{
	unsigned long err;
	while ((err = ERR_get_error()) != 0)
	{
		Debug("%s error %X: %s\n", server_mode ? "SSL_accept" : "SSL_connect", err, ERR_reason_error_string(err));
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

// Add the Windows ROOT store's certificates to a client's verification store (caller holds openssl_lock)
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

	ssl_ctx = NewSSLCtx(sock->ServerMode);
	if (ssl_ctx == NULL)
	{
		goto FAIL;
	}

	Lock(openssl_lock);
	{
		if (sock->ServerMode)
		{
#ifdef	SSL_OP_NO_TLSv1
			if (sock->SslAcceptSettings.Tls_Disable1_0)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_1
			if (sock->SslAcceptSettings.Tls_Disable1_1)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_1);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_2
			if (sock->SslAcceptSettings.Tls_Disable1_2)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_2);
			}
#endif

#ifdef	SSL_OP_NO_TLSv1_3
			if (sock->SslAcceptSettings.Tls_Disable1_3)
			{
				SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TLSv1_3);
			}
#endif

			Unlock(openssl_lock);
			if (chain == NULL)
			{
				AddChainSslCertOnDirectory(ssl_ctx);
			}
			else
			{
				UINT i;
				X *x;
				LockList(chain);
				{
					for (i = 0;i < LIST_NUM(chain);i++)
					{
						x = LIST_DATA(chain, i);
						AddChainSslCert(ssl_ctx, x);
					}
				}
				UnlockList(chain);
			}
			Lock(openssl_lock);
		}
		else
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

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) ||  LIBRESSL_VERSION_NUMBER >= 0x3060000L
		if (sock->SslAcceptSettings.Override_Security_Level)
		{
			SSL_CTX_set_security_level(ssl_ctx, sock->SslAcceptSettings.Override_Security_Level_Value);
		}
#endif

		sock->ssl = SSL_new(ssl_ctx);

		if (sock->ssl == NULL)
		{
			Unlock(openssl_lock);
			goto FAIL;
		}

		SSL_set_fd(sock->ssl, (int)sock->socket);

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
		if (sock->ServerMode == false)
		{
			if (IsEmptyStr(sni_hostname) == false)
			{
				SSL_set_tlsext_host_name(sock->ssl, sni_hostname);
			}
		}
#endif

	}
	Unlock(openssl_lock);

	if (x != NULL)
	{
		if (CheckXandK(x, priv))
		{
			x509 = x->x509;
			key = priv->pkey;

			Lock(openssl_lock);
			{
				SSL_use_certificate(sock->ssl, x509);
				SSL_use_PrivateKey(sock->ssl, key);
			}
			Unlock(openssl_lock);
		}
	}

	if (sock->WaitToUseCipher != NULL)
	{
		Lock(openssl_lock);
		{
			if (SSL_set_cipher_list(sock->ssl, sock->WaitToUseCipher) == 0)
				SSL_set_cipher_list(sock->ssl, DEFAULT_CIPHER_LIST);
		}
		Unlock(openssl_lock);
	}

	#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		SSL_set1_groups_list(sock->ssl, PQ_GROUP_LIST);
	#endif
	
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
		Lock(openssl_lock);
		{
			SslHandshakeError(sock->ServerMode, ssl_err);
		}
		Unlock(openssl_lock);
		goto FAIL;
	}

	if (sock->ServerMode)
	{

#ifdef	SSL_CTRL_SET_TLSEXT_HOSTNAME
#ifdef	TLSEXT_NAMETYPE_host_name
		if (true)
		{
			const char *sni_recv_hostname = SSL_get_servername(sock->ssl, TLSEXT_NAMETYPE_host_name);

			if (IsEmptyStr((char *)sni_recv_hostname) == false)
			{
				StrCpy(sock->SniHostname, sizeof(sock->SniHostname), (char *)sni_recv_hostname);
			}
		}
#endif
#endif
	}

	Lock(openssl_lock);
	{
		x509 = SSL_get_peer_certificate(sock->ssl);
		ssl_verify_err = SSL_get_verify_result(sock->ssl);
		sock->SslVersion = SSL_get_version(sock->ssl);
	}
	Unlock(openssl_lock);

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

	Lock(openssl_lock);
	{
		x509 = SSL_get_certificate(sock->ssl);
	}
	Unlock(openssl_lock);

	if (x509 == NULL)
	{
		sock->LocalX = NULL;
	}
	else
	{
		// The certificate belongs to the SSL object: neither X509ToX (when it refuses it) nor the X frees it
		X *local_x;
		local_x = X509ToX(x509);
		if (local_x == NULL)
		{
			sock->LocalX = NULL;
		}
		else
		{
			local_x->do_not_free = true;
			sock->LocalX = CloneX(local_x);
			FreeX(local_x);
		}
	}

	SSL_set_mode(sock->ssl, SSL_MODE_AUTO_RETRY);

	SSL_set_mode(sock->ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

	sock->ssl_ctx = ssl_ctx;

	Lock(openssl_lock);
	{
		sock->CipherName = CopyStr((char *)SSL_get_cipher(sock->ssl));
	}
	Unlock(openssl_lock);

	// The only success point: Recv/Send(secure) and Disconnect see SecureMode with a live ssl and ssl_ctx
	sock->SecureMode = true;

	Unlock(sock->ssl_lock);

	return true;

FAIL:
	// The one failure exit: no SSL object, no context, no lock held, not secure
	if (sock->ssl != NULL)
	{
		Lock(openssl_lock);
		{
			SSL_free(sock->ssl);
		}
		Unlock(openssl_lock);
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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		// OpenSSL 3: both 0 and negative values may be retryable; use SSL_get_error().
		// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
		if (ret == 0)
		{
			Disconnect(sock);
			return 0;
		}
#endif
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

#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0)
#else
		if (ret <= 0)
#endif
		{
			e = SSL_get_error(sock->ssl, ret);
		}

	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->RecvNum++;
		}
		Unlock(sock->lock);

		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	// OpenSSL 3: both 0 and negative values may be retryable; use SSL_get_error().
	// See: https://github.com/openssl/openssl/blob/435981cbadad2c58c35bacd30ca5d8b4c9bea72f/doc/man3/SSL_read.pod
	if (ret == 0)
	{
		Disconnect(sock);
		return 0;
	}
#endif

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
#if OPENSSL_VERSION_NUMBER < 0x30000000L
		if (ret < 0)
#else
		if (ret <= 0)
#endif
		{
			e = SSL_get_error(sock->ssl, ret);
		}
	}
	Unlock(sock->ssl_lock);

	if (ret > 0)
	{
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
		return (UINT)ret;
	}

#if OPENSSL_VERSION_NUMBER < 0x30000000L
	if (ret == 0)
	{
		Disconnect(sock);
		return 0;
	}
#endif

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
		Lock(sock->lock);
		{
			sock->RecvSize += (UINT64)ret;
			sock->RecvNum++;
		}
		Unlock(sock->lock);
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
		Lock(sock->lock);
		{
			sock->SendSize += (UINT64)ret;
			sock->SendNum++;
		}
		Unlock(sock->lock);
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
static SOCKET ListenBind(struct sockaddr *addr, int addr_size, bool v6only)
{
	SOCKET s = socket(addr->sa_family, SOCK_STREAM, 0);

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

		s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false);
	}
	else if (listen_ip == NULL || IsZeroIP(listen_ip))
	{
		if (ipv4_only == false)
		{
			s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), false);
			is_ipv6 = true;
		}

		if (s == INVALID_SOCKET)
		{
			// IPv6 is unsupported or off, or another process holds the port in one family: the free family listens
			s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false);
			is_ipv6 = false;

			if (s == INVALID_SOCKET && ipv4_only == false)
			{
				s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), true);
				is_ipv6 = true;
			}
		}
	}
	else if (IsIP4(listen_ip))
	{
		IPToInAddr(&addr4.sin_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr4, sizeof(addr4), false);
	}
	else if (ipv4_only == false)
	{
		IPToInAddr6(&addr6.sin6_addr, listen_ip);

		s = ListenBind((struct sockaddr *)&addr6, sizeof(addr6), true);
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

	Lock(disconnect_function_lock);

	Lock(sock->disconnect_lock);

	if (sock->Type == SOCK_TCP)
	{
		Lock(sock->lock);
		{
			if (sock->socket == INVALID_SOCKET)
			{
				Unlock(sock->lock);
				Unlock(sock->disconnect_lock);
				Unlock(disconnect_function_lock);
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
						Lock(openssl_lock);
						{
							SSL_free(sock->ssl);
							FreeSSLCtx(sock->ssl_ctx);
						}
						Unlock(openssl_lock);
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
				Unlock(disconnect_function_lock);
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

	Unlock(disconnect_function_lock);
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

#ifdef	IP_TOS
	(void)setsockopt(s->socket, IPPROTO_IP, IP_TOS, (char *)&tos, sizeof(int));
#endif

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
		UINT dw;
		UINT opt_value = 0;

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

		if (sock->IsRawSocket)
		{
			sock->LocalPort = sock->RemotePort = MAKE_SPECIAL_PORT(sock->RawSocketIPProtocol);
		}

		if (sock->Type == SOCK_UDP)
		{
			if (true)
			{
				UINT max_value = 0;
				int len = sizeof(UINT);

				if (getsockopt(sock->socket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char *)&max_value, &len) == 0)
				{
				}
			}
		}

		if (sock->IPv6)
		{
#ifdef	IPV6_UNICAST_HOPS
			opt_value = IPV6_UNICAST_HOPS;
#endif
		}
		else
		{
#ifdef	IP_TTL
			opt_value = IP_TTL;
#endif
		}

		size = sizeof(UINT);
		if (opt_value == 0 ||
		        getsockopt(sock->socket, (sock->IPv6 ? IPPROTO_IPV6 : IPPROTO_IP), opt_value, (char *)&dw, &size) != 0)
		{
		}
		else
		{
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
		if (s->ListenMode == false && s->ServerMode)
		{
			Print("");
		}
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
	if (s->LocalX != NULL)
	{
		FreeX(s->LocalX);
		s->LocalX = NULL;
	}

	if (s->CipherName != NULL)
	{
		Free(s->CipherName);
		s->CipherName = NULL;
	}

	Free(s->WaitToUseCipher);
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
		const BYTE *ipv4 = IPV4(ip->address);
		Format(str, size, "%hhu.%hhu.%hhu.%hhu", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	}
}

bool StrToIP(IP *ip, char *str)
{
	TOKEN_LIST *token;
	char *tmp;
	if (ip == NULL || str == NULL)
	{
		return false;
	}

	if (StrToIP6(ip, str))
	{
		return true;
	}

	ZeroIP4(ip);

	tmp = CopyStr(str);
	Trim(tmp);
	token = ParseToken(tmp, ".");
	Free(tmp);

	if (token->NumTokens != 4)
	{
		FreeToken(token);
		return false;
	}
	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		char *s = token->Token[i];
		if (s[0] < '0' || s[0] > '9' ||
		        (ToInt(s) >= 256))
		{
			FreeToken(token);
			return false;
		}
	}

	for (BYTE i = 0; i < IPV4_SIZE; ++i)
	{
		IPV4(ip->address)[i] = (BYTE)ToInt(token->Token[i]);
	}

	FreeToken(token);

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
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());
	if(ctx == NULL)
	{
		return NULL;
	}
	if (server_mode)
	{
		SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());
	}
	else
	{
		SSL_CTX_set_ssl_version(ctx, SSLv23_client_method());
	}

#ifdef	SSL_OP_NO_SSLv3
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);
#endif

#ifdef	SSL_OP_NO_TICKET
	SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
#endif

#ifdef	SSL_OP_CIPHER_SERVER_PREFERENCE
	if (server_mode)
	{
		SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
	}
#endif

	SSL_CTX_set_tmp_dh_callback(ctx, TmpDhCallback);

#ifdef	SSL_CTX_set_ecdh_auto
	SSL_CTX_set_ecdh_auto(ctx, 1);
#endif

	return ctx;
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
	struct ssl_ctx_st *ctx = SSL_CTX_new(SSLv23_method());

	if (ctx == NULL)
	{
		return security_level_new;
	}


#if (OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)) || LIBRESSL_VERSION_NUMBER >= 0x3060000L
	security_level_new = SSL_CTX_get_security_level(ctx);
#endif

	security_level_set_ssl_version = SSL_CTX_set_ssl_version(ctx, SSLv23_server_method());

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
	disconnect_function_lock = NewLock();
	machine_ip_process_hash_lock = NewLock();
	local_mac_list_lock = NewLock();

	current_global_ip_lock = NewLock();
	current_global_ip_set = false;
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

	DeleteLock(machine_name_lock);
	DeleteLock(disconnect_function_lock);
	DeleteLock(machine_ip_process_hash_lock);
	machine_name_lock = disconnect_function_lock = machine_ip_process_hash_lock = NULL;

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

bool GetSniNameFromSslPacket(UCHAR *packet_buf, UINT packet_size, char *sni, UINT sni_size)
{
	BUF *buf;
	bool ret = false;
	UCHAR content_type;
	USHORT version;
	USHORT handshake_length;

	if (packet_buf == NULL || packet_size <= 11)
	{
		return false;
	}

	if (!(packet_buf[0] == 0x16 && packet_buf[1] >= 0x03 &&
	        packet_buf[5] == 0x01 && packet_buf[6] == 0x00 &&
	        packet_buf[9] >= 0x03))
	{
		return false;
	}

	buf = NewBufFromMemory(packet_buf, packet_size);

	if (ReadBuf(buf, &content_type, sizeof(UCHAR)) == sizeof(UCHAR) &&
	        ReadBuf(buf, &version, sizeof(USHORT)) == sizeof(USHORT) &&
	        ReadBuf(buf, &handshake_length, sizeof(USHORT)) == sizeof(USHORT))
	{
		version = Endian16(version);
		handshake_length = Endian16(handshake_length);

		if (content_type == 0x16 && version >= 0x0301)
		{
			UCHAR *handshake_data = Malloc(handshake_length);

			if (ReadBuf(buf, handshake_data, handshake_length) == handshake_length)
			{
				BUF *buf2 = NewBufFromMemory(handshake_data, handshake_length);
				USHORT handshake_type;
				USHORT handshake_length_2;

				if (ReadBuf(buf2, &handshake_type, sizeof(USHORT)) == sizeof(USHORT) &&
				        ReadBuf(buf2, &handshake_length_2, sizeof(USHORT)) == sizeof(USHORT))
				{
					handshake_type = Endian16(handshake_type);
					handshake_length_2 = Endian16(handshake_length_2);

					if (handshake_type == 0x0100 && handshake_length_2 <= (handshake_length - 4))
					{
						USHORT version2;

						if (ReadBuf(buf2, &version2, sizeof(USHORT)) == sizeof(USHORT))
						{
							version2 = Endian16(version2);

							if (version2 >= 0x0301)
							{
								UCHAR rand[32];

								if (ReadBuf(buf2, rand, sizeof(rand)) == sizeof(rand))
								{
									UCHAR session_id_len;

									if (ReadBuf(buf2, &session_id_len, sizeof(UCHAR)) == sizeof(UCHAR))
									{
										if (ReadBuf(buf2, NULL, session_id_len) == session_id_len)
										{
											USHORT cipher_len;

											if (ReadBuf(buf2, &cipher_len, sizeof(USHORT)) == sizeof(USHORT))
											{
												cipher_len = Endian16(cipher_len);

												if (ReadBuf(buf2, NULL, cipher_len) == cipher_len)
												{
													UCHAR comps_len;

													if (ReadBuf(buf2, &comps_len, sizeof(UCHAR)) == sizeof(UCHAR))
													{
														if (ReadBuf(buf2, NULL, comps_len) == comps_len)
														{
															USHORT ext_length;

															if (ReadBuf(buf2, &ext_length, sizeof(USHORT)) == sizeof(USHORT))
															{
																UCHAR *ext_buf;

																ext_length = Endian16(ext_length);

																ext_buf = Malloc(ext_length);

																if (ReadBuf(buf2, ext_buf, ext_length) == ext_length)
																{
																	BUF *ebuf = NewBufFromMemory(ext_buf, ext_length);

																	while (ret == false)
																	{
																		USHORT type;
																		USHORT data_len;
																		UCHAR *data;

																		if (ReadBuf(ebuf, &type, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		if (ReadBuf(ebuf, &data_len, sizeof(USHORT)) != sizeof(USHORT))
																		{
																			break;
																		}

																		type = Endian16(type);
																		data_len = Endian16(data_len);

																		data = Malloc(data_len);

																		if (ReadBuf(ebuf, data, data_len) != data_len)
																		{
																			Free(data);
																			break;
																		}

																		if (type == 0x0000)
																		{
																			BUF *dbuf = NewBufFromMemory(data, data_len);

																			USHORT total_len;

																			if (ReadBuf(dbuf, &total_len, sizeof(USHORT)) == sizeof(USHORT))
																			{
																				UCHAR c;
																				total_len = Endian16(total_len);

																				if (ReadBuf(dbuf, &c, sizeof(UCHAR)) == sizeof(UCHAR))
																				{
																					if (c == 0)
																					{
																						USHORT name_len;

																						if (ReadBuf(dbuf, &name_len, sizeof(USHORT)) == sizeof(USHORT))
																						{
																							char *name_buf;
																							name_len = Endian16(name_len);

																							name_buf = ZeroMalloc(name_len + 1);

																							if (ReadBuf(dbuf, name_buf, name_len) == name_len)
																							{
																								if (StrLen(name_buf) >= 1)
																								{
																									ret = true;

																									StrCpy(sni, sni_size, name_buf);
																								}
																							}

																							Free(name_buf);
																						}
																					}
																				}
																			}

																			FreeBuf(dbuf);
																		}

																		Free(data);
																	}

																	FreeBuf(ebuf);
																}

																Free(ext_buf);
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}

				FreeBuf(buf2);
			}

			Free(handshake_data);
		}
	}

	FreeBuf(buf);

	if (ret)
	{
		Trim(sni);

		if (IsEmptyStr(sni))
		{
			ret = false;
		}
	}

	return ret;
}

void SetDhParam(DH_CTX *dh)
{
	if (dh_param)
	{
		DhFree(dh_param);
	}

	dh_param = dh;
}
