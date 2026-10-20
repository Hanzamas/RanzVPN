#include "DNS.h"

#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"
#include "Tick64.h"

#include <WS2tcpip.h>

static bool cache_enabled;

static LIST *cache;
static LIST *cache_reverse;

static COUNTER *threads_counter;
static UINT threads_max;

static int DnsCacheCompare(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	const DNS_CACHE *c1 = *(DNS_CACHE **)p1;
	const DNS_CACHE *c2 = *(DNS_CACHE **)p2;

	return StrCmpi(c1->Hostname, c2->Hostname);
}

static int DnsCacheReverseCompare(void *p1, void *p2)
{
	if (p1 == NULL || p2 == NULL)
	{
		return (p1 == NULL && p2 == NULL ? 0 : (p1 == NULL ? -1 : 1));
	}

	const DNS_CACHE_REVERSE *c1 = *(DNS_CACHE_REVERSE **)p1;
	const DNS_CACHE_REVERSE *c2 = *(DNS_CACHE_REVERSE **)p2;

	return CmpIpAddr(&c1->IP, &c2->IP);
}

void DnsInit()
{
	threads_counter = NewCounter();
	DnsThreadNumMaxSet(DNS_THREAD_DEFAULT_NUM_MAX);

	cache = NewList(DnsCacheCompare);
	cache_reverse = NewList(DnsCacheReverseCompare);
	DnsCacheToggle(true);
}

void DnsFree()
{
	DnsCacheToggle(false);

	LockList(cache);
	{
		for (UINT i = 0; i < LIST_NUM(cache); ++i)
		{
			DNS_CACHE *entry = LIST_DATA(cache, i);
			Free((void *)entry->Hostname);
			FreeHostIPAddressList(entry->IPList_v6);
			FreeHostIPAddressList(entry->IPList_v4);
			Free(entry);
		}
	}
	UnlockList(cache);

	ReleaseList(cache);
	cache = NULL;

	LockList(cache_reverse);
	{
		for (UINT i = 0; i < LIST_NUM(cache_reverse); ++i)
		{
			DNS_CACHE_REVERSE *entry = LIST_DATA(cache_reverse, i);
			Free(entry->Hostname);
			Free(entry);
		}
	}
	UnlockList(cache_reverse);

	ReleaseList(cache_reverse);
	cache_reverse = NULL;

	DeleteCounter(threads_counter);
	threads_counter = NULL;
}

UINT DnsThreadNum()
{
	return Count(threads_counter);
}

UINT DnsThreadNumMax()
{
	return threads_max;
}

void DnsThreadNumMaxSet(const UINT max)
{
	threads_max = max;
}

static bool DnsCacheIsEnabled()
{
	return cache_enabled;
}

void DnsCacheToggle(const bool enabled)
{
	cache_enabled = enabled;
}

// Copy the unexpired cache entry of hostname into *iplist_v6 and *iplist_v4 under the lock
static bool DnsCacheFind(const char *hostname, LIST **iplist_v6, LIST **iplist_v4)
{
	if (DnsCacheIsEnabled() == false || IsEmptyStr(hostname))
	{
		return false;
	}

	bool found = false;

	LockList(cache);
	{
		DNS_CACHE t;
		t.Hostname = hostname;
		const DNS_CACHE *entry = Search(cache, &t);

		if (entry != NULL && entry->Expiration > Tick64())
		{
			*iplist_v6 = CloneIPAddressList(entry->IPList_v6);
			*iplist_v4 = CloneIPAddressList(entry->IPList_v4);
			found = true;
		}
	}
	UnlockList(cache);

	return found;
}

static void DnsCacheUpdateEx(const char *hostname, const LIST *iplist_v6, const LIST *iplist_v4)
{
	if (DnsCacheIsEnabled() == false || IsEmptyStr(hostname))
	{
		return;
	}

	LockList(cache);
	{
		DNS_CACHE t;
		t.Hostname = hostname;
		DNS_CACHE *entry = Search(cache, &t);

		if (iplist_v6 == NULL && iplist_v4 == NULL)
		{
			if (entry != NULL)
			{
				Delete(cache, entry);
				Free((void *)entry->Hostname);
				FreeHostIPAddressList(entry->IPList_v6);
				FreeHostIPAddressList(entry->IPList_v4);
				Free(entry);
			}
		}
		else
		{
			if (entry == NULL)
			{
				entry = ZeroMalloc(sizeof(DNS_CACHE));
				entry->Hostname = CopyStr(hostname);

				Add(cache, entry);
			}

			entry->Expiration = Tick64() + DNS_CACHE_EXPIRATION;

			FreeHostIPAddressList(entry->IPList_v6);
			FreeHostIPAddressList(entry->IPList_v4);

			if (iplist_v6 != NULL)
			{
				entry->IPList_v6 = CloneIPAddressList(iplist_v6);
			}
			else
			{
				entry->IPList_v6 = NULL;
			}

			if (iplist_v4 != NULL)
			{
				entry->IPList_v4 = CloneIPAddressList(iplist_v4);
			}
			else
			{
				entry->IPList_v4 = NULL;
			}
		}
	}
	UnlockList(cache);
}

// Copy the unexpired cached host name of ip into dst under the lock
static bool DnsCacheReverseFind(const IP *ip, char *dst, const UINT size)
{
	if (DnsCacheIsEnabled() == false || ip == NULL)
	{
		return false;
	}

	bool found = false;

	LockList(cache_reverse);
	{
		DNS_CACHE_REVERSE t;
		Copy(&t.IP, ip, sizeof(t.IP));
		const DNS_CACHE_REVERSE *entry = Search(cache_reverse, &t);

		if (entry != NULL && entry->Expiration > Tick64())
		{
			StrCpy(dst, size, entry->Hostname);
			found = true;
		}
	}
	UnlockList(cache_reverse);

	return found;
}

void DnsCacheReverseUpdate(const IP *ip, const char *hostname)
{
	if (DnsCacheIsEnabled() == false || IsZeroIP(ip))
	{
		return;
	}

	LockList(cache_reverse);
	{
		DNS_CACHE_REVERSE t;
		Copy(&t.IP, ip, sizeof(t.IP));
		DNS_CACHE_REVERSE *entry = Search(cache_reverse, &t);

		if (IsEmptyStr(hostname))
		{
			if (entry != NULL)
			{
				Delete(cache_reverse, entry);
				Free(entry->Hostname);
				Free(entry);
			}
		}
		else
		{
			if (entry == NULL)
			{
				entry = ZeroMalloc(sizeof(DNS_CACHE_REVERSE));
				Copy(&entry->IP, ip, sizeof(entry->IP));

				Add(cache_reverse, entry);
			}

			entry->Expiration = Tick64() + DNS_CACHE_EXPIRATION;

			if (StrCmp(entry->Hostname, hostname) != 0)
			{
				Free(entry->Hostname);
				entry->Hostname = CopyStr(hostname);
			}
		}
	}
	UnlockList(cache_reverse);
}

// Wait for a lookup worker until it ends, the timeout passes or *cancel_flag is set; releases the worker
static bool DnsWaitWorker(THREAD *worker, const UINT timeout, volatile const bool *cancel_flag)
{
	bool finished = false;

	Inc(threads_counter);

	WaitThreadInit(worker);

	if (cancel_flag == NULL)
	{
		finished = WaitThread(worker, timeout);
	}
	else
	{
		const UINT64 end = Tick64() + timeout;

		while (FlagRead(cancel_flag) == false)
		{
			const UINT64 now = Tick64();
			if (now >= end)
			{
				break;
			}

			BYTE next = MIN(end - now, 100);
			if (WaitThread(worker, next))
			{
				finished = true;
				break;
			}
		}
	}

	ReleaseThread(worker);

	Dec(threads_counter);

	return finished;
}

bool DnsResolve(IP *ipv6, IP *ipv4, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if ((ipv6 == NULL && ipv4 == NULL) || IsEmptyStr(hostname))
	{
		return false;
	}

	LIST *iplist_v6 = NULL;
	LIST *iplist_v4 = NULL;

	bool ret = DnsResolveEx(&iplist_v6, &iplist_v4, hostname, timeout, cancel_flag);

	if (ipv6 != NULL && LIST_NUM(iplist_v6) > 0)
	{
		IP *ip = LIST_DATA(iplist_v6, 0);
		Copy(ipv6, ip, sizeof(IP));
	}
	else
	{
		Zero(ipv6, sizeof(IP));
	}

	if (ipv4 != NULL && LIST_NUM(iplist_v4) > 0)
	{
		IP *ip = LIST_DATA(iplist_v4, 0);
		Copy(ipv4, ip, sizeof(IP));
	}
	else
	{
		ZeroIP4(ipv4);
	}

	FreeHostIPAddressList(iplist_v6);
	FreeHostIPAddressList(iplist_v4);

	return ret;
}
bool DnsResolveEx(LIST **iplist_v6, LIST **iplist_v4, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if (iplist_v6 == NULL || iplist_v4 == NULL || IsEmptyStr(hostname))
	{
		return false;
	}

	if (StrCmpi(hostname, "localhost") == 0)
	{
		IP ipv6, ipv4;
		GetLocalHostIP6(&ipv6);
		GetLocalHostIP4(&ipv4);
		*iplist_v6 = NewListFast(NULL);
		*iplist_v4 = NewListFast(NULL);
		AddHostIPAddressToList(*iplist_v6, &ipv6);
		AddHostIPAddressToList(*iplist_v4, &ipv4);
		return true;
	}

	IP ip;
	if (StrToIP(&ip, hostname))
	{
		if (IsIP6(&ip))
		{
			*iplist_v6 = NewListFast(NULL);
			AddHostIPAddressToList(*iplist_v6, &ip);
			return true;
		}
		else
		{
			*iplist_v4 = NewListFast(NULL);
			AddHostIPAddressToList(*iplist_v4, &ip);
			return true;
		}
	}

	if (DnsThreadNum() > DnsThreadNumMax())
	{
		Debug("DnsResolve(): Too many threads! Current: %u, Maximum: %u\n",
			  DnsThreadNum(), DnsThreadNumMax());

		goto CACHE;
	}

	if (cancel_flag != NULL && FlagRead(cancel_flag))
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = DNS_RESOLVE_DEFAULT_TIMEOUT;
	}

	DNS_RESOLVER *resolver;
	resolver = ZeroMalloc(sizeof(DNS_RESOLVER));
	resolver->Ref = NewRef();
	resolver->IPList_v6 = NewListFast(NULL);
	resolver->IPList_v4 = NewListFast(NULL);
	resolver->Hostname = CopyStr(hostname);

	// The lists belong to the worker until it has finished
	if (DnsWaitWorker(NewThread(DnsResolver, resolver), timeout, cancel_flag) && FlagRead(&resolver->OK))
	{
		*iplist_v6 = resolver->IPList_v6;
		*iplist_v4 = resolver->IPList_v4;
		resolver->IPList_v6 = NULL;
		resolver->IPList_v4 = NULL;
		DnsCacheUpdateEx(hostname, *iplist_v6, *iplist_v4);
		ReleaseDnsResolver(resolver);

		return true;
	}

	ReleaseDnsResolver(resolver);

CACHE:
	Debug("DnsResolve(): Could not resolve \"%s\". Searching for it in the cache...\n", hostname);

	return DnsCacheFind(hostname, iplist_v6, iplist_v4);
}

void DnsResolver(THREAD *t, void *param)
{
	if (t == NULL || param == NULL)
	{
		return;
	}

	DNS_RESOLVER *resolver = param;

	AddRef(resolver->Ref);

	NoticeThreadInit(t);
	AddWaitThread(t);

	ADDRINFOW hints;
	Zero(&hints, sizeof(hints));

	if (HasIPv6Address())
	{
		hints.ai_family = AF_INET6;
		hints.ai_flags = AI_ALL | AI_ADDRCONFIG | AI_V4MAPPED;
	}
	else
	{
		hints.ai_family = AF_INET;
	}

	// getaddrinfo() took the name in the ANSI code page: convert it the same way
	int ret = EAI_FAIL;
	bool converted = false;
	ADDRINFOW *results = NULL;
	const int hostname_len = MultiByteToWideChar(CP_ACP, 0, resolver->Hostname, -1, NULL, 0);
	if (hostname_len > 0)
	{
		wchar_t *hostname_w = Malloc(sizeof(wchar_t) * (UINT)hostname_len);
		if (MultiByteToWideChar(CP_ACP, 0, resolver->Hostname, -1, hostname_w, hostname_len) == hostname_len)
		{
			converted = true;
			ret = GetAddrInfoW(hostname_w, NULL, &hints, &results);
		}
		Free(hostname_w);
	}

	if (converted == false)
	{
		Debug("DnsResolver(): MultiByteToWideChar() failed to convert the host name!\n");
	}
	else if (ret == 0)
	{
		for (ADDRINFOW *result = results; result != NULL; result = result->ai_next)
		{
			IP ip;
			if (hints.ai_family == AF_INET6)
			{
				const struct sockaddr_in6 *in = (struct sockaddr_in6 *)result->ai_addr;
				InAddrToIP6(&ip, &in->sin6_addr);
				if (IsIP6(&ip))
				{
					ip.ipv6_scope_id = in->sin6_scope_id;
					AddHostIPAddressToList(resolver->IPList_v6, &ip);
				}
				else if (IsIP4(&ip))
				{
					AddHostIPAddressToList(resolver->IPList_v4, &ip);
				}
			}
			else
			{
				const struct sockaddr_in *in = (struct sockaddr_in *)result->ai_addr;
				InAddrToIP(&ip, &in->sin_addr);
				if (IsIP4(&ip))
				{
					AddHostIPAddressToList(resolver->IPList_v4, &ip);
				}
			}
		}

		// Publish OK only after the lists are complete
		FlagWrite(&resolver->OK, true);

		FreeAddrInfoW(results);
	}

	ReleaseDnsResolver(resolver);

	DelWaitThread(t);
}

bool DnsResolveReverse(char *dst, const UINT size, const IP *ip, UINT timeout, volatile const bool *cancel_flag)
{
	if (dst == NULL || size == 0 || IsZeroIP(ip))
	{
		return false;
	}

	if (DnsThreadNum() > DnsThreadNumMax())
	{
		Debug("DnsResolveReverse(): Too many threads! Current: %u, Maximum: %u\n",
			  DnsThreadNum(), DnsThreadNumMax());

		goto CACHE;
	}

	if (cancel_flag != NULL && FlagRead(cancel_flag))
	{
		return false;
	}

	if (timeout == 0)
	{
		timeout = DNS_RESOLVE_REVERSE_DEFAULT_TIMEOUT;
	}

	DNS_RESOLVER_REVERSE *resolver;
	resolver = ZeroMalloc(sizeof(DNS_RESOLVER_REVERSE));
	resolver->Ref = NewRef();
	Copy(&resolver->IP, ip, sizeof(resolver->IP));

	// The host name belongs to the worker until it has finished
	if (DnsWaitWorker(NewThread(DnsResolverReverse, resolver), timeout, cancel_flag) && FlagRead(&resolver->OK))
	{
		StrCpy(dst, size, resolver->Hostname);
		DnsCacheReverseUpdate(ip, dst);
		ReleaseDnsResolverReverse(resolver);

		return true;
	}

	ReleaseDnsResolverReverse(resolver);

CACHE:
	{
		char ip_str[MAX_SIZE];

		IPToStr(ip_str, sizeof(ip_str), ip);
		Debug("DnsResolveReverse(): Could not resolve \"%s\". Searching for it in the cache...\n", ip_str);
	}

	return DnsCacheReverseFind(ip, dst, size);
}

void DnsResolverReverse(THREAD *t, void *param)
{
	if (t == NULL || param == NULL)
	{
		return;
	}

	DNS_RESOLVER_REVERSE *resolver = param;

	AddRef(resolver->Ref);

	NoticeThreadInit(t);
	AddWaitThread(t);

	struct sockaddr_in6 in;
	Zero(&in, sizeof(in));
	in.sin6_family = AF_INET6;
	IPToInAddr6(&in.sin6_addr, &resolver->IP);

	char tmp[NI_MAXHOST];
	wchar_t tmp_w[NI_MAXHOST];
	const int ret = GetNameInfoW((struct sockaddr *)&in, sizeof(in), tmp_w, sizeof(tmp_w) / sizeof(tmp_w[0]), NULL, 0, NI_NAMEREQD);
	if (ret == 0)
	{
		// getnameinfo() returned the name in the ANSI code page: convert it the same way
		if (WideCharToMultiByte(CP_ACP, 0, tmp_w, -1, tmp, sizeof(tmp), NULL, NULL) != 0)
		{
			resolver->Hostname = CopyStr(tmp);
			// Publish OK only after the host name is set
			FlagWrite(&resolver->OK, true);
		}
		else
		{
			Debug("DnsResolverReverse(): WideCharToMultiByte() failed with error %u!\n", GetLastError());
		}
	}

	ReleaseDnsResolverReverse(resolver);

	DelWaitThread(t);
}

bool GetIPEx(IP *ip, const char *hostname, UINT timeout, volatile const bool *cancel_flag)
{
	if (ip == NULL || IsEmptyStr(hostname))
	{
		return false;
	}

	IP ipv6, ipv4;
	if (DnsResolve(&ipv6, &ipv4, hostname, timeout, cancel_flag) == false)
	{
		return false;
	}

	if (IsZeroIP(&ipv6) == false)
	{
		Copy(ip, &ipv6, sizeof(IP));
		return true;
	}
	else if (IsZeroIP(&ipv4) == false)
	{
		Copy(ip, &ipv4, sizeof(IP));
		return true;
	}

	return false;
}

void ReleaseDnsResolver(DNS_RESOLVER *p)
{
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		FreeHostIPAddressList(p->IPList_v6);
		FreeHostIPAddressList(p->IPList_v4);
		Free(p->Hostname);
		Free(p);
	}
}

void ReleaseDnsResolverReverse(DNS_RESOLVER_REVERSE *p)
{
	if (p == NULL)
	{
		return;
	}

	if (Release(p->Ref) == 0)
	{
		Free(p->Hostname);
		Free(p);
	}
}