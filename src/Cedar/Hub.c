// Hub.c
// Virtual HUB module

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "PacketLog.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/DNS.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include <string.h>
#include "HubInternal.h"


static LIST *NewUserList() {
	LIST *o = NewList(CompareUserList);

	return o;
}

static bool IsUserMatchInUserListWithCacheExpires(LIST *o, char *filename, UINT64 user_hash, UINT64 lifetime) {
	bool ret = false;
	UINT64 now = Tick64();
	if (o == NULL || filename == NULL || user_hash == 0)
		return false;

	LockList(o);
	{
		if (lifetime != 0) {
			if (o->Param1 == 0 || (now >= (o->Param1 + lifetime))) {
				DeleteAllUserListCache(o);

				o->Param1 = now;
			}
		}

		ret = IsUserMatchInUserList(o, filename, user_hash);
	}
	UnlockList(o);

	return ret;
}
static bool IsUserMatchInUserListWithCacheExpiresAcl(LIST *o, char *name_in_acl, UINT64 user_hash, UINT64 lifetime) {
	char tmp[16];
	bool exclude = false;
	char filename[MAX_SIZE];
	char filename2[MAX_SIZE];
	bool is_full_path = false;
	bool ret = false;
	if (o == NULL || name_in_acl == NULL || user_hash == 0 || StrLen(name_in_acl) < 9)
		return false;

	StrCpy(tmp, sizeof(tmp), name_in_acl);
	StrLower(tmp);

	tmp[8] = 0;

	if (Cmp(tmp, ACCESS_LIST_INCLUDED_PREFIX, 8) == 0)
		exclude = false;
	else
		exclude = true;

	StrCpy(filename, sizeof(filename), name_in_acl + 8);
	Trim(filename);

	if (filename[0] == '\\' || filename[0] == '/' || (filename[1] == ':' && filename[2] == '\\'))
		is_full_path = true;

	if (is_full_path == false) {
		StrCpy(filename2, sizeof(filename2), "@");
		StrCat(filename2, sizeof(filename2), filename);
		StrCpy(filename, sizeof(filename), filename2);
	}

	ret = IsUserMatchInUserListWithCacheExpires(o, filename, user_hash, lifetime);

	if (exclude)
		ret = NEGATIVE_BOOL(ret);

	return ret;
}

static void FreeUserList(LIST *o) {
	if (o == NULL)
		return;

	DeleteAllUserListCache(o);

	ReleaseList(o);
}

static int CompareAdminOption(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	ADMIN_OPTION *a1 = *(ADMIN_OPTION **)p1;
	ADMIN_OPTION *a2 = *(ADMIN_OPTION **)p2;
	if (a1 == NULL || a2 == NULL)
		return 0;
	return StrCmpi(a1->Name, a2->Name);
}

static void StartHubWatchDog(HUB *h) {
	if (h == NULL)
		return;

	h->HaltWatchDog = false;
	h->WatchDogEvent = NewEvent();

	THREAD *t = NewThread(HubWatchDogThread, h);
	WaitThreadInit(t);
	ReleaseThread(t);
}

static void StopHubWatchDog(HUB *h) {
	if (h == NULL)
		return;

	h->HaltWatchDog = true;
	Set(h->WatchDogEvent);

	WaitThread(h->WatchDogThread, INFINITE);
	ReleaseThread(h->WatchDogThread);
	h->WatchDogThread = NULL;
	h->HaltWatchDog = false;

	ReleaseEvent(h->WatchDogEvent);
	h->WatchDogEvent = NULL;
}

// Most due IP table entries one watchdog wake copies out and probes
#define HUB_WATCHDOG_SLICE 128

// One due ARP/NS probe target, copied out of the IP table under the MacHashTable lock
typedef struct HUB_WATCHDOG_PROBE {
	IP Ip;
	UCHAR MacAddress[6];
} HUB_WATCHDOG_PROBE;

// Send one ARP request (IPv4) or neighbor solicitation (IPv6) to a known IP table entry
static void HubWatchDogSendProbe(HUB *hub, HUB_WATCHDOG_PROBE *probe) {
	PKT *packet;

	if (IsIP4(&probe->Ip)) {
		MAC_HEADER *mac = ZeroMalloc(sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
		ARPV4_HEADER *p = (ARPV4_HEADER *)(((UCHAR *)mac) + sizeof(MAC_HEADER));

		Copy(mac->DestAddress, probe->MacAddress, 6);
		Copy(mac->SrcAddress, hub->HubMacAddr, 6);
		mac->Protocol = Endian16(MAC_PROTO_ARPV4);

		p->HardwareType = Endian16(ARP_HARDWARE_TYPE_ETHERNET);
		p->ProtocolType = Endian16(MAC_PROTO_IPV4);
		p->HardwareSize = 6;
		p->ProtocolSize = 4;
		p->Operation = Endian16(ARP_OPERATION_REQUEST);
		Copy(p->SrcAddress, hub->HubMacAddr, 6);
		p->SrcIP = IPToUINT(&hub->HubIp);
		// TargetAddress stays all zero from ZeroMalloc
		p->TargetIP = IPToUINT(&probe->Ip);

		packet = ParsePacket((UCHAR *)mac, sizeof(MAC_HEADER) + sizeof(ARPV4_HEADER));
		if (packet != NULL)
			StorePacket(hub, NULL, packet);
		else
			Free(mac);
	} else if (IsIP6(&probe->Ip)) {
		IPV6_ADDR ip6addr;
		MAC_HEADER mac;

		if (IPToIPv6Addr(&ip6addr, &probe->Ip) == false)
			return;

		BUF *ns = BuildNeighborSolicitation(&hub->HubIpV6, &ip6addr, hub->HubMacAddr);
		if (ns == NULL)
			return;

		Zero(&mac, sizeof(mac));
		Copy(mac.DestAddress, probe->MacAddress, 6);
		Copy(mac.SrcAddress, hub->HubMacAddr, 6);
		mac.Protocol = Endian16(MAC_PROTO_IPV6);

		BUF *buf = NewBuf();
		WriteBuf(buf, &mac, sizeof(MAC_HEADER));
		WriteBuf(buf, ns->Buf, ns->Size);
		FreeBuf(ns);

		packet = ParsePacket(buf->Buf, buf->Size);
		if (packet != NULL)
			StorePacket(hub, NULL, packet);
		else
			Free(buf->Buf);

		Free(buf);
	}
}

// Keeps the IP table fresh by probing silent entries. An entry falls due one HUB_ARP_SEND_INTERVAL after
// it was last seen or last probed. Probes are spread so that one probe of every entry fits in one interval,
// never closer than 1 ms apart, and the thread sleeps until the next entry falls due.
void HubWatchDogThread(THREAD *t, void *param) {
	HUB_WATCHDOG_PROBE probes[HUB_WATCHDOG_SLICE];
	UINT64 last_sent = 0;
	if (t == NULL || param == NULL)
		return;

	HUB *hub = (HUB *)param;

	hub->WatchDogThread = t;
	AddRef(t->ref);

	NoticeThreadInit(t);

	while (hub->HaltWatchDog == false) {
		UINT64 interval = (UINT64)HUB_ARP_SEND_INTERVAL;
		UINT64 step = interval;
		UINT64 window;
		UINT64 now = Tick64();
		UINT64 next_due = 0;
		UINT64 wait_time = interval;
		UINT num = 0;

		HubLockTables(hub);
		{
			UINT num_entries = HubIpTableNum(hub);
			bool arp_polling = (hub->Option->NoArpPolling == false);
			bool ns_polling = (hub->Option->NoIPv6AddrPolling == false);

			if (num_entries != 0)
				step = MAX(interval / (UINT64)num_entries, (UINT64)1);

			// Entries falling due within this window ride along with this slice, so a table whose due
			// times are staggered is not rescanned once per probe
			window = MIN(step * HUB_WATCHDOG_SLICE, interval / 4);

			for (UINT i = 0; i < num_entries; i++) {
				IP_TABLE_ENTRY *e = IpTableGet(hub, i);

				if (e == NULL || (e->UpdatedTime + (UINT64)(IP_TABLE_EXPIRE_TIME)) <= now)
					continue;

				if (e->MacAddress[0] == 0xff && e->MacAddress[1] == 0xff && e->MacAddress[2] == 0xff &&
				    e->MacAddress[3] == 0xff && e->MacAddress[4] == 0xff && e->MacAddress[5] == 0xff)
					continue;

				if ((arp_polling == false || IsIP4(&e->Ip) == false) &&
				    (ns_polling == false || IsIP6(&e->Ip) == false))
					continue;

				UINT64 due = MAX(e->UpdatedTime, e->LastProbeTime) + interval;
				if (due <= (now + window)) {
					if (num < HUB_WATCHDOG_SLICE) {
						Copy(&probes[num].Ip, &e->Ip, sizeof(IP));
						Copy(probes[num].MacAddress, e->MacAddress, 6);

						// Probes of one slice go out one step apart
						e->LastProbeTime = now + step * (UINT64)num;
						due = e->LastProbeTime + interval;
						num++;
					} else {
						// Slice full: come back for the rest after one step
						due = now;
					}
				}

				if (next_due == 0 || due < next_due)
					next_due = due;
			}
		}
		HubUnlockTables(hub);

		for (UINT i = 0; i < num; i++) {
			if (i != 0) {
				Wait(hub->WatchDogEvent, (UINT)step);
				if (hub->HaltWatchDog)
					break;
			}

			HubWatchDogSendProbe(hub, &probes[i]);
			last_sent = Tick64();
		}

		if (hub->HaltWatchDog)
			break;

		// Sleep until the next entry falls due, but at least one step after the last probe. With nothing to
		// probe, wake once per interval: a new entry falls due no earlier than one interval after it is seen.
		if (next_due != 0) {
			UINT64 wake = MAX(next_due, last_sent + step);

			now = Tick64();
			wait_time = (wake > now ? wake - now : 0);
			wait_time = MIN(wait_time, interval);
		}

		Wait(hub->WatchDogEvent, (UINT)wait_time);
	}
}

// Whether the IPv4 address in an Ethernet ARP packet (the target address when dest, else the sender) lies in addr/mask.
// False for an ARP of another kind, an unset or broadcast address, or a hub-internal address sent from a hub MAC
static bool ArpAddrMatches(PKT *p, bool dest, UINT addr, UINT mask) {
	ARPV4_HEADER *arp = p->L3.ARPv4Header;

	if (arp->HardwareSize != 6 ||
	    Endian16(arp->HardwareType) != ARP_HARDWARE_TYPE_ETHERNET ||
	    arp->ProtocolSize != 4 ||
	    Endian16(arp->ProtocolType) != 0x0800)
		return false;

	UINT uint_ip = dest ? arp->TargetIP : arp->SrcIP;

	if (uint_ip == 0 || uint_ip == 0xffffffff || (IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
		return false;

	return (uint_ip & mask) == (addr & mask);
}

// A port range with both ends 0 holds every port
static bool PortInRange(UINT port, UINT start, UINT end) {
	if (start == 0 && end == 0)
		return true;

	return port >= start && port <= end;
}

// Whether a user (name_in_acl is an include: or exclude: list) matches for hub; never for an internal session.
// user_session is the session of that user, NULL when it is not known
static bool MatchIncludeExcludeUser(HUB *hub, SESSION *user_session, char *name_in_acl, UINT64 user_hash) {
	if (user_session != NULL && user_session->NormalClient == false) {
		// exclude: and include: filters never match internal sessions
		return false;
	}

	return IsUserMatchInUserListWithCacheExpiresAcl(hub->UserList, name_in_acl, user_hash,
	                                                hub->Option->AccessListIncludeFileCacheLifetime * 1000);
}

static bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session) {
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	if (s == NULL || p == NULL || a == NULL)
		return false;
	if (a->Active == false)
		return false;

	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	UINT64 src_username = pa->UsernameHash;
	UINT64 src_groupname = pa->GroupnameHash;

	if (a->CheckSrcMac != false) {
		for (UINT i = 0; i < 6; i++)
			if ((a->SrcMacAddress[i] & a->SrcMacMask[i]) != (a->SrcMacMask[i] & p->MacAddressSrc[i]))
				return false;
	}

	if (a->CheckDstMac != false) {
		for (UINT i = 0; i < 6; i++)
			if ((a->DstMacAddress[i] & a->DstMacMask[i]) != (a->DstMacMask[i] & p->MacAddressDest[i]))
				return false;
	}

	if (a->SrcUsernameHash != 0) {
		if (a->IsSrcUsernameIncludeOrExclude == false) {
			if ((a->SrcUsernameHash != src_username) && (a->SrcUsernameHash != src_groupname))
				return false;
		} else if (s->Hub != NULL && MatchIncludeExcludeUser(s->Hub, s, a->SrcUsername, src_username) == false) {
			return false;
		}
	}

	if (a->DestUsernameHash != 0) {
		if (a->IsDestUsernameIncludeOrExclude == false) {
			if ((a->DestUsernameHash != dest_username) && (a->DestUsernameHash != dest_groupname))
				return false;
		} else if (s->Hub != NULL && MatchIncludeExcludeUser(s->Hub, dest_session, a->DestUsername, dest_username) == false) {
			return false;
		}
	}

	bool is_ipv4_packet = (p->TypeL3 == L3_IPV4);
	bool is_ipv6_packet = (p->TypeL3 == L3_IPV6);
	bool is_arp_packet = (p->TypeL3 == L3_ARPV4);

	if (is_ipv4_packet)
		ip = p->L3.IPv4Header;

	if (is_ipv6_packet)
		ip6 = p->L3.IPv6Header;

	if (a->IsIPv6 == false) {

		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0) {
			if (is_ipv4_packet == false) {
				if (is_arp_packet == false || ArpAddrMatches(p, false, a->SrcIpAddress, a->SrcSubnetMask) == false)
					return false;
			} else {
				if ((ip->SrcIP & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
					return false;
			}
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0) {
			if (is_ipv4_packet == false) {
				if (is_arp_packet == false || ArpAddrMatches(p, true, a->DestIpAddress, a->DestSubnetMask) == false)
					return false;
			} else {
				if ((ip->DstIP & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
					return false;
			}
		}
	} else {

		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false ||
		    IsZeroIP6Addr(&a->SrcSubnetMask6) == false) {
			if (is_ipv6_packet == false) {
				return false;
			} else {
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->SrcIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->SrcSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->SrcAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
					return false;
			}
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false ||
		    IsZeroIP6Addr(&a->DestSubnetMask6) == false) {
			if (is_ipv6_packet == false) {
				return false;
			} else {
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->DestIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->DestSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->DestAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
					return false;
			}
		}
	}

	if (is_arp_packet && (s->Hub == NULL || s->Hub->Option->ApplyIPv4AccessListOnArpPacket == false))
		return false;

	if (a->Protocol != 0) {
		if (a->IsIPv6 == false) {
			if (is_ipv4_packet == false)
				return false;
			else if (ip->Protocol != a->Protocol)
				return false;
		} else {
			if (is_ipv6_packet == false)
				return false;
			else if (p->IPv6HeaderPacketInfo.Protocol != a->Protocol)
				return false;
		}
	}

	if (a->SrcPortStart != 0 || a->DestPortStart != 0 ||
	    a->SrcPortEnd != 0 || a->DestPortEnd != 0) {
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
		    (a->IsIPv6 && is_ipv6_packet == false)) {
			return false;
		} else {
			UINT src_port;
			UINT dest_port;

			if (p->TypeL4 == L4_TCP) {
				src_port = Endian16(p->L4.TCPHeader->SrcPort);
				dest_port = Endian16(p->L4.TCPHeader->DstPort);
			} else if (p->TypeL4 == L4_UDP) {
				src_port = Endian16(p->L4.UDPHeader->SrcPort);
				dest_port = Endian16(p->L4.UDPHeader->DstPort);
			} else {
				return false;
			}

			if (PortInRange(src_port, a->SrcPortStart, a->SrcPortEnd) == false ||
			    PortInRange(dest_port, a->DestPortStart, a->DestPortEnd) == false)
				return false;
		}
	}

	if (a->CheckTcpState != false) {
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
		    (a->IsIPv6 && is_ipv6_packet == false)) {
			return false;
		} else if (p->TypeL4 == L4_TCP) {
			TCP_HEADER *tcp = p->L4.TCPHeader;
			bool est = true;

			if ((tcp->Flag & TCP_SYN) && (!(tcp->Flag & TCP_ACK)))
				est = false;

			if ((INT_TO_BOOL(a->Established) ^ INT_TO_BOOL(est)))
				return false;
		} else {
			return false;
		}
	}

	return true;
}

static bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p) {
	bool pass = true;
	bool skip = true;
	if (hub == NULL || src_session == NULL || p == NULL || dest_session == NULL)
		return false;

	if (p->AccessChecked)
		return true;

	LockList(hub->AccessList);
	{
		for (UINT i = 0; i < LIST_NUM(hub->AccessList); i++) {
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
				skip = false;

			if (skip == false) {
				if (IsPacketMaskedByAccessList(src_session, p, a,
				                               ((HUB_PA *)dest_session->PacketAdapter->Param)->UsernameHash,
				                               ((HUB_PA *)dest_session->PacketAdapter->Param)->GroupnameHash,
				                               dest_session)) {
					pass = a->Discard ? false : true;

					break;
				}
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

// Percent-encode src into dst (RFC 3986): every byte but the unreserved A-Z a-z 0-9 - . _ ~ becomes %XX.
// Byte by byte, because the hash covers exactly the bytes sent and the names have no fixed code page
// (UrlEscapeW takes UTF-16). False when dst is too small
static bool HubUrlEncode(char *dst, UINT size, char *src) {
	static char hex[] = "0123456789ABCDEF";
	UINT len = StrLen(src);
	UINT n = 0;
	if (dst == NULL || size == 0)
		return false;

	for (UINT i = 0; i < len; i++) {
		UCHAR c = (UCHAR)src[i];

		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		    c == '-' || c == '.' || c == '_' || c == '~') {
			if (n + 1 >= size)
				return false;

			dst[n++] = (char)c;
		} else {
			if (n + 3 >= size)
				return false;

			dst[n++] = '%';
			dst[n++] = hex[c >> 4];
			dst[n++] = hex[c & 0x0F];
		}
	}

	dst[n] = 0;

	return true;
}

// Whether url can go into a Location header and an href as it is: not empty, no space, no control character
static bool IsRedirectUrlSafe(char *url) {
	UINT len = StrLen(url);

	if (len == 0)
		return false;

	for (UINT i = 0; i < len; i++) {
		UCHAR c = (UCHAR)url[i];

		if (c <= 0x20 || c == 0x7F)
			return false;
	}

	return true;
}

// HTTP 302 to redirect_url, the payload of a reply forged for session s. When the URL ends in |secret, its
// <INFO> tag becomes user|session|client IP|time|hash, the user and session names percent-encoded and the hash
// the SHA-1 of the text before it and the secret. NULL when a name does not fit or the URL would still hold a
// space or a control character (CR and LF would end the Location line)
static BUF *BuildRedirectToUrlPayload(SESSION *s, char *redirect_url) {
	char username[MAX_USERNAME_LEN * 3 + 1];
	char session_name[MAX_SESSION_NAME_LEN * 3 + 1];
	char info[sizeof(username) + sizeof(session_name) + MAX_SIZE];
	char redirect_url2[MAX_REDIRECT_URL_LEN + sizeof(info)];
	char html[sizeof(redirect_url2) + MAX_SIZE];
	char header[sizeof(redirect_url2) + MAX_SIZE];
	if (s == NULL || redirect_url == NULL)
		return NULL;

	StrCpy(redirect_url2, sizeof(redirect_url2), redirect_url);
	Trim(redirect_url2);

	if (InStr(redirect_url2, ACCESS_LIST_URL_INFO_TAG)) {
		char secret[MAX_SIZE];

		ClearStr(secret, sizeof(secret));

		// The secret follows the last '|'
		char *sep = strrchr(redirect_url2, '|');
		if (sep != NULL) {
			StrCpy(secret, sizeof(secret), sep + 1);
			*sep = 0;
		}

		// Without a secret the tag stays as it is
		if (IsEmptyStr(secret) == false) {
			UCHAR hash[SHA1_SIZE];
			char hash_str[MAX_SIZE];
			char client_ip[MAX_SIZE];
			SYSTEMTIME st;

			// The client chooses its user name: encoded, it cannot end the URL or a header line, nor add a '|' field
			if (HubUrlEncode(username, sizeof(username), s->Username) == false ||
			    HubUrlEncode(session_name, sizeof(session_name), s->Name) == false)
				return NULL;

			SystemTime(&st);
			IPToStr(client_ip, sizeof(client_ip), &s->Connection->ClientIp);

			Format(info, sizeof(info), "%s|%s|%s|%04u%02u%02u%02u%02u%02u|",
			       username, session_name, client_ip,
			       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

			BUF *b2 = NewBuf();
			WriteBuf(b2, info, StrLen(info));
			WriteBuf(b2, secret, StrLen(secret));

			Sha1(hash, b2->Buf, b2->Size);

			BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));

			FreeBuf(b2);

			StrCat(info, sizeof(info), hash_str);

			ReplaceStrEx(redirect_url2, sizeof(redirect_url2), redirect_url2,
			             ACCESS_LIST_URL_INFO_TAG, info, false);
		}
	}

	if (IsRedirectUrlSafe(redirect_url2) == false)
		return NULL;

	Format(html, sizeof(html),
	       "<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"%s\">here</a>.</h2>\r\n</body></html>\r\n\r\n",
	       redirect_url2);

	Format(header, sizeof(header),
	       "HTTP/1.1 302 Found\r\nLocation: %s\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %u\r\n\r\n",
	       redirect_url2, StrLen(html));

	BUF *b = NewBuf();

	WriteBuf(b, header, StrLen(header));
	WriteBuf(b, html, StrLen(html));

	return b;
}

static void ForceRedirectToUrl(SESSION *src_session, PKT *p, char *redirect_url) {
	if (src_session == NULL || p == NULL || redirect_url == NULL)
		return;
	if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6)
		return;
	if (p->TypeL4 != L4_TCP)
		return;

	TCP_HEADER *src_tcp = p->L4.TCPHeader;
	if (src_tcp == NULL)
		return;

	BUF *payload = BuildRedirectToUrlPayload(src_session, redirect_url);
	if (payload == NULL)
		return;

	// The reply goes back as a single frame
	UINT ip_header_size = (p->TypeL3 == L3_IPV4 ? sizeof(IPV4_HEADER) : sizeof(IPV6_HEADER));
	UINT tcp_size = sizeof(TCP_HEADER) + payload->Size;
	if (sizeof(MAC_HEADER) + ip_header_size + tcp_size > MAX_PACKET_SIZE) {
		FreeBuf(payload);
		return;
	}

	TCP_HEADER *tcp_data = (TCP_HEADER *)ZeroMalloc(tcp_size);
	tcp_data->SrcPort = src_tcp->DstPort;
	tcp_data->DstPort = src_tcp->SrcPort;
	tcp_data->SeqNumber = src_tcp->AckNumber;
	tcp_data->AckNumber = Endian32(Endian32(src_tcp->SeqNumber) + p->PayloadSize);
	TCP_SET_HEADER_SIZE(tcp_data, 5);
	tcp_data->Flag = TCP_ACK | TCP_PSH;
	tcp_data->WindowSize = Endian16(0xFFFF);
	Copy(((UCHAR *)tcp_data) + sizeof(TCP_HEADER), payload->Buf, payload->Size);

	if (p->TypeL3 == L3_IPV4)
		tcp_data->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->DstIP, p->L3.IPv4Header->SrcIP, IP_PROTO_TCP,
		                                         tcp_data, tcp_size, 0);
	else
		tcp_data->Checksum = CalcChecksumForIPv6(&p->IPv6HeaderPacketInfo.IPv6Header->DestAddress,
		                                         &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, IP_PROTO_TCP, tcp_data, tcp_size, 0);

	BUF *b = NewBuf();

	WriteBuf(b, p->MacHeader->SrcAddress, 6);
	WriteBuf(b, p->MacHeader->DestAddress, 6);
	WriteBuf(b, &p->MacHeader->Protocol, 2);

	if (p->TypeL3 == L3_IPV4) {
		IPV4_HEADER v4;

		Zero(&v4, sizeof(v4));

		IPV4_SET_VERSION(&v4, 4);
		IPV4_SET_HEADER_LEN(&v4, 5);
		v4.TotalLength = Endian16((USHORT)(sizeof(IPV4_HEADER) + tcp_size));
		v4.Identification = Endian16(Rand16());
		IPV4_SET_FLAGS(&v4, 0x02);
		v4.TimeToLive = 128;
		v4.Protocol = IP_PROTO_TCP;
		v4.SrcIP = p->L3.IPv4Header->DstIP;
		v4.DstIP = p->L3.IPv4Header->SrcIP;
		v4.Checksum = IpChecksum(&v4, sizeof(v4));

		WriteBuf(b, &v4, sizeof(v4));
	} else {
		IPV6_HEADER v6;

		Zero(&v6, sizeof(v6));

		IPV6_SET_VERSION(&v6, 6);
		v6.PayloadLength = Endian16((USHORT)tcp_size);
		v6.NextHeader = IP_PROTO_TCP;
		v6.HopLimit = 64;

		Copy(&v6.SrcAddress, &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress, sizeof(IPV6_ADDR));
		Copy(&v6.DestAddress, &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, sizeof(IPV6_ADDR));

		WriteBuf(b, &v6, sizeof(v6));
	}

	WriteBuf(b, tcp_data, tcp_size);

	StorePacketToHubPa((HUB_PA *)src_session->PacketAdapter->Param,
	                   NULL, b->Buf, b->Size, NULL, false);

	Free(tcp_data);
	FreeBuf(payload);
	Free(b);
}

// DHCPv4: UDP over IPv4 that the parser knows as DHCP
static bool IsDhcpv4(PKT *p) {
	return (p->TypeL3 == L3_IPV4 && p->TypeL4 == L4_UDP && p->TypeL7 == L7_DHCPV4);
}

// DHCPv6: UDP over IPv6 with a destination port of 546 or 547
static bool IsDhcpv6Port(PKT *p) {
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_UDP) {
		USHORT port = Endian16(p->L4.UDPHeader->DstPort);

		return (port == 546 || port == 547);
	}

	return false;
}

// EtherType of the MAC header is IPv4 or ARP (false without a MAC header)
static bool IsEtherTypeIPv4(PKT *p) {
	if (p->MacHeader != NULL) {
		USHORT proto = Endian16(p->MacHeader->Protocol);

		return (proto == 0x0800 || proto == 0x0806);
	}

	return false;
}

// EtherType of the MAC header is IPv6 (false without a MAC header)
static bool IsEtherTypeIPv6(PKT *p) {
	if (p->MacHeader != NULL)
		return (Endian16(p->MacHeader->Protocol) == 0x86dd);

	return false;
}

// EtherType of the MAC header is neither IPv4, ARP nor IPv6 (false without a MAC header)
static bool IsEtherTypeNonIP(PKT *p) {
	return (p->MacHeader != NULL && IsEtherTypeIPv4(p) == false && IsEtherTypeIPv6(p) == false);
}

static bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p) {
	bool pass = true;
	bool use_redirect_url = false;
	char redirect_url[MAX_REDIRECT_URL_LEN + 1];
	if (hub == NULL || s == NULL || p == NULL)
		return false;

	HUB_OPTION *opt = hub->Option;

	if (opt->FilterPPPoE) {
		if (p->MacHeader != NULL) {
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x8863 || proto == 0x8864)
				return false;
		}
	}

	if (opt->FilterOSPF) {
		if (p->TypeL3 == L3_IPV4) {
			if (p->L3.IPv4Header != NULL) {
				if (p->L3.IPv4Header->Protocol == 89)
					return false;
			}
		}
	}

	if (opt->FilterIPv4 && IsEtherTypeIPv4(p))
		return false;

	if (opt->FilterIPv6 && IsEtherTypeIPv6(p))
		return false;

	if (opt->FilterNonIP && IsEtherTypeNonIP(p))
		return false;

	if (opt->FilterBPDU) {
		if (p->MacHeader != NULL) {
			if (p->TypeL3 == L3_BPDU)
				return false;
		}
	}

	LockList(hub->AccessList);
	{
		for (UINT i = 0; i < LIST_NUM(hub->AccessList); i++) {
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
				break;

			if (IsPacketMaskedByAccessList(s, p, a, 0, 0, NULL)) {
				pass = a->Discard ? false : true;

				// Mark the packet so the access list skips it on the way out
				p->AccessChecked = true;

				p->Delay = a->Delay;
				p->Jitter = a->Jitter;
				p->Loss = a->Loss;

				if (a->RedirectUrl[0] != 0) {
					if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
					    p->TypeL4 == L4_TCP) {
						TCP_HEADER *tcp = p->L4.TCPHeader;

						if (tcp != NULL) {
							if (tcp->Flag & TCP_ACK) {
								if ((tcp->Flag & TCP_SYN) == 0 &&
								    (tcp->Flag & TCP_RST) == 0 &&
								    (tcp->Flag & TCP_URG) == 0) {
									if (p->PayloadSize != 0) {
										use_redirect_url = true;
										StrCpy(redirect_url, sizeof(redirect_url), a->RedirectUrl);
									}
								}
							}
						}
					}
				}

				break;
			}
		}
	}
	UnlockList(hub->AccessList);

	if (use_redirect_url) {
		if (s->NormalClient) {
			// Normal VPN clients get the URL redirect; local bridges only drop the packet
			ForceRedirectToUrl(s, p, redirect_url);
		}

		pass = false;
	}

	return pass;
}

static void InitAccessList(HUB *hub) {
	if (hub == NULL)
		return;

	hub->AccessList = NewList(CmpAccessList);
}

static void FreeAccessList(HUB *hub) {
	if (hub == NULL)
		return;

	for (UINT i = 0; i < LIST_NUM(hub->AccessList); i++) {
		ACCESS *a = LIST_DATA(hub->AccessList, i);
		Free(a);
	}

	ReleaseList(hub->AccessList);
	hub->AccessList = NULL;
}

void MakeSimpleUsernameRemoveNtDomain(char *dst, UINT dst_size, char *src) {
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	if (dst == NULL || src == NULL)
		return;

	ParseNtUsername(src, tmp1, sizeof(tmp1), tmp2, sizeof(tmp2), false);

	StrCpy(dst, dst_size, tmp1);
}

UINT64 UsernameToInt64(char *name) {
	UCHAR hash[SHA1_SIZE];
	UINT64 ret;
	char tmp[MAX_USERNAME_LEN + 1];
	if (name == 0 || IsEmptyStr(name))
		return 0;

	if (StartWith(name, ACCESS_LIST_INCLUDED_PREFIX) || StartWith(name, ACCESS_LIST_EXCLUDED_PREFIX))
		return Rand64();

	MakeSimpleUsernameRemoveNtDomain(tmp, sizeof(tmp), name);
	Trim(tmp);
	StrUpper(tmp);

	if (StrLen(tmp) == 0)
		return 0;

	Sha0(hash, tmp, StrLen(tmp));
	Copy(&ret, hash, sizeof(ret));

	return ret;
}

SESSION *GetSessionByName(HUB *hub, char *name) {
	if (hub == NULL || name == NULL)
		return NULL;

	LockList(hub->SessionList);
	{
		for (UINT i = 0; i < LIST_NUM(hub->SessionList); i++) {
			SESSION *s = LIST_DATA(hub->SessionList, i);
			if (StrCmpi(s->Name, name) == 0) {
				AddRef(s->ref);
				UnlockList(hub->SessionList);
				return s;
			}
		}
	}
	UnlockList(hub->SessionList);

	return NULL;
}

// Count the hub's sessions that count against the multi-login limit of username:
// not bridge, not cascade server side, at least one TCP connection, and a UniqueId
// that is zero or different from unique_id.
// Lock order: hub->lock, then SessionList, then s->lock, then the TcpSockList lock.
// The caller must not hold hub->lock (ServerAccept unlocks it around this call).
UINT HubCountUserSessions(HUB *h, char *username, UCHAR *unique_id) {
	UINT num = 0;
	if (h == NULL || username == NULL || unique_id == NULL)
		return 0;

	LockList(h->SessionList);
	{
		for (UINT i = 0; i < LIST_NUM(h->SessionList); i++) {
			SESSION *s = LIST_DATA(h->SessionList, i);
			Lock(s->lock);
			{
				UINT num_tcp;
				LockList(s->Connection->Tcp->TcpSockList);
				{
					num_tcp = s->Connection->Tcp->TcpSockList->num_item;
				}
				UnlockList(s->Connection->Tcp->TcpSockList);

				if (s->BridgeMode == false && s->LinkModeServer == false && num_tcp != 0 &&
				    StrCmpi(s->Username, username) == 0 &&
				    (IsZero(s->NodeInfo.UniqueId, 16) || Cmp(s->NodeInfo.UniqueId, unique_id, 16) != 0))
					num++;
			}
			Unlock(s->lock);
		}
	}
	UnlockList(h->SessionList);

	return num;
}

// SessionGetInfo of every session of the hub, in SessionList order, all taken under the SessionList lock.
// The caller frees the array with Free
SESSION_INFO *HubEnumSessions(HUB *h, UINT *num) {
	SESSION_INFO *ret;
	if (h == NULL || num == NULL)
		return NULL;

	LockList(h->SessionList);
	{
		*num = LIST_NUM(h->SessionList);
		ret = ZeroMalloc(sizeof(SESSION_INFO) * (*num));

		for (UINT i = 0; i < *num; i++)
			SessionGetInfo(LIST_DATA(h->SessionList, i), &ret[i]);
	}
	UnlockList(h->SessionList);

	return ret;
}

static void IpTableSetEntry(IP_TABLE_ENTRY *e, SESSION *s, IP *ip, UCHAR *mac, bool dhcp_allocated, UINT64 now) {
	e->CreatedTime = e->UpdatedTime = now;
	e->DhcpAllocated = dhcp_allocated;
	Copy(&e->Ip, ip, sizeof(IP));
	Copy(e->MacAddress, mac, 6);
	e->Session = s;
}

// The table is sorted by address, so the last entry has the highest one: the entry a full table evicts. O(1)
static void DeleteHighestIpTableEntry(LIST *o) {
	if (LIST_NUM(o) == 0)
		return;

	IP_TABLE_ENTRY *e = LIST_DATA(o, LIST_NUM(o) - 1);
	o->num_item--;
	Free(e);
}

// The one place that creates an IP table entry: drop the expired entries, evict the highest address when the
// table is full (MAX_IP_TABLES), then insert the new entry for ip. The expiry pass runs only when an entry can have
// expired (IpTableExpiryDue), not as a scan of the whole table on every new address. StorePacket frees the entries
// it takes out after the table lock
void IpTableAddEntry(HUB *h, SESSION *s, IP *ip, UCHAR *mac, bool dhcp_allocated, UINT64 now) {
	IP_TABLE_ENTRY *e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));

	IpTableSetEntry(e, s, ip, mac, dhcp_allocated, now);

	UINT64 tick = Tick64();
	if (IpTableExpiryDue(&h->IpTableExpiry, tick))
		DeleteExpiredIpTableEntry(h->IpTable, &h->IpTableExpiry, tick);

	if (LIST_NUM(h->IpTable) >= MAX_IP_TABLES)
		DeleteHighestIpTableEntry(h->IpTable);

	Insert(h->IpTable, e);
	IpTableExpiryNote(&h->IpTableExpiry, e);
}

// A frame of the session of IP table entry e refreshed it
static void IpTableTouch(HUB *h, IP_TABLE_ENTRY *e, UINT64 now) {
	e->UpdatedTime = now;
	IpTableExpiryNote(&h->IpTableExpiry, e);
}

// True when session s may not learn one more IPv6 (v6) or IPv4 address: it holds the cap of its policy
// (NoRouting / NoRoutingV6, MaxIP / MaxIPv6). Logs LH_IP_LIMIT or LH_ROUTING_LIMIT for ip then. no_cap lifts the
// cap (DHCPv6 and router discovery packets).
static bool IpTableSessionAtLimit(HUB *h, SESSION *s, IP *ip, bool v6, bool no_cap, bool no_heavy) {
	bool no_routing = v6 ? s->Policy->NoRoutingV6 : s->Policy->NoRouting;
	UINT max_ip = v6 ? s->Policy->MaxIPv6 : s->Policy->MaxIP;
	UINT limited_count = 0xffffffff;
	char tmp[64];

	if (no_routing == false && max_ip == 0)
		return false;

	UINT num_ip_for_me = CountSessionIps(h, s, v6);

	if (no_routing)
		limited_count = MIN(limited_count, v6 ? IP_LIMIT_WHEN_NO_ROUTING_V6 : IP_MIN_LIMIT_COUNT);
	if (max_ip != 0)
		limited_count = MIN(limited_count, max_ip);
	limited_count = MAX(limited_count, v6 ? IP_MIN_LIMIT_COUNT_V6 : IP_MIN_LIMIT_COUNT);

	if (no_cap)
		limited_count = 0xffffffff;

	if (num_ip_for_me < limited_count)
		return false;

	if (no_heavy == false) {
		IPToStr(tmp, sizeof(tmp), ip);
		HLog(h, no_routing ? "LH_ROUTING_LIMIT" : "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
	}

	return true;
}

// Broadcast storm guard: filter frequent broadcasts from a single endpoint
static bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p) {
	IP src_ip, dest_ip;
	UINT64 now = Tick64();
	SESSION *sess = s;
	bool ret = true;
	if (s == NULL || p == NULL || hub == NULL)
		return false;

	if (s->Policy->NoBroadcastLimiter)
		return true;

	bool strict = hub->Option->BroadcastLimiterStrictMode;
	bool no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;

	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	Zero(&src_ip, sizeof(IP));
	Zero(&dest_ip, sizeof(IP));

	if (p->TypeL3 == L3_IPV4) {
		UINTToIP(&src_ip, p->L3.IPv4Header->SrcIP);
		UINTToIP(&dest_ip, p->L3.IPv4Header->DstIP);
	} else if (p->TypeL3 == L3_ARPV4) {
		UINTToIP(&src_ip, p->L3.ARPv4Header->SrcIP);
		Zero(&dest_ip, sizeof(IP));
	} else if (p->TypeL3 == L3_IPV6) {
		IPv6AddrToIP(&src_ip, &p->L3.IPv6Header->SrcAddress);
		IPv6AddrToIP(&dest_ip, &p->L3.IPv6Header->DestAddress);
	}

	UINT limit_start_count = 32;

	if (hub->Option->BroadcastStormDetectionThreshold != 0)
		limit_start_count = hub->Option->BroadcastStormDetectionThreshold;

	LockList(pa->StormList);
	{
		UINT num;
		STORM *s = SearchStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		if (s == NULL)
			s = AddStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);

		s->CurrentBroadcastNum++;

		if ((s->CheckStartTick + STORM_CHECK_SPAN) < now ||
		    s->CheckStartTick == 0 || s->CheckStartTick > now) {
			UINT64 diff_time;
			if (s->CheckStartTick < now)
				diff_time = now - s->CheckStartTick;
			else
				diff_time = 0;
			s->CheckStartTick = now;
			num = (UINT)((UINT64)s->CurrentBroadcastNum * (UINT64)1000 / (UINT64)STORM_CHECK_SPAN);
			s->CurrentBroadcastNum = 0;
			if (num >= limit_start_count) {
				char ip1[64];
				char ip2[64];
				char mac[MAX_SIZE];
				IPToStr(ip1, sizeof(ip1), &src_ip);
				IPToStr(ip2, sizeof(ip2), &dest_ip);
				ret = false;
				if (s->DiscardValue < STORM_DISCARD_VALUE_END)
					s->DiscardValue = MAX(s->DiscardValue, 1) * 2;

				MacToStr(mac, sizeof(mac), p->MacAddressSrc);

				if (no_heavy == false)
					HLog(sess->Hub, "LH_BCAST_STORM", sess->Name, mac, ip1, ip2, num);
			} else {
				if (s->DiscardValue >= 1)
					s->DiscardValue = (UINT)((UINT64)s->DiscardValue / MAX((UINT64)2, (UINT64)diff_time / (UINT64)STORM_CHECK_SPAN));
			}
		}

		if (s->DiscardValue >= STORM_DISCARD_VALUE_START) {
			if (s->DiscardValue >= 128)
				ret = false;
			else if ((Rand32() % s->DiscardValue) != 0)
				ret = false;
		}
	}
	UnlockList(pa->StormList);

	return ret;
}

// D-Link switches send their spanning tree frames from these two source MACs (FixForDLinkBPDU)
static bool IsDLinkStpMac(UCHAR *mac) {
	static UCHAR dlink_mac_1[6] = {0x00, 0x80, 0xc8, 0x00, 0x00, 0x00};
	static UCHAR dlink_mac_2[6] = {0x00, 0x0d, 0x88, 0x00, 0x00, 0x00};

	return (Cmp(mac, dlink_mac_1, 6) == 0 || Cmp(mac, dlink_mac_2, 6) == 0);
}

// Security log line for a MAC address that session s now owns in the MAC table
static void HubLogMacRegist(HUB *hub, SESSION *s, UCHAR *mac, UINT vlan_id) {
	char mac_address[32];

	MacToStr(mac_address, sizeof(mac_address), mac);

	if (vlan_id == 0)
		HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
	else
		HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, vlan_id);
}

// Destination policy: true when the policy of the session a frame goes to drops it. The rule set of the
// unicast branch and of the flood loop of StorePacket (the source side is StorePacketFilterByPolicy)
static bool PolicyDropsPacket(POLICY *pol, PKT *p) {
	if (pol->RSandRAFilter) {
		if (p->TypeL3 == L3_IPV6 &&
		    p->TypeL4 == L4_ICMPV6 &&
		    (p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
		     p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
			return true;
	}

	if (pol->DHCPFilter) {
		if (IsDhcpv4(p))
			return true;
	}

	if (pol->DHCPv6Filter) {
		if (IsDhcpv6Port(p))
			return true;
	}

	if (pol->ArpDhcpOnly) {
		if (p->BroadcastPacket) {
			bool b = true;

			if (IsDhcpv4(p))
				b = false;
			else if (p->TypeL3 == L3_ARPV4)
				b = false;
			else if (IsDhcpv6Port(p))
				b = false;
			else if (p->TypeL3 == L3_IPV6 &&
			         p->TypeL4 == L4_ICMPV6)
				b = false;

			if (b)
				return true;
		}
	}

	if (pol->FilterIPv4) {
		if (p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_ARPV4)
			return true;
	}

	if (pol->FilterIPv6) {
		if (p->TypeL3 == L3_IPV6)
			return true;
	}

	if (pol->FilterNonIP) {
		if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_ARPV4 && p->TypeL3 != L3_IPV6)
			return true;
	}

	return false;
}

void StorePacket(HUB *hub, SESSION *s, PKT *packet) {
	MAC_TABLE_ENTRY *entry = NULL;
	UINT vlan_id;
	void *data;
	UINT size;
	bool broadcast_mode;
	HUB_PA *dest_pa;
	SESSION *dest_session;
	UINT64 now = Tick64();
	bool no_heavy = false;
	bool drop_broadcast_packet_privacy = false;
	bool drop_arp_packet_privacy = false;
	bool allow_same_user_packet_privacy = false;
	UINT tcp_queue_quota = 0;
	UINT64 dormant_interval = 0;
	IP_TABLE_ENTRY *expired = NULL;
	bool log_wait = false;
	if (hub == NULL || packet == NULL)
		return;

	if (s != NULL) {
		if (((HUB_PA *)s->PacketAdapter->Param)->MonitorPort) {
			Free(packet->PacketData);
			FreePacket(packet);
			return;
		}
	}

	no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	drop_broadcast_packet_privacy = hub->Option->DropBroadcastsInPrivacyFilterMode;
	drop_arp_packet_privacy = hub->Option->DropArpInPrivacyFilterMode;
	allow_same_user_packet_privacy = hub->Option->AllowSameUserInPrivacyFilterMode;
	tcp_queue_quota = hub->Option->FloodingSendQueueBufferQuota;
	if (hub->Option->DetectDormantSessionInterval != 0)
		dormant_interval = (UINT64)hub->Option->DetectDormantSessionInterval * (UINT64)1000;

	if (dormant_interval != 0) {
		if (s != NULL && s->NormalClient) {
			if (packet->MacAddressSrc != NULL) {
				if (IsHubMacAddress(packet->MacAddressSrc) == false)
					s->LastCommTimeForDormant = now;
			}
		}
	}

	HubLockTables(hub);
	{
		if (s != NULL && (packet->DelayedForwardTick == 0 && StorePacketFilter(s, packet) == false)) {
		DISCARD_PACKET:
			Free(packet->PacketData);
			FreePacket(packet);
		} else {
			bool forward_now = true;

			if (packet->Loss >= 1) {
				UINT r = Rand32() % 100;
				if ((packet->Loss >= 100) || (r < packet->Loss))
					goto DISCARD_PACKET;
			}

			if (packet->Delay >= 1) {
				// Jitter is a percentage of the delay, in whole ms: a span below 1 ms means no jitter, never a
				// modulo by zero (Delay 10 with Jitter 5 gave a span of 0)
				UINT jitter_span = (UINT)((UINT64)packet->Jitter * (UINT64)packet->Delay / 100);
				UINT jitter = 0;
				UINT delay_uint = packet->Delay;
				bool f = Rand1();
				if (jitter_span != 0)
					jitter = Rand32() % jitter_span;

				if (f)
					delay_uint += jitter;
				else
					delay_uint = (jitter < delay_uint ? delay_uint - jitter : 0);

				if (delay_uint >= 1) {
					forward_now = false;
					packet->Loss = packet->Jitter = packet->Delay = 0;
					packet->DelayedForwardTick = TickHighres64() + (UINT64)delay_uint;

					LockList(s->DelayedPacketList);
					{
						Add(s->DelayedPacketList, packet);
					}
					UnlockList(s->DelayedPacketList);
				}
			}

			if (forward_now) {
				if (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) == 0) {
					if (s != NULL) {
						// A packet from this hub's own session came back in from outside
						goto DISCARD_PACKET;
					}
				}
				// With a session, a frame from the hub's own MAC address is gone by now
				if (s != NULL) {
					if (hub->Option->NoManageVlanId == false)
						vlan_id = packet->VlanId;
					else
						vlan_id = 0;
					entry = MacTableLookup(hub, packet->MacAddressSrc, vlan_id);

					if (entry == NULL) {
						if (hub->LastFlushTick == 0 || (hub->LastFlushTick + (UINT64)OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL) < now) {
							hub->LastFlushTick = now;

							DeleteExpiredMacTableEntry(hub->MacHashTable);
						}

						if (s->Policy->MaxMac != 0 || s->Policy->NoBridge) {
							UINT num_mac_for_me = 0;
							UINT limited_count;
							MAC_TABLE_ENTRY **pp;
							UINT num_pp;

							pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num_pp);

							for (UINT i = 0; i < num_pp; i++) {
								MAC_TABLE_ENTRY *e = pp[i];
								if (e->Session == s)
									num_mac_for_me++;
							}

							Free(pp);

							limited_count = 0xffffffff;
							if (s->Policy->NoBridge)
								limited_count = MIN(limited_count, MAC_MIN_LIMIT_COUNT);
							if (s->Policy->MaxMac != 0)
								limited_count = MIN(limited_count, s->Policy->MaxMac);
							limited_count = MAX(limited_count, MAC_MIN_LIMIT_COUNT);

							if (num_mac_for_me >= limited_count) {
								char mac_str[64];

								MacToStr(mac_str, sizeof(mac_str), packet->MacAddressSrc);
								if (s->Policy->NoBridge) {
									if (no_heavy == false)
										HLog(hub, "LH_BRIDGE_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
								} else {
									if (no_heavy == false)
										HLog(hub, "LH_MAC_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
								}

								goto DISCARD_PACKET;
							}
						}

						entry = MacTableLearn(hub, s, packet->MacAddressSrc, vlan_id, now);
						if (entry == NULL)
							goto DISCARD_PACKET;

						if (hub->Option->NoMacAddressLog == false && no_heavy == false)
							HubLogMacRegist(hub, s, packet->MacAddressSrc, packet->VlanId);
					} else if (entry->Session == s) {
						entry->UpdatedTime = now;
					} else {
						bool check_mac = s->Policy->CheckMac;

						if (check_mac == false) {
							if (s->BridgeMode) {
								check_mac = true;

								if (hub->Option->DisableCheckMacOnLocalBridge)
									check_mac = false;
							}
						}

						if (check_mac && ((entry->UpdatedTime + MAC_TABLE_EXCLUSIVE_TIME) >= now)) {
							if (hub->Option->FixForDLinkBPDU && IsDLinkStpMac(packet->MacAddressSrc)) {
								// D-Link sends spanning tree packets from these addresses. CheckMac on a local
								// bridge would break them, so they are handled separately.
								UCHAR hash[MD5_SIZE];
								UINT64 tick_diff = Tick64() - s->LastDLinkSTPPacketSendTick;

								Md5(hash, packet->PacketData, packet->PacketSize);

								if ((s->LastDLinkSTPPacketSendTick != 0) &&
								    (tick_diff < 750ULL) &&
								    (Cmp(hash, s->LastDLinkSTPPacketDataHash, MD5_SIZE) == 0)) {
									// Drop a repeat of the same packet within 750 ms
									goto DISCARD_PACKET;
								} else {
									goto UPDATE_FDB;
								}
							}

							goto DISCARD_PACKET;
						} else {
						UPDATE_FDB:
							entry->Session = s;
							entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
							entry->UpdatedTime = entry->CreatedTime = now;

							if (no_heavy == false)
								HubLogMacRegist(hub, s, packet->MacHeader->SrcAddress, packet->VlanId);
						}
					}
				}

				broadcast_mode = false;
				dest_pa = NULL;
				dest_session = NULL;

				if (packet->BroadcastPacket) {
					broadcast_mode = true;
				} else {
					if (hub->Option->NoManageVlanId == false)
						vlan_id = packet->VlanId;
					else
						vlan_id = 0;
					entry = MacTableLookup(hub, packet->MacAddressDest, vlan_id);

					if (entry == NULL) {
						broadcast_mode = true;
					} else if (entry->Session != s) {
						dest_pa = entry->HubPa;
						dest_session = entry->Session;
					} else {
						goto DISCARD_PACKET;
					}
				}

				if (s != NULL && hub->Option->NoIpTable == false) {
					if (packet->TypeL3 == L3_IPV6) {
						IP ip;
						bool b = true;
						UINT ip_type;
						bool dhcp_or_ra = false;

						IPv6AddrToIP(&ip, &packet->L3.IPv6Header->SrcAddress);
						ip_type = GetIPv6AddrType(&packet->L3.IPv6Header->SrcAddress);

						if (!(ip_type & IPV6_ADDR_UNICAST))
							b = false;
						else if ((ip_type & IPV6_ADDR_LOOPBACK) || (ip_type & IPV6_ADDR_ZERO))
							b = false;

						if (packet->TypeL4 == L4_ICMPV6) {
							if (packet->ICMPv6HeaderPacketInfo.Type == 133 ||
							    packet->ICMPv6HeaderPacketInfo.Type == 134)
								dhcp_or_ra = true;
						} else if (IsDhcpv6Port(packet)) {
							dhcp_or_ra = true;
						}

						if (IsHubMacAddress(packet->MacAddressSrc) &&
						    IsHubIpAddress64(&packet->L3.IPv6Header->SrcAddress))
							b = false;

						if (b) {
							IP_TABLE_ENTRY *e = IpTableLookup(hub, &ip);

							if (e == NULL) {
								if (IpTableSessionAtLimit(hub, s, &ip, true, dhcp_or_ra, no_heavy))
									goto DISCARD_PACKET;

								if (IsIPManagementTargetForHUB(&ip, hub))
									IpTableAddEntry(hub, s, &ip, packet->MacAddressSrc, false, now);
							} else if (e->Session == s) {
								IpTableTouch(hub, e, now);
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							} else if ((s->Policy->CheckIPv6) &&
							           ((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now)) {
								if (no_heavy == false)
									LogIpConflict(hub, s, &ip, e, now);

								goto DISCARD_PACKET;
							}
						}
					}
				}

				if (
				    (s != NULL) &&
				    (hub->Option->NoIpTable == false) &&
				    ((packet->TypeL3 == L3_IPV4 ||
				      (packet->TypeL3 == L3_ARPV4 && packet->L3.ARPv4Header->HardwareSize == 6 &&
				       Endian16(packet->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
				       packet->L3.ARPv4Header->ProtocolSize == 4 &&
				       Endian16(packet->L3.ARPv4Header->ProtocolType) == 0x0800)) &&
				     (packet->TypeL7 != L7_DHCPV4))) {
					IP_TABLE_ENTRY *e;
					IP ip;
					UINT uint_ip = 0;

					if (packet->TypeL3 == L3_IPV4)
						uint_ip = packet->L3.IPv4Header->SrcIP;
					else if (packet->TypeL3 == L3_ARPV4)
						uint_ip = packet->L3.ARPv4Header->SrcIP;

					if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(packet->MacAddressSrc))) {
						UINTToIP(&ip, uint_ip);

						e = IpTableLookup(hub, &ip);

						if (e == NULL) {
							if (s->Policy->DHCPForce) {
								char ipstr[MAX_SIZE];

								IPToStr32(ipstr, sizeof(ipstr), uint_ip);
								if (no_heavy == false)
									HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
								goto DISCARD_PACKET;
							}

							if (IpTableSessionAtLimit(hub, s, &ip, false, false, no_heavy))
								goto DISCARD_PACKET;

							if (IsIPManagementTargetForHUB(&ip, hub))
								IpTableAddEntry(hub, s, &ip, packet->MacAddressSrc, false, now);
						} else if (e->Session == s) {
							IpTableTouch(hub, e, now);
							Copy(e->MacAddress, packet->MacAddressSrc, 6);
						} else {
							if ((s->Policy->CheckIP || s->Policy->DHCPForce) &&
							    ((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now)) {
								if (no_heavy == false)
									LogIpConflict(hub, s, &ip, e, now);

								goto DISCARD_PACKET;
							}

							if (s->Policy->DHCPForce) {
								if (e->DhcpAllocated == false) {
									char ipstr[MAX_SIZE];

									IPToStr32(ipstr, sizeof(ipstr), uint_ip);
									if (no_heavy == false)
										HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
									goto DISCARD_PACKET;
								}
							}

							e->Session = s;
							IpTableTouch(hub, e, now);
							Copy(e->MacAddress, packet->MacAddressSrc, 6);
						}
					}
				}

				if (s != NULL && broadcast_mode) {
					if (CheckBroadcastStorm(hub, s, packet) == false)
						goto DISCARD_PACKET;
				}

				if (hub->MonitorList->num_item != 0) {
					LockList(hub->MonitorList);
					{
						void *data;
						UINT size = packet->PacketSize;
						for (UINT i = 0; i < LIST_NUM(hub->MonitorList); i++) {
							SESSION *monitor_session = (SESSION *)LIST_DATA(hub->MonitorList, i);

							if (monitor_session->PacketAdapter->Param != NULL) {
								data = Malloc(size);
								Copy(data, packet->PacketData, size);
								StorePacketToHubPa((HUB_PA *)monitor_session->PacketAdapter->Param,
								                   s, data, size, packet, false);
							}
						}
					}
					UnlockList(hub->MonitorList);
				}

				if (broadcast_mode == false) {
					if (dest_pa != NULL) {
						if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
						    (dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
						    (hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
							DeleteIPv6DefaultRouterInRA(packet);
						if (PolicyDropsPacket(dest_session->Policy, packet))
							goto DISCARD_UNICAST_PACKET;

						if (s != NULL &&
						    ((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
						     s->Policy->PrivacyFilter &&
						     dest_session->Policy->PrivacyFilter)) {
							if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4) {
								if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
									goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL) {
							if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
							    Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
								goto DISCARD_UNICAST_PACKET;
						}

						if (s != NULL) {
							if (PacketLog(s->Hub, s, dest_session, packet, now, &log_wait) == false)
								goto DISCARD_UNICAST_PACKET;
						}

						StorePacketToHubPa(dest_pa, s, packet->PacketData, packet->PacketSize, packet, false);
					} else {
					DISCARD_UNICAST_PACKET:
						Free(packet->PacketData);
					}
				} else {
					UINT current_tcp_queue_size = 0;

					if (s != NULL) {
						if (PacketLog(s->Hub, s, NULL, packet, now, &log_wait) == false)
							goto DISCARD_BROADCAST_PACKET;
					}

					LockList(hub->SessionList);
					{
						UINT num = LIST_NUM(hub->SessionList);
						for (UINT i = 0; i < num; i++) {
							SESSION *dest_session = LIST_DATA(hub->SessionList, i);
							HUB_PA *dest_pa = (HUB_PA *)dest_session->PacketAdapter->Param;
							bool discard = false;

							if (dest_session != s) {
								bool delete_default_router_in_ra = false;

								if (dest_session->IsMonitorMode)
									discard = true;

								if (dest_session->NormalClient) {
									if (dormant_interval != 0) {
										if (dest_session->LastCommTimeForDormant == 0 ||
										    (dest_session->LastCommTimeForDormant + dormant_interval) < now)
											discard = true;
									}
								}

								if (tcp_queue_quota != 0) {
									current_tcp_queue_size = CedarGetCurrentTcpQueueSize(hub->Cedar);

									if (current_tcp_queue_size >= tcp_queue_quota) {
										// A Tunnel of the new core is a client's network connection, as a TCP one is
										if (dest_session->Connection != NULL &&
										    (dest_session->Connection->Protocol == CONNECTION_TCP || dest_session->Connection->Protocol == CONNECTION_NOISE))
											discard = true;

										if (dest_session->LinkModeServer)
											discard = true;
									}
								}

								if (dest_session->VLanId != 0 && packet->TypeL3 == L3_TAGVLAN &&
								    packet->VlanId != dest_session->VLanId)
									discard = true;

								if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
								    (dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
								    (hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session)) {
									if (packet->TypeL3 == L3_IPV6 && packet->TypeL4 == L4_ICMPV6 &&
									    (packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)) {
										if (packet->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
											delete_default_router_in_ra = true;
									}
								}
								if (PolicyDropsPacket(dest_session->Policy, packet))
									discard = true;

								if (s != NULL &&
								    ((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
								     s->Policy->PrivacyFilter &&
								     dest_session->Policy->PrivacyFilter)) {
									if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4) {
										if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
											discard = true;
									}
								}

								if (s != NULL) {
									if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
									    Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
										discard = true;
								}

								if (discard == false && dest_pa != NULL) {
									if (s == NULL ||
									    ApplyAccessListToForwardPacket(s->Hub, s, dest_pa->Session, packet)) {
										data = Malloc(packet->PacketSize);
										Copy(data, packet->PacketData, packet->PacketSize);
										size = packet->PacketSize;

										if (delete_default_router_in_ra) {
											PKT *pkt2 = ParsePacket(data, size);

											DeleteIPv6DefaultRouterInRA(pkt2);

											FreePacket(pkt2);
										}

										StorePacketToHubPa(dest_pa, s, data, size, packet, true);
									}
								}
							}
						}
					}
					UnlockList(hub->SessionList);

				DISCARD_BROADCAST_PACKET:
					Free(packet->PacketData);
				}
				FreePacket(packet);
			}
		}

		// The entries that the IP table expiry took out are freed after the lock
		expired = hub->IpTableExpiry.Expired;
		hub->IpTableExpiry.Expired = NULL;
	}
	HubUnlockTables(hub);

	FreeIpTableEntries(expired);

	// The packet log back-pressure of the source session waits here, after the lock, so the other sessions of the
	// hub forward in the meantime. The server side of a cascade still holds its received-blocks queue lock, as it
	// did for the wait under the hub lock (that lock comes before MacHashTable in the lock order)
	if (log_wait)
		PacketLogWait(s);
}


void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool from_flood) {
	if (dest == NULL || data == NULL)
		return;

	if (size < 14) {
		Free(data);
		return;
	}

	// Flooded frames passed the access list once already
	if (from_flood == false) {
		if (src != NULL) {
			if (ApplyAccessListToForwardPacket(src->Hub, src, dest->Session, packet) == false) {
				Free(data);
				return;
			}
		}
	}

	if (src != NULL) {
		if (dest->Session->Policy->MaxDownload != 0) {
			if (packet != NULL && IsMostHighestPriorityPacket(dest->Session, packet) == false) {
				TRAFFIC_LIMITER *tr = &dest->DownloadLimiter;
				IntoTrafficLimiter(tr, packet);

				if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > dest->Session->Policy->MaxDownload) {
					Free(data);
					return;
				}
			}
		}
	}

	if (packet != NULL && src != NULL && src->Hub != NULL && src->Hub->Option->FixForDLinkBPDU) {
		// Workaround for D-Link BPDUs sent from these source MACs
		if (IsDLinkStpMac(packet->MacAddressSrc)) {
			SESSION *session = dest->Session;

			if (session != NULL) {
				if (session->Policy != NULL && session->Policy->CheckMac) {
					UCHAR hash[MD5_SIZE];
					Md5(hash, packet->PacketData, packet->PacketSize);

					Copy(session->LastDLinkSTPPacketDataHash, hash, MD5_SIZE);
					session->LastDLinkSTPPacketSendTick = Tick64();
				}
			}
		}
	}

	if (dest->Session != NULL && dest->Session->VLanId != 0) {
		UINT vlan_tpid = 0;
		if (src != NULL && src->Hub != NULL)
			vlan_tpid = src->Hub->Option->VlanTypeId;
		if (VLanRemoveTag(&data, &size, dest->Session->VLanId, vlan_tpid) == false) {
			Free(data);
			return;
		}
	}

	if (src != NULL && dest->Session != NULL && src->Hub != NULL) {
		if (dest->Session->AdjustMss != 0 ||
		    (dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0)) {
			if (src->Hub->Option->DisableAdjustTcpMss == false) {
				UINT target_mss = INFINITE;

				if (dest->Session->AdjustMss != 0)
					target_mss = MIN(target_mss, dest->Session->AdjustMss);

				if (dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0)
					target_mss = MIN(target_mss, dest->Session->UdpAccelMss);

				if (target_mss != INFINITE)
					AdjustTcpMssL2(data, size, target_mss, src->Hub->Option->VlanTypeId);
			}
		}
	}

	BLOCK *b = NewBlock(data, size, 0);

	LockQueue(dest->PacketQueue);
	{
		if (dest->PacketQueue->num_item < MAX_STORED_QUEUE_NUM) {
			InsertQueue(dest->PacketQueue, b);

			if (from_flood) {
				if (src != NULL) {
					b->IsFlooding = true;
					CedarAddCurrentTcpQueueSize(src->Cedar, b->Size);
				}
			}
		} else {
			FreeBlock(b);
		}
	}
	UnlockQueue(dest->PacketQueue);

	if (src != NULL)
		AddCancelList(src->CancelList, dest->Cancel);
	else
		Cancel(dest->Cancel);
}

static bool StorePacketFilterByPolicy(SESSION *s, PKT *p) {
	bool no_heavy = false;
	if (s == NULL || p == NULL)
		return false;

	HUB *hub = s->Hub;

	if (hub != NULL)
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;

	POLICY *pol = s->Policy;

	if (pol->NoServer) {
		if (p->TypeL3 == L3_IPV4) {
			if (p->TypeL4 == L4_TCP) {
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK)) {
					char ip1[64], ip2[64];

					IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
					IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

					if (no_heavy == false)
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, Endian16(p->L4.TCPHeader->DstPort),
						     ip1, Endian16(p->L4.TCPHeader->SrcPort));

					return false;
				}
			}
		}
	}

	if (pol->NoServerV6) {
		if (p->TypeL3 == L3_IPV6) {
			if (p->TypeL4 == L4_TCP) {
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK)) {
					char ip1[128], ip2[128];

					IP6AddrToStr(ip1, sizeof(ip1), &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
					IP6AddrToStr(ip2, sizeof(ip2), &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

					if (no_heavy == false)
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, Endian16(p->L4.TCPHeader->DstPort),
						     ip1, Endian16(p->L4.TCPHeader->SrcPort));

					return false;
				}
			}
		}
	}

	if (pol->ArpDhcpOnly && p->BroadcastPacket) {
		bool ok = false;

		if (p->TypeL3 == L3_ARPV4)
			ok = true;
		if (IsDhcpv4(p))
			ok = true;
		if (p->TypeL3 == L3_IPV6) {
			if (p->TypeL4 == L4_ICMPV6)
				ok = true;
		}

		if (IsDhcpv6Port(p))
			ok = true;

		if (ok == false)
			return false;
	}

	if (pol->FilterIPv4) {
		if (IsEtherTypeIPv4(p))
			return false;
	}

	if (pol->FilterIPv6) {
		if (IsEtherTypeIPv6(p))
			return false;
	}

	if (pol->FilterNonIP) {
		if (IsEtherTypeNonIP(p))
			return false;
	}

	if (pol->DHCPFilter) {
		if (IsDhcpv4(p))
			return false;
	}

	if (pol->DHCPv6Filter) {
		if (IsDhcpv6Port(p))
			return false;
	}

	if (pol->DHCPNoServer) {
		if (IsDhcpv4(p)) {
			DHCPV4_HEADER *h = p->L7.DHCPv4Header;
			if (h->OpCode == 2) {
				char ip1[64], ip2[64];

				IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
				IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

				if (no_heavy == false)
					HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);

				return false;
			}
		}
	}

	if (pol->DHCPv6NoServer) {
		if (p->TypeL3 == L3_IPV6 &&
		    p->TypeL4 == L4_UDP &&
		    (Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->SrcPort) == 547)) {
			char ip1[128], ip2[128];

			IP6AddrToStr(ip1, sizeof(ip1), &p->L3.IPv6Header->SrcAddress);
			IP6AddrToStr(ip2, sizeof(ip2), &p->L3.IPv6Header->DestAddress);

			if (no_heavy == false)
				HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);

			return false;
		}
	}

	if (pol->RSandRAFilter) {
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		    (p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
		     p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
			return false;
	}

	if (pol->RAFilter) {
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		    p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
			return false;
	}

	if (IsDhcpv4(p) &&
	    (s->Hub != NULL && s->Hub->Option->NoIpTable == false)) {
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		if (h->OpCode == 2 && p->DhcpOpCode == DHCP_ACK) {
			if (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET) {
				if (h->HardwareAddressSize == 6) {
					if (h->YourIP != 0 && h->YourIP != 0xffffffff) {
						UINT ip_uint = h->YourIP;
						IP ip;
						IP_TABLE_ENTRY *e;
						MAC_TABLE_ENTRY *mac_table = MacTableLookup(hub, h->ClientMacAddress, 0);

						if (mac_table != NULL) {
							UINTToIP(&ip, ip_uint);

							e = IpTableLookup(hub, &ip);
							if (e != NULL) {
								// A lease the table holds already: the ACK gives it to this client again
								IpTableSetEntry(e, mac_table->Session, &ip, p->MacAddressDest, true, Tick64());
								IpTableExpiryNote(&hub->IpTableExpiry, e);
							} else {
								IpTableAddEntry(hub, mac_table->Session, &ip, p->MacAddressDest, true, Tick64());

								if ((hub->Option->NoDhcpPacketLogOutsideHub == false) || mac_table->Session != s) {
									char dhcp_mac_addr[64];
									char dest_mac_addr[64];
									char dest_ip_addr[64];
									char server_ip_addr[64];
									MacToStr(dhcp_mac_addr, sizeof(dhcp_mac_addr), p->MacAddressSrc);
									MacToStr(dest_mac_addr, sizeof(dest_mac_addr), h->ClientMacAddress);
									IPToStr(dest_ip_addr, sizeof(dest_ip_addr), &ip);
									IPToStr32(server_ip_addr, sizeof(server_ip_addr), p->L3.IPv4Header->SrcIP);

									if (no_heavy == false)
										HLog(s->Hub, "LH_REGIST_DHCP", s->Name, dhcp_mac_addr, server_ip_addr,
										     mac_table->Session->Name, dest_mac_addr, dest_ip_addr);
								}
							}
						}
					}
				}
			}
		}
	}

	return true;
}

bool IsMostHighestPriorityPacket(SESSION *s, PKT *p) {
	if (s == NULL || p == NULL)
		return false;

	if (p->TypeL3 == L3_ARPV4)
		return true;

	if (p->TypeL3 == L3_IPV4) {
		if (p->TypeL4 == L4_ICMPV4)
			return true;

		if (p->TypeL4 == L4_TCP) {
			if ((p->L4.TCPHeader->Flag & TCP_SYN) || (p->L4.TCPHeader->Flag & TCP_FIN) || (p->L4.TCPHeader->Flag & TCP_RST))
				return true;
		}

		if (IsDhcpv4(p))
			return true;
	}

	return false;
}

static bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p) {
	if (s == NULL || p == NULL)
		return false;

	if (s->Policy->MaxUpload == 0)
		return true;

	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	TRAFFIC_LIMITER *tr = &pa->UploadLimiter;

	if (IsMostHighestPriorityPacket(s, p))
		return true;

	IntoTrafficLimiter(tr, p);

	if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > s->Policy->MaxUpload)
		return false;

	return true;
}

bool StorePacketFilter(SESSION *s, PKT *packet) {
	if (s == NULL || packet == NULL)
		return false;

	if (StorePacketFilterByTrafficLimiter(s, packet) == false)
		return false;

	if (StorePacketFilterByPolicy(s, packet) == false)
		return false;

	if (ApplyAccessListToStoredPacket(s->Hub, s, packet) == false)
		return false;

	return true;
}

static void StopAllSession(HUB *h) {
	SESSION **s;
	UINT num;
	if (h == NULL)
		return;

	LockList(h->SessionList);
	{
		num = LIST_NUM(h->SessionList);
		s = ToArray(h->SessionList);
		DeleteAll(h->SessionList);
	}
	UnlockList(h->SessionList);

	// Signal every session first so they all shut down in parallel, then wait for each one.
	for (UINT i = 0; i < num; i++)
		StopSessionEx(s[i], true);

	for (UINT i = 0; i < num; i++) {
		StopSession(s[i]);
		ReleaseSession(s[i]);
	}

	Free(s);
}

void DelSession(HUB *h, SESSION *s) {
	if (h == NULL || s == NULL)
		return;

	LockList(h->SessionList);
	{
		if (Delete(h->SessionList, s))
			ReleaseSession(s);
	}
	UnlockList(h->SessionList);
}

void AddSession(HUB *h, SESSION *s) {
	if (h == NULL || s == NULL)
		return;

	LockList(h->SessionList);
	{
		Insert(h->SessionList, s);
		AddRef(s->ref);
	}
	UnlockList(h->SessionList);
}

void StopHub(HUB *h) {
	bool old_status = false;
	if (h == NULL)
		return;

	old_status = h->Offline;
	h->HubIsOnlineButHalting = true;

	SetHubOffline(h);

	if (h->Halt == false) {
		SLog(h->Cedar, "LS_HUB_STOP", h->Name);
		h->Halt = true;
	}

	h->Offline = old_status;
	h->HubIsOnlineButHalting = false;
}

void SetHubOnline(HUB *h) {
	if (h == NULL)
		return;

	Lock(h->lock_online);
	{
		if (h->Offline == false) {
			Unlock(h->lock_online);
			return;
		}
		HLog(h, "LH_ONLINE");

		// The cascades of the hub (Link.c), through the hooks of the SE-VPN code
		if (SeVpnHooks.StartAllLink != NULL)
			SeVpnHooks.StartAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			for (UINT i = 0; i < LIST_NUM(h->Cedar->LocalBridgeList); i++) {
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0) {
					if (br->Bridge == NULL)
						br->Bridge = BrNewBridge(h, br);
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = false;
	}
	Unlock(h->lock_online);
}

void SetHubOffline(HUB *h) {
	if (h == NULL)
		return;

	Lock(h->lock_online);
	{
		if (h->Offline || h->Halt) {
			Unlock(h->lock_online);
			return;
		}

		HLog(h, "LH_OFFLINE");

		if (SeVpnHooks.StopAllLink != NULL)
			SeVpnHooks.StopAllLink(h);

		LockList(h->Cedar->LocalBridgeList);
		{
			for (UINT i = 0; i < LIST_NUM(h->Cedar->LocalBridgeList); i++) {
				LOCALBRIDGE *br = LIST_DATA(h->Cedar->LocalBridgeList, i);

				if (StrCmpi(br->HubName, h->Name) == 0) {
					BrFreeBridge(br->Bridge);
					br->Bridge = NULL;
				}
			}
		}
		UnlockList(h->Cedar->LocalBridgeList);

		h->Offline = true;

		StopAllSession(h);
	}
	Unlock(h->lock_online);
}

// Bring a freshly created hub into its configured state. A new hub is neither online nor offline yet, so the flag
// is set opposite to the wanted state first, which lets the setter do the whole transition
void HubApplyInitialState(HUB *h, bool online) {
	if (h == NULL)
		return;

	h->Offline = online;

	if (online)
		SetHubOnline(h);
	else
		SetHubOffline(h);
}

bool IsHub(CEDAR *cedar, char *name) {
	if (cedar == NULL || name == NULL)
		return false;

	HUB *h = GetHub(cedar, name);
	if (h == NULL)
		return false;

	ReleaseHub(h);

	return true;
}

HUB *GetHub(CEDAR *cedar, char *name) {
	HUB t;
	if (cedar == NULL || name == NULL)
		return NULL;

	LockHubList(cedar);

	t.Name = name;
	HUB *h = Search(cedar->HubList, &t);
	if (h == NULL) {
		UnlockHubList(cedar);
		return NULL;
	}

	AddRef(h->ref);

	UnlockHubList(cedar);

	return h;
}

void LockHubList(CEDAR *cedar) {
	if (cedar == NULL)
		return;

	LockList(cedar->HubList);
}

void UnlockHubList(CEDAR *cedar) {
	if (cedar == NULL)
		return;

	UnlockList(cedar->HubList);
}

void ReleaseHub(HUB *h) {
	if (h == NULL)
		return;

	if (Release(h->ref) == 0)
		CleanupHub(h);
}

void CleanupHub(HUB *h) {
	char name[MAX_SIZE];
	if (h == NULL)
		return;

	StrCpy(name, sizeof(name), h->Name);

	if (h->WatchDogStarted)
		StopHubWatchDog(h);

	FreeAccessList(h);

	if (SeVpnHooks.ReleaseAllLink != NULL)
		SeVpnHooks.ReleaseAllLink(h);
	DeleteHubDb(h->HubDb);
	ReleaseCedar(h->Cedar);
	DeleteLock(h->lock);
	DeleteLock(h->lock_online);
	Free(h->Name);
	ReleaseList(h->SessionList);
	ReleaseHashList(h->MacHashTable);
	FreeIpTableEntries(h->IpTableExpiry.Expired);
	ReleaseList(h->IpTable);
	ReleaseList(h->MonitorList);
	ReleaseList(h->LinkList);
	DeleteCounter(h->NumSessions);
	DeleteCounter(h->NumSessionsClient);
	DeleteCounter(h->NumSessionsBridge);
	DeleteCounter(h->SessionCounter);
	FreeTraffic(h->Traffic);
	Free(h->Option);

	DeleteLock(h->TrafficLock);

	FreeLog(h->PacketLogger);
	FreeLog(h->SecurityLogger);

	DeleteAllHubAdminOption(h);
	ReleaseList(h->AdminOptionList);

	if (h->Msg != NULL)
		Free(h->Msg);

	FreeUserList(h->UserList);

	Free(h);
}

static UINT GetHashOfMacTable(void *p) {
	MAC_TABLE_ENTRY *e = p;

	if (e == NULL)
		return 0;

	UINT v = e->MacAddress[0] + e->MacAddress[1] + e->MacAddress[2] +
	         e->MacAddress[3] + e->MacAddress[4] + e->MacAddress[5] +
	         e->VlanId;

	return v;
}

static int CompareMacTable(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	MAC_TABLE_ENTRY *e1 = *(MAC_TABLE_ENTRY **)p1;
	MAC_TABLE_ENTRY *e2 = *(MAC_TABLE_ENTRY **)p2;
	if (e1 == NULL || e2 == NULL)
		return 0;
	int r = Cmp(e1->MacAddress, e2->MacAddress, 6);
	if (r != 0)
		return r;
	if (e1->VlanId > e2->VlanId)
		return 1;
	else if (e1->VlanId < e2->VlanId)
		return -1;
	return 0;
}

int CompareHub(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	HUB *h1 = *(HUB **)p1;
	HUB *h2 = *(HUB **)p2;
	if (h1 == NULL || h2 == NULL)
		return 0;
	return StrCmpi(h1->Name, h2->Name);
}

bool IsHubMacAddress(UCHAR *mac) {
	if (mac == NULL)
		return false;

	if (mac[0] == 0x00 && mac[1] == SE_HUB_MAC_ADDR_SIGN)
		return true;

	return false;
}

bool IsHubIpAddress32(UINT ip32) {
	IP ip;

	UINTToIP(&ip, ip32);

	return IsHubIpAddress(&ip);
}
bool IsHubIpAddress(IP *ip) {
	if (ip == NULL)
		return false;

	const BYTE *ipv4 = IPV4(ip->address);

	if (ipv4[0] == 172 && ipv4[1] == 31) {
		if (ipv4[2] >= 1 && ipv4[2] <= 254) {
			if (ipv4[3] >= 1 && ipv4[3] <= 254)
				return true;
		}
	}

	return false;
}
bool IsHubIpAddress64(IPV6_ADDR *addr) {
	if (addr == NULL)
		return false;

	if (addr->Value[0] == 0xfe && addr->Value[1] == 0x80 &&
	    addr->Value[2] == 0 &&
	    addr->Value[3] == 0 &&
	    addr->Value[4] == 0 &&
	    addr->Value[5] == 0 &&
	    addr->Value[6] == 0 &&
	    addr->Value[7] == 0 &&
	    addr->Value[8] == 0x02 && addr->Value[9] == 0xae &&
	    addr->Value[11] == 0xff && addr->Value[12] == 0xfe)
		return true;

	return false;
}

// Hash of the machine-unique hash and the trimmed, upper-cased hub name;
// the hub MAC and IP addresses both derive from it
static void HubNameHash(UCHAR *hash, UCHAR *machine_hash, char *name) {
	char tmp1[MAX_SIZE];
	char tmp2[MAX_SIZE];
	if (hash == NULL || machine_hash == NULL || name == NULL)
		return;

	StrCpy(tmp1, sizeof(tmp1), name);
	Trim(tmp1);
	BinToStr(tmp2, sizeof(tmp2), machine_hash, SHA1_SIZE);
	StrCat(tmp2, sizeof(tmp2), tmp1);
	StrUpper(tmp2);

	Sha0(hash, tmp2, StrLen(tmp2));
}

static void GenHubIpAddress(IP *ip, UCHAR *hash) {
	if (ip == NULL || hash == NULL)
		return;

	SetIP(ip, 172, 31, hash[0] % 254 + 1, hash[1] % 254 + 1);
}

static void GenHubMacAddress(UCHAR *mac, UCHAR *hash) {
	if (mac == NULL || hash == NULL)
		return;

	mac[0] = 0x00;
	mac[1] = SE_HUB_MAC_ADDR_SIGN;
	mac[2] = hash[0];
	mac[3] = hash[1];
	mac[4] = hash[2];
	mac[5] = hash[3];
}

// Read model for the hub counters: the admin RPC handlers and /metrics all
// read them here. Lock order is h->lock, then one list or table lock at a
// time (never nested), then TrafficLock.
void HubGetStats(HUB *h, HUB_STATS *st) {
	if (h == NULL || st == NULL)
		return;

	Zero(st, sizeof(HUB_STATS));

	Lock(h->lock);
	{
		st->Online = h->Offline ? false : true;

		LockList(h->SessionList);
		{
			st->NumSessions = LIST_NUM(h->SessionList);
		}
		UnlockList(h->SessionList);

		st->NumSessionsClient = Count(h->NumSessionsClient);
		st->NumSessionsBridge = Count(h->NumSessionsBridge);

		LockList(h->AccessList);
		{
			st->NumAccessLists = LIST_NUM(h->AccessList);
		}
		UnlockList(h->AccessList);

		if (h->HubDb != NULL) {
			LockList(h->HubDb->UserList);
			{
				st->NumUsers = LIST_NUM(h->HubDb->UserList);
			}
			UnlockList(h->HubDb->UserList);

			LockList(h->HubDb->GroupList);
			{
				st->NumGroups = LIST_NUM(h->HubDb->GroupList);
			}
			UnlockList(h->HubDb->GroupList);
		}

		HubLockTables(h);
		{
			st->NumMacTables = HubMacTableNum(h);
			st->NumIpTables = HubIpTableNum(h);
		}
		HubUnlockTables(h);

		Lock(h->TrafficLock);
		{
			Copy(&st->Traffic, h->Traffic, sizeof(TRAFFIC));
		}
		Unlock(h->TrafficLock);

		st->NumLogin = h->NumLogin;
		st->LastCommTime = h->LastCommTime;
		st->LastLoginTime = h->LastLoginTime;
		st->CreatedTime = h->CreatedTime;
	}
	Unlock(h->lock);
}

HUB *NewHub(CEDAR *cedar, char *HubName, HUB_OPTION *option) {
	char packet_logger_name[MAX_SIZE];
	char tmp[MAX_SIZE];
	char log_dir[MAX_SIZE];
	char safe_hub_name[MAX_HUBNAME_LEN + 1];
	UCHAR machine_hash[SHA1_SIZE];
	UCHAR hash[SHA1_SIZE];
	IP ip6;
	if (cedar == NULL || option == NULL || HubName == NULL)
		return NULL;

	HUB *h = ZeroMalloc(sizeof(HUB));
	Sha0(h->HashedPassword, "", 0);
	HashPassword(h->SecurePassword, ADMINISTRATOR_USERNAME, "");
	h->lock = NewLock();
	h->lock_online = NewLock();
	h->ref = NewRef();
	h->Cedar = cedar;
	AddRef(h->Cedar->ref);

	ConvertSafeFileName(safe_hub_name, sizeof(safe_hub_name), HubName);
	h->Name = CopyStr(safe_hub_name);


	h->AdminOptionList = NewList(CompareAdminOption);
	AddHubAdminOptionsDefaults(h, true);

	h->LastCommTime = SystemTime64();
	h->LastLoginTime = SystemTime64();
	h->NumLogin = 0;

	h->TrafficLock = NewLock();

	h->HubDb = NewHubDb();

	h->SessionList = NewList(NULL);
	h->SessionCounter = NewCounter();
	h->NumSessions = NewCounter();
	h->NumSessionsClient = NewCounter();
	h->NumSessionsBridge = NewCounter();
	h->MacHashTable = NewHashList(GetHashOfMacTable, CompareMacTable, 8);
	h->IpTable = NewList(CompareIpTable);
	IpTableExpiryInit(&h->IpTableExpiry);
	h->MonitorList = NewList(NULL);
	h->LinkList = NewList(NULL);

	h->Traffic = NewTraffic();

	h->Option = ZeroMalloc(sizeof(HUB_OPTION));
	Copy(h->Option, option, sizeof(HUB_OPTION));

	if (h->Option->VlanTypeId == 0)
		h->Option->VlanTypeId = MAC_PROTO_TAGVLAN;

	GenerateMachineUniqueHash(cedar, machine_hash);
	HubNameHash(hash, machine_hash, h->Name);
	GenHubMacAddress(h->HubMacAddr, hash);
	GenHubIpAddress(&h->HubIp, hash);

	GenerateEui64LocalAddress(&ip6, h->HubMacAddr);
	IPToIPv6Addr(&h->HubIpV6, &ip6);

	InitAccessList(h);

	h->UserList = NewUserList();

	SetDefaultHubLog(&h->LogSetting);

	// The log directories (LogPaths) under the directory of the executable, which "@" names in a log file path
	HubSecurityLogDir(log_dir, sizeof(log_dir), NULL);
	Format(tmp, sizeof(tmp), "@%s", log_dir);
	MakeDir(tmp);
	HubPacketLogDir(log_dir, sizeof(log_dir), NULL);
	Format(tmp, sizeof(tmp), "@%s", log_dir);
	MakeDir(tmp);

	HubPacketLogDir(log_dir, sizeof(log_dir), h->Name);
	Format(packet_logger_name, sizeof(packet_logger_name), "@%s", log_dir);
	h->PacketLogger = NewLog(packet_logger_name, HUB_PACKET_LOG_PREFIX, h->LogSetting.PacketLogSwitchType,
	                         cedar->MaxLogSize);

	HubSecurityLogDir(log_dir, sizeof(log_dir), h->Name);
	Format(tmp, sizeof(tmp), "@%s", log_dir);
	h->SecurityLogger = NewLog(tmp, HUB_SECURITY_LOG_PREFIX, h->LogSetting.SecurityLogSwitchType, cedar->MaxLogSize);

	if (h->Option->NoArpPolling == false && h->Option->NoIpTable == false) {
		StartHubWatchDog(h);
		h->WatchDogStarted = true;
	}

	SLog(h->Cedar, "LS_HUB_START", h->Name);

	MacToStr(tmp, sizeof(tmp), h->HubMacAddr);
	SLog(h->Cedar, "LS_HUB_MAC", h->Name, tmp);

	return h;
}

void DeleteHubDb(HUBDB *d) {
	if (d == NULL)
		return;

	LockList(d->UserList);
	{
		LockList(d->GroupList);
		{
			USER **users = ToArray(d->UserList);
			USERGROUP **groups = ToArray(d->GroupList);

			for (UINT i = 0; i < LIST_NUM(d->UserList); i++)
				ReleaseUser(users[i]);
			for (UINT i = 0; i < LIST_NUM(d->GroupList); i++)
				ReleaseGroup(groups[i]);

			Free(users);
			Free(groups);
		}
		UnlockList(d->GroupList);
	}
	UnlockList(d->UserList);

	LockList(d->RootCertList);
	{
		for (UINT i = 0; i < LIST_NUM(d->RootCertList); i++) {
			X *x = LIST_DATA(d->RootCertList, i);
			FreeX(x);
		}
	}
	UnlockList(d->RootCertList);

	LockList(d->CrlList);
	{
		for (UINT i = 0; i < LIST_NUM(d->CrlList); i++) {
			CRL *crl = LIST_DATA(d->CrlList, i);
			FreeCrl(crl);
		}
	}
	UnlockList(d->CrlList);

	FreeAcList(d->AcList);

	ReleaseList(d->GroupList);
	ReleaseList(d->UserList);
	ReleaseList(d->RootCertList);
	ReleaseList(d->CrlList);
	Free(d);
}

HUBDB *NewHubDb() {
	HUBDB *d = ZeroMalloc(sizeof(HUBDB));

	d->GroupList = NewList(CompareGroupName);
	d->UserList = NewList(CompareUserName);
	d->RootCertList = NewList(CompareCert);
	d->CrlList = NewList(NULL);
	d->AcList = NewList(CmpAc);

	return d;
}


