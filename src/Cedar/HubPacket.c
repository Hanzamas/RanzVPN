// HubPacket.c
// Virtual Hub packet forwarding: StorePacket with its policy, access list and traffic-limiter filters, the broadcast storm list and the hub packet adapter

#include "Hub.h"

#include "Admin.h"
#include "Bridge.h"
#include "Connection.h"
#include "Link.h"
#include "Protocol.h"
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
#include "HubInternal.h"

bool IsPacketMaskedByAccessList(SESSION *s, PKT *p, ACCESS *a, UINT64 dest_username, UINT64 dest_groupname, SESSION *dest_session)
{
	UINT64 src_username;
	UINT64 src_username_simple;
	UINT64 src_groupname;
	HUB_PA *pa;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	bool is_ipv4_packet = false;
	bool is_ipv6_packet = false;
	bool is_arp_packet = false;
	if (s == NULL || p == NULL || a == NULL)
	{
		return false;
	}
	if (a->Active == false)
	{
		return false;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	src_username = pa->UsernameHash;
	src_username_simple = pa->UsernameHashSimple;
	src_groupname = pa->GroupnameHash;

	if (a->CheckSrcMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if((a->SrcMacAddress[i] & a->SrcMacMask[i]) != (a->SrcMacMask[i] & p->MacAddressSrc[i]))
			{
				return false;
			}
		}
	}

	if (a->CheckDstMac != false)
	{
		UINT i;
		for (i = 0; i < 6; i++)
		{
			if ((a->DstMacAddress[i] & a->DstMacMask[i]) != (a->DstMacMask[i] & p->MacAddressDest[i]))
			{
				return false;
			}
		}
	}

	if (a->SrcUsernameHash != 0)
	{
		if (a->IsSrcUsernameIncludeOrExclude == false)
		{
			if ((a->SrcUsernameHash != src_username) && (a->SrcUsernameHash != src_groupname))
			{
				return false;
			}
		}
		else
		{
			HUB *hub = s->Hub;

			if (hub != NULL)
			{
				LIST *o = hub->UserList;

				if (s->NormalClient == false)
				{
					// exclude: and include: filters never match internal sessions
					return false;
				}

				if (IsUserMatchInUserListWithCacheExpiresAcl(o, a->SrcUsername, src_username,
					hub->Option->AccessListIncludeFileCacheLifetime * 1000) == false)
				{
					return false;
				}
			}
		}
	}

	if (a->DestUsernameHash != 0)
	{
		if (a->IsDestUsernameIncludeOrExclude == false)
		{
			if ((a->DestUsernameHash != dest_username) && (a->DestUsernameHash != dest_groupname))
			{
				return false;
			}
		}
		else
		{
			HUB *hub = s->Hub;

			if (hub != NULL)
			{
				LIST *o = hub->UserList;

				if (dest_session != NULL && dest_session->NormalClient == false)
				{
					// exclude: and include: filters never match internal sessions
					return false;
				}

				if (IsUserMatchInUserListWithCacheExpiresAcl(o, a->DestUsername, dest_username,
					hub->Option->AccessListIncludeFileCacheLifetime * 1000) == false)
				{
					return false;
				}
			}
		}
	}

	if (p->TypeL3 != L3_IPV4)
	{
		is_ipv4_packet = false;
	}
	else
	{
		is_ipv4_packet = true;
	}

	if (p->TypeL3 != L3_IPV6)
	{
		is_ipv6_packet = false;
	}
	else
	{
		is_ipv6_packet = true;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		is_arp_packet = true;
	}

	if (is_ipv4_packet)
	{
		ip = p->L3.IPv4Header;
	}

	if (is_ipv6_packet)
	{
		ip6 = p->L3.IPv6Header;
	}

	if (a->IsIPv6 == false)
	{

		if (a->SrcIpAddress != 0 || a->SrcSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->SrcIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->SrcIP & a->SrcSubnetMask) != (a->SrcIpAddress & a->SrcSubnetMask))
				{
					return false;
				}
			}
		}

		if (a->DestIpAddress != 0 || a->DestSubnetMask != 0)
		{
			if (is_ipv4_packet == false)
			{
				if (p->TypeL3 == L3_ARPV4)
				{
					bool arp_match = false;
					if (p->L3.ARPv4Header->HardwareSize == 6 &&
						Endian16(p->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
						p->L3.ARPv4Header->ProtocolSize == 4 &&
						Endian16(p->L3.ARPv4Header->ProtocolType) == 0x0800)
					{
						UINT uint_ip = p->L3.ARPv4Header->TargetIP;

						if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(p->MacAddressSrc)))
						{
							if ((uint_ip & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
							{
							}
							else
							{
								arp_match = true;
							}
						}
					}

					if (arp_match == false)
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}
			else
			{
				if ((ip->DstIP & a->DestSubnetMask) != (a->DestIpAddress & a->DestSubnetMask))
				{
					return false;
				}
			}
		}
	}
	else
	{

		if (IsZeroIP6Addr(&a->SrcIpAddress6) == false ||
			IsZeroIP6Addr(&a->SrcSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->SrcIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->SrcSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->SrcAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}

		if (IsZeroIP6Addr(&a->DestIpAddress6) == false ||
			IsZeroIP6Addr(&a->DestSubnetMask6) == false)
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				IP a_ip, a_subnet, p_ip;
				IP and1, and2;

				IPv6AddrToIP(&a_ip, &a->DestIpAddress6);
				IPv6AddrToIP(&a_subnet, &a->DestSubnetMask6);
				IPv6AddrToIP(&p_ip, &ip6->DestAddress);

				IPAnd6(&and1, &a_ip, &a_subnet);
				IPAnd6(&and2, &p_ip, &a_subnet);

				if (CmpIpAddr(&and1, &and2) != 0)
				{
					return false;
				}
			}
		}
	}

	if (is_arp_packet)
	{
		if (s->Hub != NULL && s->Hub->Option != NULL && s->Hub->Option->ApplyIPv4AccessListOnArpPacket)
		{
		}
		else
		{
			return false;
		}
	}

	if (a->Protocol != 0)
	{
		if (a->IsIPv6 == false)
		{
			if (is_ipv4_packet == false)
			{
				return false;
			}
			else
			{
				if (ip->Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
		else
		{
			if (is_ipv6_packet == false)
			{
				return false;
			}
			else
			{
				if (p->IPv6HeaderPacketInfo.Protocol != a->Protocol)
				{
					return false;
				}
			}
		}
	}

	if (a->SrcPortStart != 0 || a->DestPortStart != 0 ||
		a->SrcPortEnd != 0 || a->DestPortEnd != 0)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if (p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(tcp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(tcp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else if (p->TypeL4 == L4_UDP)
			{
				UDP_HEADER *udp = p->L4.UDPHeader;
				if (a->SrcPortStart != 0 || a->SrcPortEnd != 0)
				{
					UINT src_port = Endian16(udp->SrcPort);
					if (src_port < a->SrcPortStart || src_port > a->SrcPortEnd)
					{
						return false;
					}
				}

				if (a->DestPortStart != 0 || a->DestPortEnd != 0)
				{
					UINT dest_port = Endian16(udp->DstPort);
					if (dest_port < a->DestPortStart || dest_port > a->DestPortEnd)
					{
						return false;
					}
				}
			}
			else
			{
				return false;
			}
		}
	}

	if (a->CheckTcpState != false)
	{
		if ((a->IsIPv6 == false && is_ipv4_packet == false) ||
			(a->IsIPv6 && is_ipv6_packet == false))
		{
			return false;
		}
		else
		{
			if(p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;
				bool est = true;

				if ((tcp->Flag & TCP_SYN) && (!(tcp->Flag & TCP_ACK)))
				{
					est = false;
				}

				if((INT_TO_BOOL(a->Established) ^ INT_TO_BOOL(est)))
				{
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	return true;
}

bool ApplyAccessListToForwardPacket(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *p)
{
	UINT i;
	bool pass = true;
	bool skip = true;
	if (hub == NULL || src_session == NULL || p == NULL || dest_session == NULL)
	{
		return false;
	}

	if (p->AccessChecked)
	{
		return true;
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				skip = false;
			}

			if (skip == false)
			{
				if (IsPacketMaskedByAccessList(src_session, p, a,
					((HUB_PA *)dest_session->PacketAdapter->Param)->UsernameHash,
					((HUB_PA *)dest_session->PacketAdapter->Param)->GroupnameHash,
					dest_session))
				{
					pass = a->Discard ? false : true;

					break;
				}
			}
		}
	}
	UnlockList(hub->AccessList);

	return pass;
}

BUF *BuildRedirectToUrlPayload(HUB *hub, SESSION *s, char *redirect_url)
{
	char html[MAX_REDIRECT_URL_LEN * 2 + 1 + MAX_SIZE];
	char header[MAX_REDIRECT_URL_LEN * 2 + 1 + MAX_SIZE];
	char redirect_url2[MAX_REDIRECT_URL_LEN * 2];
	BUF *b;
	if (hub == NULL || s == NULL || redirect_url == NULL)
	{
		return NULL;
	}

	StrCpy(redirect_url2, sizeof(redirect_url2), redirect_url);
	Trim(redirect_url2);

	if (InStr(redirect_url2, ACCESS_LIST_URL_INFO_TAG))
	{
		char secret[MAX_SIZE];
		char tmp[MAX_SIZE];
		SYSTEMTIME st;
		UINT i, len, isp;

		isp = INFINITE;

		SystemTime(&st);
		ClearStr(secret, sizeof(secret));

		len = StrLen(redirect_url2);

		for (i = 0;i < len;i++)
		{
			char c = redirect_url2[i];
			if (c == '|')
			{
				isp = i;
			}
		}

		if (isp != INFINITE)
		{
			StrCpy(secret, sizeof(secret), redirect_url2 + isp + 1);
			redirect_url2[isp] = 0;
		}

		Format(tmp, sizeof(tmp), "%s|%s|%r|%04u%02u%02u%02u%02u%02u%s",
			s->Username, s->Name, &s->Connection->ClientIp,
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, (IsEmptyStr(secret) ? "" : "|"));

		if (IsEmptyStr(secret) == false)
		{
			UCHAR hash[SHA1_SIZE];
			char hash_str[MAX_SIZE];
			BUF *b2 = NewBuf();

			WriteBuf(b2, tmp, StrLen(tmp));
			WriteBuf(b2, secret, StrLen(secret));

			Sha1(hash, b2->Buf, b2->Size);

			BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));

			FreeBuf(b2);

			StrCat(tmp, sizeof(tmp), hash_str);

			ReplaceStrEx(redirect_url2, sizeof(redirect_url2), redirect_url2,
				ACCESS_LIST_URL_INFO_TAG, tmp, false);
		}
	}

	Format(html, sizeof(html),
		"<html><head><title>Object moved</title></head><body>\r\n<h2>Object moved to <a href=\"%s\">here</a>.</h2>\r\n</body></html>\r\n\r\n",
		redirect_url2);

	Format(header, sizeof(header),
		"HTTP/1.1 302 Found\r\nLocation: %s\r\nCache-Control: private\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %u\r\n\r\n",
		redirect_url2, StrLen(redirect_url2));

	b = NewBuf();

	WriteBuf(b, header, StrLen(header));
	WriteBuf(b, html, StrLen(html));

	return b;
}

void ForceRedirectToUrl(HUB *hub, SESSION *src_session, PKT *p, char *redirect_url)
{
	BUF *payload;
	UINT tcp_size;
	TCP_HEADER *tcp_data;
	TCP_HEADER *src_tcp;
	BUF *b;
	if (hub == NULL || src_session == NULL || p == NULL || redirect_url == NULL)
	{
		return;
	}
	if (p->TypeL3 != L3_IPV4 && p->TypeL3 != L3_IPV6)
	{
		return;
	}
	if (p->TypeL4 != L4_TCP)
	{
		return;
	}

	src_tcp = p->L4.TCPHeader;
	if (src_tcp == NULL)
	{
		return;
	}

	payload = BuildRedirectToUrlPayload(hub, src_session, redirect_url);
	if (payload == NULL)
	{
		return;
	}

	tcp_size = sizeof(TCP_HEADER) + payload->Size;
	tcp_data = (TCP_HEADER *)ZeroMalloc(tcp_size);
	tcp_data->SrcPort = src_tcp->DstPort;
	tcp_data->DstPort = src_tcp->SrcPort;
	tcp_data->SeqNumber = src_tcp->AckNumber;
	tcp_data->AckNumber = Endian32(Endian32(src_tcp->SeqNumber) + p->PayloadSize);
	TCP_SET_HEADER_SIZE(tcp_data, 5);
	tcp_data->Flag = TCP_ACK | TCP_PSH;
	tcp_data->WindowSize = Endian16(0xFFFF);
	Copy(((UCHAR *)tcp_data) + sizeof(TCP_HEADER), payload->Buf, payload->Size);

	if (p->TypeL3 == L3_IPV4)
	{
		tcp_data->Checksum = CalcChecksumForIPv4(p->L3.IPv4Header->DstIP, p->L3.IPv4Header->SrcIP, IP_PROTO_TCP,
			tcp_data, tcp_size, 0);
	}
	else
	{
		tcp_data->Checksum = CalcChecksumForIPv6(&p->IPv6HeaderPacketInfo.IPv6Header->DestAddress,
			&p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, IP_PROTO_TCP, tcp_data, tcp_size, 0);
	}

	b = NewBuf();

	WriteBuf(b, p->MacHeader->SrcAddress, 6);
	WriteBuf(b, p->MacHeader->DestAddress, 6);
	WriteBuf(b, &p->MacHeader->Protocol, 2);

	if (p->TypeL3 == L3_IPV4)
	{
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
	}
	else
	{
		IPV6_HEADER v6;

		Zero(&v6, sizeof(v6));

		IPV6_SET_VERSION(&v6, 6);
		v6.PayloadLength = Endian16(tcp_size);
		v6.NextHeader = IP_PROTO_TCP;
		v6.HopLimit = 64;

		Copy(&v6.SrcAddress, &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress, sizeof(IPV6_ADDR));
		Copy(&v6.DestAddress, &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress, sizeof(IPV6_ADDR));

		WriteBuf(b, &v6, sizeof(v6));
	}

	WriteBuf(b, tcp_data, tcp_size);

	StorePacketToHubPa((HUB_PA *)src_session->PacketAdapter->Param,
		NULL, b->Buf, b->Size, NULL, false, false);

	Free(tcp_data);
	FreeBuf(payload);
	Free(b);
}

bool ApplyAccessListToStoredPacket(HUB *hub, SESSION *s, PKT *p)
{
	UINT i;
	bool pass = true;
	bool use_redirect_url = false;
	char redirect_url[MAX_REDIRECT_URL_LEN + 1];
	if (hub == NULL || s == NULL || p == NULL)
	{
		return false;
	}

	if (hub->Option != NULL && hub->Option->FilterPPPoE)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x8863 || proto == 0x8864)
			{
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterOSPF)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->L3.IPv4Header != NULL)
			{
				if (p->L3.IPv4Header->Protocol == 89)
				{
					return false;
				}
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				return false;
			}
		}
	}

	if (hub->Option != NULL && hub->Option->FilterBPDU)
	{
		if (p->MacHeader != NULL)
		{
			if (p->TypeL3 == L3_BPDU)
			{
				return false;
			}
		}
	}

	LockList(hub->AccessList);
	{
		for (i = 0;i < LIST_NUM(hub->AccessList);i++)
		{
			ACCESS *a = LIST_DATA(hub->AccessList, i);

			if (a->DestUsernameHash != 0)
			{
				break;
			}

			if (IsPacketMaskedByAccessList(s, p, a, 0, 0, NULL))
			{
				pass = a->Discard ? false : true;

				// Mark the packet so the access list skips it on the way out
				p->AccessChecked = true;

				p->Delay = a->Delay;
				p->Jitter = a->Jitter;
				p->Loss = a->Loss;

				if (a->RedirectUrl[0] != 0)
				{
					if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
						p->TypeL4 == L4_TCP)
					{
						TCP_HEADER *tcp = p->L4.TCPHeader;

						if (tcp != NULL)
						{
							if (tcp->Flag & TCP_ACK)
							{
								if ((tcp->Flag & TCP_SYN) == 0 &&
									(tcp->Flag & TCP_RST) == 0 &&
									(tcp->Flag & TCP_URG) == 0)
								{
									if (p->PayloadSize != 0)
									{
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

	if (pass)
	{
		if (s->FirstTimeHttpRedirect && s->FirstTimeHttpAccessCheckIp != 0)
		{
			if ((p->TypeL3 == L3_IPV4 || p->TypeL3 == L3_IPV6) &&
				p->TypeL4 == L4_TCP)
			{
				TCP_HEADER *tcp = p->L4.TCPHeader;

				if (tcp != NULL)
				{
					if (tcp->DstPort == Endian16(80))
					{
						if (p->L3.IPv4Header->DstIP == s->FirstTimeHttpAccessCheckIp)
						{
							s->FirstTimeHttpRedirect = false;
						}
						else if (tcp->Flag & TCP_ACK)
						{
							if ((tcp->Flag & TCP_SYN) == 0 &&
								(tcp->Flag & TCP_RST) == 0 &&
								(tcp->Flag & TCP_URG) == 0)
							{
								if (p->PayloadSize != 0)
								{
									if (IsTcpPacketNcsiHttpAccess(p) == false)
									{
										if (IsEmptyStr(s->FirstTimeHttpRedirectUrl) == false)
										{
											use_redirect_url = true;
											StrCpy(redirect_url, sizeof(redirect_url), s->FirstTimeHttpRedirectUrl);
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

	if (use_redirect_url)
	{
		if (s->NormalClient)
		{
			// Normal VPN clients get the URL redirect; local bridges only drop the packet
			ForceRedirectToUrl(hub, s, p, redirect_url);
		}
		else
		{
		}

		pass = false;
	}

	return pass;
}

bool IsTcpPacketNcsiHttpAccess(PKT *p)
{
	if (p == NULL)
	{
		return false;
	}

	if (p->TypeL4 != L4_TCP)
	{
		return false;
	}

	if (p->Payload == NULL || p->PayloadSize == 0)
	{
		return false;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, "NCSI", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".jpeg", 5) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".jpg", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".gif", 4) != INFINITE)
	{
		return true;
	}

	if (SearchBin(p->Payload, 0, p->PayloadSize, ".css", 4) != INFINITE)
	{
		return true;
	}

	return false;
}

int CompareStormList(void *p1, void *p2)
{
	STORM *s1, *s2;
	UINT r;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	s1 = *(STORM **)p1;
	s2 = *(STORM **)p2;
	if (s1 == NULL || s2 == NULL)
	{
		return 0;
	}
	if (s1->StrictMode == false && s2->StrictMode == false)
	{
		r = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		if (r != 0)
		{
			return r;
		}
		r = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r != 0)
		{
			return r;
		}
	}
	else
	{
		int r1, r2;
		r1 = CmpIpAddr(&s1->DestIp, &s2->DestIp);
		r2 = CmpIpAddr(&s1->SrcIp, &s2->SrcIp);
		if (r1 == 0 || r2 == 0)
		{
		}
		else
		{
			if (r1 != 0)
			{
				return r1;
			}

			if (r2 != 0)
			{
				return r2;
			}
		}
	}
	r = Cmp(s1->MacAddress, s2->MacAddress, 6);
	return r;
}

bool HubPaInit(SESSION *s)
{
	HUB_PA *pa = ZeroMalloc(sizeof(HUB_PA));
	pa->Cancel = NewCancel();
	pa->PacketQueue = NewQueue();
	pa->Now = Tick64();
	pa->Session = s;
	pa->StormList = NewList(CompareStormList);
	pa->UsernameHash = UsernameToInt64(s->Username);
	pa->GroupnameHash = UsernameToInt64(s->GroupName);

	s->PacketAdapter->Param = pa;

	if (s->Policy->MonitorPort)
	{
		pa->MonitorPort = true;

		LockList(s->Hub->MonitorList);
		{
			Insert(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	return true;
}

void HubPaFree(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	HUB *hub = s->Hub;

	if (pa->MonitorPort)
	{
		LockList(s->Hub->MonitorList);
		{
			Delete(s->Hub->MonitorList, s);
		}
		UnlockList(s->Hub->MonitorList);
	}

	LockHashList(hub->MacHashTable);
	{
		UINT i, num;
		MAC_TABLE_ENTRY **pp;
		LIST *o = NewListFast(NULL);

		pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num);
		for (i = 0;i < num;i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)pp[i];
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			MAC_TABLE_ENTRY *e = (MAC_TABLE_ENTRY *)LIST_DATA(o, i);
			DeleteHash(hub->MacHashTable, e);
			Free(e);
		}
		ReleaseList(o);
		Free(pp);
	}
	{
		UINT i, num = LIST_NUM(hub->IpTable);
		LIST *o = NewListFast(NULL);
		for (i = 0;i < num;i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);
			if (e->Session == s)
			{
				Add(o, e);
			}
		}
		for (i = 0;i < LIST_NUM(o);i++)
		{
			IP_TABLE_ENTRY *e = LIST_DATA(o, i);
			Delete(hub->IpTable, e);
			Free(e);
		}
		ReleaseList(o);
	}
	UnlockHashList(hub->MacHashTable);

	LockList(pa->StormList);
	{
		UINT i;
		for (i = 0;i < LIST_NUM(pa->StormList);i++)
		{
			STORM *s = (STORM *)LIST_DATA(pa->StormList, i);
			Free(s);
		}
		DeleteAll(pa->StormList);
	}
	UnlockList(pa->StormList);

	ReleaseList(pa->StormList);

	LockQueue(pa->PacketQueue);
	{
		BLOCK *b;

		while (b = GetNext(pa->PacketQueue))
		{
			if (b->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)b->Size));
			}

			FreeBlock(b);
		}
	}
	UnlockQueue(pa->PacketQueue);

	ReleaseQueue(pa->PacketQueue);

	ReleaseCancel(pa->Cancel);

	Free(pa);
	s->PacketAdapter->Param = NULL;
}

CANCEL *HubPaGetCancel(SESSION *s)
{
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	AddRef(pa->Cancel->ref);
	return pa->Cancel;
}

UINT HubPaGetNextPacket(SESSION *s, void **data)
{
	UINT ret = 0;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;

	LockQueue(pa->PacketQueue);
	{
		BLOCK *block = GetNext(pa->PacketQueue);
		if (block == NULL)
		{
			ret = 0;
		}
		else
		{
			if (block->IsFlooding)
			{
				CedarAddCurrentTcpQueueSize(s->Cedar, -((int)block->Size));
			}

			*data = block->Buf;
			ret = block->Size;
			Free(block);
		}
	}
	UnlockQueue(pa->PacketQueue);

	return ret;
}

bool HubPaPutPacket(SESSION *s, void *data, UINT size)
{
	PKT *packet;
	HUB_PA *pa = (HUB_PA *)s->PacketAdapter->Param;
	bool b = false;
	HUB *hub;
	bool no_l3 = false;
	bool no_http = false;
	LIST *o = NULL;
	UINT i;
	UINT vlan_type_id = 0;
	bool no_look_bpdu_bridge_id = false;
	bool no_parse_dhcp = false;
	bool no_correct_checksum = false;

	hub = s->Hub;

	pa->Now = Tick64();

	if (hub != NULL && hub->Option != NULL && hub->Option->DisableAdjustTcpMss == false && s != NULL)
	{
		UINT target_mss = (hub->Option->AdjustTcpMssValue == 0 ? INFINITE : hub->Option->AdjustTcpMssValue);
		UINT session_mss = (s->AdjustMss == 0 ? INFINITE : s->AdjustMss);

		target_mss = MIN(target_mss, session_mss);

		if (s->UseUdpAcceleration && s->UdpAccelMss != 0)
		{
			target_mss = MIN(target_mss, s->UdpAccelMss);
		}

		if (target_mss != INFINITE)
		{
			AdjustTcpMssL2(data, size, target_mss, hub->Option->VlanTypeId);
		}
	}

	if (data == NULL)
	{
		o = NULL;
		LockList(s->DelayedPacketList);
		{
			UINT i;
			if (LIST_NUM(s->DelayedPacketList) >= 1)
			{
				UINT64 now = TickHighres64();
				for (i = 0;i < LIST_NUM(s->DelayedPacketList);i++)
				{
					PKT *p = LIST_DATA(s->DelayedPacketList, i);

					if (now >= p->DelayedForwardTick)
					{
						if (o == NULL)
						{
							o = NewListFast(NULL);
						}

						Add(o, p);
					}
				}
			}

			if (o != NULL)
			{
				for (i = 0;i < LIST_NUM(o);i++)
				{
					PKT *p = LIST_DATA(o, i);

					Delete(s->DelayedPacketList, p);
				}
			}
		}
		UnlockList(s->DelayedPacketList);

		if (o != NULL)
		{
			for (i = 0;i < LIST_NUM(o);i++)
			{
				PKT *p = LIST_DATA(o, i);

				StorePacket(s->Hub, s, p);
			}

			ReleaseList(o);
		}

		CancelList(s->CancelList);

		if (hub != NULL)
		{
			if (hub->Option != NULL && hub->Option->YieldAfterStorePacket)
			{
				YieldCpu();
			}
		}

		return true;
	}

	if (hub != NULL && hub->Option != NULL)
	{
		no_l3 = hub->Option->DisableIPParsing;
		no_http = hub->Option->DisableHttpParsing;
		vlan_type_id = hub->Option->VlanTypeId;
		no_look_bpdu_bridge_id = hub->Option->NoLookBPDUBridgeId;
		no_correct_checksum = hub->Option->DisableCorrectIpOffloadChecksum;
	}

	if (s->VLanId != 0)
	{
		VLanInsertTag(&data, &size, s->VLanId, vlan_type_id);
	}

LABEL_TRY_AGAIN:
	packet = ParsePacketEx4(data, size, no_l3, vlan_type_id, !no_look_bpdu_bridge_id, no_http, !no_correct_checksum);

	if (packet != NULL)
	{
		if (packet->InvalidSourcePacket)
		{
			FreePacket(packet);
			packet = NULL;
		}
	}


	if (no_parse_dhcp == false && packet != NULL)
	{
		if (hub != NULL && hub->Option != NULL && hub->Option->RemoveDefGwOnDhcpForLocalhost)
		{
			if (packet->TypeL7 == L7_DHCPV4)
			{
				if (packet->TypeL3 == L3_IPV4)
				{
					if (packet->TypeL4 == L4_UDP)
					{
						if (packet->L7.DHCPv4Header != NULL)
						{
							DHCPV4_HEADER *dhcp = packet->L7.DHCPv4Header;

							if (dhcp->OpCode == 2)
							{
								if (IsMacAddressLocalFast(dhcp->ClientMacAddress))
								{
									BUF *new_buf;
									DHCP_MODIFY_OPTION m;
									WHERE;

									Zero(&m, sizeof(m));
									m.RemoveDefaultGatewayOnReply = true;

									new_buf = DhcpModifyIPv4(&m, data, size);

									if (new_buf != NULL)
									{
										Free(data);

										data = new_buf->Buf;
										size = new_buf->Size;

										Free(new_buf);

										no_parse_dhcp = true;

										FreePacket(packet);

										goto LABEL_TRY_AGAIN;
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if (packet != NULL)
	{
		StorePacket(s->Hub, s, packet);
	}
	else
	{
		Free(data);
	}

	return true;
}

// Broadcast storm guard: filter frequent broadcasts from a single endpoint
bool CheckBroadcastStorm(HUB *hub, SESSION *s, PKT *p)
{
	IP src_ip, dest_ip;
	HUB_PA *pa;
	UINT64 now = Tick64();
	UINT limit_start_count;
	SESSION *sess = s;
	bool ret = true;
	bool strict = false;
	bool no_heavy = false;
	if (s == NULL || p == NULL || hub == NULL)
	{
		return false;
	}

	if (s->Policy->NoBroadcastLimiter)
	{
		return true;
	}

	if (hub->Option != NULL)
	{
		strict = hub->Option->BroadcastLimiterStrictMode;
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;

	Zero(&src_ip, sizeof(IP));
	Zero(&dest_ip, sizeof(IP));

	if (p->TypeL3 == L3_IPV4)
	{
		UINTToIP(&src_ip, p->L3.IPv4Header->SrcIP);
		UINTToIP(&dest_ip, p->L3.IPv4Header->DstIP);
	}
	else if (p->TypeL3 == L3_ARPV4)
	{
		UINTToIP(&src_ip, p->L3.ARPv4Header->SrcIP);
		Zero(&dest_ip, sizeof(IP));
	}
	else if (p->TypeL3 == L3_IPV6)
	{
		IPv6AddrToIP(&src_ip, &p->L3.IPv6Header->SrcAddress);
		IPv6AddrToIP(&dest_ip, &p->L3.IPv6Header->DestAddress);
	}

	limit_start_count = 32;

	if (s->Hub != NULL && s->Hub->Option->BroadcastStormDetectionThreshold != 0)
	{
		limit_start_count = s->Hub->Option->BroadcastStormDetectionThreshold;
	}

	LockList(pa->StormList);
	{
		STORM *s;
		UINT num;
		s = SearchStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		if (s == NULL)
		{
			s = AddStormList(pa, p->MacAddressSrc, &src_ip, &dest_ip, strict);
		}

		s->CurrentBroadcastNum++;

		if ((s->CheckStartTick + STORM_CHECK_SPAN) < now ||
			s->CheckStartTick == 0 || s->CheckStartTick > now)
		{
			UINT64 diff_time;
			if (s->CheckStartTick < now)
			{
				diff_time = now - s->CheckStartTick;
			}
			else
			{
				diff_time = 0;
			}
			s->CheckStartTick = now;
			num = (UINT)((UINT64)s->CurrentBroadcastNum * (UINT64)1000 / (UINT64)STORM_CHECK_SPAN);
			s->CurrentBroadcastNum = 0;
			if (num >= limit_start_count)
			{
				char ip1[64];
				char ip2[64];
				char mac[MAX_SIZE];
				IPToStr(ip1, sizeof(ip1), &src_ip);
				IPToStr(ip2, sizeof(ip2), &dest_ip);
				ret = false;
				if (s->DiscardValue < STORM_DISCARD_VALUE_END)
				{
					s->DiscardValue = MAX(s->DiscardValue, 1) * 2;
				}

				MacToStr(mac, sizeof(mac), p->MacAddressSrc);

				if (no_heavy == false)
				{
					HLog(sess->Hub, "LH_BCAST_STORM", sess->Name, mac, ip1, ip2, num);
				}
			}
			else
			{
				if (s->DiscardValue >= 1)
				{
					s->DiscardValue = (UINT)((UINT64)s->DiscardValue / MAX((UINT64)2, (UINT64)diff_time / (UINT64)STORM_CHECK_SPAN));
				}
			}
		}

		if (s->DiscardValue >= STORM_DISCARD_VALUE_START)
		{
			if (s->DiscardValue >= 128)
			{
				ret = false;
			}
			else if ((rand() % s->DiscardValue) != 0)
			{
				ret = false;
			}
		}

	}
	UnlockList(pa->StormList);

	return ret;
}

void StorePacket(HUB *hub, SESSION *s, PKT *packet)
{
	MAC_TABLE_ENTRY *entry = NULL;
	MAC_TABLE_ENTRY t;
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
	if (hub == NULL || packet == NULL)
	{
		return;
	}

	if (s != NULL)
	{
		if (((HUB_PA *)s->PacketAdapter->Param)->MonitorPort)
		{
			Free(packet->PacketData);
			FreePacket(packet);
			return;
		}
	}

	if (hub->Option != NULL)
	{
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
		drop_broadcast_packet_privacy = hub->Option->DropBroadcastsInPrivacyFilterMode;
		drop_arp_packet_privacy = hub->Option->DropArpInPrivacyFilterMode;
		allow_same_user_packet_privacy = hub->Option->AllowSameUserInPrivacyFilterMode;
		tcp_queue_quota = hub->Option->FloodingSendQueueBufferQuota;
		if (hub->Option->DetectDormantSessionInterval != 0)
		{
			dormant_interval = (UINT64)hub->Option->DetectDormantSessionInterval * (UINT64)1000;
		}
	}

	if (dormant_interval != 0)
	{
		if (s != NULL && s->NormalClient)
		{
			if (packet->MacAddressSrc != NULL)
			{
				if (IsHubMacAddress(packet->MacAddressSrc) == false)
				{
					s->LastCommTimeForDormant = now;
				}
			}
		}
	}

	LockHashList(hub->MacHashTable);
	{
		if (s != NULL && (packet->DelayedForwardTick == 0 && StorePacketFilter(s, packet) == false))
		{
DISCARD_PACKET:
			Free(packet->PacketData);
			FreePacket(packet);
		}
		else
		{
			bool forward_now = true;

			if (packet->Loss >= 1)
			{
				UINT r = rand() % 100;
				if ((packet->Loss >= 100) || (r < packet->Loss))
				{
					goto DISCARD_PACKET;
				}
			}

			if (packet->Delay >= 1)
			{
				float delay = (float)packet->Delay;
				float jitter;
				UINT delay_uint;
				bool f = Rand1();
				if (packet->Jitter == 0)
				{
					jitter = 0;
				}
				else
				{
					jitter = (float)(Rand32() % (int)((float)packet->Jitter * delay / 100.0f));
				}

				delay += jitter * (f ? 1 : -1);
				delay_uint = (UINT)delay;

				if (delay_uint >= 1)
				{
					forward_now = false;
					packet->Loss = packet->Jitter = packet->Delay = 0;
					packet->DelayedForwardTick = TickHighres64() + (UINT64)delay_uint;
					packet->DelayedSrcSession = s;

					LockList(s->DelayedPacketList);
					{
						Add(s->DelayedPacketList, packet);
					}
					UnlockList(s->DelayedPacketList);
				}
			}

			if (forward_now)
			{
				if (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) == 0)
				{
					if (s != NULL)
					{
						// A packet from this hub's own session came back in from outside
						goto DISCARD_PACKET;
					}
				}
				if (s != NULL && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0))
				{
					Copy(t.MacAddress, packet->MacAddressSrc, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = SearchHash(hub->MacHashTable, &t);

					if (entry == NULL)
					{
						if (hub->LastFlushTick == 0 || (hub->LastFlushTick + (UINT64)OLD_MAC_ADDRESS_ENTRY_FLUSH_INTERVAL) < now)
						{
							hub->LastFlushTick = now;

							DeleteExpiredMacTableEntry(hub->MacHashTable);
						}

						if (s->Policy->MaxMac != 0 || s->Policy->NoBridge)
						{
							UINT i, num_mac_for_me = 0;
							UINT limited_count;
							MAC_TABLE_ENTRY **pp;
							UINT num_pp;

							pp = (MAC_TABLE_ENTRY **)HashListToArray(hub->MacHashTable, &num_pp);

							for (i = 0;i < num_pp;i++)
							{
								MAC_TABLE_ENTRY *e = pp[i];
								if (e->Session == s)
								{
									num_mac_for_me++;
								}
							}

							Free(pp);

							limited_count = 0xffffffff;
							if (s->Policy->NoBridge)
							{
								limited_count = MIN(limited_count, MAC_MIN_LIMIT_COUNT);
							}
							if (s->Policy->MaxMac != 0)
							{
								limited_count = MIN(limited_count, s->Policy->MaxMac);
							}
							limited_count = MAX(limited_count, MAC_MIN_LIMIT_COUNT);

							if (num_mac_for_me >= limited_count)
							{
								char mac_str[64];

								if (s != NULL)
								{
									MacToStr(mac_str, sizeof(mac_str), packet->MacAddressSrc);
									if (s->Policy->NoBridge)
									{
										if (no_heavy == false)
										{
											HLog(hub, "LH_BRIDGE_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
										}
									}
									else
									{
										if (no_heavy == false)
										{
											HLog(hub, "LH_MAC_LIMIT", s->Name, mac_str, num_mac_for_me, limited_count);
										}
									}
								}

								goto DISCARD_PACKET;
							}
						}

						if (HASH_LIST_NUM(hub->MacHashTable) >= MAX_MAC_TABLES)
						{
							goto DISCARD_PACKET;
						}

						entry = ZeroMalloc(sizeof(MAC_TABLE_ENTRY));
						entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
						Copy(entry->MacAddress, packet->MacAddressSrc, 6);
						if (hub->Option->NoManageVlanId == false)
						{
							entry->VlanId = packet->VlanId;
						}
						else
						{
							entry->VlanId = 0;
						}
						entry->Session = s;
						entry->UpdatedTime = entry->CreatedTime = now;

						AddHash(hub->MacHashTable, entry);

						if (hub->Option->NoMacAddressLog == false)
						{
							char mac_address[32];

							if (s != NULL)
							{
								if (no_heavy == false)
								{
									MacToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc);

									if (packet->VlanId == 0)
									{
										HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
									}
									else
									{
										HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
									}
								}
							}
						}
					}
					else
					{
						if (entry->Session == s)
						{
							entry->UpdatedTime = now;
						}
						else
						{
							bool check_mac = s->Policy->CheckMac;

							if (check_mac == false)
							{
								if (s->BridgeMode)
								{
									check_mac = true;

									if (hub->Option != NULL && hub->Option->DisableCheckMacOnLocalBridge)
									{
										check_mac = false;
									}
								}
							}

							if (check_mac && (Cmp(packet->MacAddressSrc, hub->HubMacAddr, 6) != 0) &&
								((entry->UpdatedTime + MAC_TABLE_EXCLUSIVE_TIME) >= now))
							{
								UCHAR *mac = packet->MacAddressSrc;
								if (hub->Option != NULL && hub->Option->FixForDLinkBPDU &&
									(mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
									(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
								{
									// D-Link sends spanning tree packets from these addresses. CheckMac on a local
									// bridge would break them, so they are handled separately.
									UCHAR hash[MD5_SIZE];
									UINT64 tick_diff = Tick64() - s->LastDLinkSTPPacketSendTick;

									Md5(hash, packet->PacketData, packet->PacketSize);

									if ((s->LastDLinkSTPPacketSendTick != 0) &&
										(tick_diff < 750ULL) &&
										(Cmp(hash, s->LastDLinkSTPPacketDataHash, MD5_SIZE) == 0))
									{
										// Drop a repeat of the same packet within 750 ms
										goto DISCARD_PACKET;
									}
									else
									{
										goto UPDATE_FDB;
									}
								}

								goto DISCARD_PACKET;
							}
							else
							{
								char mac_address[32];
UPDATE_FDB:
								BinToStr(mac_address, sizeof(mac_address), packet->MacAddressSrc, 6);

								entry->Session = s;
								entry->HubPa = (HUB_PA *)s->PacketAdapter->Param;
								entry->UpdatedTime = entry->CreatedTime = now;

								if (1)
								{
									char mac_address[32];

									if (s != NULL)
									{
										if (no_heavy == false)
										{
											MacToStr(mac_address, sizeof(mac_address), packet->MacHeader->SrcAddress);
											if (packet->VlanId == 0)
											{
												HLog(hub, "LH_MAC_REGIST", s->Name, mac_address);
											}
											else
											{
												HLog(hub, "LH_MAC_REGIST_VLAN", s->Name, mac_address, packet->VlanId);
											}
										}
									}
								}
							}
						}
					}
				}

				broadcast_mode = false;
				dest_pa = NULL;
				dest_session = NULL;

				if (packet->BroadcastPacket)
				{
					broadcast_mode = true;
				}
				else
				{
					Copy(t.MacAddress, packet->MacAddressDest, 6);
					if (hub->Option->NoManageVlanId == false)
					{
						t.VlanId = packet->VlanId;
					}
					else
					{
						t.VlanId = 0;
					}
					entry = SearchHash(hub->MacHashTable, &t);

					if (entry == NULL)
					{
						broadcast_mode = true;
					}
					else
					{
						if (entry->Session != s)
						{
							dest_pa = entry->HubPa;
							dest_session = entry->Session;
						}
						else
						{
							goto DISCARD_PACKET;
						}
					}
				}

				if (s != NULL && hub->Option->NoIpTable == false)
				{
					if (packet->TypeL3 == L3_IPV6)
					{
						IP ip;
						bool b = true;
						UINT ip_type;
						bool dhcp_or_ra = false;

						IPv6AddrToIP(&ip, &packet->L3.IPv6Header->SrcAddress);
						ip_type = GetIPv6AddrType(&packet->L3.IPv6Header->SrcAddress);

						if (!(ip_type & IPV6_ADDR_UNICAST))
						{
							b = false;
						}
						else if ((ip_type & IPV6_ADDR_LOOPBACK) || (ip_type & IPV6_ADDR_ZERO))
						{
							b = false;
						}

						if (packet->TypeL4 == L4_ICMPV6)
						{
							if (packet->ICMPv6HeaderPacketInfo.Type == 133 ||
								packet->ICMPv6HeaderPacketInfo.Type == 134)
							{
								dhcp_or_ra = true;
							}
						}
						else if (packet->TypeL4 == L4_UDP)
						{
							if (Endian16(packet->L4.UDPHeader->DstPort) == 546 ||
								Endian16(packet->L4.UDPHeader->DstPort) == 547)
							{
								dhcp_or_ra = true;
							}
						}

						if (IsHubMacAddress(packet->MacAddressSrc) &&
							IsHubIpAddress64(&packet->L3.IPv6Header->SrcAddress))
						{
							b = false;
						}

						if (b)
						{
							IP_TABLE_ENTRY t, *e;

							Copy(&t.Ip, &ip, sizeof(IP));

							e = Search(hub->IpTable, &t);

							if (e == NULL)
							{
								if (s->Policy->NoRoutingV6 || s->Policy->MaxIPv6 != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP6(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRoutingV6)
									{
										limited_count = MIN(limited_count, IP_LIMIT_WHEN_NO_ROUTING_V6);
									}
									if (s->Policy->MaxIPv6 != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIPv6);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT_V6);

									if (dhcp_or_ra)
									{
										limited_count = 0xffffffff;
									}

									if (num_ip_for_me >= limited_count)
									{
										char tmp[64];
										IPToStr(tmp, sizeof(tmp), &ip);
										if (s->Policy->NoRoutingV6 == false)
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										else
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);
								}
							}
							else
							{
								if (e->Session == s)
								{
									e->UpdatedTime = now;
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
								}
								else
								{
									if ((s->Policy->CheckIPv6) &&
										((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
									{
										char ip_address[32];
										char mac_str[48];
										IPToStr(ip_address, sizeof(ip_address), &ip);


										MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

										if (no_heavy == false)
										{
											HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
												e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
										}

										goto DISCARD_PACKET;
									}
								}
							}
						}
					}
				}

				if (
					(s != NULL) &&
					(hub->Option->NoIpTable == false) &&
					(
						(packet->TypeL3 == L3_IPV4 ||
							(packet->TypeL3 == L3_ARPV4 && packet->L3.ARPv4Header->HardwareSize == 6 &&
							Endian16(packet->L3.ARPv4Header->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
							packet->L3.ARPv4Header->ProtocolSize == 4 &&
							Endian16(packet->L3.ARPv4Header->ProtocolType) == 0x0800)
						) &&
						(packet->TypeL7 != L7_DHCPV4)
					)
					)
				{
					IP_TABLE_ENTRY t, *e;
					IP ip;
					UINT uint_ip = 0;

					if (packet->TypeL3 == L3_IPV4)
					{
						uint_ip = packet->L3.IPv4Header->SrcIP;
					}
					else if (packet->TypeL3 == L3_ARPV4)
					{
						uint_ip = packet->L3.ARPv4Header->SrcIP;
					}

					if (uint_ip != 0 && uint_ip != 0xffffffff && !(IsHubIpAddress32(uint_ip) && IsHubMacAddress(packet->MacAddressSrc)))
					{
						UINTToIP(&ip, uint_ip);
						Copy(&t.Ip, &ip, sizeof(IP));

						e = Search(hub->IpTable, &t);

						if (e == NULL)
						{
							if (s->Policy->DHCPForce)
							{
								char ipstr[MAX_SIZE];

								IPToStr32(ipstr, sizeof(ipstr), uint_ip);
								if (no_heavy == false)
								{
									HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
								}
								goto DISCARD_PACKET;
							}

							{
								if (s->Policy->NoRouting || s->Policy->MaxIP != 0)
								{
									UINT i, num_ip_for_me = 0;
									UINT limited_count = 0xffffffff;

									for (i = 0;i < LIST_NUM(hub->IpTable);i++)
									{
										IP_TABLE_ENTRY *e = LIST_DATA(hub->IpTable, i);

										if (e->Session == s)
										{
											if (IsIP4(&e->Ip))
											{
												num_ip_for_me++;
											}
										}
									}

									if (s->Policy->NoRouting)
									{
										limited_count = MIN(limited_count, IP_MIN_LIMIT_COUNT);
									}
									if (s->Policy->MaxIP != 0)
									{
										limited_count = MIN(limited_count, s->Policy->MaxIP);
									}
									limited_count = MAX(limited_count, IP_MIN_LIMIT_COUNT);

									if (num_ip_for_me >= limited_count)
									{
										char tmp[64];
										IPToStr32(tmp, sizeof(tmp), uint_ip);
										if (s->Policy->NoRouting == false)
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_IP_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										else
										{
											if (no_heavy == false)
											{
												HLog(hub, "LH_ROUTING_LIMIT", s->Name, tmp, num_ip_for_me, limited_count);
											}
										}
										goto DISCARD_PACKET;
									}
								}

								if (IsIPManagementTargetForHUB(&ip, hub))
								{
									e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
									e->CreatedTime = e->UpdatedTime = now;
									e->DhcpAllocated = false;
									Copy(&e->Ip, &ip, sizeof(IP));
									Copy(e->MacAddress, packet->MacAddressSrc, 6);
									e->Session = s;

									DeleteExpiredIpTableEntry(hub->IpTable);

									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										DeleteOldIpTableEntry(hub->IpTable);
									}

									Insert(hub->IpTable, e);
								}
							}
						}
						else
						{
							if (e->Session == s)
							{
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
							else
							{
								if ((s->Policy->CheckIP || s->Policy->DHCPForce) &&
									((e->UpdatedTime + IP_TABLE_EXCLUSIVE_TIME) >= now))
								{
									char ip_address[32];
									char mac_str[48];
									IPToStr(ip_address, sizeof(ip_address), &ip);


									MacToStr(mac_str, sizeof(mac_str), e->MacAddress);

									if (no_heavy == false)
									{
										HLog(hub, "LH_IP_CONFLICT", s->Name, ip_address, e->Session->Name, mac_str,
											e->CreatedTime, e->UpdatedTime, e->DhcpAllocated, now);
									}

									goto DISCARD_PACKET;
								}

								if (s->Policy->DHCPForce)
								{
									if (e->DhcpAllocated == false)
									{
										char ipstr[MAX_SIZE];

										IPToStr32(ipstr, sizeof(ipstr), uint_ip);
										if (no_heavy == false)
										{
											HLog(hub, "LH_DHCP_FORCE", s->Name, ipstr);
										}
										goto DISCARD_PACKET;
									}
								}

								e->Session = s;
								e->UpdatedTime = now;
								Copy(e->MacAddress, packet->MacAddressSrc, 6);
							}
						}
					}
				}

				if (s != NULL && broadcast_mode)
				{
					if (CheckBroadcastStorm(hub, s, packet) == false)
					{
						goto DISCARD_PACKET;
					}
				}

				if (hub->MonitorList->num_item != 0)
				{
					LockList(hub->MonitorList);
					{
						UINT i;
						void *data;
						UINT size = packet->PacketSize;
						for (i = 0;i < LIST_NUM(hub->MonitorList);i++)
						{
							SESSION *monitor_session = (SESSION *)LIST_DATA(hub->MonitorList, i);

							if (monitor_session->PacketAdapter->Param != NULL)
							{
								data = MallocFast(size);
								Copy(data, packet->PacketData, size);
								StorePacketToHubPa((HUB_PA *)monitor_session->PacketAdapter->Param,
									s, data, size, packet, false, false);
							}
						}
					}
					UnlockList(hub->MonitorList);
				}

				if (broadcast_mode == false)
				{
					if (dest_pa != NULL)
					{
						if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
							(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
							(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
						{
							DeleteIPv6DefaultRouterInRA(packet);
						}
						if (dest_session->Policy->RSandRAFilter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_ICMPV6 &&
								(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
								 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPFilter)
						{
							if (packet->TypeL3 == L3_IPV4 &&
								packet->TypeL4 == L4_UDP &&
								packet->TypeL7 == L7_DHCPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->DHCPv6Filter)
						{
							if (packet->TypeL3 == L3_IPV6 &&
								packet->TypeL4 == L4_UDP &&
								(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->ArpDhcpOnly)
						{
							if (packet->BroadcastPacket)
							{
								bool b = true;

								if (packet->TypeL3 == L3_IPV4 &&
									packet->TypeL4 == L4_UDP &&
									packet->TypeL7 == L7_DHCPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_ARPV4)
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_UDP &&
									(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
								{
									b = false;
								}
								else if (packet->TypeL3 == L3_IPV6 &&
									packet->TypeL4 == L4_ICMPV6)
								{
									b = false;
								}

								if (b)
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}
						if (dest_session->Policy->FilterIPv4)
						{
							if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterIPv6)
						{
							if (packet->TypeL3 == L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}
						if (dest_session->Policy->FilterNonIP)
						{
							if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL &&
							((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
							s->Policy->PrivacyFilter &&
							dest_session->Policy->PrivacyFilter)
							)
						{
							if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
							{
								if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
								{
									goto DISCARD_UNICAST_PACKET;
								}
							}
						}

						if (s != NULL)
						{
							if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
								Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						if (s != NULL)
						{
							if (PacketLog(s->Hub, s, dest_session, packet, now) == false)
							{
								goto DISCARD_UNICAST_PACKET;
							}
						}

						StorePacketToHubPa(dest_pa, s, packet->PacketData, packet->PacketSize, packet, false, false);
					}
					else
					{
DISCARD_UNICAST_PACKET:
						Free(packet->PacketData);
					}
				}
				else
				{
					UINT current_tcp_queue_size = 0;

					if (s != NULL)
					{
						if (PacketLog(s->Hub, s, NULL, packet, now) == false)
						{
							goto DISCARD_BROADCAST_PACKET;
						}
					}

					LockList(hub->SessionList);
					{
						UINT i, num = LIST_NUM(hub->SessionList);
						for (i = 0;i < num;i++)
						{
							SESSION *dest_session = LIST_DATA(hub->SessionList, i);
							HUB_PA *dest_pa = (HUB_PA *)dest_session->PacketAdapter->Param;
							bool discard = false;

							if (dest_session != s)
							{
								bool delete_default_router_in_ra = false;

								if (dest_session->IsMonitorMode)
								{
									discard = true;
								}

								if (dest_session->NormalClient)
								{
									if (dormant_interval != 0)
									{
										if (dest_session->LastCommTimeForDormant == 0 ||
											(dest_session->LastCommTimeForDormant + dormant_interval) < now)
										{
											discard = true;
										}
									}
								}

								if (tcp_queue_quota != 0)
								{
									current_tcp_queue_size = CedarGetCurrentTcpQueueSize(hub->Cedar);

									if (current_tcp_queue_size >= tcp_queue_quota)
									{
										if (dest_session->Connection != NULL &&
											dest_session->Connection->Protocol == CONNECTION_TCP)
										{
											discard = true;
										}

										if (dest_session->LinkModeServer)
										{
											LINK *k = dest_session->Link;

											discard = true;
										}
									}
								}

								if (dest_session->VLanId != 0 && packet->TypeL3 == L3_TAGVLAN &&
									packet->VlanId != dest_session->VLanId)
								{
									discard = true;
								}

								if (dest_session->Policy->NoIPv6DefaultRouterInRA ||
									(dest_session->Policy->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session) ||
									(hub->Option->NoIPv6DefaultRouterInRAWhenIPv6 && dest_session->IPv6Session))
								{
									if (packet->TypeL3 == L3_IPV6 && packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										if (packet->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
										{
											delete_default_router_in_ra = true;
										}
									}
								}
								if (dest_session->Policy->RSandRAFilter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_ICMPV6 &&
										(packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
										 packet->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPFilter)
								{
									if (packet->TypeL3 == L3_IPV4 &&
										packet->TypeL4 == L4_UDP &&
										packet->TypeL7 == L7_DHCPV4)
									{
										discard = true;
									}
								}

								if (dest_session->Policy->DHCPv6Filter)
								{
									if (packet->TypeL3 == L3_IPV6 &&
										packet->TypeL4 == L4_UDP &&
										(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
									{
										discard = true;
									}
								}

								if (dest_session->Policy->ArpDhcpOnly)
								{
									if (packet->BroadcastPacket)
									{
										bool b = true;

										if (packet->TypeL3 == L3_IPV4 &&
											packet->TypeL4 == L4_UDP &&
											packet->TypeL7 == L7_DHCPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_ARPV4)
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_UDP &&
											(Endian16(packet->L4.UDPHeader->DstPort) == 546 || Endian16(packet->L4.UDPHeader->DstPort) == 547))
										{
											b = false;
										}
										else if (packet->TypeL3 == L3_IPV6 &&
											packet->TypeL4 == L4_ICMPV6)
										{
											b = false;
										}

										if (discard == false)
										{
											discard = b;
										}
									}
								}

								if (dest_session->Policy->FilterIPv4)
								{
									if (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterIPv6)
								{
									if (packet->TypeL3 == L3_IPV6)
									{
										discard = true;
									}
								}
								if (dest_session->Policy->FilterNonIP)
								{
									if (packet->TypeL3 != L3_IPV4 && packet->TypeL3 != L3_ARPV4 && packet->TypeL3 != L3_IPV6)
									{
										discard = true;
									}
								}

								if (s != NULL &&
									((drop_broadcast_packet_privacy || packet->BroadcastPacket == false) &&
									s->Policy->PrivacyFilter &&
									dest_session->Policy->PrivacyFilter)
									)
								{
									if (drop_arp_packet_privacy || packet->TypeL3 != L3_ARPV4)
									{
										if (allow_same_user_packet_privacy == false || StrCmp(s->Username, dest_session->Username))
										{
											discard = true;
										}
									}
								}

								if (s != NULL)
								{
									if (Cmp(packet->MacAddressSrc, s->Hub->HubMacAddr, 6) == 0 ||
										Cmp(packet->MacAddressDest, s->Hub->HubMacAddr, 6) == 0)
									{
										discard = true;
									}
								}

								if (discard == false && dest_pa != NULL)
								{
									if (s == NULL ||
										ApplyAccessListToForwardPacket(s->Hub, s, dest_pa->Session, packet))
									{
										data = MallocFast(packet->PacketSize);
										Copy(data, packet->PacketData, packet->PacketSize);
										size = packet->PacketSize;

										if (delete_default_router_in_ra)
										{
											PKT *pkt2 = ParsePacket(data, size);

											DeleteIPv6DefaultRouterInRA(pkt2);

											FreePacket(pkt2);
										}

										StorePacketToHubPa(dest_pa, s, data, size, packet, true, true);
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
	}
	UnlockHashList(hub->MacHashTable);
}

bool CheckMaxLoggedPacketsPerMinute(SESSION *s, UINT max_packets, UINT64 now)
{
	UINT64 minute = 60 * 1000;
	if (s == NULL || max_packets == 0)
	{
		return true;
	}

	if ((s->Policy != NULL && s->Policy->NoBroadcastLimiter) ||
		s->BridgeMode || s->LinkModeServer || s->LinkModeClient)
	{
		return true;
	}

	if (s->MaxLoggedPacketsPerMinuteStartTick == 0 ||
		((s->MaxLoggedPacketsPerMinuteStartTick + minute) <= now))
	{
		s->MaxLoggedPacketsPerMinuteStartTick = now;
		s->CurrentNumPackets = 0;
	}

	s->CurrentNumPackets++;
	if (s->CurrentNumPackets > max_packets)
	{
		return false;
	}

	return true;
}

bool IsIPManagementTargetForHUB(IP *ip, HUB *hub)
{
	if (ip == NULL || hub == NULL)
	{
		return false;
	}

	if (hub->Option == NULL)
	{
		return true;
	}

	if (IsIP4(ip))
	{
		if (hub->Option->ManageOnlyPrivateIP)
		{
			if (IsIPPrivate(ip) == false)
			{
				return false;
			}
		}
	}
	else
	{
		if (hub->Option->ManageOnlyLocalUnicastIPv6)
		{
			UINT ip_type = GetIPAddrType6(ip);

			if (!(ip_type & IPV6_ADDR_LOCAL_UNICAST))
			{
				return false;
			}
		}
	}

	return true;
}

STORM *AddStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM *s;
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	s = ZeroMalloc(sizeof(STORM));
	if (src_ip != NULL)
	{
		Copy(&s->SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&s->DestIp, dest_ip, sizeof(IP));
	}
	Copy(s->MacAddress, mac_address, 6);
	s->StrictMode = strict;

	Insert(pa->StormList, s);

	return s;
}

STORM *SearchStormList(HUB_PA *pa, UCHAR *mac_address, IP *src_ip, IP *dest_ip, bool strict)
{
	STORM t, *s;
	if (pa == NULL || mac_address == NULL)
	{
		return NULL;
	}

	Zero(&t, sizeof(t));
	if (src_ip != NULL)
	{
		Copy(&t.SrcIp, src_ip, sizeof(IP));
	}
	if (dest_ip != NULL)
	{
		Copy(&t.DestIp, dest_ip, sizeof(IP));
	}
	Copy(t.MacAddress, mac_address, 6);

	t.StrictMode = strict;

	s = Search(pa->StormList, &t);

	return s;
}

void StorePacketToHubPa(HUB_PA *dest, SESSION *src, void *data, UINT size, PKT *packet, bool is_flooding, bool no_check_acl)
{
	BLOCK *b;
	if (dest == NULL || data == NULL)
	{
		return;
	}

	if (size < 14)
	{
		Free(data);
		return;
	}

	if (no_check_acl == false)
	{
		if (src != NULL)
		{
			if (ApplyAccessListToForwardPacket(src->Hub, src, dest->Session, packet) == false)
			{
				Free(data);
				return;
			}
		}
	}

	if (src != NULL)
	{
		if (dest->Session->Policy->MaxDownload != 0)
		{
			if (packet != NULL && IsMostHighestPriorityPacket(dest->Session, packet) == false)
			{
				TRAFFIC_LIMITER *tr = &dest->DownloadLimiter;
				IntoTrafficLimiter(tr, packet);

				if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > dest->Session->Policy->MaxDownload)
				{
					Free(data);
					return;
				}
			}
		}
	}

	if (packet != NULL && src != NULL && src->Hub != NULL && src->Hub->Option != NULL && src->Hub->Option->FixForDLinkBPDU)
	{
		// Workaround for D-Link BPDUs sent from these source MACs
		UCHAR *mac = packet->MacAddressSrc;
		if ((mac[0] == 0x00 && mac[1] == 0x80 && mac[2] == 0xc8 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00) ||
			(mac[0] == 0x00 && mac[1] == 0x0d && mac[2] == 0x88 && mac[3] == 0x00 && mac[4] == 0x00 && mac[5] == 0x00))
		{
			SESSION *session = dest->Session;

			if (session != NULL)
			{
				if (session->Policy != NULL && session->Policy->CheckMac)
				{
					UCHAR hash[MD5_SIZE];
					Md5(hash, packet->PacketData, packet->PacketSize);

					Copy(session->LastDLinkSTPPacketDataHash, hash, MD5_SIZE);
					session->LastDLinkSTPPacketSendTick = Tick64();
				}
			}
		}
	}

	if (dest->Session != NULL && dest->Session->VLanId != 0)
	{
		UINT vlan_tpid = 0;
		if (src != NULL && src->Hub != NULL && src->Hub->Option != NULL)
		{
			vlan_tpid = src->Hub->Option->VlanTypeId;
		}
		if (VLanRemoveTag(&data, &size, dest->Session->VLanId, vlan_tpid) == false)
		{
			Free(data);
			return;
		}
	}

	if (src != NULL && dest->Session != NULL && src->Hub != NULL && src->Hub->Option != NULL)
	{
		if (dest->Session->AdjustMss != 0 ||
			(dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0))
		{
			if (src->Hub->Option->DisableAdjustTcpMss == false)
			{
				UINT target_mss = INFINITE;
				
				if (dest->Session->AdjustMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->AdjustMss);
				}

				if (dest->Session->UseUdpAcceleration && dest->Session->UdpAccelMss != 0)
				{
					target_mss = MIN(target_mss, dest->Session->UdpAccelMss);
				}

				if (target_mss != INFINITE)
				{
					AdjustTcpMssL2(data, size, target_mss, src->Hub->Option->VlanTypeId);
				}
			}
		}
	}

	b = NewBlock(data, size, 0);

	LockQueue(dest->PacketQueue);
	{
		if (dest->PacketQueue->num_item < MAX_STORED_QUEUE_NUM)
		{
			InsertQueue(dest->PacketQueue, b);

			if (is_flooding)
			{
				if (src != NULL)
				{
					b->IsFlooding = true;
					CedarAddCurrentTcpQueueSize(src->Cedar, b->Size);
				}
			}
		}
		else
		{
			FreeBlock(b);
		}
	}
	UnlockQueue(dest->PacketQueue);

	if (src != NULL)
	{
		AddCancelList(src->CancelList, dest->Cancel);
	}
	else
	{
		Cancel(dest->Cancel);
	}
}

bool DeleteIPv6DefaultRouterInRA(PKT *p)
{
	if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
		(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
	{
		if (p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime != 0)
		{
			p->ICMPv6HeaderPacketInfo.Headers.RouterAdvertisementHeader->Lifetime = 0;

			p->L4.ICMPHeader->Checksum = 0;
			p->L4.ICMPHeader->Checksum =
				CalcChecksumForIPv6(&p->L3.IPv6Header->SrcAddress,
					&p->L3.IPv6Header->DestAddress, IP_PROTO_ICMPV6,
					p->L4.ICMPHeader, p->IPv6HeaderPacketInfo.PayloadSize, 0);
		}
	}

	return false;
}

bool StorePacketFilterByPolicy(SESSION *s, PKT *p)
{
	POLICY *pol;
	HUB *hub;
	bool no_heavy = false;
	if (s == NULL || p == NULL)
	{
		return false;
	}

	hub = s->Hub;

	if (hub != NULL && hub->Option != NULL)
	{
		no_heavy = hub->Option->DoNotSaveHeavySecurityLogs;
	}

	pol = s->Policy;

	if (pol->NoServer)
	{
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[64], ip2[64];

					IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
					IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
							ip1, p->L4.TCPHeader->SrcPort);
					}

					return false;
				}
			}
		}
	}

	if (pol->NoServerV6)
	{
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_TCP)
			{
				UCHAR flag = p->L4.TCPHeader->Flag;
				if ((flag & TCP_SYN) && (flag & TCP_ACK))
				{
					char ip1[128], ip2[128];

					IP6AddrToStr(ip1, sizeof(ip1), &p->IPv6HeaderPacketInfo.IPv6Header->SrcAddress);
					IP6AddrToStr(ip2, sizeof(ip2), &p->IPv6HeaderPacketInfo.IPv6Header->DestAddress);

					if (no_heavy == false)
					{
						HLog(s->Hub, "LH_NO_SERVER", s->Name, ip2, p->L4.TCPHeader->DstPort,
							ip1, p->L4.TCPHeader->SrcPort);
					}

					return false;
				}
			}
		}
	}

	if (pol->ArpDhcpOnly && p->BroadcastPacket)
	{
		bool ok = false;

		if (p->TypeL3 == L3_ARPV4)
		{
			ok = true;
		}
		if (p->TypeL3 == L3_IPV4)
		{
			if (p->TypeL4 == L4_UDP)
			{
				if (p->TypeL7 == L7_DHCPV4)
				{
					ok = true;
				}
			}
		}
		if (p->TypeL3 == L3_IPV6)
		{
			if (p->TypeL4 == L4_ICMPV6)
			{
				ok = true;
			}
		}

		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->DstPort) == 547))
		{
			ok = true;
		}

		if (ok == false)
		{
			return false;
		}
	}

	if (pol->FilterIPv4)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x0800 || proto == 0x0806)
			{
				return false;
			}
		}
	}

	if (pol->FilterIPv6)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (proto == 0x86dd)
			{
				return false;
			}
		}
	}

	if (pol->FilterNonIP)
	{
		if (p->MacHeader != NULL)
		{
			USHORT proto = Endian16(p->MacHeader->Protocol);
			if (!(proto == 0x86dd || proto == 0x0800 || proto == 0x0806))
			{
				return false;
			}
		}
	}

	if (pol->DHCPFilter)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{

			return false;
		}
	}

	if (pol->DHCPv6Filter)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP)
		{
			if (Endian16(p->L4.UDPHeader->DstPort) == 546 ||
				Endian16(p->L4.UDPHeader->DstPort) == 547)
			{

				return false;
			}
		}
	}

	if (pol->DHCPNoServer)
	{
		if (p->TypeL3 == L3_IPV4 &&
			p->TypeL4 == L4_UDP &&
			p->TypeL7 == L7_DHCPV4)
		{
			DHCPV4_HEADER *h = p->L7.DHCPv4Header;
			if (h->OpCode == 2)
			{
				char ip1[64], ip2[64];

				IPToStr32(ip1, sizeof(ip1), p->L3.IPv4Header->SrcIP);
				IPToStr32(ip2, sizeof(ip2), p->L3.IPv4Header->DstIP);

				if (no_heavy == false)
				{
					HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
				}

				return false;
			}
		}
	}

	if (pol->DHCPv6NoServer)
	{
		if (p->TypeL3 == L3_IPV6 &&
			p->TypeL4 == L4_UDP &&
			(Endian16(p->L4.UDPHeader->DstPort) == 546 || Endian16(p->L4.UDPHeader->SrcPort) == 547))
		{
			char ip1[128], ip2[128];

			IP6AddrToStr(ip1, sizeof(ip1), &p->L3.IPv6Header->SrcAddress);
			IP6AddrToStr(ip2, sizeof(ip2), &p->L3.IPv6Header->DestAddress);

			if (no_heavy == false)
			{
				HLog(s->Hub, "LH_NO_DHCP", s->Name, ip1, ip2);
			}

			return false;
		}
	}

	if (pol->RSandRAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			(p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_SOLICIATION ||
			 p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT))
		{
			return false;
		}
	}

	if (pol->RAFilter)
	{
		if (p->TypeL3 == L3_IPV6 && p->TypeL4 == L4_ICMPV6 &&
			p->ICMPv6HeaderPacketInfo.Type == ICMPV6_TYPE_ROUTER_ADVERTISEMENT)
		{
			return false;
		}
	}

	if (p->TypeL3 == L3_IPV4 &&
		p->TypeL4 == L4_UDP &&
		p->TypeL7 == L7_DHCPV4 &&
		(s->Hub != NULL && s->Hub->Option->NoIpTable == false))
	{
		DHCPV4_HEADER *h = p->L7.DHCPv4Header;
		if (h->OpCode == 2 && p->DhcpOpCode == DHCP_ACK)
		{
			if (h->HardwareType == ARP_HARDWARE_TYPE_ETHERNET)
			{
				if (h->HardwareAddressSize == 6)
				{
					if (h->YourIP != 0 && h->YourIP != 0xffffffff)
					{
						UINT ip_uint = h->YourIP;
						IP ip;
						IP_TABLE_ENTRY *e, t;
						MAC_TABLE_ENTRY *mac_table, mt;
						mt.VlanId = 0;
						Copy(&mt.MacAddress, &h->ClientMacAddress, 6);
						mac_table = SearchHash(hub->MacHashTable, &mt);

						if (mac_table != NULL)
						{
							bool new_entry = true;
							UINTToIP(&ip, ip_uint);
							Copy(&t.Ip, &ip, sizeof(IP));

							e = Search(hub->IpTable, &t);
							if (e == NULL)
							{
								e = ZeroMalloc(sizeof(IP_TABLE_ENTRY));
UPDATE_DHCP_ALLOC_ENTRY:
								e->CreatedTime = e->UpdatedTime = Tick64();
								e->DhcpAllocated = true;
								Copy(&e->Ip, &ip, sizeof(IP));
								e->Session = mac_table->Session;
								Copy(e->MacAddress, p->MacAddressDest, 6);

								if (new_entry)
								{
									DeleteExpiredIpTableEntry(hub->IpTable);
									if (LIST_NUM(hub->IpTable) >= MAX_IP_TABLES)
									{
										DeleteOldIpTableEntry(hub->IpTable);
									}
									Insert(hub->IpTable, e);

								
									if ((hub->Option != NULL && hub->Option->NoDhcpPacketLogOutsideHub == false) || mac_table->Session != s)
									{
										char dhcp_mac_addr[64];
										char dest_mac_addr[64];
										char dest_ip_addr[64];
										char server_ip_addr[64];
										MacToStr(dhcp_mac_addr, sizeof(dhcp_mac_addr), p->MacAddressSrc);
										MacToStr(dest_mac_addr, sizeof(dest_mac_addr), h->ClientMacAddress);
										IPToStr(dest_ip_addr, sizeof(dest_ip_addr), &ip);
										IPToStr32(server_ip_addr, sizeof(server_ip_addr), p->L3.IPv4Header->SrcIP);

										if (no_heavy == false)
										{
											HLog(s->Hub, "LH_REGIST_DHCP", s->Name, dhcp_mac_addr, server_ip_addr,
												mac_table->Session->Name, dest_mac_addr, dest_ip_addr);
										}
									}
								}
							}
							else
							{
								new_entry = false;
								goto UPDATE_DHCP_ALLOC_ENTRY;
							}
						}
					}
				}
			}
		}
	}

	return true;
}

bool IsMostHighestPriorityPacket(SESSION *s, PKT *p)
{
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (p->TypeL3 == L3_ARPV4)
	{
		return true;
	}

	if (p->TypeL3 == L3_IPV4)
	{
		if (p->TypeL4 == L4_ICMPV4)
		{
			return true;
		}

		if (p->TypeL4 == L4_TCP)
		{
			if ((p->L4.TCPHeader->Flag & TCP_SYN) || (p->L4.TCPHeader->Flag & TCP_FIN)
				|| (p->L4.TCPHeader->Flag & TCP_RST))
			{
				return true;
			}
		}

		if (p->TypeL4 == L4_UDP)
		{
			if (p->TypeL7 == L7_DHCPV4)
			{
				return true;
			}
		}
	}

	return false;
}

void IntoTrafficLimiter(TRAFFIC_LIMITER *tr, PKT *p)
{
	UINT64 now = Tick64();
	if (tr == NULL || p == NULL)
	{
		return;
	}

	if (tr->LastTime == 0 || tr->LastTime > now ||
		(tr->LastTime + LIMITER_SAMPLING_SPAN) < now)
	{
		tr->Value = 0;
		tr->LastTime = now;
	}

	tr->Value += (UINT64)p->PacketSize * (UINT64)8;
}

bool StorePacketFilterByTrafficLimiter(SESSION *s, PKT *p)
{
	HUB_PA *pa;
	TRAFFIC_LIMITER *tr;
	if (s == NULL || p == NULL)
	{
		return false;
	}

	if (s->Policy->MaxUpload == 0)
	{
		return true;
	}

	pa = (HUB_PA *)s->PacketAdapter->Param;
	tr = &pa->UploadLimiter;

	if (IsMostHighestPriorityPacket(s, p))
	{
		return true;
	}

	IntoTrafficLimiter(tr, p);

	if ((tr->Value * (UINT64)1000 / (UINT64)LIMITER_SAMPLING_SPAN) > s->Policy->MaxUpload)
	{
		return false;
	}

	return true;
}

bool StorePacketFilter(SESSION *s, PKT *packet)
{
	if (s == NULL || packet == NULL)
	{
		return false;
	}

	if (StorePacketFilterByTrafficLimiter(s, packet) == false)
	{
		return false;
	}

	if (StorePacketFilterByPolicy(s, packet) == false)
	{
		return false;
	}

	if (ApplyAccessListToStoredPacket(s->Hub, s, packet) == false)
	{
		return false;
	}

	return true;
}

PACKET_ADAPTER *GetHubPacketAdapter()
{
	PACKET_ADAPTER *pa = NewPacketAdapter(HubPaInit,
		HubPaGetCancel, HubPaGetNextPacket, HubPaPutPacket, HubPaFree);

	return pa;
}
