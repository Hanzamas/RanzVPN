// PacketLog.c
// Packet log of the Virtual Hubs: which frames are logged, and their CSV line

#include "PacketLog.h"

#include "Hub.h"
#include "LogWriter.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"

// Log the frame packet of src_session (to dest_session, NULL for a flooded frame) when the hub logs its kind. False
// drops the frame (MaxLoggedPacketsPerMinute). wait gets true when the source session has PACKET_LOG_WAIT_RECORDS or
// more records queued: the caller then calls PacketLogWait once it holds no hub lock. With wait NULL the wait happens
// here
bool PacketLog(HUB *hub, SESSION *src_session, SESSION *dest_session, PKT *packet, UINT64 now, bool *wait) {
	HUB_OPTION *opt = NULL;
	if (hub == NULL || src_session == NULL || packet == NULL)
		return true;

	if (hub->LogSetting.SavePacketLog == false)
		return true;

	if (Cmp(hub->HubMacAddr, packet->MacAddressSrc, 6) == 0 ||
	    Cmp(hub->HubMacAddr, packet->MacAddressDest, 6) == 0)
		return true;

	opt = hub->Option;

	UINT level = CalcPacketLoggingLevel(&hub->LogSetting, packet);
	if (level == PACKET_LOG_NONE)
		return true;

	if (opt->NoIPv4PacketLog && (packet->TypeL3 == L3_IPV4 || packet->TypeL3 == L3_ARPV4))
		return true;

	if (opt->NoIPv6PacketLog && packet->TypeL3 == L3_IPV6)
		return true;

	if (opt->MaxLoggedPacketsPerMinute != 0) {
		if (CheckMaxLoggedPacketsPerMinute(src_session, opt->MaxLoggedPacketsPerMinute, now) == false)
			return false;
	}

	PKT *p = ClonePacket(packet, level == PACKET_LOG_ALL ? true : false);

	PACKET_LOG *pl = ZeroMalloc(sizeof(PACKET_LOG));

	pl->Cedar = hub->Cedar;
	pl->Packet = p;
	pl->SrcSessionName = CopyStr(src_session->Name);
	if (dest_session != NULL)
		pl->DestSessionName = CopyStr(dest_session->Name);
	else
		pl->DestSessionName = CopyStr("");

	if (opt == NULL || opt->NoPhysicalIPOnPacketLog == false) {
		if (src_session->NormalClient)
			StrCpy(pl->SrcPhysicalIP, sizeof(pl->SrcPhysicalIP), src_session->ClientIP);

		if (dest_session != NULL && dest_session->NormalClient)
			StrCpy(pl->DestPhysicalIP, sizeof(pl->DestPhysicalIP), dest_session->ClientIP);

		pl->WritePhysicalIP = true;
	}

	// Back-pressure: a session with too many records that the log writer has not written yet waits for it. StorePacket
	// calls PacketLog under the hub-wide MacHashTable lock, so it waits after the lock (PacketLogWait); a wait under
	// the lock stalled the forwarding of every session of the hub for up to 250 ms per frame
	if (src_session->LoggingRecordCount != NULL && src_session->LoggingRecordCount->c >= PACKET_LOG_WAIT_RECORDS) {
		if (wait != NULL)
			*wait = true;
		else
			PacketLogWait(src_session);
	}

	pl->SrcSession = src_session;
	AddRef(src_session->ref);

	Inc(src_session->LoggingRecordCount);

	InsertRecord(hub->PacketLogger, pl, PacketLogParseProc, PacketLogFreeProc, true);

	return true;
}

// The back-pressure wait of PacketLog: up to 250 ms, in steps of 50 ms, while src_session has PACKET_LOG_WAIT_RECORDS
// or more packet log records queued. The caller holds no hub lock
void PacketLogWait(SESSION *src_session) {
	if (src_session == NULL || src_session->LoggingRecordCount == NULL)
		return;

	UINT n = 0;
	while (src_session->LoggingRecordCount->c >= PACKET_LOG_WAIT_RECORDS) {
		SleepThread(50);
		n++;
		if (n >= 5)
			break;
	}
}

// A TCP segment that opens or closes a connection
static bool IsTcpConnectionFlag(UCHAR flag) {
	return ((flag & (TCP_SYN | TCP_RST | TCP_FIN)) != 0);
}

UINT CalcPacketLoggingLevel(HUB_LOG *g, PKT *packet) {
	UINT ret = 0;
	if (g == NULL || packet == NULL)
		return PACKET_LOG_NONE;

	ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ETHERNET]);

	switch (packet->TypeL3) {
	case L3_ARPV4:
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ARP]);
		break;

	case L3_IPV4:
	case L3_IPV6:
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_IP]);

		switch (packet->TypeL4) {
		case L4_ICMPV4:
		case L4_ICMPV6:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_ICMP]);
			break;

		case L4_TCP:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP]);

			if (IsTcpConnectionFlag(packet->L4.TCPHeader->Flag))
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);

			break;

		case L4_UDP:
			ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_UDP]);

			switch (packet->TypeL7) {
			case L7_DHCPV4:
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_DHCP]);
				break;

			case L7_IKECONN:
			case L7_DNS:
				ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);
				break;
			}

			break;
		}

		break;
	}

	if (packet->HttpLog != NULL)
		ret = MAX(ret, g->PacketLogConfig[PACKET_LOG_TCP_CONN]);

	return ret;
}

static char *BuildHttpLogStr(HTTPLOG *h) {
	char url[MAX_SIZE];
	char nullchar = 0;
	if (h == NULL)
		return CopyStr("");

	BUF *b = NewBuf();

	if (StartWith(h->Path, "http://") || StartWith(h->Path, "https://")) {
		StrCpy(url, sizeof(url), h->Path);
	} else {
		if (h->IsSsl == false)
			if (h->Port == 80)
				Format(url, sizeof(url), "http://%s%s",
				       h->Hostname, h->Path);
			else
				Format(url, sizeof(url), "http://%s:%u%s",
				       h->Hostname, h->Port, h->Path);
		else if (h->Port == 443)
			Format(url, sizeof(url), "https://%s/",
			       h->Hostname);
		else
			Format(url, sizeof(url), "https://%s:%u/",
			       h->Hostname, h->Port);
	}

	AddLogBufToStr(b, "HttpMethod", h->Method);
	AddLogBufToStr(b, "HttpUrl", url);
	AddLogBufToStr(b, "HttpProtocol", h->Protocol);
	AddLogBufToStr(b, "HttpReferer", h->Referer);
	AddLogBufToStr(b, "HttpUserAgent", h->UserAgent);

	WriteBuf(b, &nullchar, 1);

	char *ret = CopyStr(b->Buf);

	FreeBuf(b);

	return ret;
}

void AddLogBufToStr(BUF *b, char *name, char *value) {
	char tmp[MAX_SIZE * 2];
	char *p = NULL;
	if (b == NULL || value == NULL)
		return;

	if (IsEmptyStr(value))
		return;

	tmp[0] = 0;

	if (IsEmptyStr(name) == false) {
		p = &tmp[StrLen(tmp)];
		StrCat(tmp, sizeof(tmp), name);
		MakeSafeLogStr(p);
		StrCat(tmp, sizeof(tmp), "=");
	}

	p = &tmp[StrLen(tmp)];
	StrCat(tmp, sizeof(tmp), value);
	MakeSafeLogStr(p);
	StrCat(tmp, sizeof(tmp), " ");

	WriteBuf(b, tmp, StrLen(tmp));
}

void MakeSafeLogStr(char *str) {
	bool is_http = false;
	if (str == NULL)
		return;

	if (str[0] == 'h' && str[1] == 't' && str[2] == 't' && str[3] == 'p' &&
	    ((str[4] == 's' && str[5] == ':') || (str[4] == ':')))
		is_http = true;

	EnPrintableAsciiStr(str, '?');

	UINT len = StrLen(str);
	for (UINT i = 0; i < len; i++) {
		if (str[i] == ',') {
			str[i] = '.';
		} else if (str[i] == ' ') {
			if (is_http == false)
				str[i] = '_';
		}
	}
}

// The packet log tokens of a TCP segment. suffix is "v4" or "v6"
static void PacketLogTcp(TOKEN_LIST *t, PACKET_LOG *pl, PKT *p, char *suffix) {
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "%s%s", (IsTcpConnectionFlag(p->L4.TCPHeader->Flag) ? "TCP_CONNECT" : "TCP_DATA"), suffix);
	t->Token[6] = CopyStr(tmp);
	t->Token[7] = TcpFlagStr(p->L4.TCPHeader->Flag);

	t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->SrcPort), false);
	t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.TCPHeader->DstPort), false);

	ToStr(tmp, Endian32(p->L4.TCPHeader->SeqNumber));
	t->Token[12] = CopyStr(tmp);

	ToStr(tmp, Endian32(p->L4.TCPHeader->AckNumber));
	t->Token[13] = CopyStr(tmp);

	snprintf(tmp, sizeof(tmp), "WindowSize=%u", Endian16(p->L4.TCPHeader->WindowSize));

	if (p->HttpLog != NULL) {
		char *http_str = BuildHttpLogStr(p->HttpLog);

		UINT tmp2_size = StrLen(http_str) + 16 + StrLen(tmp);
		char *tmp2 = Malloc(tmp2_size);

		StrCpy(tmp2, tmp2_size, tmp);

		if (IsEmptyStr(http_str) == false) {
			StrCat(tmp2, tmp2_size, " ");
			StrCat(tmp2, tmp2_size, http_str);
		}

		Free(http_str);

		t->Token[14] = tmp2;
	} else {
		t->Token[14] = CopyStr(tmp);
	}
}

// The packet log tokens of an IKE connection packet. suffix is "v4" or "v6"
static void PacketLogIke(TOKEN_LIST *t, const PKT *p, char *suffix) {
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "IKE_CONNECT%s", suffix);
	t->Token[6] = CopyStr(tmp);

	if (p->L7.IkeHeader != NULL) {
		if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_MAIN)
			t->Token[7] = CopyStr("MainMode");
		else if (p->L7.IkeHeader->ExchangeType == IKE_EXCHANGE_TYPE_AGGRESSIVE)
			t->Token[7] = CopyStr("AggressiveMode");

		Format(tmp, sizeof(tmp), "InitiatorCookie=%I64u ResponderCookie=%I64u "
		                         "Version=0x%x ExchangeType=0x%x Flag=0x%x MessageId=%u MessageSize=%u",
		       Endian64(p->L7.IkeHeader->InitiatorCookie),
		       Endian64(p->L7.IkeHeader->ResponderCookie),
		       p->L7.IkeHeader->Version,
		       p->L7.IkeHeader->ExchangeType,
		       p->L7.IkeHeader->Flag,
		       Endian32(p->L7.IkeHeader->MessageId),
		       Endian32(p->L7.IkeHeader->MessageSize));

		t->Token[14] = CopyStr(tmp);
	}
}

// The packet log tokens of a DNS query. suffix is "v4" or "v6"
static void PacketLogDns(TOKEN_LIST *t, const PKT *p, char *suffix) {
	char tmp[MAX_SIZE];

	snprintf(tmp, sizeof(tmp), "DNS%s", suffix);
	t->Token[6] = CopyStr(tmp);
	t->Token[7] = CopyStr("DNS_Query");
	// The query name holds raw label bytes from the wire
	t->Token[14] = CopyStr(p->DnsQueryHost);
	MakeSafeLogStr(t->Token[14]);
}

// The packet log tokens of a UDP datagram. suffix is "v4" or "v6"
static void PacketLogUdp(TOKEN_LIST *t, PACKET_LOG *pl, const PKT *p, char *suffix) {
	char tmp[MAX_SIZE];

	t->Token[9] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->SrcPort), true);
	t->Token[11] = PortStr(pl->Cedar, Endian16(p->L4.UDPHeader->DstPort), true);

	switch (p->TypeL7) {
	case L7_DHCPV4:
		t->Token[6] = CopyStr("DHCPv4");
		if (p->L7.DHCPv4Header->OpCode == 1)
			t->Token[7] = CopyStr("Request");
		else
			t->Token[7] = CopyStr("Response");

		{
			char ip1[64], ip2[64], ip3[64], ip4[64];
			IPToStr32(ip1, sizeof(ip1), p->L7.DHCPv4Header->ClientIP);
			IPToStr32(ip2, sizeof(ip2), p->L7.DHCPv4Header->YourIP);
			IPToStr32(ip3, sizeof(ip3), p->L7.DHCPv4Header->ServerIP);
			IPToStr32(ip4, sizeof(ip4), p->L7.DHCPv4Header->RelayIP);

			snprintf(tmp, sizeof(tmp),
			         "TransactionId=%u ClientIP=%s YourIP=%s ServerIP=%s RelayIP=%s",
			         Endian32(p->L7.DHCPv4Header->TransactionId),
			         ip1, ip2, ip3, ip4);

			t->Token[14] = CopyStr(tmp);
		}

		break;

	case L7_IKECONN:
		PacketLogIke(t, p, suffix);
		break;

	case L7_DNS:
		PacketLogDns(t, p, suffix);
		break;

	default:
		snprintf(tmp, sizeof(tmp), "UDP%s", suffix);
		t->Token[6] = CopyStr(tmp);
		break;
	}
}

// The packet log tokens of an ARP packet: the request and the response differ only in the text
static void PacketLogArp(TOKEN_LIST *t, const PKT *p) {
	ARPV4_HEADER *a = p->L3.ARPv4Header;
	char tmp[MAX_SIZE];
	bool request;

	t->Token[6] = CopyStr("ARPv4");

	switch (Endian16(a->Operation)) {
	case ARP_OPERATION_REQUEST:
		t->Token[7] = CopyStr("Request");
		request = true;
		break;

	case ARP_OPERATION_RESPONSE:
		t->Token[7] = CopyStr("Response");
		request = false;
		break;

	default:
		return;
	}

	if (Endian16(a->HardwareType) == ARP_HARDWARE_TYPE_ETHERNET &&
	    a->HardwareSize == 6 &&
	    Endian16(a->ProtocolType) == MAC_PROTO_IPV4 &&
	    a->ProtocolSize == 4) {
		char src_mac[16];
		char src_ip[16];
		IP src_ip_st;
		BinToStr(src_mac, sizeof(src_mac), a->SrcAddress, 6);
		UINTToIP(&src_ip_st, a->SrcIP);
		IPToStr(src_ip, sizeof(src_ip), &src_ip_st);

		if (request) {
			char dst_ip[16];
			IP dst_ip_st;
			UINTToIP(&dst_ip_st, a->TargetIP);
			IPToStr(dst_ip, sizeof(dst_ip), &dst_ip_st);
			snprintf(tmp, sizeof(tmp), "Who has %s? Please Tell %s(%s)",
			         dst_ip, src_mac, src_ip);
		} else {
			snprintf(tmp, sizeof(tmp), "%s has %s",
			         src_mac, src_ip);
		}

		t->Token[14] = CopyStr(tmp);
	}
}

char *PacketLogParseProc(RECORD *rec) {
	char tmp[MAX_SIZE];
	if (rec == NULL)
		return NULL;

	PACKET_LOG *pl = (PACKET_LOG *)rec->Data;
	PKT *p = pl->Packet;

	TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = 16;
	if (pl->WritePhysicalIP)
		t->NumTokens += 2;
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	t->Token[0] = pl->SrcSessionName;

	t->Token[1] = pl->DestSessionName;

	BinToStr(tmp, sizeof(tmp), p->MacAddressSrc, 6);

	t->Token[2] = CopyStr(tmp);
	BinToStr(tmp, sizeof(tmp), p->MacAddressDest, 6);

	t->Token[3] = CopyStr(tmp);

	snprintf(tmp, sizeof(tmp), "0x%04X", Endian16(p->MacHeader->Protocol));
	t->Token[4] = CopyStr(tmp);

	ToStr(tmp, p->PacketSize);
	t->Token[5] = CopyStr(tmp);

	switch (p->TypeL3) {
	case L3_ARPV4:
		PacketLogArp(t, p);
		break;

	case L3_IPV4:
		switch (p->TypeL4) {
		case L4_ICMPV4:
			t->Token[6] = CopyStr("ICMPv4");

			switch (p->L4.ICMPHeader->Type) {
			case ICMP_TYPE_ECHO_REQUEST:
				t->Token[7] = CopyStr("Echo Request");
				break;

			case ICMP_TYPE_ECHO_RESPONSE:
				t->Token[7] = CopyStr("Echo Reply");
				break;
			}
			break;

		case L4_TCP:
			PacketLogTcp(t, pl, p, "v4");
			break;

		case L4_UDP:
			PacketLogUdp(t, pl, p, "v4");
			break;

		case L4_FRAGMENT:
			snprintf(tmp, sizeof(tmp), "IPv4_Fragment(0x%02X)", p->L3.IPv4Header->Protocol);
			t->Token[6] = CopyStr(tmp);
			break;

		case L4_UNKNOWN:
			snprintf(tmp, sizeof(tmp), "IPv4(0x%02X)", p->L3.IPv4Header->Protocol);
			t->Token[6] = CopyStr(tmp);
			break;
		}

		IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->SrcIP);
		t->Token[8] = CopyStr(tmp);

		IPToStr32(tmp, sizeof(tmp), p->L3.IPv4Header->DstIP);
		t->Token[10] = CopyStr(tmp);

		break;

	case L3_IPV6:
		switch (p->TypeL4) {
		case L4_ICMPV6: {
			char info[MAX_SIZE];
			ICMPV6_HEADER_INFO *icmp = &p->ICMPv6HeaderPacketInfo;
			ICMPV6_OPTION_LIST *ol = &icmp->OptionList;

			Zero(info, sizeof(info));

			t->Token[6] = CopyStr("ICMPv6");

			switch (icmp->Type) {
			case ICMPV6_TYPE_ECHO_REQUEST:
				t->Token[7] = CopyStr("Echo Request");
				snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
				StrCat(info, sizeof(info), tmp);
				break;

			case ICMPV6_TYPE_ECHO_RESPONSE:
				t->Token[7] = CopyStr("Echo Reply");
				snprintf(tmp, sizeof(tmp), "EchoDataSize=%u ", icmp->EchoDataSize);
				StrCat(info, sizeof(info), tmp);
				break;

			case ICMPV6_TYPE_ROUTER_SOLICIATION:
				t->Token[7] = CopyStr("Router Soliciation");
				break;

			case ICMPV6_TYPE_ROUTER_ADVERTISEMENT: {
				ICMPV6_ROUTER_ADVERTISEMENT_HEADER *h = icmp->Headers.RouterAdvertisementHeader;
				t->Token[7] = CopyStr("Router Advertisement");

				if (h != NULL) {
					snprintf(tmp, sizeof(tmp), "CurHopLimit=%u "
					                           "Flags=0x%02X Lifetime=%u ",
					         h->CurHopLimit, h->Flags, Endian16(h->Lifetime));
					StrCat(info, sizeof(info), tmp);
				}
			} break;

			case ICMPV6_TYPE_NEIGHBOR_SOLICIATION: {
				ICMPV6_NEIGHBOR_SOLICIATION_HEADER *h = icmp->Headers.NeighborSoliciationHeader;
				t->Token[7] = CopyStr("Neighbor Soliciation");

				if (h != NULL) {
					char tmp2[MAX_SIZE];

					IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

					snprintf(tmp, sizeof(tmp), "TargetAddress=%s ",
					         tmp2);
					StrCat(info, sizeof(info), tmp);
				}
			} break;

			case ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT: {
				ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *h = icmp->Headers.NeighborAdvertisementHeader;
				t->Token[7] = CopyStr("Neighbor Advertisement");

				if (h != NULL) {
					char tmp2[MAX_SIZE];

					IP6AddrToStr(tmp2, sizeof(tmp2), &h->TargetAddress);

					snprintf(tmp, sizeof(tmp), "TargetAddress=%s Flags=0x%02X ",
					         tmp2, h->Flags);
					StrCat(info, sizeof(info), tmp);
				}
			} break;

			default: {
				snprintf(tmp, sizeof(tmp), "Type=%u", icmp->Type);
				t->Token[7] = CopyStr(tmp);
			} break;
			}

			if (ol->SourceLinkLayer != NULL) {
				char tmp2[MAX_SIZE];
				BinToStr(tmp2, sizeof(tmp2), ol->SourceLinkLayer->Address, 6);
				snprintf(tmp, sizeof(tmp), "SourceLinkLayer=%s ", tmp2);
				StrCat(info, sizeof(info), tmp);
			}
			if (ol->TargetLinkLayer != NULL) {
				char tmp2[MAX_SIZE];
				BinToStr(tmp2, sizeof(tmp2), ol->TargetLinkLayer->Address, 6);
				snprintf(tmp, sizeof(tmp), "TargetLinkLayer=%s ", tmp2);
				StrCat(info, sizeof(info), tmp);
			}
			for (UINT i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++) {
				if (ol->Prefix[i] != NULL) {
					char tmp2[MAX_SIZE];
					IP6AddrToStr(tmp2, sizeof(tmp2), &ol->Prefix[i]->Prefix);
					snprintf(tmp, sizeof(tmp), "Prefix=%s/%u PrefixFlag=0x%02X ", tmp2,
					         ol->Prefix[i]->SubnetLength, ol->Prefix[i]->Flags);
					StrCat(info, sizeof(info), tmp);
				} else {
					break;
				}
			}
			if (ol->Mtu != NULL) {
				snprintf(tmp, sizeof(tmp), "Mtu=%u ", Endian32(ol->Mtu->Mtu));
				StrCat(info, sizeof(info), tmp);
			}

			Trim(info);

			if (IsEmptyStr(info) == false)
				t->Token[14] = CopyStr(info);
		} break;

		case L4_TCP:
			PacketLogTcp(t, pl, p, "v6");
			break;

		case L4_UDP:
			PacketLogUdp(t, pl, p, "v6");
			break;

		case L4_FRAGMENT:
			snprintf(tmp, sizeof(tmp), "IPv6_Fragment(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
			t->Token[6] = CopyStr(tmp);
			break;

		case L4_UNKNOWN:
			snprintf(tmp, sizeof(tmp), "IPv6(0x%02X)", p->IPv6HeaderPacketInfo.Protocol);
			t->Token[6] = CopyStr(tmp);
			break;
		}

		IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->SrcAddress);
		t->Token[8] = CopyStr(tmp);

		IP6AddrToStr(tmp, sizeof(tmp), &p->L3.IPv6Header->DestAddress);
		t->Token[10] = CopyStr(tmp);

		break;

	case L3_UNKNOWN:
		snprintf(tmp, sizeof(tmp), "Proto=0x%04X", Endian16(p->MacHeader->Protocol));
		t->Token[6] = CopyStr(tmp);
		break;
	}

	if (p->PacketData != NULL) {
		char *data = Malloc(p->PacketSize * 2 + 1);
		BinToStr(data, p->PacketSize * 2 + 1, p->PacketData, p->PacketSize);
		t->Token[15] = data;
	}

	if (StrLen(pl->SrcPhysicalIP) != 0)
		t->Token[16] = CopyStr(pl->SrcPhysicalIP);
	if (StrLen(pl->DestPhysicalIP) != 0)
		t->Token[17] = CopyStr(pl->DestPhysicalIP);

	char *s = GenCsvLine(t);
	FreeToken(t);

	FreeClonePacket(p);

	if (pl->SrcSession != NULL) {
		Dec(pl->SrcSession->LoggingRecordCount);
		ReleaseSession(pl->SrcSession);
	}
	Free(pl);

	return s;
}

// Release a packet log record that is not written, without making its line: its packet and session names, its
// logging record count and its reference to the source session
void PacketLogFreeProc(void *data) {
	PACKET_LOG *pl = (PACKET_LOG *)data;
	if (pl == NULL)
		return;

	Free(pl->SrcSessionName);
	Free(pl->DestSessionName);

	FreeClonePacket(pl->Packet);

	if (pl->SrcSession != NULL) {
		Dec(pl->SrcSession->LoggingRecordCount);
		ReleaseSession(pl->SrcSession);
	}
	Free(pl);
}

char *TcpFlagStr(UCHAR flag) {
	char tmp[MAX_SIZE];
	StrCpy(tmp, sizeof(tmp), "");

	if (flag & TCP_FIN)
		StrCat(tmp, sizeof(tmp), "FIN+");

	if (flag & TCP_SYN)
		StrCat(tmp, sizeof(tmp), "SYN+");

	if (flag & TCP_RST)
		StrCat(tmp, sizeof(tmp), "RST+");

	if (flag & TCP_PSH)
		StrCat(tmp, sizeof(tmp), "PSH+");

	if (flag & TCP_ACK)
		StrCat(tmp, sizeof(tmp), "ACK+");

	if (flag & TCP_URG)
		StrCat(tmp, sizeof(tmp), "URG+");

	if (StrLen(tmp) >= 1) {
		if (tmp[StrLen(tmp) - 1] == '+')
			tmp[StrLen(tmp) - 1] = 0;
	}

	return CopyStr(tmp);
}

char *PortStr(CEDAR *cedar, UINT port, bool udp) {
	char tmp[MAX_SIZE];
	if (cedar == NULL)
		return NULL;

	char *name = GetSvcName(cedar, udp, port);

	if (name == NULL)
		snprintf(tmp, sizeof(tmp), "%u", port);
	else
		snprintf(tmp, sizeof(tmp), "%s(%u)", name, port);

	return CopyStr(tmp);
}

char *GenCsvLine(TOKEN_LIST *t) {
	if (t == NULL)
		return NULL;

	BUF *b = NewBuf();
	for (UINT i = 0; i < t->NumTokens; i++) {
		if (t->Token[i] != NULL) {
			ReplaceForCsv(t->Token[i]);
			if (StrLen(t->Token[i]) == 0)
				WriteBuf(b, "-", 1);
			else
				WriteBuf(b, t->Token[i], StrLen(t->Token[i]));
		} else {
			WriteBuf(b, "-", 1);
		}
		if (i != (t->NumTokens - 1))
			WriteBuf(b, ",", 1);
	}
	WriteBuf(b, "\0", 1);

	char *ret = (char *)b->Buf;

	Free(b);

	return ret;
}

void ReplaceForCsv(char *str) {
	if (str == NULL)
		return;

	UINT len = StrLen(str);

	// A comma, a CR, an LF or another control character would split the record (a NUL ends the token)
	for (UINT i = 0; i < len; i++)
		if (str[i] == ',' || (UCHAR)str[i] < 0x20 || (UCHAR)str[i] == 0x7F)
			str[i] = '_';
}
