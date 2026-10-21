// PktIpv6.c
// IPv6: the IPv6 header and extension header parse, ICMPv6 and its options (parse, clone, free) and the Neighbor Solicitation builder

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"

// Builds the IPv6 packet of a Neighbor Solicitation (RFC 4861 4.3) from src_ip to target_ip, sent to
// the unicast address of the target: IPv6 header, ICMPv6 header, the target address and the source
// link-layer address option with my_mac_address, 72 bytes. The hop limit is 255; the flow label is
// 0. Returns NULL when an argument is NULL
BUF *BuildNeighborSolicitation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address)
{
	UINT icmp_size = sizeof(ICMP_HEADER) + sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER) +
		sizeof(ICMPV6_OPTION_LINK_LAYER);
	UCHAR *packet;
	IPV6_HEADER *ip;
	ICMP_HEADER *icmp;
	ICMPV6_NEIGHBOR_SOLICIATION_HEADER *ns;
	ICMPV6_OPTION_LINK_LAYER *link;
	BUF *ret;
	if (src_ip == NULL || target_ip == NULL || my_mac_address == NULL)
	{
		return NULL;
	}

	packet = ZeroMalloc(sizeof(IPV6_HEADER) + icmp_size);
	ip = (IPV6_HEADER *)packet;
	icmp = (ICMP_HEADER *)(packet + sizeof(IPV6_HEADER));
	ns = (ICMPV6_NEIGHBOR_SOLICIATION_HEADER *)(icmp + 1);
	link = (ICMPV6_OPTION_LINK_LAYER *)(ns + 1);

	IPV6_SET_VERSION(ip, 6);
	ip->PayloadLength = Endian16((USHORT)icmp_size);
	ip->NextHeader = IP_PROTO_ICMPV6;
	ip->HopLimit = 255;
	Copy(&ip->SrcAddress, src_ip, sizeof(IPV6_ADDR));
	Copy(&ip->DestAddress, target_ip, sizeof(IPV6_ADDR));

	icmp->Type = ICMPV6_TYPE_NEIGHBOR_SOLICIATION;
	Copy(&ns->TargetAddress, target_ip, sizeof(IPV6_ADDR));
	link->IcmpOptionHeader.Type = ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER;
	link->IcmpOptionHeader.Length = sizeof(ICMPV6_OPTION_LINK_LAYER) / 8;
	Copy(link->Address, my_mac_address, 6);

	icmp->Checksum = CalcChecksumForIPv6(src_ip, target_ip, IP_PROTO_ICMPV6, icmp, icmp_size, 0);

	ret = NewBufFromMemory(packet, sizeof(IPV6_HEADER) + icmp_size);

	Free(packet);

	return ret;
}

static bool ParseIPv6ExtHeader(IPV6_HEADER_PACKET_INFO *info, UCHAR next_header, UCHAR *buf, UINT size)
{
	IPV6_OPTION_HEADER *option_header;
	UINT option_header_size;
	UCHAR next_header_2 = IPV6_HEADER_NONE;
	if (info == NULL || buf == NULL)
	{
		return false;
	}

	info->IsFragment = false;

	while (true)
	{
		if (size > 8)
		{
			next_header_2 = *((UCHAR *)buf);
		}

		switch (next_header)
		{
		case IPV6_HEADER_HOP:
		case IPV6_HEADER_ENDPOINT:
		case IPV6_HEADER_ROUTING:
			if (size < 8)
			{
				return false;
			}

			option_header = (IPV6_OPTION_HEADER *)buf;
			option_header_size = (option_header->Size + 1) * 8;
			if (size < option_header_size)
			{
				return false;
			}

			switch (next_header)
			{
			case IPV6_HEADER_HOP:
				info->HopHeader = (IPV6_OPTION_HEADER *)buf;
				info->HopHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ENDPOINT:
				info->EndPointHeader = (IPV6_OPTION_HEADER *)buf;
				info->EndPointHeaderSize = option_header_size;
				break;

			case IPV6_HEADER_ROUTING:
				info->RoutingHeader = (IPV6_OPTION_HEADER *)buf;
				info->RoutingHeaderSize = option_header_size;
				break;
			}

			buf += option_header_size;
			size -= option_header_size;
			break;

		case IPV6_HEADER_FRAGMENT:
			if (size < sizeof(IPV6_FRAGMENT_HEADER))
			{
				return false;
			}

			info->FragmentHeader = (IPV6_FRAGMENT_HEADER *)buf;

			if (IPV6_GET_FRAGMENT_OFFSET(info->FragmentHeader) != 0)
			{
				info->IsFragment = true;
			}

			buf += sizeof(IPV6_FRAGMENT_HEADER);
			size -= sizeof(IPV6_FRAGMENT_HEADER);
			break;

		default:
			if (next_header != IPV6_HEADER_NONE)
			{
				info->Payload = buf;
				info->PayloadSize = size;
			}
			else
			{
				info->Payload = NULL;
				info->PayloadSize = 0;
			}
			info->Protocol = next_header;
			return true;
		}

		next_header = next_header_2;
	}
}

bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size)
{
	if (info == NULL || buf == NULL)
	{
		Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));
		return false;
	}

	Zero(info, sizeof(IPV6_HEADER_PACKET_INFO));

	if (size < sizeof(IPV6_HEADER))
	{
		return false;
	}

	info->IPv6Header = (IPV6_HEADER *)buf;
	buf += sizeof(IPV6_HEADER);
	size -= sizeof(IPV6_HEADER);

	if (IPV6_GET_VERSION(info->IPv6Header) != 6)
	{
		return false;
	}

	if (ParseIPv6ExtHeader(info, info->IPv6Header->NextHeader, buf, size) == false)
	{
		return false;
	}

	if (info->Payload != NULL)
	{
		info->TotalHeaderSize = (UINT)((UINT64)(info->Payload) - (UINT64)(info->IPv6Header));
	}

	return true;
}

static bool ParseICMPv6Options(ICMPV6_OPTION_LIST *o, UCHAR *buf, UINT size)
{
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	Zero(o, sizeof(ICMPV6_OPTION_LIST));

	while (true)
	{
		ICMPV6_OPTION *option_header;
		UINT header_total_size;
		UCHAR *header_pointer;
		if (size < sizeof(ICMPV6_OPTION))
		{
			return true;
		}

		option_header = (ICMPV6_OPTION *)buf;
		header_total_size = option_header->Length * 8;
		if (header_total_size == 0)
		{
			return true;
		}
		if (size < header_total_size)
		{
			return true;
		}

		header_pointer = buf;
		buf += header_total_size;
		size -= header_total_size;

		switch (option_header->Type)
		{
		case ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER:
		case ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER:
			if (header_total_size >= sizeof(ICMPV6_OPTION_LINK_LAYER))
			{
				if (option_header->Type == ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER)
				{
					o->SourceLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
				else
				{
					o->TargetLinkLayer = (ICMPV6_OPTION_LINK_LAYER *)header_pointer;
				}
			}
			else
			{
				return false;
			}
			break;

		case ICMPV6_OPTION_TYPE_PREFIX:
			if (header_total_size >= sizeof(ICMPV6_OPTION_PREFIX))
			{
				UINT i;
				for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
				{
					if (o->Prefix[i] == NULL)
					{
						o->Prefix[i] = (ICMPV6_OPTION_PREFIX *)header_pointer;
						break;
					}
				}
			}
			break;

		case ICMPV6_OPTION_TYPE_MTU:
			if (header_total_size >= sizeof(ICMPV6_OPTION_MTU))
			{
				o->Mtu = (ICMPV6_OPTION_MTU *)header_pointer;
			}
			break;
		}
	}
}

// The ICMPv6 messages that have a fixed header followed by options, and the size of that header
static const struct
{
	UCHAR Type;
	UINT HeaderSize;
} icmpv6_option_messages[] =
{
	{ICMPV6_TYPE_ROUTER_SOLICIATION, sizeof(ICMPV6_ROUTER_SOLICIATION_HEADER)},
	{ICMPV6_TYPE_ROUTER_ADVERTISEMENT, sizeof(ICMPV6_ROUTER_ADVERTISEMENT_HEADER)},
	{ICMPV6_TYPE_NEIGHBOR_SOLICIATION, sizeof(ICMPV6_NEIGHBOR_SOLICIATION_HEADER)},
	{ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT, sizeof(ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER)},
};

static bool ParseICMPv6(PKT *p, UCHAR *buf, UINT size)
{
	ICMPV6_HEADER_INFO icmp_info;
	ICMP_HEADER *icmp;
	ICMP_ECHO *echo;
	UINT msg_size;
	UINT i;
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	Zero(&icmp_info, sizeof(icmp_info));

	if (size < sizeof(ICMP_HEADER))
	{
		return false;
	}

	icmp = (ICMP_HEADER *)buf;
	p->L4.ICMPHeader = icmp;

	msg_size = size - sizeof(ICMP_HEADER);

	icmp_info.Type = icmp->Type;
	icmp_info.Data = ((UCHAR *)buf) + sizeof(ICMP_HEADER);
	icmp_info.DataSize = msg_size;

	if (icmp_info.Type == ICMPV6_TYPE_ECHO_REQUEST || icmp_info.Type == ICMPV6_TYPE_ECHO_RESPONSE)
	{
		if (icmp_info.DataSize < sizeof(ICMP_ECHO))
		{
			return false;
		}

		echo = (ICMP_ECHO *)icmp_info.Data;

		icmp_info.EchoHeader.Identifier = Endian16(echo->Identifier);
		icmp_info.EchoHeader.SeqNo = Endian16(echo->SeqNo);
		icmp_info.EchoData = (UCHAR *)echo + sizeof(ICMP_ECHO);
		icmp_info.EchoDataSize = icmp_info.DataSize - sizeof(ICMP_ECHO);
	}

	for (i = 0; i < sizeof(icmpv6_option_messages) / sizeof(icmpv6_option_messages[0]); i++)
	{
		if (icmpv6_option_messages[i].Type == icmp_info.Type)
		{
			UINT header_size = icmpv6_option_messages[i].HeaderSize;

			if (icmp_info.DataSize < header_size)
			{
				return false;
			}

			icmp_info.Headers.HeaderPointer = icmp_info.Data;

			if (ParseICMPv6Options(&icmp_info.OptionList, ((UCHAR *)icmp_info.Headers.HeaderPointer) + header_size,
			                       icmp_info.DataSize - header_size) == false)
			{
				return false;
			}

			break;
		}
	}

	p->TypeL4 = L4_ICMPV6;
	Copy(&p->ICMPv6HeaderPacketInfo, &icmp_info, sizeof(ICMPV6_HEADER_INFO));

	return true;
}

void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	Free(o->SourceLinkLayer);
	Free(o->TargetLinkLayer);

	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		Free(o->Prefix[i]);
		o->Prefix[i] = NULL;
	}
	Free(o->Mtu);
}

void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src)
{
	UINT i;
	if (dst == NULL || src == NULL)
	{
		return;
	}

	Zero(dst, sizeof(ICMPV6_OPTION_LIST));

	dst->SourceLinkLayer = Clone(src->SourceLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	dst->TargetLinkLayer = Clone(src->TargetLinkLayer, sizeof(ICMPV6_OPTION_LINK_LAYER));
	for (i = 0; i < ICMPV6_OPTION_PREFIXES_MAX_COUNT; i++)
	{
		if (src->Prefix[i] != NULL)
		{
			dst->Prefix[i] = Clone(src->Prefix[i], sizeof(ICMPV6_OPTION_PREFIX));
		}
		else
		{
			break;
		}
	}
	dst->Mtu = Clone(src->Mtu, sizeof(ICMPV6_OPTION_MTU));
}

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size)
{
	if (p == NULL || buf == NULL)
	{
		return false;
	}

	if (ParsePacketIPv6Header(&p->IPv6HeaderPacketInfo, buf, size) == false)
	{
		return false;
	}

	p->TypeL3 = L3_IPV6;
	p->L3.IPv6Header = p->IPv6HeaderPacketInfo.IPv6Header;

	if (p->IPv6HeaderPacketInfo.Payload == NULL)
	{
		return true;
	}

	buf = p->IPv6HeaderPacketInfo.Payload;
	size = p->IPv6HeaderPacketInfo.PayloadSize;

	if (p->IPv6HeaderPacketInfo.IsFragment)
	{
		// This is a fragmented packet. Quit interpreting
		p->TypeL4 = L4_FRAGMENT;
		return true;
	}

	switch (p->IPv6HeaderPacketInfo.Protocol)
	{
	case IP_PROTO_ICMPV6:
		if (ParseICMPv6(p, buf, size) == false)
		{
			// Returns true also if it fails to parse ICMPv6
			return true;
		}
		else
		{
			return true;
		}

	case IP_PROTO_TCP:
		return ParseTCP(p, buf, size);

	case IP_PROTO_UDP:
		return ParseUDP(p, buf, size);

	default:
		return true;
	}
}
