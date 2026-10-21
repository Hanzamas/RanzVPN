// TcpIp.c
// Utility module for TCP/IP packet processing

#include "TcpIp.h"

#include "Cfg.h"
#include "Memory.h"
#include "Str.h"
#include "TcpIpInternal.h"

bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid) {
	if (src == NULL || src_size == 0 || mss == 0)
		return false;
	if (tag_vlan_tpid == 0)
		tag_vlan_tpid = MAC_PROTO_TAGVLAN;

	if (src_size < sizeof(MAC_HEADER))
		return false;

	MAC_HEADER *mac = (MAC_HEADER *)src;

	src += sizeof(MAC_HEADER);
	src_size -= sizeof(MAC_HEADER);

	USHORT proto = Endian16(mac->Protocol);

	if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6) {
		return AdjustTcpMssL3(src, src_size, mss);
	} else if (proto == tag_vlan_tpid) {
		if (src_size < 4)
			return false;

		src += 2;
		src_size -= 2;

		proto = READ_USHORT(src);

		if (proto == MAC_PROTO_IPV4 || proto == MAC_PROTO_IPV6) {
			if (mss >= 5) {
				mss -= 4;

				src += 2;
				src_size -= 2;

				return AdjustTcpMssL3(src, src_size, mss);
			}
		}
	}

	return false;
}

UINT GetIpHeaderSize(UCHAR *src, UINT src_size) {
	IPV4_HEADER *ip = NULL;
	if (src == NULL || src_size == 0)
		return 0;

	UCHAR ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4) {
		if (src_size < sizeof(IPV4_HEADER))
			return 0;

		ip = (IPV4_HEADER *)src;

		UINT ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
			return 0;

		if (src_size < ip_header_size)
			return 0;

		return ip_header_size;
	} else if (ip_ver == 6) {
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
			return 0;

		if (v6.IPv6Header == NULL)
			return 0;

		if (src_size < v6.TotalHeaderSize)
			return 0;

		return v6.TotalHeaderSize;
	} else {
		return 0;
	}
}

bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss) {
	TCP_HEADER *tcp = NULL;
	UINT tcp_size = 0;
	UCHAR *mss_option = NULL;
	IPV4_HEADER *ip = NULL;
	IPV6_HEADER *ip6 = NULL;
	if (src == NULL || src_size == 0 || mss == 0)
		return false;

	UCHAR ip_ver = (src[0] >> 4) & 0x0f;

	if (ip_ver == 4) {
		if (src_size < sizeof(IPV4_HEADER))
			return false;

		ip = (IPV4_HEADER *)src;

		if (ip->Protocol != IP_PROTO_TCP)
			return false;

		if (IPV4_GET_OFFSET(ip) != 0)
			return false;

		if (IPV4_GET_FLAGS(ip) & 0x01)
			return false;

		UINT ip_header_size = IPV4_GET_HEADER_LEN(ip) * 4;
		if (ip_header_size < sizeof(IPV4_HEADER))
			return false;

		if (src_size < ip_header_size)
			return false;

		UINT ip_total_length = READ_USHORT(&ip->TotalLength);

		if (ip_total_length < ip_header_size)
			return false;

		if (src_size < ip_total_length)
			return false;

		src += ip_header_size;
		src_size = ip_total_length - ip_header_size;

		if (src_size < sizeof(TCP_HEADER))
			return false;

		tcp = (TCP_HEADER *)src;
		tcp_size = src_size;
	} else if (ip_ver == 6) {
		IPV6_HEADER_PACKET_INFO v6;

		if (ParsePacketIPv6Header(&v6, src, src_size) == false)
			return false;

		ip6 = v6.IPv6Header;
		if (ip6 == NULL)
			return false;

		if (v6.Protocol != IP_PROTO_TCP)
			return false;

		if (v6.IsFragment)
			return false;

		if (v6.FragmentHeader != NULL) {
			if (IPV6_GET_FLAGS(v6.FragmentHeader) & IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS)
				return false;
		}

		tcp = (TCP_HEADER *)v6.Payload;
		tcp_size = v6.PayloadSize;
	} else {
		return false;
	}

	if (tcp == NULL || tcp_size < sizeof(TCP_HEADER))
		return false;

	UINT tcp_header_size = TCP_GET_HEADER_SIZE(tcp) * 4;
	if (tcp_header_size < sizeof(TCP_HEADER))
		return false;

	if (tcp_size < tcp_header_size)
		return false;

	if (((tcp->Flag & TCP_SYN) == false) ||
	    ((tcp->Flag & TCP_RST) ||
	     (tcp->Flag & TCP_PSH) ||
	     (tcp->Flag & TCP_URG)))
		return false;

	UCHAR *options = ((UCHAR *)tcp) + sizeof(TCP_HEADER);
	UINT options_size = tcp_header_size - sizeof(TCP_HEADER);

	// Find the MSS option (kind 2, length 4) wherever it is in the option list (RFC 9293 3.1):
	// End of Option List (kind 0) ends the list, No-Operation (kind 1) is one byte, and every other
	// option has a length byte of at least 2 that keeps it inside the options. A list that does not
	// keep to that is left alone.
	UINT i = 0;
	while (i < options_size) {
		UCHAR kind = options[i];

		if (kind == 0x00)
			break;

		if (kind == 0x01) {
			i++;
			continue;
		}

		if ((options_size - i) < 2)
			break;

		UINT len = options[i + 1];
		if (len < 2 || len > (options_size - i))
			break;

		if (kind == 0x02 && len == 4) {
			mss_option = options + i;
			break;
		}

		i += len;
	}

	if (ip6 != NULL) {
		// Reduce MSS by 20 since an IP header for IPv6 is 20 bytes larger than IPv4
		if (mss >= 20)
			mss -= 20;
	}

	// MSS should be at least 64
	mss = MAX(mss, 64);

	if (mss_option != NULL) {
		USHORT current_mss = READ_USHORT(mss_option + 2);

		if (current_mss <= mss) {
			// Leave the MSS alone if it is already at or below the target
			return false;
		} else {
			WRITE_USHORT(mss_option + 2, mss);

			tcp->Checksum = 0;

			if (ip != NULL)
				tcp->Checksum = CalcChecksumForIPv4(ip->SrcIP, ip->DstIP, IP_PROTO_TCP, tcp, tcp_size, 0);
			else
				tcp->Checksum = CalcChecksumForIPv6(&ip6->SrcAddress, &ip6->DestAddress,
				                                    IP_PROTO_TCP, tcp, tcp_size, 0);

			return true;
		}
	} else {
		return false;
	}
}
