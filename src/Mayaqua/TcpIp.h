// TcpIp.h
// Header of TcpIp.c

#ifndef	TCPIP_H
#define	TCPIP_H

#include "Mayaqua.h"
#include "Network.h"

#pragma pack(push, 1)

#define	MTU_FOR_PPPOE		(1500 - 46)

struct MAC_HEADER
{
	UCHAR	DestAddress[6];
	UCHAR	SrcAddress[6];
	USHORT	Protocol;
};

#define	MAC_PROTO_ARPV4		0x0806
#define	MAC_PROTO_IPV4		0x0800
#define	MAC_PROTO_IPV6		0x86dd
#define	MAC_PROTO_TAGVLAN	0x8100

struct LLC_HEADER
{
	UCHAR	Dsap;
	UCHAR	Ssap;
	UCHAR	Ctl;
};

#define	LLC_DSAP_BPDU		0x42
#define	LLC_SSAP_BPDU		0x42

struct BPDU_HEADER
{
	USHORT	ProtocolId;				// Protocol ID (STP == 0x0000)
	UCHAR	Version;
	UCHAR	Type;
	UCHAR	Flags;
	USHORT	RootPriority;
	UCHAR	RootMacAddress[6];
	UINT	RootPathCost;
	USHORT	BridgePriority;
	UCHAR	BridgeMacAddress[6];
	USHORT	BridgePortId;
	USHORT	MessageAge;
	USHORT	MaxAge;
	USHORT	HelloTime;
	USHORT	ForwardDelay;
};

struct ARPV4_HEADER
{
	USHORT	HardwareType;
	USHORT	ProtocolType;
	UCHAR	HardwareSize;
	UCHAR	ProtocolSize;
	USHORT	Operation;
	UCHAR	SrcAddress[6];
	UINT	SrcIP;
	UCHAR	TargetAddress[6];
	UINT	TargetIP;
};

#define	ARP_HARDWARE_TYPE_ETHERNET		0x0001

#define	ARP_OPERATION_REQUEST			1
#define	ARP_OPERATION_RESPONSE			2

struct TAGVLAN_HEADER
{
	UCHAR TagID[2];
	UCHAR Protocol[2];
};

struct IPV4_HEADER
{
	UCHAR	VersionAndHeaderLength;
	UCHAR	TypeOfService;
	USHORT	TotalLength;
	USHORT	Identification;
	UCHAR	FlagsAndFragmentOffset[2];
	UCHAR	TimeToLive;
	UCHAR	Protocol;
	USHORT	Checksum;
	UINT	SrcIP;
	UINT	DstIP;
};

#define	IPV4_SET_VERSION(h, v)		((h)->VersionAndHeaderLength |= (((v) & 0x0f) << 4))
#define	IPV4_GET_HEADER_LEN(h)		((h)->VersionAndHeaderLength & 0x0f)
#define	IPV4_SET_HEADER_LEN(h, v)	((h)->VersionAndHeaderLength |= ((v) & 0x0f))

#define	IPV4_GET_FLAGS(h)			(((h)->FlagsAndFragmentOffset[0] >> 5) & 0x07)
#define	IPV4_SET_FLAGS(h, v)		((h)->FlagsAndFragmentOffset[0] |= (((v) & 0x07) << 5))
#define	IPV4_GET_OFFSET(h)			(((h)->FlagsAndFragmentOffset[0] & 0x1f) * 256 + ((h)->FlagsAndFragmentOffset[1]))

#define	IP_PROTO_TCP		0x06
#define	IP_PROTO_UDP		0x11


struct UDP_HEADER
{
	USHORT	SrcPort;
	USHORT	DstPort;
	USHORT	PacketLength;
	USHORT	Checksum;
};

struct IPV4_PSEUDO_HEADER
{
	UINT	SrcIP;
	UINT	DstIP;
	UCHAR	Reserved;
	UCHAR	Protocol;
	USHORT	PacketLength;
};

struct TCP_HEADER
{
	USHORT	SrcPort;
	USHORT	DstPort;
	UINT	SeqNumber;
	UINT	AckNumber;
	UCHAR	HeaderSizeAndReserved;
	UCHAR	Flag;
	USHORT	WindowSize;
	USHORT	Checksum;
	USHORT	UrgentPointer;
};

#define	TCP_GET_HEADER_SIZE(h)	(((h)->HeaderSizeAndReserved >> 4) & 0x0f)
#define	TCP_SET_HEADER_SIZE(h, v)	((h)->HeaderSizeAndReserved = (((v) & 0x0f) << 4))

#define	TCP_FIN						1
#define	TCP_SYN						2
#define	TCP_RST						4
#define	TCP_PSH						8
#define	TCP_ACK						16
#define	TCP_URG						32

struct ICMP_HEADER
{
	UCHAR	Type;
	UCHAR	Code;
	USHORT	Checksum;
};

struct ICMP_ECHO
{
	USHORT	Identifier;
	USHORT	SeqNo;
};

#define	ICMP_TYPE_ECHO_REQUEST						8
#define	ICMP_TYPE_ECHO_RESPONSE						0

struct DHCPV4_HEADER
{
	UCHAR	OpCode;
	UCHAR	HardwareType;
	UCHAR	HardwareAddressSize;
	UCHAR	Hops;
	UINT	TransactionId;
	USHORT	Seconds;
	USHORT	Flags;
	UINT	ClientIP;
	UINT	YourIP;
	UINT	ServerIP;
	UINT	RelayIP;
	UCHAR	ClientMacAddress[6];
	UCHAR	Padding[10];
};

struct DNSV4_HEADER
{
	USHORT	TransactionId;
	UCHAR	Flag1;
	UCHAR	Flag2;
	USHORT	NumQuery;
	USHORT	AnswerRRs;
	USHORT	AuthorityRRs;
	USHORT	AdditionalRRs;
};

#define	DHCP_MAGIC_COOKIE	0x63825363

struct IPV6_HEADER_PACKET_INFO
{
	IPV6_HEADER *IPv6Header;
	IPV6_OPTION_HEADER *HopHeader;
	UINT HopHeaderSize;
	IPV6_OPTION_HEADER *EndPointHeader;
	UINT EndPointHeaderSize;
	IPV6_OPTION_HEADER *RoutingHeader;
	UINT RoutingHeaderSize;
	IPV6_FRAGMENT_HEADER *FragmentHeader;
	void *Payload;
	UINT PayloadSize;
	UCHAR Protocol;
	bool IsFragment;
	UINT TotalHeaderSize;
};

struct IPV6_HEADER
{
	UCHAR VersionAndTrafficClass1;		// Version (4 bit) and Traffic Class high (4 bit)
	UCHAR TrafficClass2AndFlowLabel1;	// Traffic Class low (4 bit) and Flow Label 1 (4 bit)
	UCHAR FlowLabel2;					// Flow Label 2 (8 bit)
	UCHAR FlowLabel3;					// Flow Label 3 (8 bit)
	USHORT PayloadLength;				// Payload length (includes extension headers)
	UCHAR NextHeader;
	UCHAR HopLimit;
	IPV6_ADDR SrcAddress;
	IPV6_ADDR DestAddress;
};


#define IPV6_GET_VERSION(h)			(((h)->VersionAndTrafficClass1 >> 4) & 0x0f)
#define IPV6_SET_VERSION(h, v)		((h)->VersionAndTrafficClass1 = ((h)->VersionAndTrafficClass1 & 0x0f) | ((v) << 4) & 0xf0)


#define IPV6_HEADER_HOP					0
#define IPV6_HEADER_ENDPOINT			60
#define IPV6_HEADER_ROUTING				43
#define IPV6_HEADER_FRAGMENT			44
#define IPV6_HEADER_NONE				59

struct IPV6_OPTION_HEADER
{
	UCHAR NextHeader;
	UCHAR Size;							// Header size (/8)
};

// The unfragmentable part runs up to the routing header, the hop-by-hop
// header, the first extension header or the payload
struct IPV6_FRAGMENT_HEADER
{
	UCHAR NextHeader;
	UCHAR Reserved;
	UCHAR FragmentOffset1;				// Fragment offset 1 (/8, 8 bit)
	UCHAR FragmentOffset2AndFlags;		// Fragment offset 2 (/8, 5 bit) + Reserved (2 bit) + More flag (1 bit)
	UINT Identification;
};

#define IPV6_GET_FRAGMENT_OFFSET(h)		(((((h)->FragmentOffset1) << 5) & 0x1fe0) | (((h)->FragmentOffset2AndFlags >> 3) & 0x1f))
#define IPV6_GET_FLAGS(h)				((h)->FragmentOffset2AndFlags & 0x0f)

#define IPV6_FRAGMENT_HEADER_FLAG_MORE_FRAGMENTS		0x01

struct IPV6_PSEUDO_HEADER
{
	IPV6_ADDR SrcAddress;
	IPV6_ADDR DestAddress;
	UINT UpperLayerPacketSize;
	UCHAR Padding[3];
	UCHAR NextHeader;
};

struct ICMPV6_ROUTER_SOLICIATION_HEADER
{
	UINT Reserved;
};

struct ICMPV6_ROUTER_ADVERTISEMENT_HEADER
{
	UCHAR CurHopLimit;
	UCHAR Flags;
	USHORT Lifetime;
	UINT ReachableTime;
	UINT RetransTimer;
};

struct ICMPV6_NEIGHBOR_SOLICIATION_HEADER
{
	UINT Reserved;
	IPV6_ADDR TargetAddress;
};

struct ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER
{
	UCHAR Flags;
	UCHAR Reserved[3];
	IPV6_ADDR TargetAddress;
};

#define ICMPV6_OPTION_PREFIXES_MAX_COUNT				10

struct ICMPV6_OPTION_LIST
{
	ICMPV6_OPTION_LINK_LAYER *SourceLinkLayer;
	ICMPV6_OPTION_LINK_LAYER *TargetLinkLayer;
	ICMPV6_OPTION_PREFIX *Prefix[ICMPV6_OPTION_PREFIXES_MAX_COUNT];
	ICMPV6_OPTION_MTU *Mtu;
};

struct ICMPV6_OPTION
{
	UCHAR Type;
	UCHAR Length;							// Length (/8, include type and length)
};

#define	ICMPV6_OPTION_TYPE_SOURCE_LINK_LAYER	1
#define ICMPV6_OPTION_TYPE_TARGET_LINK_LAYER	2
#define ICMPV6_OPTION_TYPE_PREFIX				3
#define ICMPV6_OPTION_TYPE_MTU					5

struct ICMPV6_OPTION_LINK_LAYER
{
	ICMPV6_OPTION IcmpOptionHeader;
	UCHAR Address[6];
};

struct ICMPV6_OPTION_PREFIX
{
	ICMPV6_OPTION IcmpOptionHeader;
	UCHAR SubnetLength;
	UCHAR Flags;
	UINT ValidLifetime;
	UINT PreferredLifetime;
	UINT Reserved;
	IPV6_ADDR Prefix;
};

struct ICMPV6_OPTION_MTU
{
	ICMPV6_OPTION IcmpOptionHeader;
	USHORT Reserved;
	UINT Mtu;
};


struct ICMPV6_HEADER_INFO
{
	UCHAR Type;
	USHORT DataSize;
	void *Data;
	ICMP_ECHO EchoHeader;
	void *EchoData;
	UINT EchoDataSize;

	union
	{
		ICMPV6_ROUTER_SOLICIATION_HEADER *RouterSoliciationHeader;
		ICMPV6_ROUTER_ADVERTISEMENT_HEADER *RouterAdvertisementHeader;
		ICMPV6_NEIGHBOR_SOLICIATION_HEADER *NeighborSoliciationHeader;
		ICMPV6_NEIGHBOR_ADVERTISEMENT_HEADER *NeighborAdvertisementHeader;
		void *HeaderPointer;
	} Headers;

	ICMPV6_OPTION_LIST OptionList;
};

#define ICMPV6_TYPE_ECHO_REQUEST				128
#define ICMPV6_TYPE_ECHO_RESPONSE				129
#define ICMPV6_TYPE_ROUTER_SOLICIATION			133
#define ICMPV6_TYPE_ROUTER_ADVERTISEMENT		134
#define ICMPV6_TYPE_NEIGHBOR_SOLICIATION		135
#define ICMPV6_TYPE_NEIGHBOR_ADVERTISEMENT		136

#define	DHCP_MIN_SIZE				300

#define	DHCP_ID_MESSAGE_TYPE		0x35
#define	DHCP_ID_REQUEST_IP_ADDRESS	0x32
#define	DHCP_ID_HOST_NAME			0x0c
#define	DHCP_ID_DOMAIN_NAME			0x0f
#define	DHCP_ID_GATEWAY_ADDR		0x03
#define	DHCP_ID_DNS_ADDR			0x06
#define	DHCP_ID_WINS_ADDR			0x2C
#define	DHCP_ID_PRIVATE				0xFA


#define	DHCP_DISCOVER		1
#define	DHCP_REQUEST		3

#define	DHCP_OFFER			2
#define	DHCP_ACK			5

struct HTTPLOG
{
	char Method[32];
	char Hostname[MAX_HOST_NAME_LEN + 1];
	UINT Port;
	char Path[MAX_SIZE];
	char Protocol[64];
	char UserAgent[MAX_SIZE];
	char Referer[MAX_SIZE];
	bool IsSsl;
};

struct PKT
{
	UCHAR			*PacketData;
	UINT			PacketSize;
	MAC_HEADER		*MacHeader;
	UCHAR			*MacAddressSrc;
	UCHAR			*MacAddressDest;
	bool			BroadcastPacket;
	bool			InvalidSourcePacket;
	bool			AccessChecked;
	UINT			VlanId;
	UINT			Delay;
	UINT			Jitter;
	UINT			Loss;
	UINT64			DelayedForwardTick;
	UINT			TypeL3;
	IPV6_HEADER_PACKET_INFO IPv6HeaderPacketInfo;	// Only for TypeL3 == L3_IPV6
	ICMPV6_HEADER_INFO ICMPv6HeaderPacketInfo;		// Only for TypeL4 == L4_ICMPV6
	UINT			DhcpOpCode;
	union
	{
		IPV4_HEADER		*IPv4Header;
		ARPV4_HEADER	*ARPv4Header;
		IPV6_HEADER		*IPv6Header;
		TAGVLAN_HEADER	*TagVlanHeader;
		BPDU_HEADER		*BpduHeader;
		void			*PointerL3;
	} L3;
	UINT			TypeL4;
	UINT			IPv4PayloadSize;
	union
	{
		UDP_HEADER	*UDPHeader;
		TCP_HEADER	*TCPHeader;
		ICMP_HEADER	*ICMPHeader;
		void		*PointerL4;
	} L4;
	UINT			TypeL7;
	union
	{
		DHCPV4_HEADER	*DHCPv4Header;
		IKE_HEADER		*IkeHeader;
		void			*PointerL7;
	} L7;
	UCHAR				*Payload;
	UINT				PayloadSize;
	struct HTTPLOG		*HttpLog;
	char DnsQueryHost[64];
};

#define	L3_UNKNOWN			0
#define	L3_ARPV4			1
#define	L3_IPV4				2
#define	L3_TAGVLAN			3
#define	L3_BPDU				4
#define L3_IPV6				5

#define	L4_UNKNOWN			0
#define	L4_UDP				1
#define	L4_TCP				2
#define	L4_ICMPV4			3
#define	L4_ICMPV6			4
#define	L4_FRAGMENT			5

#define	L7_UNKNOWN			0
#define	L7_DHCPV4			1
#define	L7_IKECONN			2
#define L7_DNS				4


struct IKE_HEADER
{
	UINT64 InitiatorCookie;
	UINT64 ResponderCookie;
	UCHAR NextPayload;
	UCHAR Version;
	UCHAR ExchangeType;
	UCHAR Flag;
	UINT MessageId;
	UINT MessageSize;
};

#define	IKE_EXCHANGE_TYPE_MAIN				2
#define IKE_EXCHANGE_TYPE_AGGRESSIVE		4

struct DHCP_OPTION
{
	UINT Id;
	UINT Size;
	void *Data;
};

struct DHCP_MODIFY_OPTION
{
	bool RemoveDefaultGatewayOnReply;
};


PKT *ParsePacket(UCHAR *buf, UINT size);
PKT *ParsePacketEx4(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum);
PKT *ParsePacketEx5(UCHAR *buf, UINT size, bool no_l3, UINT vlan_type_id, bool bridge_id_as_mac_address, bool no_http, bool correct_checksum, bool no_dns);
void FreePacket(PKT *p);
bool ParsePacketL2Ex(PKT *p, UCHAR *buf, UINT size, bool no_l3, USHORT vlan_tpid);
bool ParsePacketL3(PKT *p, UCHAR *buf, UINT size, USHORT proto, bool no_l3);
bool ParsePacketARPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv4(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketBPDU(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketTAGVLAN(PKT *p, UCHAR *buf, UINT size, bool no_l3);
bool ParseICMPv4(PKT *p, UCHAR *buf, UINT size);
bool ParseTCP(PKT *p, UCHAR *buf, UINT size);
bool ParseUDP(PKT *p, UCHAR *buf, UINT size);
void ParseDHCPv4(PKT *p, UCHAR *buf, UINT size);
PKT *ClonePacket(PKT *p, bool copy_data);
void FreeClonePacket(PKT *p);

void CorrectChecksum(PKT *p);

bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size);
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src);
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o);
USHORT CalcChecksumForIPv4(UINT src_ip, UINT dst_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
USHORT CalcChecksumForIPv6(IPV6_ADDR *src_ip, IPV6_ADDR *dest_ip, UCHAR protocol, void *data, UINT size, UINT real_size);
BUF *BuildNeighborSolicitation(IPV6_ADDR *src_ip, IPV6_ADDR *target_ip, UCHAR *my_mac_address);

bool VLanRemoveTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);
void VLanInsertTag(void **packet_data, UINT *packet_size, UINT vlan_id, UINT vlan_tpid);

bool AdjustTcpMssL3(UCHAR *src, UINT src_size, UINT mss);
bool AdjustTcpMssL2(UCHAR *src, UINT src_size, UINT mss, USHORT tag_vlan_tpid);
UINT GetIpHeaderSize(UCHAR *src, UINT src_size);

bool IsDhcpPacketForSpecificMac(UCHAR *data, UINT size, UCHAR *mac_address);

USHORT IpChecksum(void *buf, UINT size);

void GenMacAddress(UCHAR *mac);

DHCP_OPTION *GetDhcpOption(LIST *o, UINT id);
void FreeDhcpOptions(LIST *o);
LIST *ParseDhcpOptions(void *data, UINT size);
HTTPLOG *ParseHttpAccessLog(PKT *pkt);
HTTPLOG *ParseHttpsAccessLog(PKT *pkt);

BUF *DhcpModify(DHCP_MODIFY_OPTION *m, void *data, UINT size);
BUF *DhcpModifyIPv4(DHCP_MODIFY_OPTION *m, void *data, UINT size);


#pragma pack(pop)

#endif

