// TcpIpInternal.h
// Module-internal declarations of the TcpIp module: only its own files include this header

#ifndef TCPIP_INTERNAL_H
#define TCPIP_INTERNAL_H

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
void CorrectChecksum(PKT *p);
bool ParsePacketIPv6(PKT *p, UCHAR *buf, UINT size);
bool ParsePacketIPv6Header(IPV6_HEADER_PACKET_INFO *info, UCHAR *buf, UINT size);
void CloneICMPv6Options(ICMPV6_OPTION_LIST *dst, ICMPV6_OPTION_LIST *src);
void FreeCloneICMPv6Options(ICMPV6_OPTION_LIST *o);
UINT GetIpHeaderSize(UCHAR *src, UINT src_size);
HTTPLOG *ParseHttpAccessLog(PKT *pkt);
HTTPLOG *ParseHttpsAccessLog(PKT *pkt);

#endif // TCPIP_INTERNAL_H
