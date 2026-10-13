// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Stun.h
// Header of Stun.c

#ifndef STUN_H
#define STUN_H

#include "MayaType.h"

// Constants
#define STUN_DEFAULT_PORT        3478       // Default STUN server port (RFC 5389)
#define STUN_HEADER_SIZE         20         // Size of the STUN message header
#define STUN_ATTR_HEADER_SIZE    4          // Size of the STUN attribute header
#define STUN_TRANSACTION_ID_SIZE 12         // Size of the transaction ID
#define STUN_MAGIC_COOKIE        0x2112A442 // Magic cookie

#define STUN_BINDING_REQUEST          0x0001 // Message type: Binding Request
#define STUN_BINDING_SUCCESS_RESPONSE 0x0101 // Message type: Binding Success Response
#define STUN_BINDING_ERROR_RESPONSE   0x0111 // Message type: Binding Error Response

#define STUN_ATTR_MAPPED_ADDRESS     0x0001 // Attribute: MAPPED-ADDRESS
#define STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020 // Attribute: XOR-MAPPED-ADDRESS

#define STUN_ADDRESS_FAMILY_IPV4 0x01 // Address family: IPv4
#define STUN_ADDRESS_FAMILY_IPV6 0x02 // Address family: IPv6

#define STUN_RECV_BUFFER_SIZE    2048 // Receive buffer size
#define STUN_DNS_RESOLVE_TIMEOUT 1000 // Timeout for resolving the STUN server host name (ms)
#define STUN_WAIT_FIRST          500  // Wait for a response after the first request (ms)
#define STUN_WAIT_RETRANSMIT     1000 // Wait for a response after the retransmission (ms)
#define STUN_TOTAL_TIMEOUT       2000 // Time limit of one query, name resolution included (ms)

// Function prototype
UINT StunBuildBindingRequest(UCHAR *buf, UINT buf_size, UCHAR *transaction_id);
bool StunParseBindingResponse(UCHAR *buf, UINT size, UCHAR *transaction_id, IP *mapped_ip, UINT *mapped_port);
bool StunParseServerStr(char *src, char *host, UINT host_size, UINT *port);
bool StunGetMappedAddress(SOCK *udp_sock, char *server_host_port, IP *mapped_ip, UINT *mapped_port);

#endif // STUN_H
