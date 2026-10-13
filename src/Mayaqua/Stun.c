// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// Stun.c
// STUN client (RFC 5389 Binding Request / Response only, no TURN, no authentication, no ICE)

#include "Stun.h"

#include "DNS.h"
#include "Encrypt.h"
#include "Memory.h"
#include "Network.h"
#include "Str.h"
#include "Tick64.h"

// Parse the value of a MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute
static bool StunParseAddressAttr(UCHAR *value, UINT value_size, bool xor_mapped, UCHAR *transaction_id, IP *ip, UINT *port) {
	UCHAR family;
	UINT addr_size;
	UINT port_value;
	UCHAR addr[16];
	UCHAR xor_key[16];
	UINT i;
	// Validate arguments
	if (value == NULL || transaction_id == NULL || ip == NULL || port == NULL)
		return false;

	// Reserved (1 byte), family (1 byte) and port (2 bytes)
	if (value_size < 4)
		return false;

	family = value[1];
	if (family == STUN_ADDRESS_FAMILY_IPV4)
		addr_size = 4;
	else if (family == STUN_ADDRESS_FAMILY_IPV6)
		addr_size = 16;
	else
		return false;

	if (value_size < (4 + addr_size))
		return false;

	port_value = READ_USHORT(value + 2);
	Copy(addr, value + 4, addr_size);

	if (xor_mapped) {
		// The port is XORed with the most significant 16 bits of the magic cookie.
		// The address is XORed with the magic cookie (IPv4), or with the magic
		// cookie followed by the transaction ID (IPv6).
		WRITE_UINT(xor_key, STUN_MAGIC_COOKIE);
		Copy(xor_key + 4, transaction_id, STUN_TRANSACTION_ID_SIZE);

		port_value ^= (STUN_MAGIC_COOKIE >> 16);

		for (i = 0; i < addr_size; i++)
			addr[i] ^= xor_key[i];
	}

	if (port_value == 0)
		return false;

	if (family == STUN_ADDRESS_FAMILY_IPV4)
		SetIP(ip, addr[0], addr[1], addr[2], addr[3]);
	else
		SetIP6(ip, addr);

	*port = port_value;

	return true;
}

// Build a Binding Request (header only) and return its size, or 0 if the buffer is too small
UINT StunBuildBindingRequest(UCHAR *buf, UINT buf_size, UCHAR *transaction_id) {
	// Validate arguments
	if (buf == NULL || transaction_id == NULL)
		return 0;

	if (buf_size < STUN_HEADER_SIZE)
		return 0;

	// Message type and message length (no attributes)
	WRITE_USHORT(buf, STUN_BINDING_REQUEST);
	WRITE_USHORT(buf + 2, 0);

	// Magic cookie
	WRITE_UINT(buf + 4, STUN_MAGIC_COOKIE);

	// Transaction ID
	Copy(buf + 8, transaction_id, STUN_TRANSACTION_ID_SIZE);

	return STUN_HEADER_SIZE;
}

// Parse a Binding Success Response and get the mapped address.
// XOR-MAPPED-ADDRESS is preferred, MAPPED-ADDRESS is the fallback, other attributes are skipped.
// Unknown comprehension-required attributes (0x0000-0x7FFF) are skipped too. This deliberately
// differs from RFC 5389 section 7.3.3, so that a response that also carries RFC 3489 attributes
// (such as SOURCE-ADDRESS or CHANGED-ADDRESS) is still accepted. Only the mapped address is used.
bool StunParseBindingResponse(UCHAR *buf, UINT size, UCHAR *transaction_id, IP *mapped_ip, UINT *mapped_port) {
	UINT msg_type;
	UINT msg_len;
	UINT pos, end;
	bool has_xor_mapped = false;
	bool has_mapped = false;
	IP xor_mapped_ip, plain_mapped_ip;
	UINT xor_mapped_port = 0, plain_mapped_port = 0;
	// Validate arguments
	if (buf == NULL || transaction_id == NULL || mapped_ip == NULL || mapped_port == NULL)
		return false;

	Zero(&xor_mapped_ip, sizeof(xor_mapped_ip));
	Zero(&plain_mapped_ip, sizeof(plain_mapped_ip));

	// Header
	if (size < STUN_HEADER_SIZE)
		return false;

	msg_type = READ_USHORT(buf);
	msg_len = READ_USHORT(buf + 2);

	if (msg_type != STUN_BINDING_SUCCESS_RESPONSE)
		return false;

	if (READ_UINT(buf + 4) != STUN_MAGIC_COOKIE)
		return false;

	if (Cmp(buf + 8, transaction_id, STUN_TRANSACTION_ID_SIZE) != 0)
		return false;

	// The message length is a multiple of 4 and must fit in the received data
	if ((msg_len % 4) != 0)
		return false;

	if (msg_len > (size - STUN_HEADER_SIZE))
		return false;

	pos = STUN_HEADER_SIZE;
	end = STUN_HEADER_SIZE + msg_len;

	// Attributes
	while (pos < end) {
		UINT attr_type;
		UINT attr_len;
		UINT padded_len;
		UCHAR *value;

		if ((end - pos) < STUN_ATTR_HEADER_SIZE)
			return false;

		attr_type = READ_USHORT(buf + pos);
		attr_len = READ_USHORT(buf + pos + 2);
		pos += STUN_ATTR_HEADER_SIZE;

		// The value is padded to a multiple of 4 bytes
		padded_len = (attr_len + 3) & ~((UINT)3);
		if (padded_len > (end - pos))
			return false;

		value = buf + pos;

		if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && has_xor_mapped == false) {
			if (StunParseAddressAttr(value, attr_len, true, transaction_id, &xor_mapped_ip, &xor_mapped_port) == false)
				return false;

			has_xor_mapped = true;
		} else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && has_mapped == false) {
			if (StunParseAddressAttr(value, attr_len, false, transaction_id, &plain_mapped_ip, &plain_mapped_port) == false)
				return false;

			has_mapped = true;
		}

		pos += padded_len;
	}

	if (has_xor_mapped) {
		Copy(mapped_ip, &xor_mapped_ip, sizeof(IP));
		*mapped_port = xor_mapped_port;

		return true;
	}

	if (has_mapped) {
		Copy(mapped_ip, &plain_mapped_ip, sizeof(IP));
		*mapped_port = plain_mapped_port;

		return true;
	}

	return false;
}

// Parse a STUN server string: "host", "host:port", "[IPv6 address]:port" or a bare IPv6 address.
// The port defaults to STUN_DEFAULT_PORT.
bool StunParseServerStr(char *src, char *host, UINT host_size, UINT *port) {
	char tmp[MAX_SIZE];
	char *host_part;
	char *port_part = NULL;
	UINT port_value = STUN_DEFAULT_PORT;
	UINT len, i;
	// Validate arguments
	if (src == NULL || host == NULL || host_size == 0 || port == NULL)
		return false;

	StrCpy(tmp, sizeof(tmp), src);
	Trim(tmp);

	len = StrLen(tmp);
	if (len == 0)
		return false;

	if (tmp[0] == '[') {
		// "[IPv6 address]" or "[IPv6 address]:port"
		char *close = NULL;

		for (i = 1; i < len; i++) {
			if (tmp[i] == ']') {
				close = &tmp[i];
				break;
			}
		}

		if (close == NULL)
			return false;

		*close = 0;
		host_part = &tmp[1];

		if (close[1] != 0) {
			if (close[1] != ':')
				return false;

			port_part = &close[2];
		}
	} else {
		UINT num_colons = 0;
		UINT colon_pos = 0;

		for (i = 0; i < len; i++) {
			if (tmp[i] == ':') {
				num_colons++;
				colon_pos = i;
			}
		}

		host_part = tmp;

		if (num_colons == 1) {
			// "host:port"
			tmp[colon_pos] = 0;
			port_part = &tmp[colon_pos + 1];
		}

		// Two or more colons: a bare IPv6 address with the default port
	}

	if (port_part != NULL) {
		UINT port_len = StrLen(port_part);

		if (port_len == 0 || port_len > 5)
			return false;

		port_value = 0;

		for (i = 0; i < port_len; i++) {
			if (port_part[i] < '0' || port_part[i] > '9')
				return false;

			port_value = port_value * 10 + (UINT)(port_part[i] - '0');
		}

		if (port_value == 0 || port_value > 65535)
			return false;
	}

	Trim(host_part);

	if (StrLen(host_part) == 0 || StrLen(host_part) >= host_size)
		return false;

	StrCpy(host, host_size, host_part);
	*port = port_value;

	return true;
}

// Learn the public (mapped) endpoint of a UDP socket from a STUN server.
// The Binding Request is sent on the given socket, so the mapping belongs to its port.
// The request is sent once and retransmitted once; the call returns false if no valid
// response arrives in time. Name resolution and both waits share one time limit
// (STUN_TOTAL_TIMEOUT), so the call blocks for about 2 seconds at most. Datagrams from
// other sources or with another transaction ID are ignored. No thread is created apart
// from the DNS resolver thread for a host name (it can outlive the call after a resolve
// timeout); nothing is retried after the call returns.
bool StunGetMappedAddress(SOCK *udp_sock, char *server_host_port, IP *mapped_ip, UINT *mapped_port) {
	char host[MAX_HOST_NAME_LEN + 1];
	UINT server_port;
	IP server_ip;
	bool resolved;
	UCHAR transaction_id[STUN_TRANSACTION_ID_SIZE];
	UCHAR request[STUN_HEADER_SIZE];
	UCHAR recv_buf[STUN_RECV_BUFFER_SIZE];
	UINT request_size;
	UINT wait_list[] = {STUN_WAIT_FIRST, STUN_WAIT_RETRANSMIT};
	UINT i;
	UINT64 limit;
	// Validate arguments
	if (udp_sock == NULL || server_host_port == NULL || mapped_ip == NULL || mapped_port == NULL)
		return false;

	if (udp_sock->Type != SOCK_UDP)
		return false;

	if (StunParseServerStr(server_host_port, host, sizeof(host), &server_port) == false) {
		Debug("StunGetMappedAddress(): invalid STUN server: %s\n", server_host_port);
		return false;
	}

	// One time limit covers name resolution, the request and its retransmission
	limit = Tick64() + (UINT64)STUN_TOTAL_TIMEOUT;

	// Resolve the server in the address family of the socket
	if (udp_sock->IPv6)
		resolved = GetIP6Ex(&server_ip, host, STUN_DNS_RESOLVE_TIMEOUT, NULL);
	else
		resolved = GetIP4Ex(&server_ip, host, STUN_DNS_RESOLVE_TIMEOUT, NULL);

	if (resolved == false || IsZeroIP(&server_ip)) {
		Debug("StunGetMappedAddress(): failed to resolve %s\n", host);
		return false;
	}

	Rand(transaction_id, sizeof(transaction_id));

	request_size = StunBuildBindingRequest(request, sizeof(request), transaction_id);
	if (request_size == 0)
		return false;

	for (i = 0; i < (sizeof(wait_list) / sizeof(wait_list[0])); i++) {
		UINT64 deadline;

		if (Tick64() >= limit) {
			// The time limit is used up
			break;
		}

		// Send (or retransmit) the Binding Request
		if (SendTo(udp_sock, &server_ip, server_port, request, request_size) == 0) {
			if (udp_sock->IgnoreSendErr == false) {
				Debug("StunGetMappedAddress(): SendTo() failed. IP: %r, port: %u\n", &server_ip, server_port);
				return false;
			}
		}

		deadline = Tick64() + (UINT64)wait_list[i];
		if (deadline > limit)
			deadline = limit;

		while (true) {
			UINT64 now = Tick64();
			UINT num_ignore_errors = 0;
			SOCKSET set;

			if (now >= deadline)
				break;

			// Wait for a datagram. Select() puts the socket into the asynchronous
			// (non-blocking) mode that the UDP acceleration polling loop puts it in
			// anyway; no socket option or timeout is changed.
			InitSockSet(&set);
			AddSockSet(&set, udp_sock);
			Select(&set, (UINT)(deadline - now), NULL, NULL);

			// Read every queued datagram (up to the deadline, so that a stream of
			// datagrams from other sources cannot extend the wait)
			while (true) {
				IP src_ip;
				UINT src_port;
				UINT ret;

				if (Tick64() >= deadline)
					break;

				ret = RecvFrom(udp_sock, &src_ip, &src_port, recv_buf, sizeof(recv_buf));

				if (ret == SOCK_LATER)
					break;

				if (ret == 0) {
					if (udp_sock->IgnoreRecvErr == false || (num_ignore_errors++) >= MAX_NUM_IGNORE_ERRORS) {
						// Serious UDP reception error
						Debug("StunGetMappedAddress(): RecvFrom() failed.\n");
						return false;
					}

					continue;
				}

				// Ignore datagrams from other sources
				if (CmpIpAddr(&src_ip, &server_ip) != 0 || src_port != server_port)
					continue;

				// The server rejected this request: stop instead of waiting for the timeout
				if (ret >= STUN_HEADER_SIZE && READ_USHORT(recv_buf) == STUN_BINDING_ERROR_RESPONSE &&
				    READ_UINT(recv_buf + 4) == STUN_MAGIC_COOKIE &&
				    Cmp(recv_buf + 8, transaction_id, STUN_TRANSACTION_ID_SIZE) == 0) {
					Debug("StunGetMappedAddress(): Binding Error Response from %s\n", host);
					return false;
				}

				if (StunParseBindingResponse(recv_buf, ret, transaction_id, mapped_ip, mapped_port)) {
					Debug("StunGetMappedAddress(): mapped address: %r, port: %u\n", mapped_ip, *mapped_port);
					return true;
				}
			}
		}
	}

	Debug("StunGetMappedAddress(): no response from %s\n", host);

	return false;
}
