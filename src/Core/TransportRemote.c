// TransportRemote.c
// The text of the address of the other end of a stream (AUD1-DT-11, #459; Core/Transport.h). The TLS transport takes it
// from the TCP connection of a stream, the QUIC transport from its connection, and the node puts it into the report of a
// session that two holders of one key replace again and again (NodeFlap.c), so that the report names where each came from.

#include "Core/TransportInternal.h"

#include <stdio.h>
#include <string.h>

bool TransportAddressText(const struct sockaddr *addr, char *out, UINT size) {
	static const UCHAR mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
	char ip[INET6_ADDRSTRLEN];
	int len = -1;

	if (out == NULL || size == 0)
		return false;

	out[0] = 0;
	if (addr == NULL)
		return false;

	if (addr->sa_family == AF_INET) {
		const SOCKADDR_IN *in = (const SOCKADDR_IN *)addr;
		const UCHAR *b = (const UCHAR *)&in->sin_addr;

		len = snprintf(out, size, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(in->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		const SOCKADDR_IN6 *in6 = (const SOCKADDR_IN6 *)addr;
		const UCHAR *b = (const UCHAR *)&in6->sin6_addr;

		// A dual-stack socket tells an IPv4 peer as an IPv4-mapped address: the address of the peer is the IPv4 one
		if (memcmp(b, mapped, sizeof(mapped)) == 0)
			len = snprintf(out, size, "%u.%u.%u.%u:%u", b[12], b[13], b[14], b[15], ntohs(in6->sin6_port));
		else if (inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip)) != NULL)
			len = snprintf(out, size, "[%s]:%u", ip, ntohs(in6->sin6_port));
	}

	// Another family, or an address that does not fit whole: none
	if (len < 0 || (UINT)len >= size) {
		out[0] = 0;
		return false;
	}

	return true;
}
