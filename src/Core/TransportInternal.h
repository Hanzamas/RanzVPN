// TransportInternal.h
// Module-internal declarations of the transport module: the outbound path of a client transport (TransportPath.c), which
// the TLS transport (TransportTls.c) dials along. Only the Transport files include this header.

#ifndef CORE_TRANSPORT_INTERNAL_H
#define CORE_TRANSPORT_INTERNAL_H

#include <winsock2.h>
#include <ws2tcpip.h>

#include "Core/Transport.h"

// A TCP connection to host and port along path (NULL: direct): through the proxy of the path, the system's (which
// WinHTTP finds on the thread pool), an HTTP proxy (CONNECT) or a SOCKS5 proxy, from the interface and the local address
// of its underlay. It gives the socket, blocking, at the start of the server's stream; INVALID_SOCKET when the underlay
// is not one of the machine, no address of the server or of the proxy answers, the proxy refuses the server or does not
// answer within its time, or cancel (a manual-reset event, or NULL) was set.
SOCKET TransportPathConnect(const TRANSPORT_PATH *path, const char *host, const char *port, HANDLE cancel);

// The underlay that path (NULL: none) binds: the index of its interface into *ifindex, 0 for none, and its local address
// into *local, of the family AF_UNSPEC for none, its port 0. False when the path names an interface that the machine
// does not have, or a local address that is not a numeric one.
bool TransportPathUnderlay(const TRANSPORT_PATH *path, ULONG *ifindex, SOCKADDR_INET *local);

#endif // CORE_TRANSPORT_INTERNAL_H
