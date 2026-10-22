// ConnectionInternal.h
// Module-internal declarations of the Connection module: only its own files include this header

#ifndef CONNECTION_INTERNAL_H
#define CONNECTION_INTERNAL_H

// ConnectionTunnel.c: the receive and the send of a Connection of type CONNECTION_NOISE, and the free of its Tunnel
void TunnelReceiveBlocks(CONNECTION *c, CANCEL *c1, CANCEL *c2);
void TunnelSendBlocks(CONNECTION *c);
void FreeTunnel(CONNECTION *c);

#endif // CONNECTION_INTERNAL_H
