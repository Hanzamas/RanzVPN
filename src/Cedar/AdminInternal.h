// AdminInternal.h
// Module-internal declarations of the Admin module: only its own files include this header

#ifndef	ADMIN_INTERNAL_H
#define	ADMIN_INTERNAL_H

UINT ScGetBridgeSupport(RPC *r, RPC_BRIDGE_SUPPORT *t);
UINT ScGetCaps(RPC *r, CAPSLIST *t);
UINT ScReadLogFile(RPC *r, RPC_READ_LOG_FILE *t);

#endif	// ADMIN_INTERNAL_H
