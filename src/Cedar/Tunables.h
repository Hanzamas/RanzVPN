// Tunables.h
// Header of Tunables.c

#ifndef TUNABLES_H
#define TUNABLES_H

#include "Mayaqua/MayaType.h"

#define NUM_GLOBAL_PARAMS             128
#define GP_MAX_SEND_SOCKET_QUEUE_SIZE 1
#define GP_MIN_SEND_SOCKET_QUEUE_SIZE 2
#define GP_MAX_SEND_SOCKET_QUEUE_NUM  3
#define GP_SELECT_TIME                4
#define GP_MAX_STORED_QUEUE_NUM       5
#define GP_MAX_BUFFERING_PACKET_SIZE  6
#define GP_HUB_ARP_SEND_INTERVAL      7
#define GP_MAC_TABLE_EXPIRE_TIME      8
#define GP_IP_TABLE_EXPIRE_TIME       9
#define GP_IP_TABLE_EXPIRE_TIME_DHCP  10
#define GP_STORM_CHECK_SPAN           11
#define GP_STORM_DISCARD_VALUE_START  12
#define GP_STORM_DISCARD_VALUE_END    13
#define GP_MAX_MAC_TABLES             14
#define GP_MAX_IP_TABLES              15
#define GP_MAX_HUB_LINKS              16
#define GP_MEM_FIFO_REALLOC_MEM_SIZE  17
#define GP_QUEUE_BUDGET               18
#define GP_FIFO_BUDGET                19

// A stored 0 means "use the default of the table entry"
extern UINT vpn_global_parameters[NUM_GLOBAL_PARAMS];

UINT TunablesGet(UINT id);
static inline UINT VPN_GP(UINT id) {
	return TunablesGet(id);
}
void TunablesLoad(FOLDER *f);
void TunablesSave(FOLDER *f);

#define NUM_GLOBAL_SERVER_FLAGS       128
#define GSF_DISABLE_SESSION_RECONNECT 9

void SetGlobalServerFlag(UINT index, UINT value);
UINT GetGlobalServerFlag(UINT index);

#endif // TUNABLES_H

