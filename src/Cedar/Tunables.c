// Tunables.c
// Global tunables (GlobalParams): ids, config keys and defaults in one table

#include "Tunables.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Memory.h"

UINT vpn_global_parameters[NUM_GLOBAL_PARAMS] = {0};

typedef struct TUNABLE {
	UINT Id;
	char *Key;
	UINT DefaultValue;
} TUNABLE;

// In id order, which is also the config key order. TunablesGet indexes by id.
static TUNABLE tunables[] =
    {
        {GP_MAX_SEND_SOCKET_QUEUE_SIZE, "MAX_SEND_SOCKET_QUEUE_SIZE", 1600 * 1600 * 1},
        {GP_MIN_SEND_SOCKET_QUEUE_SIZE, "MIN_SEND_SOCKET_QUEUE_SIZE", 1600 * 200 * 1},
        {GP_MAX_SEND_SOCKET_QUEUE_NUM, "MAX_SEND_SOCKET_QUEUE_NUM", 128},
        {GP_SELECT_TIME, "SELECT_TIME", 256},
        {GP_MAX_STORED_QUEUE_NUM, "MAX_STORED_QUEUE_NUM", 1024},
        {GP_MAX_BUFFERING_PACKET_SIZE, "MAX_BUFFERING_PACKET_SIZE", 1600 * 1600},
        {GP_HUB_ARP_SEND_INTERVAL, "HUB_ARP_SEND_INTERVAL", 5 * 1000},
        {GP_MAC_TABLE_EXPIRE_TIME, "MAC_TABLE_EXPIRE_TIME", 600 * 1000},
        {GP_IP_TABLE_EXPIRE_TIME, "IP_TABLE_EXPIRE_TIME", 60 * 1000},
        {GP_IP_TABLE_EXPIRE_TIME_DHCP, "IP_TABLE_EXPIRE_TIME_DHCP", 5 * 60 * 1000},
        {GP_STORM_CHECK_SPAN, "STORM_CHECK_SPAN", 500},
        {GP_STORM_DISCARD_VALUE_START, "STORM_DISCARD_VALUE_START", 3},
        {GP_STORM_DISCARD_VALUE_END, "STORM_DISCARD_VALUE_END", 1024},
        {GP_MAX_MAC_TABLES, "MAX_MAC_TABLES", 65536},
        {GP_MAX_IP_TABLES, "MAX_IP_TABLES", 65536},
        {GP_MAX_HUB_LINKS, "MAX_HUB_LINKS", 1024},
        {GP_MEM_FIFO_REALLOC_MEM_SIZE, "MEM_FIFO_REALLOC_MEM_SIZE", 65536 * 10},
        {GP_QUEUE_BUDGET, "QUEUE_BUDGET", 2048},
        {GP_FIFO_BUDGET, "FIFO_BUDGET", 1600 * 1600 * 4},
};

#define NUM_TUNABLES (sizeof(tunables) / sizeof(tunables[0]))

UINT TunablesGet(UINT id) {
	if (id == 0 || id > NUM_TUNABLES)
		return 0;

	return vpn_global_parameters[id] != 0 ? vpn_global_parameters[id] : tunables[id - 1].DefaultValue;
}

// f == NULL resets every tunable to its default
void TunablesLoad(FOLDER *f) {
	for (UINT i = 0; i < NUM_TUNABLES; i++)
		vpn_global_parameters[tunables[i].Id] = CfgGetInt(f, tunables[i].Key);

	SetFifoCurrentReallocMemSize(TunablesGet(GP_MEM_FIFO_REALLOC_MEM_SIZE));
}

void TunablesSave(FOLDER *f) {
	if (f == NULL)
		return;

	for (UINT i = 0; i < NUM_TUNABLES; i++)
		CfgAddInt(f, tunables[i].Key, TunablesGet(tunables[i].Id));
}

static volatile UINT global_server_flags[NUM_GLOBAL_SERVER_FLAGS] = {0};

void SetGlobalServerFlag(UINT index, UINT value) {
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
		return;

	global_server_flags[index] = value;
}

UINT GetGlobalServerFlag(UINT index) {
	if (index >= NUM_GLOBAL_SERVER_FLAGS)
		return 0;

	return global_server_flags[index];
}

