// SwitchInternal.h
// Module-internal declarations of the switch module (Switch.c, SwitchIp.c): only its own files include this header

#ifndef CORE_SWITCH_INTERNAL_H
#define CORE_SWITCH_INTERNAL_H

#include "Core/Switch.h"

// The IP table of a switch (SwitchIp.c; SDN-50-N, #492)
typedef struct SWITCH_IP_TABLE SWITCH_IP_TABLE;

// Switch.c: the IP table of the switch sw, NULL for no switch
SWITCH_IP_TABLE *SwitchIpTable(SWITCH *sw);

// SwitchIp.c. New makes the IP table of max entries at most, whose hash takes the random key seed: NULL when there is no
// memory; Free frees it. Learn takes the frame of size bytes that the switch took from port, of the generation gen, in the
// VLAN vlan at now, whose EtherType or length is at inner, after its addresses and its tag, and learns the source address of
// a host that it carries. Age takes out the entries that no frame refreshed for aging ms until now, and Forget the entries
// of port: their number. Stats puts the counters of the table into st.
SWITCH_IP_TABLE *SwitchIpNew(UINT max, UINT64 seed);
void SwitchIpFree(SWITCH_IP_TABLE *t);
void SwitchIpLearn(SWITCH_IP_TABLE *t, UINT64 now, UINT vlan, const UCHAR *frame, UINT size, UINT inner, UINT port, UINT gen);
UINT SwitchIpAge(SWITCH_IP_TABLE *t, UINT64 now, UINT aging);
UINT SwitchIpForget(SWITCH_IP_TABLE *t, UINT port);
void SwitchIpStats(SWITCH_IP_TABLE *t, SWITCH_STATS *st);

// SwitchIp.c: keep the entry e of size bytes among the *num entries of list, max at most, so that list holds the first max of
// all the entries that it was given, in the order of compare, as a heap: the caller sorts them once it gave the last one
void SwitchKeepFirst(void *list, UINT *num, UINT max, const void *e, SIZE_T size, int (*compare)(const void *, const void *));

#endif // CORE_SWITCH_INTERNAL_H
