// harness_int.h
// Types, scenario constants and shared helpers of the vpntest harness (harness.c, harness_pack.c)

#ifndef	HARNESS_INT_H
#define	HARNESS_INT_H

#include "Cedar/CedarType.h"

#include "Mayaqua/MayaType.h"

// Fixed scenario
#define	HARNESS_PORT				39555				// Test listener (never 443; below the dynamic port range)
#define	HARNESS_HUB_A				"HARNESS_A"
#define	HARNESS_HUB_B				"HARNESS_B"
#define	HARNESS_HUB_FLOOD			"HARNESS_FLOOD"		// Hub of the in-process flood bench ("bench" only)
#define	HARNESS_LINK_NAME			L"HARNESS_CASCADE"
#define	HARNESS_LINK_USER			"harness_cascade"
#define	HARNESS_USER_A				"tester_a"
#define	HARNESS_USER_B				"tester_b"
#define	HARNESS_PASSWORD			"Harness-Pass-1"
#define	HARNESS_CONFIG_FILE			"$vpn_harness.config"
#define	HARNESS_CONFIG_BACKUP_DIR	L"$backup.vpn_harness.config"	// Named by BackupCfgWEx after HARNESS_CONFIG_FILE
#define	HARNESS_FRAME_SIZE			96
#define	HARNESS_ETHERTYPE_HI		0x88				// EtherType 0x88B5 (IEEE local experimental)
#define	HARNESS_ETHERTYPE_LO		0xB5
#define	HARNESS_BENCH_HOST			"www.example.invalid"	// Host name in the HTTP, TLS and DNS bench frames

// Test packet adapter: injects queued frames into a hub and records the frames the hub delivers
typedef struct HARNESS_PA
{
	char Name[64];
	LOCK *Lock;
	QUEUE *SendQueue;			// HARNESS_FRAME * waiting to be handed to the session
	LIST *RecvList;				// HARNESS_FRAME * received from the hub (when Record is true)
	EVENT *RecvEvent;			// Set after a batch of received frames
	EVENT *SpaceEvent;			// Set when the send queue drains
	bool Record;				// Keep received frames (false: count only)
	bool Pending;				// Frames received since the last RecvEvent
	volatile bool Ready;		// PA Init has been called: the session is established
	UINT64 NumRecv;				// Received frames
	UINT64 RecvBytes;			// Received bytes
	SESSION *Session;			// Client session using this adapter
} HARNESS_PA;

// One harness run
typedef struct HARNESS
{
	SERVER *Server;				// In-process server
	CEDAR *ClientCedar;			// Cedar of the admin RPC and of the test sessions
	RPC *Rpc;					// Admin RPC (the client stubs of AdminClient.c)
	HARNESS_PA *PaA;			// Test session on HARNESS_A
	HARNESS_PA *PaB;			// Test session on HARNESS_B
	char *OldConfigName;		// SERVER_CONFIG_FILE_NAME before the run
	UINT NumFail;				// Failed checks
} HARNESS;

// harness.c
bool HarnessCheck(HARNESS *h, bool ok, char *what);
bool HarnessCheckErr(HARNESS *h, UINT err, char *what);
void HarnessSetPhase(char *phase, char *detail);
char *HarnessUniToUtf8(wchar_t *s);
char *HarnessBufToStr(BUF *b);
bool HarnessDirHasFiles(char *dir);
void HarnessGetFamilyDirs(char *family, char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update);
void HarnessCompareGolden(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, char *actual, bool update);
bool HarnessFindSession(HARNESS *h, char *hubname, char *username, bool link_mode, char *name, UINT name_size);

// harness_pack.c
void HarnessPackGolden(HARNESS *h);

// harness.c: in-process server of the named tests in other files (login.c)
HARNESS *HarnessOpenServer(char *test_name, UINT limit, char *hubname, char *username, bool *ok);
UINT HarnessCloseServer(HARNESS *h);
bool HarnessRestartServer(HARNESS *h);

// harness.c: a run whose test starts and stops the server itself, keeping its listeners and its configuration file
// between starts, or starting it as HarnessOpenServer does (listeners.c); HarnessCloseServer ends it
HARNESS *HarnessOpenRun(char *test_name, UINT limit);
bool HarnessStartServerKeep(HARNESS *h, bool fresh);
bool HarnessStartServerHub(HARNESS *h, char *hubname, char *username);
void HarnessStopServerKeep(HARNESS *h);

// harness_pack.c: raw-pack client of the named login tests (login.c)
SOCK *HarnessRawConnect(UCHAR *random);
PACK *HarnessRawLoginPack(char *hubname, char *username, UINT authtype);
UINT HarnessRawRequest(SOCK *s, PACK *p);
void HarnessRawClose(SOCK *s);

#endif	// HARNESS_INT_H
