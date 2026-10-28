// policyimporttest.c
// Named fork policy import test of vpntest ("policyimport" command, CORE-S4-3 #76)
//
// The import of the fork's access list and VLAN policy into the policy schema of the configuration store
// (Cedar/ConfigStoreImport.c), against the fork itself. The fixture tests/golden/policyimport/fork_policy.config has two
// hubs: LAB, whose users have the VLanId of their own policy or of their group's, with an access list that holds an entry
// of each kind that the import carries (a user, a group, a name that is both, prefixes and a mask that is no prefix,
// IPv4 and IPv6, protocols, a port range without a protocol, a source port, a MAC address, the TCP state, a redirect URL,
// a delay, a user list file, an entry that is inactive and one that matches nothing); and OFFICE, of the TPID 0x88A8 and
// without an access list. Golden family "policyimport":
// - policyimport_store.txt: the store that the fixture imports into (CsDump): its groups, the VLANs of its users and
//   groups, the VLAN settings of each network, and the entries of the access list as rules, each with its values and a
//   note that says what it leaves out.
// - policyimport_tables.txt: the golden rule table, the tables that the document of the store (CsPolicyDocument)
//   compiles to (PolicyTableText): the rules of each network in the order that the policy engine evaluates them.
// - policyimport_matches.txt: the tables of a document with every kind of match, and of a document without a network.
// - policyimport_frames.txt: the same frames through the fork and through the new core. The fork's server runs on the
//   fixture, and each user is an in-process session of its hub with the VLAN and the group that the fork gives it at its
//   login. The new core has, for each network, a switch (Core/Switch.h) with a port for each user as the store gives it
//   (CsGetPort: an access port of the user's VLAN, or a trunk port of every VLAN whose native VLAN is the untagged VLAN
//   of the network), and the policy engine with the document of the store, which judges what the switch delivers. ARP
//   requests of each member, untagged and tagged, show the VLANs; unicast frames show the access list and the default
//   action of each network. For each frame the report names the members that got it, with the VLAN of its tag, and the
//   verdict of the engine. The new core gets each frame to the same members as the fork, byte for byte, but where a case
//   says otherwise: to fewer members where an entry has a match that the policy engine lacks, which the import carries
//   so that it denies more than the fork did and never lets more through; and without its tag a frame that a member
//   without a VLAN tags with the untagged VLAN of the network, which is the native VLAN of the trunk ports.
// Print "POLICYIMPORT TEST OK" only when every check passes.

#include "harness_int.h"
#include "testlist.h"

#include "Cedar/Account.h"
#include "Cedar/Cedar.h"
#include "Cedar/ConfigStore.h"
#include "Cedar/Connection.h"
#include "Cedar/Hub.h"
#include "Cedar/Server.h"
#include "Cedar/Session.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/TcpIp.h"

#include "Core/Policy.h"
#include "Core/Switch.h"

#define	PITEST_FIXTURE			"fork_policy.config"
#define	PITEST_STORE			"policyimport_store.txt"
#define	PITEST_TABLES			"policyimport_tables.txt"
#define	PITEST_MATCHES			"policyimport_matches.txt"
#define	PITEST_FRAMES			"policyimport_frames.txt"
#define	PITEST_SERVER_CONFIG	"$policyimport_server.config"			// The copy of the fixture that the fork's server runs on, next to vpntest
#define	PITEST_SERVER_CONFIG_W	L"$policyimport_server.config"
#define	PITEST_SERVER_BACKUP_W	L"$backup.policyimport_server.config"	// ... and the backup directory of that file, if the server makes one
#define	PITEST_FRAME_MAX		128			// Bytes of a frame of a case at most
#define	PITEST_SPORT			40000		// The source port of the frame of case n is this plus n
#define	PITEST_STEP				1000		// ms of the clock of the switch and of the policy engine from one case to the next
#define	PITEST_NUM_NETS			2
#define	PITEST_BROADCAST		0xFFFFFFFF	// The destination of an ARP request: the broadcast address

// The TCP flags of a case
#define	PITEST_SYN				0x02
#define	PITEST_ACK				0x10

// The kinds of frame of a case
#define	PITEST_ARP				0			// An ARP request to the broadcast address, for the address .254 of the network
#define	PITEST_TCP				1			// A TCP segment with the flags of the case
#define	PITEST_UDP				2			// A UDP datagram of 4 bytes
#define	PITEST_PING				3			// An ICMP echo request
#define	PITEST_TCP6				4			// A TCP segment over IPv6
#define	PITEST_PING6			5			// An ICMPv6 echo request

// What the new core does with the frame of a case next to the fork
#define	PITEST_SAME				0			// The same members get the same bytes
#define	PITEST_NARROWER			1			// Some of them do not: an entry with a match that the engine lacks denies more
#define	PITEST_NATIVE			2			// The same members get it without its tag of the untagged VLAN of the network
#define	PITEST_OTHER			3			// Anything else, which no case expects
#define	PITEST_NUM_RELATIONS	4

// The users of the fixture
#define	PIU_ALICE				0
#define	PIU_BOB					1
#define	PIU_CAROL				2
#define	PIU_DAVE				3
#define	PIU_ERIN				4
#define	PIU_FRANK				5
#define	PIU_OPS					6
#define	PIU_SRV					7
#define	PIU_KIM					8
#define	PIU_LEE					9
#define	PIU_MAX					10
#define	PIU_NUM					11

// A user of the fixture, which is a member of the network of its hub
typedef struct PITEST_USER
{
	char *Network;							// Its hub
	char *Name;								// The user
	UCHAR Mac[6];							// The address it sends from
	UCHAR Ip[4];							// ... its IPv4 address
	UCHAR Ip6[16];							// ... and its IPv6 address, all 0 for none
} PITEST_USER;

static PITEST_USER pitest_users[PIU_NUM] =
{
	{"LAB", "alice", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x01}, {10, 0, 0, 1}, {0}},
	{"LAB", "bob", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x02}, {10, 0, 0, 2}, {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}},
	{"LAB", "carol", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x03}, {10, 0, 0, 3}, {0}},
	{"LAB", "dave", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x04}, {10, 0, 0, 4}, {0}},
	{"LAB", "erin", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x05}, {10, 0, 0, 5}, {0}},
	{"LAB", "frank", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x06}, {10, 0, 0, 6}, {0}},
	{"LAB", "ops", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x07}, {10, 0, 0, 7}, {0}},
	{"LAB", "srv", {0x02, 0x00, 0x00, 0x4C, 0x00, 0x0A}, {10, 0, 0, 10}, {0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}},
	{"OFFICE", "kim", {0x02, 0x00, 0x00, 0x0F, 0x00, 0x01}, {10, 1, 0, 1}, {0}},
	{"OFFICE", "lee", {0x02, 0x00, 0x00, 0x0F, 0x00, 0x02}, {10, 1, 0, 2}, {0}},
	{"OFFICE", "max", {0x02, 0x00, 0x00, 0x0F, 0x00, 0x03}, {10, 1, 0, 3}, {0}},
};

static char *pitest_networks[PITEST_NUM_NETS] = {"LAB", "OFFICE"};

static UCHAR pitest_broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static char *pitest_relations[PITEST_NUM_RELATIONS] = {"the same", "narrower", "native vlan untagged", "different"};

// The reasons of a verdict of the policy engine (POLICY_PASS_*, POLICY_DROP_*) in a report
static char *pitest_reasons[POLICY_NUM_REASONS] =
{
	"pass-rule", "pass-default", "pass-flow", "pass-related", "pass-control", "drop-rule", "drop-default", "drop-malformed",
	"drop-member", "drop-network", "drop-isolated", "drop-mac", "drop-ip", "drop-broadcast", "drop-dhcp-server", "drop-ra",
	"drop-protocol",
};

// A frame that a member sends, and what the new core must do with it next to the fork
typedef struct PITEST_CASE
{
	char *Name;
	UINT From;								// The user that sends it (PIU_*)
	UINT To;								// The user whose addresses it goes to, PITEST_BROADCAST for an ARP request
	UINT Vlan;								// The VLAN of its tag, 0 for none
	UINT Kind;								// PITEST_ARP to PITEST_PING6
	UCHAR Dst[4];							// An IPv4 destination of its own, behind the user To; all 0 for the address of To
	UINT Port;								// The destination port of TCP or UDP
	UCHAR Flags;							// The TCP flags
	UINT Expect;							// PITEST_SAME, PITEST_NARROWER or PITEST_NATIVE
} PITEST_CASE;

static PITEST_CASE pitest_cases[] =
{
	// The VLANs of LAB: an ARP request of each member, then tagged ones of the members without a VLAN, which also tell
	// the hub and the switch where those members are in the VLANs of the tags
	{"alice hello", PIU_ALICE, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"bob hello", PIU_BOB, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"carol hello", PIU_CAROL, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"dave hello", PIU_DAVE, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"erin hello", PIU_ERIN, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"frank hello", PIU_FRANK, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"ops hello", PIU_OPS, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"srv hello", PIU_SRV, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"bob hello in vlan 10", PIU_BOB, PITEST_BROADCAST, 10, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"srv hello in vlan 1", PIU_SRV, PITEST_BROADCAST, 1, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"srv hello in vlan 10", PIU_SRV, PITEST_BROADCAST, 10, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"srv hello in vlan 20", PIU_SRV, PITEST_BROADCAST, 20, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"carol hello in vlan 99", PIU_CAROL, PITEST_BROADCAST, 99, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"carol hello in the untagged vlan 2", PIU_CAROL, PITEST_BROADCAST, 2, PITEST_ARP, {0}, 0, 0, PITEST_NATIVE},
	// The access list of LAB, and what no entry matches
	{"alice tcp 22 to srv", PIU_ALICE, PIU_SRV, 0, PITEST_TCP, {0}, 22, PITEST_SYN, PITEST_SAME},
	{"bob tcp 22 to srv", PIU_BOB, PIU_SRV, 0, PITEST_TCP, {0}, 22, PITEST_SYN, PITEST_SAME},
	{"erin udp 53 to srv", PIU_ERIN, PIU_SRV, 0, PITEST_UDP, {0}, 53, 0, PITEST_SAME},
	{"frank udp 8080 to alice", PIU_FRANK, PIU_ALICE, 0, PITEST_UDP, {0}, 8080, 0, PITEST_SAME},
	{"ops tcp 3389 to carol", PIU_OPS, PIU_CAROL, 0, PITEST_TCP, {0}, 3389, PITEST_SYN, PITEST_SAME},
	{"dave tcp 443 to srv", PIU_DAVE, PIU_SRV, 0, PITEST_TCP, {0}, 443, PITEST_SYN, PITEST_SAME},
	{"bob udp 8080 to srv", PIU_BOB, PIU_SRV, 0, PITEST_UDP, {0}, 8080, 0, PITEST_SAME},
	{"bob udp 9999 to srv", PIU_BOB, PIU_SRV, 0, PITEST_UDP, {0}, 9999, 0, PITEST_NARROWER},
	{"carol tcp 80 to srv", PIU_CAROL, PIU_SRV, 0, PITEST_TCP, {0}, 80, PITEST_SYN, PITEST_NARROWER},
	{"bob tcp 80 to srv", PIU_BOB, PIU_SRV, 0, PITEST_TCP, {0}, 80, PITEST_SYN, PITEST_NARROWER},
	{"bob tcp ack 5000 to srv", PIU_BOB, PIU_SRV, 0, PITEST_TCP, {0}, 5000, PITEST_ACK, PITEST_NARROWER},
	{"bob tcp syn 5000 to srv", PIU_BOB, PIU_SRV, 0, PITEST_TCP, {0}, 5000, PITEST_SYN, PITEST_SAME},
	{"bob ping to carol", PIU_BOB, PIU_CAROL, 0, PITEST_PING, {0}, 0, 0, PITEST_SAME},
	{"carol ping to bob", PIU_CAROL, PIU_BOB, 0, PITEST_PING, {0}, 0, 0, PITEST_SAME},
	{"bob ping6 to srv", PIU_BOB, PIU_SRV, 0, PITEST_PING6, {0}, 0, 0, PITEST_SAME},
	{"bob tcp6 22 to srv", PIU_BOB, PIU_SRV, 0, PITEST_TCP6, {0}, 22, PITEST_SYN, PITEST_SAME},
	{"carol udp 7 to 172.16.5.1 through srv", PIU_CAROL, PIU_SRV, 0, PITEST_UDP, {172, 16, 5, 1}, 7, 0, PITEST_SAME},
	{"carol ping to 172.16.5.2 through srv", PIU_CAROL, PIU_SRV, 0, PITEST_PING, {172, 16, 5, 2}, 0, 0, PITEST_NARROWER},
	// OFFICE: the TPID 0x88A8, and the default action of a network without an access list
	{"kim hello", PIU_KIM, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"lee hello", PIU_LEE, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"max hello", PIU_MAX, PITEST_BROADCAST, 0, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"lee hello in vlan 30", PIU_LEE, PITEST_BROADCAST, 30, PITEST_ARP, {0}, 0, 0, PITEST_SAME},
	{"kim tcp 445 to lee", PIU_KIM, PIU_LEE, 0, PITEST_TCP, {0}, 445, PITEST_SYN, PITEST_SAME},
	{"lee udp 53 to max", PIU_LEE, PIU_MAX, 0, PITEST_UDP, {0}, 53, 0, PITEST_SAME},
};

#define	PITEST_NUM_CASES		(sizeof(pitest_cases) / sizeof(pitest_cases[0]))

// A document with every kind of match that a table shows: users, groups, tags, addresses, address groups (one of them
// empty), VLANs, port ranges, the direction both, the protocols ip, icmp and a number, and a rule of one network
static char pitest_doc_matches[] =
	"{\"networks\": [{\"name\": \"lab\", \"mode\": \"l2\"}, {\"name\": \"wan\"}],"
	" \"addressGroups\": [{\"name\": \"dmz\", \"addresses\": [\"10.2.0.0/24\", \"2001:db8:2::/64\"]}, {\"name\": \"empty\"}],"
	" \"rules\": ["
	"{\"name\": \"web\", \"action\": \"allow\", \"priority\": 5, \"networks\": [\"lab\"], \"vlans\": [10, 20],"
	" \"from\": {\"users\": [\"ann\", \"bob\"], \"groups\": [\"staff\"], \"tags\": [\"laptop\"]},"
	" \"to\": {\"tags\": [\"server\"], \"addressGroups\": [\"dmz\", \"empty\"]}, \"protocol\": \"tcp\", \"ports\": [80, \"8000-8080\"], \"direction\": \"both\"},"
	"{\"name\": \"routed\", \"action\": \"allow\", \"priority\": 10, \"from\": {\"addresses\": [\"10.1.0.0/16\", \"2001:db8::1\"]}, \"protocol\": \"ip\"},"
	"{\"name\": \"ping\", \"action\": \"allow\", \"priority\": 20, \"protocol\": \"icmp\"},"
	"{\"name\": \"gre\", \"action\": \"deny\", \"priority\": 30, \"networks\": [\"wan\"], \"protocol\": 47}]}";

// A document that the engine refuses: its networks are no array
static char pitest_doc_refused[] = "{\"networks\": 7}";

// The checks of the test, and the family "policyimport"
typedef struct PITEST_CTX
{
	UINT NumChecks;							// Checks run so far
	UINT NumFailed;							// Checks failed so far
	char OutDir[MAX_SIZE];					// The output directory of the family
	char GoldenDir[MAX_SIZE];				// ... its golden directory
	bool Update;							// Update mode: the golden files are written, not compared
	wchar_t Fixture[MAX_PATH];				// The fork configuration of the fixture
} PITEST_CTX;

// A network of the fixture, in the fork and in the new core
typedef struct PITEST_NET
{
	char *Name;								// The hub, which is the network of the store
	char PolicyName[MAX_SIZE];				// Its name in the document of the policy engine (CsPolicyNetworkName)
	HUB *Hub;								// The fork: the hub of the server
	SWITCH *Switch;							// The new core: the switch of the network
	UINT Tpid;								// The TPID of its tags (CsGetPort)
	UINT Untagged;							// Its untagged VLAN, the native VLAN of its trunk ports
} PITEST_NET;

// A user of the fixture, in the fork and in the new core
typedef struct PITEST_MEMBER
{
	PITEST_USER *User;						// The user
	PITEST_NET *Net;						// Its network
	SESSION *Session;						// The fork: its in-process session on the hub
	UINT ForkVlan;							// ... the VLAN of the session (the VLanId of the policy of the user or of its group)
	char ForkGroup[MAX_SIZE];				// ... and its group
	CS_PORT Port;							// The new core: its port, as the store gives it (CsGetPort)
	char Group[MAX_SIZE];					// ... its group in the store (CsGetUser)
	UINT SwitchPort;						// ... its port on the switch
	UINT Member;							// ... and its number in the policy engine
	UINT ForkNum;							// The frames of the current case that the hub queued for the session
	UINT ForkSize;							// ... the size of the first
	UCHAR ForkFrame[PITEST_FRAME_MAX];		// ... and its bytes
	UINT CoreNum;							// The frames of the current case that the switch delivered to the port
	UINT CoreSize;							// ... the size of the first
	UCHAR CoreFrame[PITEST_FRAME_MAX];		// ... and its bytes
	bool CoreKept;							// ... which the policy engine let through
} PITEST_MEMBER;

// The store of the fixture, and the fork and the new core on the same frames
typedef struct PITEST_RUN
{
	wchar_t Dir[MAX_PATH];					// The directory of the store
	CONFIG_STORE *Store;					// The store that the fixture imports into
	char *Document;							// The document of rules of the store (CsPolicyDocument)
	char *OldConfigName;					// SERVER_CONFIG_FILE_NAME before the fork's server started
	SERVER *Server;							// The fork's server on the fixture
	THREAD *Thread;							// The owner of the connections of the sessions; it has nothing to run
	POLICY_ENGINE *Engine;					// The policy engine of the new core, with the document of the store
	USHORT EveryVlan[SWITCH_MAX_VLAN];		// The allowed list of a trunk port: every VLAN
	PITEST_NET Nets[PITEST_NUM_NETS];
	PITEST_MEMBER Members[PIU_NUM];
	BUF *Report;							// The report of the frames (PITEST_FRAMES)
	UINT Counts[PITEST_NUM_RELATIONS];		// The cases by what the new core did next to the fork
	UINT NumWrong;							// The cases that did not do what they expect
	char Wrong[MAX_SIZE];					// ... their numbers
} PITEST_RUN;

// Record one check: print [PASS] with what, or [FAIL] with what and the formatted detail
static bool PiCheck(PITEST_CTX *ctx, bool ok, char *what, char *fmt, ...) RANZ_PRINTF_FORMAT(4, 5);
static bool PiCheck(PITEST_CTX *ctx, bool ok, char *what, char *fmt, ...)
{
	char detail[MAX_SIZE * 2];
	va_list args;

	ctx->NumChecks++;

	if (ok)
	{
		Print("  [PASS] %s\n", what);
		return true;
	}

	va_start(args, fmt);
	FormatArgs(detail, sizeof(detail), fmt, args);
	va_end(args);

	Print("  [FAIL] %s: %s\n", what, detail);
	ctx->NumFailed++;

	return false;
}

// Compare a text with the golden file file of the family; what names the check
static void PiGolden(PITEST_CTX *ctx, char *file, char *text, char *what)
{
	HARNESS h;

	Zero(&h, sizeof(h));
	HarnessCompareGolden(&h, ctx->OutDir, ctx->GoldenDir, file, text, ctx->Update);
	PiCheck(ctx, h.NumFail == 0, what, "it differs from the golden file %s (the diff is above)", file);
}

// The name of the reason of a verdict
static char *PiReason(UINT reason)
{
	return (reason < POLICY_NUM_REASONS ? pitest_reasons[reason] : "unknown");
}

// Delete the files of a directory, then the directory (it holds no subdirectory)
static void PiDeleteDir(wchar_t *dir)
{
	wchar_t path[MAX_PATH];
	DIRLIST *d = EnumDirW(dir);

	for (UINT i = 0;d != NULL && i < d->NumFiles;i++)
	{
		if (d->File[i]->Folder == false)
		{
			ConbinePathW(path, sizeof(path), dir, d->File[i]->FileNameW);
			FileDeleteW(path);
		}
	}

	if (d != NULL)
	{
		FreeDir(d);
	}
	DeleteDirW(dir);
}

// Delete the copy of the fixture that the fork's server ran on, and its backup directory
static void PiDeleteServerFiles()
{
	wchar_t path[MAX_PATH];
	wchar_t dir[MAX_PATH];

	InnerFilePathW(path, sizeof(path), PITEST_SERVER_CONFIG_W);
	FileDeleteW(path);

	InnerFilePathW(dir, sizeof(dir), PITEST_SERVER_BACKUP_W);
	PiDeleteDir(dir);
}

//
// The frames
//

// The Ethernet header of a frame at f to dst from src, with a tag of tpid and vlan unless vlan is 0, of the EtherType
// type: its size
static UINT PiEth(UCHAR *f, UCHAR *dst, UCHAR *src, UINT tpid, UINT vlan, UINT type)
{
	UINT pos = 12;

	Copy(f, dst, 6);
	Copy(f + 6, src, 6);
	if (vlan != 0)
	{
		f[pos++] = (UCHAR)(tpid >> 8);
		f[pos++] = (UCHAR)tpid;
		f[pos++] = (UCHAR)(vlan >> 8);
		f[pos++] = (UCHAR)vlan;
	}
	f[pos++] = (UCHAR)(type >> 8);
	f[pos++] = (UCHAR)type;

	return pos;
}

// The TCP, UDP, ICMP or ICMPv6 part of the frame of case c, case number n, at l4, with its checksum left 0: its size
static UINT PiTransport(UCHAR *l4, PITEST_CASE *c, UINT n)
{
	UINT sport = PITEST_SPORT + n;

	Zero(l4, 20);

	if (c->Kind == PITEST_TCP || c->Kind == PITEST_TCP6)
	{
		l4[0] = (UCHAR)(sport >> 8);
		l4[1] = (UCHAR)sport;
		l4[2] = (UCHAR)(c->Port >> 8);
		l4[3] = (UCHAR)c->Port;
		l4[7] = 1;							// Sequence number 1
		if ((c->Flags & PITEST_ACK) != 0)
		{
			l4[11] = 1;						// Acknowledgement number 1
		}
		l4[12] = 0x50;						// A header of 20 bytes
		l4[13] = c->Flags;
		l4[14] = 0x20;						// Window 8192

		return 20;
	}

	if (c->Kind == PITEST_UDP)
	{
		l4[0] = (UCHAR)(sport >> 8);
		l4[1] = (UCHAR)sport;
		l4[2] = (UCHAR)(c->Port >> 8);
		l4[3] = (UCHAR)c->Port;
		l4[5] = 12;							// Its length
		Copy(l4 + 8, "PITE", 4);

		return 12;
	}

	// An echo request with the case number as its id
	l4[0] = (UCHAR)(c->Kind == PITEST_PING6 ? 128 : 8);
	l4[4] = (UCHAR)(n >> 8);
	l4[5] = (UCHAR)n;
	l4[7] = 1;								// Sequence number 1
	Copy(l4 + 8, "PITE", 4);

	return 12;
}

// The frame of case c, case number n, that the member from sends, into f, with the checksums of its headers: its size.
// A tagged frame carries the TPID of the network of the member.
static UINT PiFrame(UCHAR *f, PITEST_MEMBER *from, PITEST_CASE *c, UINT n)
{
	PITEST_USER *u = from->User;
	UCHAR l4[64];
	UCHAR target[4];
	USHORT sum;

	if (c->Kind == PITEST_ARP)
	{
		// Who has 10.x.0.254, x of the network of the member
		UINT pos = PiEth(f, pitest_broadcast, u->Mac, from->Net->Tpid, c->Vlan, 0x0806);
		UCHAR *arp = f + pos;

		target[0] = u->Ip[0];
		target[1] = u->Ip[1];
		target[2] = 0;
		target[3] = 254;

		Zero(arp, 28);
		arp[1] = 1;							// Ethernet
		arp[2] = 0x08;						// IPv4
		arp[4] = 6;
		arp[5] = 4;
		arp[7] = 1;							// A request
		Copy(arp + 8, u->Mac, 6);
		Copy(arp + 14, u->Ip, 4);
		Copy(arp + 24, target, 4);

		return pos + 28;
	}

	PITEST_USER *to = &pitest_users[c->To];
	UINT size = PiTransport(l4, c, n);

	if (c->Kind == PITEST_TCP6 || c->Kind == PITEST_PING6)
	{
		UCHAR protocol = (UCHAR)(c->Kind == PITEST_TCP6 ? IP_PROTO_TCP : 58);
		UINT pos = PiEth(f, to->Mac, u->Mac, from->Net->Tpid, c->Vlan, 0x86DD);
		UCHAR *ip = f + pos;

		sum = CalcChecksumForIPv6((IPV6_ADDR *)u->Ip6, (IPV6_ADDR *)to->Ip6, protocol, l4, size, 0);
		Copy(l4 + (c->Kind == PITEST_TCP6 ? 16 : 2), &sum, sizeof(sum));

		Zero(ip, 40);
		ip[0] = 0x60;
		ip[4] = (UCHAR)(size >> 8);
		ip[5] = (UCHAR)size;
		ip[6] = protocol;
		ip[7] = 64;							// Hop limit
		Copy(ip + 8, u->Ip6, 16);
		Copy(ip + 24, to->Ip6, 16);
		Copy(ip + 40, l4, size);

		return pos + 40 + size;
	}

	UCHAR protocol = (UCHAR)(c->Kind == PITEST_TCP ? IP_PROTO_TCP : (c->Kind == PITEST_UDP ? IP_PROTO_UDP : 1));
	UCHAR *dst = (IsZero(c->Dst, 4) ? to->Ip : c->Dst);
	UINT src_ip;
	UINT dst_ip;
	UINT pos = PiEth(f, to->Mac, u->Mac, from->Net->Tpid, c->Vlan, 0x0800);
	UCHAR *ip = f + pos;

	Copy(&src_ip, u->Ip, 4);
	Copy(&dst_ip, dst, 4);
	if (c->Kind == PITEST_PING)
	{
		sum = IpChecksum(l4, size);
		Copy(l4 + 2, &sum, sizeof(sum));
	}
	else
	{
		sum = CalcChecksumForIPv4(src_ip, dst_ip, protocol, l4, size, 0);
		Copy(l4 + (c->Kind == PITEST_TCP ? 16 : 6), &sum, sizeof(sum));
	}

	Zero(ip, 20);
	ip[0] = 0x45;
	ip[2] = (UCHAR)((20 + size) >> 8);
	ip[3] = (UCHAR)(20 + size);
	ip[6] = 0x40;							// Don't fragment
	ip[8] = 64;								// Time to live
	ip[9] = protocol;
	Copy(ip + 12, u->Ip, 4);
	Copy(ip + 16, dst, 4);
	sum = IpChecksum(ip, 20);
	Copy(ip + 10, &sum, sizeof(sum));
	Copy(ip + 20, l4, size);

	return pos + 20 + size;
}

//
// The import: the store, its golden dump and its golden rule table
//

// The import of the fixture into a new store: false when there is no store with its document
static bool PiImport(PITEST_CTX *ctx, PITEST_RUN *run)
{
	wchar_t path[MAX_PATH];
	wchar_t tmp[MAX_PATH];
	char error[MAX_SIZE];
	CS_IMPORT r;

	Print("[import: the access lists, groups and VLANs of the fixture into a store]\n");

	UniFormat(tmp, sizeof(tmp), L"policyimport_%u", Rand32());
	ConbinePathW(run->Dir, sizeof(run->Dir), MsGetMyTempDirW(), tmp);
	MakeDirExW(run->Dir);
	ConbinePathW(path, sizeof(path), run->Dir, CS_FILE_NAME);

	run->Store = CsOpen(path);
	UINT err = CsImportForkConfig(run->Store, ctx->Fixture, &r);
	if (PiCheck(ctx, run->Store != NULL && err == ERR_NO_ERROR, "The fork configuration of the fixture imports into an empty store", "store %p, error %u",
		run->Store, err) == false)
	{
		return false;
	}

	PiCheck(ctx, r.NumNetworks == 2 && r.NumUsers == 11 && r.NumGroups == 3 && r.NumVlans == 6 && r.NumSkipped == 0,
		"The import reports 2 networks, 11 users, 3 groups and 6 VLANs of users and groups, and skips nothing",
		"%u networks, %u users, %u groups, %u VLANs, %u skipped", r.NumNetworks, r.NumUsers, r.NumGroups, r.NumVlans, r.NumSkipped);
	PiCheck(ctx, r.NumEntries == 16 && r.NumEntriesInactive == 3 && r.NumEntriesWidened == 4 && r.NumEffectsDropped == 2 && r.NumOptionsDropped == 0,
		"The import carries the 16 entries of the access list of LAB: 3 inactive, 4 that deny more than the fork did, 2 with a redirect or a delay left out",
		"%u entries, %u inactive, %u widened, %u effects and %u options left out", r.NumEntries, r.NumEntriesInactive, r.NumEntriesWidened,
		r.NumEffectsDropped, r.NumOptionsDropped);

	BUF *b = CsDump(run->Store);
	char *dump = HarnessBufToStr(b);
	FreeBuf(b);
	PiGolden(ctx, PITEST_STORE, dump, "The store holds the groups, the VLANs and the access lists as rules: it matches the golden dump " PITEST_STORE);
	Free(dump);

	run->Document = CsPolicyDocument(run->Store);
	error[0] = 0;
	char *tables = (run->Document != NULL ? PolicyTableText(run->Document, StrLen(run->Document), error, sizeof(error)) : NULL);
	if (PiCheck(ctx, tables != NULL, "The document of rules of the store compiles into the rule tables of the policy engine", "no document, or \"%s\"",
		error) == false)
	{
		return false;
	}

	PiGolden(ctx, PITEST_TABLES, tables, "The access list of the fork compiles into the golden rule table " PITEST_TABLES);
	PolicyFreeString(tables);

	return true;
}

// The rule tables of a document with every kind of match, and of a document without a network; a document that the
// engine refuses has none
static void PiMatches(PITEST_CTX *ctx)
{
	char error[MAX_SIZE];
	char refusal[MAX_SIZE];
	BUF *b = NewBuf();

	Print("[the rule tables of a document with every kind of match]\n");

	char *tables = PolicyTableText(pitest_doc_matches, StrLen(pitest_doc_matches), error, sizeof(error));
	char *none = PolicyTableText("{}", 2, error, sizeof(error));
	PiCheck(ctx, tables != NULL && none != NULL, "PolicyTableText writes the tables of a document with every kind of match, and of one without a network",
		"\"%s\"", error);

	if (tables != NULL)
	{
		WriteBuf(b, tables, StrLen(tables));
	}
	if (none != NULL)
	{
		WriteBuf(b, none, StrLen(none));
	}
	PolicyFreeString(tables);
	PolicyFreeString(none);

	char *text = HarnessBufToStr(b);
	FreeBuf(b);
	PiGolden(ctx, PITEST_MATCHES, text, "The tables match the golden file " PITEST_MATCHES);
	Free(text);

	refusal[0] = 0;
	char *refused = PolicyTableText(pitest_doc_refused, StrLen(pitest_doc_refused), refusal, sizeof(refusal));
	bool parsed = PolicyParseRules(pitest_doc_refused, StrLen(pitest_doc_refused), error, sizeof(error));
	PiCheck(ctx, refused == NULL && parsed == false && IsEmptyStr(refusal) == false && StrCmp(refusal, error) == 0,
		"A document that the engine refuses has no tables, for the reason that PolicyParseRules gives", "tables %p, \"%s\", \"%s\"", refused, refusal, error);
	PolicyFreeString(refused);
}

//
// The fork: its server on the fixture, with a session of each user
//

// The connections of the sessions have nothing to run
static void PiIdleThread(THREAD *thread, void *param)
{
}

// The policy that the fork gives a session of the user name of the hub h at its login, as HubResolveSessionPolicy of
// ProtocolServer.c chooses it: the user's own, else its group's, else the default policy; the name of the group of the
// user to group
static POLICY *PiForkPolicy(HUB *h, char *name, char *group, UINT group_size)
{
	POLICY *policy = NULL;

	StrCpy(group, group_size, "");

	AcLock(h);
	{
		USER *u = AcGetUser(h, name);

		if (u != NULL)
		{
			Lock(u->lock);
			{
				USERGROUP *g = u->Group;

				if (g != NULL)
				{
					Lock(g->lock);
					{
						StrCpy(group, group_size, g->Name);
						if (u->Policy == NULL && g->Policy != NULL)
						{
							policy = ClonePolicy(g->Policy);
						}
					}
					Unlock(g->lock);
				}

				if (u->Policy != NULL)
				{
					policy = ClonePolicy(u->Policy);
				}
			}
			Unlock(u->lock);

			ReleaseUser(u);
		}
	}
	AcUnlock(h);

	if (policy == NULL)
	{
		policy = ClonePolicy(GetDefaultPolicy());
	}

	return policy;
}

// The in-process session of the member m on the hub of its network, made as the flood bench of harness.c makes one, with
// the policy, the VLAN and the group that the fork gives the user: false when it could not be made
static bool PiForkSession(PITEST_RUN *run, PITEST_MEMBER *m)
{
	CEDAR *cedar = run->Server->Cedar;
	POLICY *policy = PiForkPolicy(m->Net->Hub, m->User->Name, m->ForkGroup, sizeof(m->ForkGroup));
	UINT vlan = policy->VLanId;
	CONNECTION *c = NewServerConnection(cedar, NULL, run->Thread);
	SESSION *s = NewServerSession(cedar, c, m->Net->Hub, m->User->Name, policy);

	c->Session = s;
	ReleaseConnection(c);
	if (s == NULL)
	{
		Free(policy);
		return false;
	}

	s->Username = CopyStr(m->User->Name);
	StrCpy(s->GroupName, sizeof(s->GroupName), m->ForkGroup);
	s->VLanId = vlan;
	s->NormalClient = true;
	s->PacketAdapter->Init(s);

	m->Session = s;
	m->ForkVlan = vlan;

	return true;
}

// The fork's server on a copy of the fixture, the hubs of the fixture and a session of each user: false when it is not
// all there
static bool PiFork(PITEST_CTX *ctx, PITEST_RUN *run)
{
	wchar_t path[MAX_PATH];
	bool ok = true;

	Print("[the fork: its server on the fixture, a session of each user]\n");

	PiDeleteServerFiles();
	InnerFilePathW(path, sizeof(path), PITEST_SERVER_CONFIG_W);
	if (PiCheck(ctx, FileCopyW(ctx->Fixture, path), "The fork's server gets a copy of the fixture as its configuration", "FileCopyW to %S failed",
		path) == false)
	{
		return false;
	}

	run->OldConfigName = SERVER_CONFIG_FILE_NAME;
	SERVER_CONFIG_FILE_NAME = PITEST_SERVER_CONFIG;
	run->Server = SiNewServer();
	run->Thread = NewThread(PiIdleThread, NULL);

	for (UINT i = 0;i < PITEST_NUM_NETS;i++)
	{
		PITEST_NET *net = &run->Nets[i];

		net->Hub = (run->Server != NULL ? GetHub(run->Server->Cedar, net->Name) : NULL);
		ok = (net->Hub != NULL && ok);
	}

	for (UINT i = 0;ok && i < PIU_NUM;i++)
	{
		ok = PiForkSession(run, &run->Members[i]);
	}

	return PiCheck(ctx, ok, "The fork's server runs the hubs LAB and OFFICE of the fixture, with an in-process session of each user",
		"server %p, a hub or a session is missing", run->Server);
}

// Take the frames that the hub queued for the session of the member m: their number, with the first one
static void PiForkTake(PITEST_MEMBER *m)
{
	void *data;
	UINT size;

	m->ForkNum = 0;
	while ((size = m->Session->PacketAdapter->GetNextPacket(m->Session, &data)) != 0)
	{
		if (m->ForkNum == 0)
		{
			m->ForkSize = MIN(size, PITEST_FRAME_MAX);
			Copy(m->ForkFrame, data, m->ForkSize);
		}
		m->ForkNum++;
		Free(data);
	}
}

// The member m sends the frame of size bytes into the hub, as the SessionMain of its session would: the hub takes a copy
static void PiForkSend(PITEST_MEMBER *m, UCHAR *frame, UINT size)
{
	void *data = Malloc(size);

	Copy(data, frame, size);
	m->Session->PacketAdapter->PutPacket(m->Session, data, size);
	m->Session->PacketAdapter->PutPacket(m->Session, NULL, 0);
}

//
// The new core: a switch for each network, with the ports that the store gives its users, and the policy engine
//

// The procedure of the port of a member: it records what the switch delivers to the member
static void PiSwitchSend(void *param, UINT port, const UCHAR *frame, UINT size)
{
	PITEST_MEMBER *m = (PITEST_MEMBER *)param;

	if (m->CoreNum == 0)
	{
		m->CoreSize = MIN(size, PITEST_FRAME_MAX);
		Copy(m->CoreFrame, frame, m->CoreSize);
	}
	m->CoreNum++;
}

// The ports of the users as the store gives them, a switch for each network with a port for each of its users, and the
// policy engine with a member for each user and the document of the store in force: false when it is not all there
static bool PiCore(PITEST_CTX *ctx, PITEST_RUN *run)
{
	char error[MAX_SIZE];
	CS_USER u;
	bool ok = true;

	Print("[the new core: the ports of the store on a switch for each network, and the policy engine]\n");

	for (UINT v = 0;v < SWITCH_MAX_VLAN;v++)
	{
		run->EveryVlan[v] = (USHORT)(v + 1);
	}

	for (UINT i = 0;i < PITEST_NUM_NETS;i++)
	{
		PITEST_NET *net = &run->Nets[i];

		ok = CsPolicyNetworkName(run->Store, net->Name, net->PolicyName, sizeof(net->PolicyName)) && ok;
	}

	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];

		Zero(&u, sizeof(u));
		ok = CsGetPort(run->Store, m->Net->Name, m->User->Name, &m->Port) && CsGetUser(run->Store, m->Net->Name, m->User->Name, &u) && ok;
		StrCpy(m->Group, sizeof(m->Group), u.Group);

		// Every port of a network has its TPID, and a trunk port has its untagged VLAN as the native VLAN
		m->Net->Tpid = m->Port.Tpid;
		if (m->Port.Mode == CS_PORT_TRUNK)
		{
			m->Net->Untagged = m->Port.Vlan;
		}
	}

	for (UINT i = 0;i < PITEST_NUM_NETS;i++)
	{
		PITEST_NET *net = &run->Nets[i];
		SWITCH_CONFIG c;

		Zero(&c, sizeof(c));
		c.Tpid = (USHORT)net->Tpid;
		c.MaxPorts = PIU_NUM;
		c.MaxMacs = 1024;
		net->Switch = SwitchNew(&c);
		ok = (net->Switch != NULL && ok);
	}

	run->Engine = PolicyNew(0);
	ok = (run->Engine != NULL && ok);

	for (UINT i = 0;ok && i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];
		SWITCH_PORT_CONFIG p;
		POLICY_MEMBER_CONFIG pc;
		const char *groups[1];

		// A trunk port carries every VLAN, and takes the frames to the broadcast address of each
		Zero(&p, sizeof(p));
		p.Mode = (m->Port.Mode == CS_PORT_ACCESS ? SWITCH_ACCESS : SWITCH_TRUNK);
		p.Vlan = m->Port.Vlan;
		if (p.Mode == SWITCH_TRUNK)
		{
			p.Allowed = run->EveryVlan;
			p.NumAllowed = SWITCH_MAX_VLAN;
		}
		p.Send = PiSwitchSend;
		p.Param = m;
		m->SwitchPort = SwitchAddPort(m->Net->Switch, &p);
		ok = (m->SwitchPort != SWITCH_PORT_NONE);

		for (UINT v = SWITCH_MIN_VLAN;ok && v <= SWITCH_MAX_VLAN;v++)
		{
			if (p.Mode == SWITCH_TRUNK || v == p.Vlan)
			{
				ok = SwitchSubscribe(m->Net->Switch, m->SwitchPort, v, pitest_broadcast);
			}
		}

		groups[0] = m->Group;
		Zero(&pc, sizeof(pc));
		pc.Network = m->Net->PolicyName;
		pc.User = m->User->Name;
		pc.Groups = groups;
		pc.NumGroups = (IsEmptyStr(m->Group) ? 0 : 1);
		m->Member = PolicyAddMember(run->Engine, &pc);
		ok = (ok && m->Member != POLICY_NO_MEMBER);
	}

	error[0] = 0;
	if (ok && PolicySetRules(run->Engine, run->Document, StrLen(run->Document), error, sizeof(error)) == false)
	{
		ok = false;
	}

	return PiCheck(ctx, ok, "The new core has a switch for each network, with a port of each user as the store gives it, and the document of the store in force",
		"a network name, a port, a switch, a subscription or a member is missing, or the engine refuses the document: \"%s\"", error);
}

//
// The cases
//

// The VLAN that the switch puts the frame of case c of the member m in: the VLAN of an access port, else the VLAN of the
// tag of the frame, or the native VLAN of the trunk port
static UINT PiFrameVlan(PITEST_MEMBER *m, PITEST_CASE *c)
{
	if (m->Port.Mode == CS_PORT_ACCESS)
	{
		return m->Port.Vlan;
	}

	return (c->Vlan != 0 ? c->Vlan : m->Port.Vlan);
}

// The verdict of the policy engine on the frame of size bytes that the member from sent and the switch delivered, in
// the VLAN vlan at now, into r. A frame to the address of one member that the switch found is the frame to that member;
// any other is the frame to no member, and each member that the switch reached then gets it when PolicyDeliver lets it.
static void PiJudge(PITEST_RUN *run, PITEST_MEMBER *from, UINT vlan, UCHAR *frame, UINT size, UINT64 now, POLICY_RESULT *r)
{
	PITEST_MEMBER *to = NULL;
	UINT num = 0;

	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];

		m->CoreKept = false;
		if (m->CoreNum != 0)
		{
			to = m;
			num++;
		}
	}

	if ((frame[0] & 1) == 0 && num == 1)
	{
		to->CoreKept = PolicyInput(run->Engine, now, from->Member, to->Member, vlan, frame, size, r);
		return;
	}

	bool pass = PolicyInput(run->Engine, now, from->Member, POLICY_NO_MEMBER, vlan, frame, size, r);

	for (UINT i = 0;pass && i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];

		m->CoreKept = (m->CoreNum != 0 && PolicyDeliver(run->Engine, from->Member, m->Member, frame, size));
	}
}

// The VLAN of the tag of the network net that frame f of size bytes carries, 0 for none
static UINT PiTagOf(PITEST_NET *net, UCHAR *f, UINT size)
{
	if (size < 18 || (((UINT)f[12] << 8) | f[13]) != net->Tpid)
	{
		return 0;
	}

	return (((UINT)f[14] << 8) | f[15]) & 0xFFF;
}

// The members of the network net that got the frame of the current case, from the new core (core) or from the fork:
// "nobody", or their names, each with /<VLAN> when its frame carries a tag
static void PiDescribe(char *dst, UINT size, PITEST_RUN *run, PITEST_NET *net, bool core)
{
	char tmp[MAX_SIZE];

	StrCpy(dst, size, "");
	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];
		bool got = (core ? m->CoreKept : m->ForkNum != 0);
		UINT vlan = (core ? PiTagOf(net, m->CoreFrame, m->CoreSize) : PiTagOf(net, m->ForkFrame, m->ForkSize));

		if (m->Net != net || got == false)
		{
			continue;
		}

		if (vlan != 0)
		{
			Format(tmp, sizeof(tmp), "%s/%u", m->User->Name, vlan);
		}
		else
		{
			StrCpy(tmp, sizeof(tmp), m->User->Name);
		}

		if (IsEmptyStr(dst) == false)
		{
			StrCat(dst, size, " ");
		}
		StrCat(dst, size, tmp);
	}

	if (IsEmptyStr(dst))
	{
		StrCpy(dst, size, "nobody");
	}
}

// Whether frame a of a_size bytes is frame b of b_size bytes without its tag of the untagged VLAN of the network net
static bool PiUntagged(PITEST_NET *net, UCHAR *a, UINT a_size, UCHAR *b, UINT b_size)
{
	return (b_size == a_size + 4 && PiTagOf(net, b, b_size) == net->Untagged && Cmp(a, b, 12) == 0 && Cmp(a + 12, b + 16, a_size - 12) == 0);
}

// What the new core did with the frame of the current case in the network net next to the fork: PITEST_SAME,
// PITEST_NARROWER, PITEST_NATIVE or PITEST_OTHER
static UINT PiRelation(PITEST_RUN *run, PITEST_NET *net)
{
	bool same = true;
	bool narrower = true;
	bool native = true;
	bool fewer = false;
	bool any = false;

	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];
		bool fork = (m->ForkNum != 0);

		if (m->Net != net)
		{
			continue;
		}

		// A member that got the frame more than once
		if (m->ForkNum > 1 || m->CoreNum > 1)
		{
			return PITEST_OTHER;
		}

		if (fork != m->CoreKept)
		{
			same = false;
			native = false;
			if (fork)
			{
				fewer = true;
			}
			else
			{
				narrower = false;
			}
			continue;
		}

		if (fork == false)
		{
			continue;
		}

		any = true;
		if (m->ForkSize != m->CoreSize || Cmp(m->ForkFrame, m->CoreFrame, m->ForkSize) != 0)
		{
			same = false;
			narrower = false;
		}
		if (PiUntagged(net, m->CoreFrame, m->CoreSize, m->ForkFrame, m->ForkSize) == false)
		{
			native = false;
		}
	}

	if (same)
	{
		return PITEST_SAME;
	}
	if (narrower && fewer)
	{
		return PITEST_NARROWER;
	}
	if (native && any)
	{
		return PITEST_NATIVE;
	}

	return PITEST_OTHER;
}

// Case n: the member c->From sends its frame into the fork's hub and into the switch of its network, and the policy
// engine judges what the switch delivers. The report gets "<n> <case>: both <members> (<verdict>)" when the new core did
// what the fork did, else "<n> <case>: fork <members>; new core <members> (<verdict>): <what it did>".
static void PiCase(PITEST_RUN *run, UINT n, PITEST_CASE *c)
{
	UCHAR frame[PITEST_FRAME_MAX];
	char fork[MAX_SIZE];
	char core[MAX_SIZE];
	char verdict[MAX_SIZE];
	char line[MAX_SIZE * 4];
	char num[16];
	POLICY_RESULT r;
	PITEST_MEMBER *from = &run->Members[c->From];
	PITEST_NET *net = from->Net;
	UINT64 now = (UINT64)n * PITEST_STEP;
	UINT size = PiFrame(frame, from, c, n);

	// The fork, after what the hub queued before the case
	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PiForkTake(&run->Members[i]);
	}
	PiForkSend(from, frame, size);
	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PiForkTake(&run->Members[i]);
	}

	// The new core
	for (UINT i = 0;i < PIU_NUM;i++)
	{
		run->Members[i].CoreNum = 0;
	}
	SwitchInput(net->Switch, now, from->SwitchPort, frame, size);
	Zero(&r, sizeof(r));
	PiJudge(run, from, PiFrameVlan(from, c), frame, size, now, &r);

	UINT relation = PiRelation(run, net);
	run->Counts[relation]++;

	PiDescribe(fork, sizeof(fork), run, net, false);
	PiDescribe(core, sizeof(core), run, net, true);
	Format(verdict, sizeof(verdict), "%s%s%s", PiReason(r.Reason), r.Rule[0] != 0 ? " " : "", r.Rule);
	if (relation == PITEST_SAME)
	{
		Format(line, sizeof(line), "%u %s: both %s (%s)\n", n, c->Name, fork, verdict);
	}
	else
	{
		Format(line, sizeof(line), "%u %s: fork %s; new core %s (%s): %s\n", n, c->Name, fork, core, verdict, pitest_relations[relation]);
	}
	WriteBuf(run->Report, line, StrLen(line));

	if (relation != c->Expect)
	{
		Format(num, sizeof(num), " %u", n);
		StrCat(run->Wrong, sizeof(run->Wrong), num);
		run->NumWrong++;
	}
}

// The frames of the cases through the fork and through the new core, and the report of what each did
static void PiCases(PITEST_CTX *ctx, PITEST_RUN *run)
{
	char line[MAX_SIZE * 2];
	UINT num_agree = 0;

	Print("[the same frames through the fork's hub and through the new core]\n");

	run->Report = NewBuf();

	// The port of each member as the store gives it, which must carry the VLAN and the group that the fork gives the user
	for (UINT i = 0;i < PITEST_NUM_NETS;i++)
	{
		PITEST_NET *net = &run->Nets[i];

		Format(line, sizeof(line), "network %s: tpid 0x%04x, untagged vlan %u\n", net->Name, net->Tpid, net->Untagged);
		WriteBuf(run->Report, line, StrLen(line));

		for (UINT k = 0;k < PIU_NUM;k++)
		{
			PITEST_MEMBER *m = &run->Members[k];
			bool access = (m->Port.Mode == CS_PORT_ACCESS);

			if (m->Net != net)
			{
				continue;
			}

			if (access)
			{
				Format(line, sizeof(line), "  %s: vlan %u (access port)", m->User->Name, m->Port.Vlan);
			}
			else
			{
				Format(line, sizeof(line), "  %s: no vlan (trunk port, native vlan %u)", m->User->Name, m->Port.Vlan);
			}
			if (IsEmptyStr(m->Group) == false)
			{
				StrCat(line, sizeof(line), ", group ");
				StrCat(line, sizeof(line), m->Group);
			}
			StrCat(line, sizeof(line), "\n");
			WriteBuf(run->Report, line, StrLen(line));

			if (m->ForkVlan == (access ? m->Port.Vlan : 0) && StrCmpi(m->ForkGroup, m->Group) == 0 && m->Port.Tpid == net->Hub->Option->VlanTypeId)
			{
				num_agree++;
			}
			else
			{
				Print("  %s: the fork gives it the VLAN %u, the group \"%s\" and the TPID 0x%04x\n", m->User->Name, m->ForkVlan, m->ForkGroup,
					net->Hub->Option->VlanTypeId);
			}
		}
	}

	PiCheck(ctx, num_agree == PIU_NUM,
		"The port of each user carries the VLAN that the fork gives its sessions: an access port of the VLanId of its policy or its group's, else a trunk port",
		"%u of %u users agree (the report is below)", num_agree, PIU_NUM);

	for (UINT n = 1;n <= PITEST_NUM_CASES;n++)
	{
		PiCase(run, n, &pitest_cases[n - 1]);
	}

	Format(line, sizeof(line), "%u cases: %u the same, %u narrower, %u native vlan untagged, %u different\n", (UINT)PITEST_NUM_CASES,
		run->Counts[PITEST_SAME], run->Counts[PITEST_NARROWER], run->Counts[PITEST_NATIVE], run->Counts[PITEST_OTHER]);
	WriteBuf(run->Report, line, StrLen(line));

	char *report = HarnessBufToStr(run->Report);

	PiCheck(ctx, run->Counts[PITEST_OTHER] == 0,
		"The new core never gets a frame to a member that the fork kept it from, nor gives a member other bytes than the fork, but the tag of the untagged VLAN",
		"%u cases differ otherwise (the report is below)", run->Counts[PITEST_OTHER]);
	PiCheck(ctx, run->NumWrong == 0,
		"Each frame reaches the members that the fork gets it to, but where an entry has a match that the engine lacks, and the default action of each network carries over",
		"cases%s did not do what they expect (the report is below)", run->Wrong);
	if (run->NumWrong != 0 || num_agree != PIU_NUM)
	{
		Print("--- the report of %s:\n%s", PITEST_FRAMES, report);
	}

	PiGolden(ctx, PITEST_FRAMES, report, "The report of the frames matches the golden file " PITEST_FRAMES);
	Free(report);
}

// Stop and free what a run made, and delete its files
static void PiFree(PITEST_RUN *run)
{
	for (UINT i = 0;i < PIU_NUM;i++)
	{
		PITEST_MEMBER *m = &run->Members[i];

		if (m->Session != NULL)
		{
			DelSession(m->Net->Hub, m->Session);
			m->Session->PacketAdapter->Free(m->Session);
			ReleaseSession(m->Session);
		}
	}

	for (UINT i = 0;i < PITEST_NUM_NETS;i++)
	{
		PITEST_NET *net = &run->Nets[i];

		if (net->Hub != NULL)
		{
			ReleaseHub(net->Hub);
		}
		SwitchFree(net->Switch);
	}

	if (run->Server != NULL)
	{
		SiReleaseServer(run->Server);
	}
	if (run->Thread != NULL)
	{
		ReleaseThread(run->Thread);
	}
	if (run->OldConfigName != NULL)
	{
		SERVER_CONFIG_FILE_NAME = run->OldConfigName;
		PiDeleteServerFiles();
	}

	PolicyFree(run->Engine);
	Free(run->Document);
	CsClose(run->Store);
	if (UniIsEmptyStr(run->Dir) == false)
	{
		PiDeleteDir(run->Dir);
	}
	FreeBuf(run->Report);
	Free(run);
}

// policyimport: the import of the fork's access list and VLAN policy, against a golden rule table and the fork itself
RANZ_TEST_TAGS("policyimport", policyimport_test, "core", "Fork policy import: the access list and VLANs of a fork configuration in the store, a golden rule table, and the same frames through the fork and the new core.");
void policyimport_test(UINT num, char **arg)
{
	PITEST_CTX ctx;
	char tmp[MAX_SIZE];

	Zero(&ctx, sizeof(ctx));

	Print("Fork policy import test: the access list and the VLANs of a fork configuration, against the fork's hub\n");

	HarnessGetFamilyDirs("policyimport", ctx.OutDir, sizeof(ctx.OutDir), ctx.GoldenDir, sizeof(ctx.GoldenDir), &ctx.Update);
	MakeDirEx(ctx.OutDir);
	Format(tmp, sizeof(tmp), "%s/%s", ctx.GoldenDir, PITEST_FIXTURE);
	StrToUni(ctx.Fixture, sizeof(ctx.Fixture), tmp);
	Print("POLICYIMPORT GOLDEN MODE %s\n", ctx.Update ? "update" : "compare");
	Print("  golden directory: %s\n", ctx.GoldenDir);

	if (PiCheck(&ctx, IsFileExistsW(ctx.Fixture), "The fork configuration fixture is there", "%S is missing", ctx.Fixture))
	{
		PITEST_RUN *run = ZeroMalloc(sizeof(PITEST_RUN));

		for (UINT i = 0;i < PITEST_NUM_NETS;i++)
		{
			run->Nets[i].Name = pitest_networks[i];
		}
		for (UINT i = 0;i < PIU_NUM;i++)
		{
			run->Members[i].User = &pitest_users[i];
			run->Members[i].Net = &run->Nets[StrCmp(pitest_users[i].Network, pitest_networks[0]) == 0 ? 0 : 1];
		}

		PiMatches(&ctx);
		if (PiImport(&ctx, run) && PiFork(&ctx, run) && PiCore(&ctx, run))
		{
			PiCases(&ctx, run);
		}

		PiFree(run);
	}

	if (ctx.NumFailed == 0)
	{
		Print("POLICYIMPORT TEST OK\n");
	}
	else
	{
		Print("POLICYIMPORT TEST FAILED (%u of %u checks failed)\n", ctx.NumFailed, ctx.NumChecks);
	}
}
