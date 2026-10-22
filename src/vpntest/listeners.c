// listeners.c
// Named listeners test of vpntest ("listeners" command, spec #43)
//
// Runs the in-process server of the harness (HarnessOpenServer: the test listener on TCP 39555 of every address, a fresh
// configuration, the hub LISTENERS_HUB with an empty Hub password) and logs in to the admin RPC as vpncmd does
// (AdminConnectEx). The test numbers its cases as spec #43 does; cases 1 to 5 belong to REL-3 (#48).
// - Case 6 (REL-4 #49): while the server admin password is empty, a server admin login with the empty password passes
//   from loopback (127.0.0.0/8 and ::1) only. From any other address it gets ERR_NULL_PASSWORD_LOCAL_ONLY (51), as a
//   Hub admin login with an empty Hub password already did. The other address is one of the machine's own
//   (GetUnicastIpAddressTable), so the server sees the login come from it. AdminOpen without a socket covers the
//   loopback range and IPv6. Once a password is set, a login with it from that address passes, subject to the admin
//   source-address list ($adminip.txt), which the case writes and then restores.
// Prints "LISTENERS TEST OK" only when every check passes.

#include "harness_int.h"

#include "Cedar/Account.h"
#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/IpAddr.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <iphlpapi.h>

#define	LISTENERS_HUB				"HARNESS_LISTENERS"	// Hub of the Hub admin logins, empty Hub password
#define	LISTENERS_USER				"tester_listeners"	// Password user of LISTENERS_HUB (HarnessOpenServer creates one)
#define	LISTENERS_LOOPBACK			"127.0.0.1"			// Host of the loopback logins
#define	LISTENERS_ADMINIP			"127.0.0.1\r\n::1\r\n"	// Admin source-address list that admits loopback only
#define	LISTENERS_OPEN_ID			4949				// Session tag RPC-n of the AdminOpen checks
#define	LISTENERS_WATCHDOG_LIMIT	60000				// "listeners" process aborted after this (ms)

// One of the machine's own addresses that is not loopback, from GetUnicastIpAddressTable: a preferred IPv4 address
// outside 127.0.0.0/8 and 169.254.0.0/16, else a preferred global unicast IPv6 address. False when there is none.
static bool ListenersOwnAddress(IP *ip)
{
	MIB_UNICASTIPADDRESS_TABLE *t = NULL;
	bool found = false;

	if (GetUnicastIpAddressTable(AF_UNSPEC, &t) != NO_ERROR)
	{
		return false;
	}

	// IPv4 first, IPv6 only on a machine without such an IPv4 address
	for (UINT pass = 0;pass < 2 && found == false;pass++)
	{
		for (ULONG i = 0;i < t->NumEntries && found == false;i++)
		{
			const MIB_UNICASTIPADDRESS_ROW *r = &t->Table[i];

			if (r->DadState != IpDadStatePreferred)
			{
				continue;
			}

			if (pass == 0 && r->Address.si_family == AF_INET)
			{
				InAddrToIP(ip, &r->Address.Ipv4.sin_addr);
				found = (IsLocalHostIP(ip) == false &&
					(IPV4(ip->address)[0] != 169 || IPV4(ip->address)[1] != 254));
			}
			else if (pass == 1 && r->Address.si_family == AF_INET6)
			{
				InAddrToIP6(ip, &r->Address.Ipv6.sin6_addr);
				UINT type = GetIPAddrType6(ip);
				found = ((type & IPV6_ADDR_GLOBAL_UNICAST) && (type & IPV6_ADDR_ZERO) == 0 &&
					(type & IPV6_ADDR_LOOPBACK) == 0);
			}
		}
	}

	FreeMibTable(t);

	return found;
}

// Log in to the admin RPC as vpncmd does (AdminConnectEx) at host, TCP HARNESS_PORT: as server admin (hubname NULL)
// or as Hub admin of hubname, with password. Returns the error; the RPC of a login that passed is disconnected again.
static UINT ListenersLogin(HARNESS *h, char *host, char *hubname, char *password)
{
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	UINT err = ERR_NO_ERROR;

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"LISTENERS_ADMIN");
	StrCpy(o.Hostname, sizeof(o.Hostname), host);
	o.Port = HARNESS_PORT;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, password, StrLen(password));

	RPC *rpc = AdminConnectEx(h->ClientCedar, &o, hubname, hashed_password, &err, NULL);
	if (rpc == NULL)
	{
		return (err != ERR_NO_ERROR ? err : ERR_INTERNAL_ERROR);
	}

	AdminDisconnect(rpc);

	return ERR_NO_ERROR;
}

// AdminOpen without a socket for a server admin login with the empty password from addr, as AdminAccept passes the
// remote address of its socket. Returns the error; a session that opened is closed again.
static UINT ListenersOpen(HARNESS *h, char *addr)
{
	ADMIN_LOGIN l;
	UCHAR hashed_password[SHA1_SIZE];
	UINT err = ERR_NO_ERROR;

	Zero(&l, sizeof(l));
	StrCpy(l.ConnName, sizeof(l.ConnName), "LISTENERS_OPEN");
	if (StrToIP(&l.RemoteIP, addr) == false)
	{
		return ERR_INTERNAL_ERROR;
	}
	l.Id = LISTENERS_OPEN_ID;
	Rand(l.Random, sizeof(l.Random));
	l.AcceptEmptyPassword = true;
	Sha0(hashed_password, "", 0);
	SecurePassword(l.SecurePassword, hashed_password, l.Random);
	l.HasSecurePassword = true;

	ADMIN *a = AdminOpen(h->Server, &l, &err);
	if (a == NULL)
	{
		return (err != ERR_NO_ERROR ? err : ERR_INTERNAL_ERROR);
	}

	AdminClose(a);

	return ERR_NO_ERROR;
}

// Check the error of a login
static void ListenersExpect(HARNESS *h, char *what, UINT err, UINT expected)
{
	char tmp[MAX_SIZE];

	if (err == expected)
	{
		HarnessCheck(h, true, what);
		return;
	}

	Format(tmp, sizeof(tmp), "%s (error %u, expected %u)", what, err, expected);
	HarnessCheck(h, false, tmp);
}

// Case 6 (REL-4 #49): the empty admin password from loopback only; host is one of the machine's own addresses that is
// not loopback
static void ListenersEmptyPassword(HARNESS *h, char *host)
{
	RPC_SET_PASSWORD t;
	char tmp[MAX_SIZE];

	Print("[6: empty server admin password]\n");
	HarnessSetPhase("listeners", "6 empty password");
	Format(tmp, sizeof(tmp), "6: server admin, empty password, at %s: ERR_NULL_PASSWORD_LOCAL_ONLY", host);
	ListenersExpect(h, tmp, ListenersLogin(h, host, NULL, ""), ERR_NULL_PASSWORD_LOCAL_ONLY);
	ListenersExpect(h, "6: server admin, empty password, at " LISTENERS_LOOPBACK ": logged in",
		ListenersLogin(h, LISTENERS_LOOPBACK, NULL, ""), ERR_NO_ERROR);

	// Unchanged: a Hub admin login with an empty Hub password was refused from a remote client before
	Format(tmp, sizeof(tmp), "6: Hub admin of " LISTENERS_HUB ", empty Hub password, at %s: ERR_NULL_PASSWORD_LOCAL_ONLY "
		"as before", host);
	ListenersExpect(h, tmp, ListenersLogin(h, host, LISTENERS_HUB, ""), ERR_NULL_PASSWORD_LOCAL_ONLY);
	ListenersExpect(h, "6: Hub admin of " LISTENERS_HUB ", empty Hub password, at " LISTENERS_LOOPBACK ": logged in as "
		"before", ListenersLogin(h, LISTENERS_LOOPBACK, LISTENERS_HUB, ""), ERR_NO_ERROR);

	// The socket logins reach 127.0.0.1 and one address of the machine; AdminOpen takes any source address
	Print("[6: AdminOpen by source address]\n");
	HarnessSetPhase("listeners", "6 source address");
	ListenersExpect(h, "6: AdminOpen, server admin, empty password, from 127.0.0.2: session opened",
		ListenersOpen(h, "127.0.0.2"), ERR_NO_ERROR);
	ListenersExpect(h, "6: AdminOpen, server admin, empty password, from ::1: session opened",
		ListenersOpen(h, "::1"), ERR_NO_ERROR);
	ListenersExpect(h, "6: AdminOpen, server admin, empty password, from 192.0.2.1: ERR_NULL_PASSWORD_LOCAL_ONLY",
		ListenersOpen(h, "192.0.2.1"), ERR_NULL_PASSWORD_LOCAL_ONLY);
	ListenersExpect(h, "6: AdminOpen, server admin, empty password, from 2001:db8::1: ERR_NULL_PASSWORD_LOCAL_ONLY",
		ListenersOpen(h, "2001:db8::1"), ERR_NULL_PASSWORD_LOCAL_ONLY);

	Print("[6: server admin password set]\n");
	HarnessSetPhase("listeners", "6 password set");
	Zero(&t, sizeof(t));
	Sha0(t.HashedPassword, HARNESS_PASSWORD, StrLen(HARNESS_PASSWORD));
	if (HarnessCheckErr(h, ScSetServerPassword(h->Rpc, &t), "6: SetServerPassword " HARNESS_PASSWORD) == false)
	{
		return;
	}

	Format(tmp, sizeof(tmp), "6: server admin, the password, at %s: logged in", host);
	ListenersExpect(h, tmp, ListenersLogin(h, host, NULL, HARNESS_PASSWORD), ERR_NO_ERROR);
	Format(tmp, sizeof(tmp), "6: server admin, empty password, at %s: ERR_ACCESS_DENIED, a wrong password as before",
		host);
	ListenersExpect(h, tmp, ListenersLogin(h, host, NULL, ""), ERR_ACCESS_DENIED);

	// The server admin password does not change the Hub admin rule
	Format(tmp, sizeof(tmp), "6: Hub admin of " LISTENERS_HUB ", empty Hub password, at %s: still "
		"ERR_NULL_PASSWORD_LOCAL_ONLY", host);
	ListenersExpect(h, tmp, ListenersLogin(h, host, LISTENERS_HUB, ""), ERR_NULL_PASSWORD_LOCAL_ONLY);

	// The admin source-address list applies to a login with the password; a list beside vpntest.exe is put back after
	Print("[6: admin source-address list]\n");
	HarnessSetPhase("listeners", "6 admin source-address list");
	BUF *saved = ReadDump(ADMINIP_TXT);
	BUF *b = NewBuf();
	WriteBuf(b, LISTENERS_ADMINIP, StrLen(LISTENERS_ADMINIP));
	if (HarnessCheck(h, DumpBuf(b, ADMINIP_TXT), "6: " ADMINIP_TXT " written: 127.0.0.1 and ::1"))
	{
		Format(tmp, sizeof(tmp), "6: server admin, the password, at %s, not in " ADMINIP_TXT ": ERR_IP_ADDRESS_DENIED",
			host);
		ListenersExpect(h, tmp, ListenersLogin(h, host, NULL, HARNESS_PASSWORD), ERR_IP_ADDRESS_DENIED);
		ListenersExpect(h, "6: server admin, the password, at " LISTENERS_LOOPBACK ", in " ADMINIP_TXT ": logged in",
			ListenersLogin(h, LISTENERS_LOOPBACK, NULL, HARNESS_PASSWORD), ERR_NO_ERROR);
	}
	FreeBuf(b);

	if (saved != NULL)
	{
		HarnessCheck(h, DumpBuf(saved, ADMINIP_TXT), "6: the former " ADMINIP_TXT " put back");
		FreeBuf(saved);
	}
	else
	{
		HarnessCheck(h, FileDelete(ADMINIP_TXT), "6: " ADMINIP_TXT " deleted again");
	}
}

// "listeners": the listeners and the admin access of a fresh server (spec #43)
void listeners_test(UINT num, char **arg)
{
	IP own;
	char own_str[MAX_SIZE];
	char tmp[MAX_SIZE];
	bool ok;

	Print("Ranz listeners: in-process server on TCP %u, hub %s\n", HARNESS_PORT, LISTENERS_HUB);

	HARNESS *h = HarnessOpenServer("LISTENERS", LISTENERS_WATCHDOG_LIMIT, LISTENERS_HUB, LISTENERS_USER, &ok);

	if (HarnessCheck(h, ok, "server and hub " LISTENERS_HUB " ready"))
	{
		StrCpy(own_str, sizeof(own_str), "none");
		ok = ListenersOwnAddress(&own);
		if (ok)
		{
			IPToStr(own_str, sizeof(own_str), &own);
		}

		Format(tmp, sizeof(tmp), "the machine has an address of its own that is not loopback: %s", own_str);
		if (HarnessCheck(h, ok, tmp))
		{
			ListenersEmptyPassword(h, own_str);
		}
	}

	UINT num_fail = HarnessCloseServer(h);
	if (num_fail == 0)
	{
		Print("LISTENERS TEST OK\n");
	}
	else
	{
		Print("LISTENERS TEST FAILED (%u failed checks)\n", num_fail);
	}
}
