// listeners.c
// Named default listener test of vpntest (REL-3 #48)
//
// "listeners": the VPN listener of a default configuration (ADR-0020 decision 6), cases 1 to 5 of spec #43. Each case
// runs the in-process server of the harness (HarnessOpenRun, HarnessStartServerKeep: the test listener on TCP 39555 and
// the admin RPC), from a fresh configuration or from the one an earlier start of the case saved, and keeps the default
// listener, which is what the case reads through ListenerList. The test holds a port as another program would: a
// dual-stack socket bound with SO_EXCLUSIVEADDRUSE and listening. A case that needs 443 or 5555 free checks that
// first and fails with a check that names the port.
// 1. Default on 443: with 443 and 5555 free, ListenerList holds 443 enabled and the test listener, no 5555, and 443
//    reaches Listening within LISTENERS_LISTEN_WAIT ms.
// 2. Fallback: with 443 held, ListenerList holds 5555 listening and no 443, and the server log has the fallback line.
//    With 443 released, a restart from the saved configuration still lists only 5555.
// 3. Both taken: with 443 and 5555 held, ListenerList holds 443 in error state and the server log has the both-taken
//    line; once 443 is released, 443 reaches Listening by its own retry within LISTENERS_RETRY_WAIT ms.
// 4. No fallback after the first start: the saved configuration lists 443, and with 443 held a restart leaves 443 in
//    error state, no 5555 and no fallback line.
// 5. Any port: ListenerCreate on the free TCP LISTENERS_ANY_PORT listens and admits an admin connection, and
//    ListenerDelete removes it.
// Then the first-start probe itself (ListenProbe), which no admin RPC shows: a port that a socket without address reuse
// holds is taken (WSAEADDRINUSE), where a probe with SO_REUSEADDR would share it; right after the probe of a free port,
// an exclusive bind of that port succeeds, so the probe has closed its socket.
// The two log lines are the one text check: the test formats them from the string table as SLog does and looks for
// them in what the server log files got during the case. HarnessStartServer of the other tests deletes the default
// listener, so the ListenerList goldens keep the test listener only.
// The test prints "LISTENERS TEST OK" only when every check passes.

#include "harness_int.h"

#include "Cedar/Admin.h"
#include "Cedar/Cedar.h"
#include "Cedar/Connection.h"
#include "Cedar/HubLog.h"
#include "Cedar/LogWriter.h"
#include "Cedar/Server.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <stdarg.h>
#include <WS2tcpip.h>

#define	LISTENERS_PORT_DEFAULT		SERVER_DEF_PORTS_1	// TCP 443: the default listener
#define	LISTENERS_PORT_FALLBACK		SERVER_DEF_PORTS_4	// TCP 5555: the default listener when 443 cannot be bound
#define	LISTENERS_ANY_PORT			39559				// Free high port of ListenerCreate (below the dynamic port range)
#define	LISTENERS_PROBE_PORT		39560				// Port of the ListenProbe checks
#define	LISTENERS_IN_USE			((UINT)WSAEADDRINUSE)	// Windows socket error of a bind on a port that another socket holds
#define	LISTENERS_LISTEN_WAIT		5000				// A listener on a free port reaches Listening within this (ms)
#define	LISTENERS_RETRY_WAIT		(LISTEN_RETRY_TIME * 3)	// A retrying listener binds a released port within this (ms)
#define	LISTENERS_POLL				50					// ListenerList poll interval while waiting (ms)
#define	LISTENERS_WATCHDOG_LIMIT	120000				// The process is aborted after this (ms)

// Hold TCP port as another program would: a dual-stack socket on [::]:port with SO_EXCLUSIVEADDRUSE, listening.
// INVALID_SOCKET when the port cannot be bound
static SOCKET ListenersHold(UINT port)
{
	struct sockaddr_in6 addr;
	DWORD v6only = 0;
	BOOL exclusive = TRUE;

	SOCKET s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

	Zero(&addr, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons((USHORT)port);

	if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, sizeof(v6only)) != 0 ||
		setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&exclusive, sizeof(exclusive)) != 0 ||
		bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(s, SOMAXCONN) != 0)
	{
		closesocket(s);
		return INVALID_SOCKET;
	}

	return s;
}

// Hold port for a case and check it
static SOCKET ListenersHoldCheck(HARNESS *h, UINT port)
{
	char tmp[MAX_SIZE];
	SOCKET s = ListenersHold(port);

	Format(tmp, sizeof(tmp), "the test holds TCP %u (exclusive, dual-stack)", port);
	HarnessCheck(h, s != INVALID_SOCKET, tmp);

	return s;
}

// Release a port that ListenersHold holds
static void ListenersRelease(SOCKET *s)
{
	if (*s != INVALID_SOCKET)
	{
		closesocket(*s);
		*s = INVALID_SOCKET;
	}
}

// Check that nothing holds port before a start: the test can hold it and release it again
static bool ListenersCheckFree(HARNESS *h, UINT port)
{
	char tmp[MAX_SIZE];
	SOCKET s = ListenersHold(port);
	bool ok = (s != INVALID_SOCKET);

	ListenersRelease(&s);

	Format(tmp, sizeof(tmp), "TCP %u is free before the start", port);
	return HarnessCheck(h, ok, tmp);
}

// Contents of a server log file of EnumLogFileDir, whose path is relative to the directory of the executable
static BUF *ListenersLogRead(LOG_FILE *f)
{
	char path[MAX_PATH];

	Format(path, sizeof(path), "@%s", f->Path);

	return ReadDump(path);
}

// The server log files and their sizes now (LOG_FILE, the size read from the file, not from the directory entry):
// ListenersLogSince reads what the server writes after this mark
static LIST *ListenersLogMark()
{
	char dir[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);

	ServerLogDir(dir, sizeof(dir));
	EnumLogFileDir(o, dir);

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		BUF *b = ListenersLogRead(f);

		f->FileSize = (b != NULL ? b->Size : 0);
		FreeBuf(b);
	}

	return o;
}

// What the server log files got after mark, in UTF-8; the mark is freed
static char *ListenersLogSince(LIST *mark)
{
	char dir[MAX_PATH];
	LIST *o = NewListFast(CmpLogFile);
	BUF *text = NewBuf();

	ServerLogDir(dir, sizeof(dir));
	EnumLogFileDir(o, dir);

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		LOG_FILE *before = Search(mark, f);
		UINT start = (before != NULL ? before->FileSize : 0);

		BUF *b = ListenersLogRead(f);
		if (b != NULL)
		{
			if (b->Size > start)
			{
				WriteBuf(text, (UCHAR *)b->Buf + start, b->Size - start);
			}

			FreeBuf(b);
		}
	}

	FreeEnumLogFile(o);
	FreeEnumLogFile(mark);

	char *ret = HarnessBufToStr(text);
	FreeBuf(text);

	return ret;
}

// The text of a server log line of the string table entry name and its arguments, formatted as SLog formats it, in
// UTF-8
static char *ListenersLogLine(char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);
	va_end(args);

	return HarnessUniToUtf8(buf);
}

// The longest text of the string table entry name between its format specifiers, in UTF-8: every line of the entry
// holds it, whatever its arguments
static char *ListenersLogSignature(char *name)
{
	char *text = HarnessUniToUtf8(_UU(name));
	UINT len = StrLen(text);
	UINT start = 0;
	UINT best_start = 0;
	UINT best_len = 0;

	for (UINT i = 0;i <= len;i++)
	{
		if (i == len || text[i] == '%')
		{
			if (i - start > best_len)
			{
				best_start = start;
				best_len = i - start;
			}

			// Skip the specifier: every one of these entries is %u
			start = i + 2;
			i++;
		}
	}

	char *ret = ZeroMalloc(best_len + 1);
	Copy(ret, text + best_start, best_len);
	Free(text);

	return ret;
}

// Check that the server log of a case has the line (has true) or has no line of the entry name (has false); the
// log is printed when the check fails
static void ListenersExpectLog(HARNESS *h, char *log_text, char *name, bool has, char *line, char *what)
{
	char *signature = ListenersLogSignature(name);
	bool ok = (has ? InStrEx(log_text, line, true) : (InStrEx(log_text, signature, true) == false));

	if (HarnessCheck(h, ok, what) == false)
	{
		Print("    expected %s: %s\n", has ? "the line" : "no line holding", has ? line : signature);
		Print("    the server log of the case:\n%s\n", log_text);
	}

	Free(signature);
}

// State of the listener on port through ListenerList; false when it is not listed
static bool ListenersState(HARNESS *h, UINT port, bool *enabled, bool *error)
{
	RPC_LISTENER_LIST t;
	bool found = false;

	*enabled = false;
	*error = false;

	Zero(&t, sizeof(t));
	if (ScEnumListener(h->Rpc, &t) != ERR_NO_ERROR)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumPort;i++)
	{
		if (t.Ports[i] == port)
		{
			found = true;
			*enabled = t.Enables[i];
			*error = t.Errors[i];
		}
	}

	FreeRpcListenerList(&t);

	return found;
}

// Check that ListenerList holds the test listener and the listener on port, enabled, and nothing else
static bool ListenersExpectOnly(HARNESS *h, UINT port, char *what)
{
	RPC_LISTENER_LIST t;
	char list[MAX_SIZE];
	char one[MAX_PATH];
	char tmp[MAX_SIZE * 2];
	bool test_listed = false;
	bool port_enabled = false;

	list[0] = 0;

	Zero(&t, sizeof(t));
	if (HarnessCheckErr(h, ScEnumListener(h->Rpc, &t), "EnumListener") == false)
	{
		return false;
	}

	for (UINT i = 0;i < t.NumPort;i++)
	{
		Format(one, sizeof(one), "%s%u %s", (i == 0 ? "" : ", "), t.Ports[i],
			(t.Enables[i] == false ? "disabled" : (t.Errors[i] ? "error" : "listening")));
		StrCat(list, sizeof(list), one);

		if (t.Ports[i] == HARNESS_PORT)
		{
			test_listed = true;
		}
		else if (t.Ports[i] == port)
		{
			port_enabled = t.Enables[i];
		}
	}

	bool ok = (t.NumPort == 2 && test_listed && port_enabled);
	FreeRpcListenerList(&t);

	if (ok)
	{
		return HarnessCheck(h, true, what);
	}

	Format(tmp, sizeof(tmp), "%s (ListenerList: %s)", what, list);
	return HarnessCheck(h, false, tmp);
}

// Wait until ListenerList shows the listener on port enabled and not in error state, at most timeout ms
static bool ListenersWaitListening(HARNESS *h, UINT port, UINT timeout, char *what)
{
	UINT64 end = Tick64() + (UINT64)timeout;
	bool found, enabled, error;
	char tmp[MAX_SIZE];

	while (true)
	{
		found = ListenersState(h, port, &enabled, &error);
		if ((found && enabled && error == false) || Tick64() >= end)
		{
			break;
		}

		SleepThread(LISTENERS_POLL);
	}

	Format(tmp, sizeof(tmp), "%s within %u ms", what, timeout);
	return HarnessCheck(h, found && enabled && error == false, tmp);
}

// Check that ListenerList shows the listener on port enabled and in error state
static bool ListenersExpectError(HARNESS *h, UINT port, char *what)
{
	bool enabled, error;
	bool found = ListenersState(h, port, &enabled, &error);

	return HarnessCheck(h, found && enabled && error, what);
}

// An admin RPC connection to 127.0.0.1:port with the empty password, as vpncmd makes it; NULL when it failed
static RPC *ListenersAdminConnect(HARNESS *h, UINT port, UINT *err)
{
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"LISTENERS_ADMIN");
	StrCpy(o.Hostname, sizeof(o.Hostname), "127.0.0.1");
	o.Port = port;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, "", 0);

	*err = ERR_NO_ERROR;

	return AdminConnectEx(h->ClientCedar, &o, NULL, hashed_password, err, NULL);
}

// 1. Default on 443
static void ListenersDefault(HARNESS *h)
{
	char tmp[MAX_SIZE];

	Print("[1: default on TCP %u]\n", LISTENERS_PORT_DEFAULT);
	HarnessSetPhase("listeners", "default");

	bool ok = ListenersCheckFree(h, LISTENERS_PORT_DEFAULT);
	ok = ListenersCheckFree(h, LISTENERS_PORT_FALLBACK) && ok;
	if (ok == false)
	{
		return;
	}

	LIST *mark = ListenersLogMark();

	if (HarnessStartServerKeep(h, true))
	{
		Format(tmp, sizeof(tmp), "ListenerList holds TCP %u enabled and the test listener, no TCP %u",
			LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
		ListenersExpectOnly(h, LISTENERS_PORT_DEFAULT, tmp);

		Format(tmp, sizeof(tmp), "TCP %u reaches Listening", LISTENERS_PORT_DEFAULT);
		ListenersWaitListening(h, LISTENERS_PORT_DEFAULT, LISTENERS_LISTEN_WAIT, tmp);
	}

	HarnessStopServerKeep(h);

	char *log_text = ListenersLogSince(mark);
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_FALLBACK", false, NULL, "the server log has no fallback line");
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_BOTH_TAKEN", false, NULL, "the server log has no both-taken line");
	Free(log_text);
}

// 2. Fallback to 5555 with 443 held, kept by a restart after 443 is free again
static void ListenersFallback(HARNESS *h)
{
	char tmp[MAX_SIZE];

	Print("[2: TCP %u held, fallback to TCP %u]\n", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
	HarnessSetPhase("listeners", "fallback");

	if (ListenersCheckFree(h, LISTENERS_PORT_FALLBACK) == false)
	{
		return;
	}

	SOCKET held = ListenersHoldCheck(h, LISTENERS_PORT_DEFAULT);
	if (held == INVALID_SOCKET)
	{
		return;
	}

	LIST *mark = ListenersLogMark();
	bool ok = HarnessStartServerKeep(h, true);

	if (ok)
	{
		Format(tmp, sizeof(tmp), "ListenerList holds TCP %u enabled and the test listener, no TCP %u",
			LISTENERS_PORT_FALLBACK, LISTENERS_PORT_DEFAULT);
		ok = ListenersExpectOnly(h, LISTENERS_PORT_FALLBACK, tmp);

		Format(tmp, sizeof(tmp), "TCP %u reaches Listening", LISTENERS_PORT_FALLBACK);
		ListenersWaitListening(h, LISTENERS_PORT_FALLBACK, LISTENERS_LISTEN_WAIT, tmp);
	}

	HarnessStopServerKeep(h);

	// The line names 443 and its error, the port vpncmd must use and how to move the listener to 443
	char *log_text = ListenersLogSince(mark);
	char *line = ListenersLogLine("LS_DEFAULT_LISTENER_FALLBACK", LISTENERS_PORT_DEFAULT, LISTENERS_IN_USE,
		LISTENERS_PORT_FALLBACK, LISTENERS_PORT_FALLBACK, LISTENERS_PORT_DEFAULT, LISTENERS_PORT_DEFAULT,
		LISTENERS_PORT_FALLBACK);
	Format(tmp, sizeof(tmp), "the server log has the fallback line: TCP %u, error %u (WSAEADDRINUSE), TCP %u for vpncmd, "
		"ListenerCreate %u and ListenerDelete %u", LISTENERS_PORT_DEFAULT, LISTENERS_IN_USE, LISTENERS_PORT_FALLBACK,
		LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_FALLBACK", true, line, tmp);
	Free(line);
	Free(log_text);

	ListenersRelease(&held);

	if (ok == false)
	{
		return;
	}

	// The saved configuration lists 5555: no probe, no change behind the operator's back
	Print("[2: restart from the saved configuration, TCP %u free again]\n", LISTENERS_PORT_DEFAULT);
	HarnessSetPhase("listeners", "fallback restart");

	mark = ListenersLogMark();

	if (HarnessStartServerKeep(h, false))
	{
		Format(tmp, sizeof(tmp), "ListenerList still holds only TCP %u and the test listener, no TCP %u",
			LISTENERS_PORT_FALLBACK, LISTENERS_PORT_DEFAULT);
		ListenersExpectOnly(h, LISTENERS_PORT_FALLBACK, tmp);

		Format(tmp, sizeof(tmp), "TCP %u reaches Listening", LISTENERS_PORT_FALLBACK);
		ListenersWaitListening(h, LISTENERS_PORT_FALLBACK, LISTENERS_LISTEN_WAIT, tmp);
	}

	HarnessStopServerKeep(h);

	log_text = ListenersLogSince(mark);
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_FALLBACK", false, NULL,
		"the server log of the restart has no fallback line");
	Free(log_text);
}

// 3. 443 and 5555 held: 443 stays and binds by its own retry once released
static void ListenersBothTaken(HARNESS *h)
{
	char tmp[MAX_SIZE];

	Print("[3: TCP %u and %u held]\n", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
	HarnessSetPhase("listeners", "both taken");

	SOCKET held_default = ListenersHoldCheck(h, LISTENERS_PORT_DEFAULT);
	SOCKET held_fallback = ListenersHoldCheck(h, LISTENERS_PORT_FALLBACK);

	if (held_default != INVALID_SOCKET && held_fallback != INVALID_SOCKET)
	{
		LIST *mark = ListenersLogMark();

		if (HarnessStartServerKeep(h, true))
		{
			Format(tmp, sizeof(tmp), "ListenerList holds TCP %u enabled and the test listener, no TCP %u",
				LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
			ListenersExpectOnly(h, LISTENERS_PORT_DEFAULT, tmp);

			Format(tmp, sizeof(tmp), "ListenerList shows TCP %u in error state", LISTENERS_PORT_DEFAULT);
			ListenersExpectError(h, LISTENERS_PORT_DEFAULT, tmp);

			HarnessSetPhase("listeners", "both taken, 443 released");
			ListenersRelease(&held_default);

			Format(tmp, sizeof(tmp), "TCP %u, released, reaches Listening by its own retry", LISTENERS_PORT_DEFAULT);
			ListenersWaitListening(h, LISTENERS_PORT_DEFAULT, LISTENERS_RETRY_WAIT, tmp);
		}

		HarnessStopServerKeep(h);

		char *log_text = ListenersLogSince(mark);
		char *line = ListenersLogLine("LS_DEFAULT_LISTENER_BOTH_TAKEN", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK,
			LISTENERS_IN_USE, LISTENERS_IN_USE, LISTENERS_PORT_DEFAULT);
		Format(tmp, sizeof(tmp), "the server log has the both-taken line: TCP %u and %u, errors %u, the listener stays "
			"on TCP %u", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK, LISTENERS_IN_USE, LISTENERS_PORT_DEFAULT);
		ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_BOTH_TAKEN", true, line, tmp);
		ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_FALLBACK", false, NULL, "the server log has no fallback line");
		Free(line);
		Free(log_text);
	}

	ListenersRelease(&held_default);
	ListenersRelease(&held_fallback);
}

// 4. A saved configuration that lists 443, with 443 held: no fallback
static void ListenersNoFallback(HARNESS *h)
{
	char tmp[MAX_SIZE];

	Print("[4: saved configuration with TCP %u, then TCP %u held]\n", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_DEFAULT);
	HarnessSetPhase("listeners", "no fallback");

	if (ListenersCheckFree(h, LISTENERS_PORT_DEFAULT) == false)
	{
		return;
	}

	bool ok = HarnessStartServerKeep(h, true);
	if (ok)
	{
		Format(tmp, sizeof(tmp), "the first start lists TCP %u and the test listener", LISTENERS_PORT_DEFAULT);
		ok = ListenersExpectOnly(h, LISTENERS_PORT_DEFAULT, tmp);
	}

	HarnessStopServerKeep(h);

	if (ok == false)
	{
		return;
	}

	SOCKET held = ListenersHoldCheck(h, LISTENERS_PORT_DEFAULT);
	if (held == INVALID_SOCKET)
	{
		return;
	}

	HarnessSetPhase("listeners", "no fallback restart");
	LIST *mark = ListenersLogMark();

	if (HarnessStartServerKeep(h, false))
	{
		Format(tmp, sizeof(tmp), "a restart from the saved configuration lists TCP %u and the test listener, no TCP %u",
			LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK);
		ListenersExpectOnly(h, LISTENERS_PORT_DEFAULT, tmp);

		Format(tmp, sizeof(tmp), "ListenerList shows TCP %u in error state", LISTENERS_PORT_DEFAULT);
		ListenersExpectError(h, LISTENERS_PORT_DEFAULT, tmp);
	}

	HarnessStopServerKeep(h);
	ListenersRelease(&held);

	char *log_text = ListenersLogSince(mark);
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_FALLBACK", false, NULL, "the server log has no fallback line");
	ListenersExpectLog(h, log_text, "LS_DEFAULT_LISTENER_BOTH_TAKEN", false, NULL, "the server log has no both-taken line");
	Free(log_text);
}

// 5. ListenerCreate and ListenerDelete on a free high port
static void ListenersAnyPort(HARNESS *h)
{
	RPC_LISTENER t;
	char tmp[MAX_SIZE];
	bool enabled, error;
	UINT err;

	Print("[5: ListenerCreate on TCP %u]\n", LISTENERS_ANY_PORT);
	HarnessSetPhase("listeners", "any port");

	if (HarnessStartServerKeep(h, true))
	{
		Zero(&t, sizeof(t));
		t.Port = LISTENERS_ANY_PORT;
		t.Enable = true;
		Format(tmp, sizeof(tmp), "ListenerCreate %u", LISTENERS_ANY_PORT);
		HarnessCheckErr(h, ScCreateListener(h->Rpc, &t), tmp);

		Format(tmp, sizeof(tmp), "TCP %u reaches Listening", LISTENERS_ANY_PORT);
		if (ListenersWaitListening(h, LISTENERS_ANY_PORT, LISTENERS_LISTEN_WAIT, tmp))
		{
			RPC_LISTENER_LIST l;

			// The admin RPC through the new listener, as vpncmd /SERVER 127.0.0.1:39559 connects
			RPC *rpc = ListenersAdminConnect(h, LISTENERS_ANY_PORT, &err);
			Format(tmp, sizeof(tmp), "admin RPC connected to 127.0.0.1:%u", LISTENERS_ANY_PORT);
			if (HarnessCheckErr(h, (rpc != NULL ? ERR_NO_ERROR : err), tmp))
			{
				Zero(&l, sizeof(l));
				HarnessCheckErr(h, ScEnumListener(rpc, &l), "EnumListener through that connection");
				FreeRpcListenerList(&l);

				AdminDisconnect(rpc);
			}
		}

		Zero(&t, sizeof(t));
		t.Port = LISTENERS_ANY_PORT;
		Format(tmp, sizeof(tmp), "ListenerDelete %u", LISTENERS_ANY_PORT);
		HarnessCheckErr(h, ScDeleteListener(h->Rpc, &t), tmp);

		Format(tmp, sizeof(tmp), "ListenerList no longer lists TCP %u", LISTENERS_ANY_PORT);
		HarnessCheck(h, ListenersState(h, LISTENERS_ANY_PORT, &enabled, &error) == false, tmp);
	}

	HarnessStopServerKeep(h);
}

// The first-start probe: ListenProbe binds without address reuse and closes its socket at once
static void ListenersProbe(HARNESS *h)
{
	char tmp[MAX_SIZE];
	UINT err;

	Print("[probe: ListenProbe on TCP %u]\n", LISTENERS_PROBE_PORT);
	HarnessSetPhase("listeners", "probe");

	// The bind of the server's listener (no SO_REUSEADDR, no SO_EXCLUSIVEADDRUSE). A bind with SO_REUSEADDR in the
	// same account would share the port with this socket and report it free.
	SOCK *plain = Listen(LISTENERS_PROBE_PORT, NULL, false);
	Format(tmp, sizeof(tmp), "the test holds TCP %u without address reuse or exclusive use", LISTENERS_PROBE_PORT);
	if (HarnessCheck(h, plain != NULL, tmp))
	{
		bool held_free = ListenProbe(LISTENERS_PROBE_PORT, NULL, false, &err);
		Format(tmp, sizeof(tmp), "ListenProbe reports the held TCP %u taken with WSAEADDRINUSE (%s, error %u)",
			LISTENERS_PROBE_PORT, (held_free ? "free" : "taken"), err);
		HarnessCheck(h, held_free == false && err == LISTENERS_IN_USE, tmp);

		Disconnect(plain);
		ReleaseSock(plain);
	}

	bool released_free = ListenProbe(LISTENERS_PROBE_PORT, NULL, false, &err);
	Format(tmp, sizeof(tmp), "ListenProbe reports the released TCP %u free (%s, error %u)", LISTENERS_PROBE_PORT,
		(released_free ? "free" : "taken"), err);
	HarnessCheck(h, released_free && err == 0, tmp);

	// A socket of the probe left open would keep this exclusive bind from the port
	SOCKET held = ListenersHold(LISTENERS_PROBE_PORT);
	Format(tmp, sizeof(tmp), "an exclusive bind of TCP %u right after the probe succeeds: the probe closed its socket",
		LISTENERS_PROBE_PORT);
	HarnessCheck(h, held != INVALID_SOCKET, tmp);
	ListenersRelease(&held);
}

// "listeners": the default VPN listener on TCP 443, its fallback to 5555, and listeners on any port (REL-3)
void listeners_test(UINT num, char **arg)
{
	Print("Default VPN listener: TCP %u on a fresh configuration, TCP %u when %u cannot be bound at that first start; "
		"the test listener on TCP %u\n", LISTENERS_PORT_DEFAULT, LISTENERS_PORT_FALLBACK, LISTENERS_PORT_DEFAULT,
		HARNESS_PORT);

	HARNESS *h = HarnessOpenRun("LISTENERS", LISTENERS_WATCHDOG_LIMIT);

	ListenersDefault(h);
	ListenersFallback(h);
	ListenersBothTaken(h);
	ListenersNoFallback(h);
	ListenersAnyPort(h);
	ListenersProbe(h);

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
