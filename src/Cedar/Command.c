// Command.c
// vpncmd Command Line Management Utility

#include "Command.h"

#include "Admin.h"
#include "BuildInfo.h"
#include "Connection.h"
#include "Console.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>
#include "CommandInternal.h"

// RSA key size of MakeCert and its MakeCert2048 alias
#define	MAKECERT_RSA_BITS		2048

static bool CheckNetwork();
static bool CheckThread();
static bool CheckFileSystem();
static bool CheckStrings();
static bool CheckMemory();
static void InputToNull(void *p);
static UINT RetZero();
static bool CheckKernel();
static void TtsAcceptProc(TTS *tts, SOCK *listen_socket);
static UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static K *CmdLoadKey(CONSOLE *c, wchar_t *filename);
static UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static wchar_t *GetSyslogSettingName(UINT n);
static UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeDefaultCAEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeDefaultCADisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode);
static UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);
static UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param);

typedef bool (CHECKER_PROC_DEF)();
typedef struct CHECKER_PROC
{
	char *Title;
	CHECKER_PROC_DEF *Proc;
} CHECKER_PROC;

static CHECKER_PROC checker_procs[] =
{
	{"CHECK_PROC_KERNEL", CheckKernel},
	{"CHECK_PROC_MEMORY", CheckMemory},
	{"CHECK_PROC_STRINGS", CheckStrings},
	{"CHECK_PROC_FILESYSTEM", CheckFileSystem},
	{"CHECK_PROC_THREAD", CheckThread},
	{"CHECK_PROC_NETWORK", CheckNetwork},
};

typedef struct CHECK_NETWORK_1
{
	SOCK *ListenSocket;
} CHECK_NETWORK_1;

typedef struct CHECK_NETWORK_2
{
	SOCK *s;
	X *x;
	K *k;
} CHECK_NETWORK_2;


static void CheckNetworkAcceptThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_2 *c = (CHECK_NETWORK_2 *)param;
	SOCK *s = c->s;
	UINT i = 0;

	if (StartSSL(s, c->x, c->k))
	{
		while (true)
		{
			i++;
			if (Send(s, &i, sizeof(UINT), true) == 0)
			{
				break;
			}
		}
	}

	Disconnect(s);
	ReleaseSock(s);

	Free(c);
}


static void CheckNetworkListenThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_1 *c = (CHECK_NETWORK_1 *)param;
	SOCK *s;
	UINT i, rsa_bits = 1024;
	K *pub, *pri;
	X *x;
	LIST *o = NewList(NULL);
	NAME *name = NewName(L"Test", L"Test", L"Test", L"JP", L"Ibaraki", L"Tsukuba");

	// RSA key size must satisfy the OpenSSL security level; level 4 needs 7680 bits
	switch (GetOSSecurityLevel())
	{
	case 2:
		rsa_bits = 2048;
		break;
	case 3:
		rsa_bits = 4096;
		break;
	default:
		break;
	}
	RsaGen(&pri, &pub, rsa_bits);
	x = NewRootX(pub, pri, name, 1000, NULL);

	FreeName(name);

	for (i = 1025;;i++)
	{
		s = Listen(i, NULL, false);
		if (s != NULL)
		{
			break;
		}
	}

	c->ListenSocket = s;
	AddRef(s->ref);

	NoticeThreadInit(thread);

	while (true)
	{
		SOCK *new_sock = Accept(s);

		if (new_sock == NULL)
		{
			break;
		}
		else
		{
			CHECK_NETWORK_2 *c;
			THREAD *t;

			c = ZeroMalloc(sizeof(CHECK_NETWORK_2));
			c->s = new_sock;
			c->k = pri;
			c->x = x;

			t = NewThread(CheckNetworkAcceptThread, c);
			Insert(o, t);
		}
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		THREAD *t = LIST_DATA(o, i);
		WaitThread(t, INFINITE);
		ReleaseThread(t);
	}

	FreeK(pri);
	FreeK(pub);

	FreeX(x);

	ReleaseSock(s);
	ReleaseList(o);
}

static bool CheckNetwork()
{
	CHECK_NETWORK_1 c;
	THREAD *t;
	SOCK *listen_socket;
	UINT port;
	UINT i, num;
	bool ok = true;
	SOCK **socks;
	SOCK_EVENT *se = NewSockEvent();

	Zero(&c, sizeof(c));
	t = NewThread(CheckNetworkListenThread, &c);
	WaitThreadInit(t);

	listen_socket = c.ListenSocket;

	port = listen_socket->LocalPort;

	num = 8;
	socks = ZeroMalloc(sizeof(SOCK *) * num);
	for (i = 0;i < num;i++)
	{
		socks[i] = Connect("localhost", port);
		if (socks[i] == NULL)
		{
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}
		if (StartSSL(socks[i], NULL, NULL) == false)
		{
			ReleaseSock(socks[i]);
			Print("Connect Failed. (%u)\n", i);
			ok = false;
			num = i;
			break;
		}

		JoinSockToSockEvent(socks[i], se);
	}

	if (ok)
	{
		while (true)
		{
			UINT i;
			bool end = false;
			bool all_blocked = true;

			for (i = 0;i < num;i++)
			{
				UINT n;
				UINT ret;

				n = 0;
				ret = Recv(socks[i], &n, sizeof(UINT), true);
				if (ret == 0)
				{
					Print("Recv Failed (Disconnected).\n");
					end = true;
					ok = false;
				}
				if (ret != SOCK_LATER)
				{
					all_blocked = false;
				}

				if (n >= 128)
				{
					end = true;
				}
			}

			if (end)
			{
				break;
			}

			if (all_blocked)
			{
				WaitSockEvent(se, INFINITE);
			}
		}
	}

	for (i = 0;i < num;i++)
	{
		Disconnect(socks[i]);
		ReleaseSock(socks[i]);
	}
	Free(socks);

	Disconnect(listen_socket);

	WaitThread(t, INFINITE);
	ReleaseThread(t);

	ReleaseSock(listen_socket);

	ReleaseSockEvent(se);

	return ok;
}

typedef struct CHECK_THREAD_1
{
	UINT num;
	LOCK *lock;
	THREAD *wait_thread;
} CHECK_THREAD_1;

static UINT check_thread_global_1 = 0;

#define	CHECK_THREAD_INCREMENT_COUNT		32

static void CheckThread1(THREAD *thread, void *param)
{
	CHECK_THREAD_1 *ct1 = (CHECK_THREAD_1 *)param;
	UINT i;
	UINT num = CHECK_THREAD_INCREMENT_COUNT;

	WaitThread(ct1->wait_thread, INFINITE);

	for (i = 0;i < num;i++)
	{
		Lock(ct1->lock);
		check_thread_global_1 = ct1->num;
		InputToNull((void *)check_thread_global_1);
		check_thread_global_1 = check_thread_global_1 + 1 + RetZero();
		ct1->num = check_thread_global_1;
		Unlock(ct1->lock);
	}
}

static void CheckThread2(THREAD *thread, void *param)
{
	EVENT *e = (EVENT *)param;
	Wait(e, INFINITE);
}

typedef struct CHECK_THREAD_3
{
	UINT num, a;
} CHECK_THREAD_3;

static void CheckThread3(THREAD *thread, void *param)
{
	CHECK_THREAD_3 *c = (CHECK_THREAD_3 *)param;
	THREAD *t;

	if (c->num == 0)
	{
		return;
	}
	c->num--;
	c->a++;

	t = NewThread(CheckThread3, c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);
}

static bool CheckThread()
{
	bool ok = true;
	CHECK_THREAD_1 ct1;
	UINT num = 32;
	UINT i;
	THREAD **threads;
	EVENT *e;
	THREAD *t2;
	THREAD *t;
	CHECK_THREAD_3 c;

	e = NewEvent();

	Zero(&ct1, sizeof(ct1));
	ct1.lock = NewLock();

	t2 = NewThread(CheckThread2, e);
	ct1.wait_thread = t2;

	threads = ZeroMalloc(sizeof(THREAD *) * num);
	for (i = 0;i < num;i++)
	{
		threads[i] = NewThread(CheckThread1, &ct1);
		if (threads[i] == NULL)
		{
			Print("Thread %u Create Failed.\n", i);
			ok = false;
		}
	}

	Set(e);

	for (i = 0;i < num;i++)
	{
		WaitThread(threads[i], INFINITE);
		ReleaseThread(threads[i]);
	}

	Free(threads);

	if (ct1.num != (num * CHECK_THREAD_INCREMENT_COUNT))
	{
		Print("Threading: %u != %u\n", ct1.num, num * CHECK_THREAD_INCREMENT_COUNT);
		ok = false;
	}

	DeleteLock(ct1.lock);

	WaitThread(t2, INFINITE);
	ReleaseThread(t2);

	ReleaseEvent(e);

	num = 32;

	Zero(&c, sizeof(c));
	c.num = num;
	t = NewThread(CheckThread3, &c);
	WaitThread(t, INFINITE);
	ReleaseThread(t);

	if (c.a != num)
	{
		Print("Threading: %u != %u\n", c.a, num);
		ok = false;
	}

	return ok;
}

static bool CheckFileSystem()
{
	bool ok = false;
	char exe[MAX_PATH];
	char exe_dir[MAX_PATH];
	DIRLIST *dirs;
	UINT i;

	GetExeName(exe, sizeof(exe));
	GetExeDir(exe_dir, sizeof(exe_dir));

	dirs = EnumDir(exe_dir);
	for (i = 0;i < dirs->NumFiles;i++)
	{
		if (EndWith(exe, dirs->File[i]->FileName))
		{
			ok = true;
			break;
		}
	}
	FreeDir(dirs);

	if (ok == false)
	{
		Print("EnumDir Failed.\n");
		return false;
	}
	else
	{
		UINT size = 1234567;
		UCHAR *buf;
		IO *io;
		wchar_t filename[MAX_PATH];
		CombinePathW(filename, sizeof(filename), MsGetMyTempDirW(), L"vpn_checker_tmp");

		buf = Malloc(size);
		for (i = 0;i < size;i++)
		{
			buf[i] = i % 256;
		}

		io = FileCreateW(filename);
		if (io == NULL)
		{
			Print("FileCreate Failed.\n");
			Free(buf);
			return false;
		}
		else
		{
			FileWrite(io, buf, size);
			Free(buf);
			FileClose(io);

			io = FileOpenW(filename, false);
			if (FileSize(io) != 1234567)
			{
				Print("FileSize Failed.\n");
				FileClose(io);
				return false;
			}
			else
			{
				BUF *b;

				FileClose(io);
				b = ReadDumpW(filename);
				if(b == NULL)
				{
					return false;
				}

				for (i = 0;i < b->Size;i++)
				{
					UCHAR c = ((UCHAR *)b->Buf)[i];

					if (c != (i % 256))
					{
						Print("FileToBuf Failed.\n");
						FreeBuf(b);
						return false;
					}
				}

				FreeBuf(b);
			}
		}

		FileDeleteW(filename);
	}

	return ok;
}

static bool CheckStrings()
{
	wchar_t *numstr = _UU("CHECK_TEST_123456789");
	char tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t num[MAX_PATH];
	UINT i;
	UINT sum, sum2;
	UNI_TOKEN_LIST *t;

	UniStrCpy(tmp2, sizeof(tmp2), L"");

	sum2 = 0;
	for (i = 0;i < 64;i++)
	{
		sum2 += i;
		UniFormat(num, sizeof(num), L",%u", i);
		UniStrCat(tmp2, sizeof(tmp2), num);
	}

	t = UniParseToken(tmp2, L",");

	sum = 0;

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];
		UINT n = UniToInt(s);

		sum += n;
	}

	UniFreeToken(t);

	if (sum != sum2)
	{
		Print("UniParseToken Failed.\n");
		return false;
	}

	if (UniToInt(numstr) != 123456789)
	{
		Print("UniToInt Failed.\n");
		return false;
	}

	UniToStr(tmp, sizeof(tmp), numstr);
	if (ToInt(tmp) != 123456789)
	{
		Print("UniToStr Failed.\n");
		return false;
	}

	return true;
}

static bool CheckMemory()
{
	UINT i, num, size, j;
	void **pp;
	bool ok = true;
	UINT old_size;

	num = 2000;
	size = 1000;
	pp = ZeroMalloc(sizeof(void *) * num);
	for (i = 0;i < num;i++)
	{
		pp[i] = ZeroMalloc(size);
		InputToNull(pp[i]);
		for (j = 0;j < size;j++)
		{
			((UCHAR *)pp[i])[j] = j % 256;
		}
	}
	old_size = size;
	size = size * 3;
	for (i = 0;i < num;i++)
	{
		pp[i] = ReAlloc(pp[i], size);
		for (j = old_size;j < size;j++)
		{
			InputToNull((void *)(UINT)(((UCHAR *)pp[i])[j] = j % 256));
		}
	}
	for (i = 0;i < num;i++)
	{
		for (j = 0;j < size;j++)
		{
			if (((UCHAR *)pp[i])[j] != (j % 256))
			{
				ok = false;
			}
		}
		Free(pp[i]);
	}
	Free(pp);

	return ok;
}

static void InputToNull(void *p)
{
	if (RetZero() == 1)
	{
		UCHAR *c = (UCHAR *)p;
		c[0] = 0x32;
	}
}

static UINT RetZero()
{
	if (g_debug == 0x123455)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


static bool CheckKernel()
{
	UINT num = 10, i;
	UINT64 s = Tick64();
	UINT64 t = Tick64();

	for (i = 0;i < num;i++)
	{
		UINT64 q = Tick64();
		if (t > q)
		{
			Print("Tick64 #1 Failed.\n");
			return false;
		}

		t = q;

		SleepThread(100);
	}

	t = (Tick64() - s);
	if (t <= 500 || t >= 2000)
	{
		Print("Tick64 #2 Failed.\n");
		return false;
	}

	return true;
}

static bool SystemCheck()
{
	UINT i;
	bool ng = false;

	UniPrint(_UU("CHECK_TITLE"));
	UniPrint(_UU("CHECK_NOTE"));
	for (i = 0;i < sizeof(checker_procs) / sizeof(checker_procs[0]);i++)
	{
		wchar_t *title;
		bool ret = false;
		CHECKER_PROC *p = &checker_procs[i];

		title = _UU(p->Title);

		UniPrint(_UU("CHECK_EXEC_TAG"), title);

		ret = p->Proc();

		if (ret == false)
		{
			ng = true;
		}

		UniPrint(L"              %s\n", ret ? _UU("CHECK_PASS") : _UU("CHECK_FAIL"));
	}

	UniPrint(L"\n");
	if (ng == false)
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_1"));
	}
	else
	{
		UniPrint(L"%s\n\n", _UU("CHECK_RESULT_2"));
	}

	return ng == false;
}


static UINT PtCheck(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (SystemCheck() == false)
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

static void PtMain(PT *pt)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	if (pt == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_TOOLS_CONNECTED"));
	pt->Console->Write(pt->Console, tmp);
	pt->Console->Write(pt->Console, L"");

	while (true)
	{
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"Check", PtCheck},
		};

		StrCpy(prompt, sizeof(prompt), "VPN Tools>");

		if (DispatchNextCmdEx(pt->Console, pt->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), pt) == false)
		{
			break;
		}
		pt->LastError = pt->Console->RetCode;

		if (pt->LastError == ERR_NO_ERROR && pt->Console->ConsoleType != CONSOLE_CSV)
		{
			pt->Console->Write(pt->Console, _UU("CMD_MSG_OK"));
			pt->Console->Write(pt->Console, L"");
		}

		if (pt->CmdLine != NULL)
		{
			break;
		}
	}
}

static PT *NewPt(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	if (c == NULL)
	{
		return NULL;
	}

	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	pt = ZeroMalloc(sizeof(PT));
	pt->Console = c;
	pt->CmdLine = CopyUniStr(cmdline);

	return pt;
}

static void FreePt(PT *pt)
{
	if (pt == NULL)
	{
		return;
	}

	Free(pt->CmdLine);
	Free(pt);
}

static UINT PtConnect(CONSOLE *c, wchar_t *cmdline)
{
	PT *pt;
	UINT ret = 0;
	if (c == NULL)
	{
		return ERR_INTERNAL_ERROR;
	}

	pt = NewPt(c, cmdline);

	PtMain(pt);

	ret = pt->LastError;

	FreePt(pt);

	return ret;
}

static void TtPrint(void *param, TT_PRINT_PROC *print_proc, wchar_t *str)
{
	if (print_proc == NULL || str == NULL)
	{
		return;
	}

	print_proc(param, str);
}

static void TtGenerateRandomData(UCHAR **buf, UINT *size)
{
	UCHAR *tmp;
	UINT sz;
	UINT i;
	if (buf == NULL || size == NULL)
	{
		return;
	}

	sz = TRAFFIC_BUF_SIZE;
	tmp = Malloc(sz);
	Rand(tmp, sz);
	for (i = 0;i < sz;i++)
	{
		if (tmp[i] == '!')
		{
			tmp[i] = '_';
		}
	}

	*buf = tmp;
	*size = sz;
}

static void TtsWorkerThread(THREAD *thread, void *param)
{
	TTS *tts;
	TTS_WORKER *w;
	UINT buf_size;
	UCHAR *send_buf_data, *recv_buf_data;
	bool all_sockets_blocked = false;
	UINT64 tmp64;
	LIST *o;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool dont_block_next_time = false;
	char *ver_str = TRAFFIC_VER_STR;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	w = (TTS_WORKER *)param;
	tts = (TTS *)w->Tts;

	w->SockEvent = NewSockEvent();
	AddRef(w->SockEvent->ref);

	w->TtsSockList = NewList(NULL);

	NoticeThreadInit(thread);

	o = NewList(NULL);

	while (FlagRead(&tts->Halt) == false)
	{
		UINT64 now = Tick64();

		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}
		dont_block_next_time = false;

		LockList(w->TtsSockList);
		{
			UINT i;

			all_sockets_blocked = false;

			while (all_sockets_blocked == false)
			{
				all_sockets_blocked = true;

				for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
				{
					UINT ret = SOCK_LATER;
					TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);
					bool blocked_for_this_socket = false;

					if (ts->SockJoined == false)
					{
						JoinSockToSockEvent(ts->Sock, w->SockEvent);
						ts->SockJoined = true;
					}

					switch (ts->State)
					{
					case 0:
						ret = Send(ts->Sock, ver_str, TRAFFIC_VER_STR_SIZE, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							ts->State = 5;
							ts->LastCommTime = now;
						}
						break;

					case 5:
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
						if (ret != 0 && ret != SOCK_LATER)
						{
							UCHAR c;

							ts->LastCommTime = now;

							// The first byte sets the direction: 0 = client to server, anything else = server to client
							c = recv_buf_data[0];

							if (c == 0)
							{
								ts->State = 1;
							}
							else
							{
								ts->State = 2;
							}

							if (ret >= (sizeof(UINT64) + sizeof(UINT64) + 1))
							{
								ts->SessionId = READ_UINT64(recv_buf_data + 1);

								ts->Span = READ_UINT64(recv_buf_data + sizeof(UINT64) + 1);

								ts->GiveupSpan = ts->Span * 3ULL + 180000ULL;
							}
						}
						break;

					case 1:
						ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ret != 0 && ret != SOCK_LATER)
						{
							UCHAR c = recv_buf_data[0];

							ts->LastCommTime = now;

							if (ts->FirstRecvTick == 0)
							{
								ts->FirstRecvTick = now;
							}
							else
							{
								if (ts->FirstRecvTick <= now)
								{
									if (ts->Span != 0)
									{
										UINT64 giveup_tick = ts->FirstRecvTick + ts->Span;

										if (now > giveup_tick)
										{
											c = '!';
										}
									}
								}
							}

							if (c == '!')
							{
								ts->State = 3;
							}
						}
						break;

					case 2:
						if (ts->NoMoreSendData == false)
						{
							ret = Send(ts->Sock, send_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}
						else
						{
							ret = Recv(ts->Sock, recv_buf_data, buf_size, false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}
						}

						if (ts->FirstSendTick == 0)
						{
							ts->FirstSendTick = now;
						}
						else
						{
							if (ts->FirstSendTick <= now)
							{
								if (ts->Span != 0)
								{
									UINT64 giveup_tick = ts->FirstSendTick + ts->Span * 3ULL + 180000ULL;

									if (now > giveup_tick)
									{
										ret = 0;
									}
								}
							}
						}

						break;

					case 3:
						tmp64 = Endian64(ts->NumBytes);

						(void)Recv(ts->Sock, recv_buf_data, buf_size, false);

						if (ts->LastWaitTick == 0 || ts->LastWaitTick <= Tick64())
						{
							ret = Send(ts->Sock, &tmp64, sizeof(tmp64), false);

							if (ret != 0 && ret != SOCK_LATER)
							{
								ts->LastCommTime = now;
							}

							if (ret != SOCK_LATER)
							{
								UINT j;

								ts->LastWaitTick = Tick64() + 100;

								if (ts->SessionId != 0)
								{
									for (j = 0;j < LIST_NUM(w->TtsSockList);j++)
									{
										TTS_SOCK *ts2 = LIST_DATA(w->TtsSockList, j);

										if (ts2->SessionId == ts->SessionId &&
											ts2 != ts)
										{
											ts2->NoMoreSendData = true;
										}
									}
								}
							}
						}
						break;
					}

					if (now > (ts->LastCommTime + ts->GiveupSpan))
					{
						ret = 0;
					}

					if (ret == 0)
					{
						Insert(o, ts);
					}
					else if (ret == SOCK_LATER)
					{
						blocked_for_this_socket = true;
						dont_block_next_time = false;
					}
					else
					{
						if (ts->State == 1)
						{
							ts->NumBytes += (UINT64)ret;
						}
					}

					if (blocked_for_this_socket == false)
					{
						all_sockets_blocked = false;
					}
				}

				if (LIST_NUM(o) != 0)
				{
					UINT i;
					for (i = 0;i < LIST_NUM(o);i++)
					{
						TTS_SOCK *ts = LIST_DATA(o, i);

						UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECTED"), ts->Id, ts->Sock->RemoteHostname);
						TtPrint(tts->Param, tts->Print, tmp);

						Disconnect(ts->Sock);
						ReleaseSock(ts->Sock);

						Delete(w->TtsSockList, ts);

						Free(ts);
					}

					DeleteAll(o);
				}

				if (w->NewSocketArrived || FlagRead(&tts->Halt))
				{
					w->NewSocketArrived = false;
					all_sockets_blocked = true;
					dont_block_next_time = true;
				}
			}
		}
		UnlockList(w->TtsSockList);
	}

	LockList(w->TtsSockList);
	{
		for (i = 0;i < LIST_NUM(w->TtsSockList);i++)
		{
			TTS_SOCK *ts = LIST_DATA(w->TtsSockList, i);

			UniFormat(tmp, sizeof(tmp), _UU("TTS_DISCONNECT"), ts->Id, ts->Sock->RemoteHostname);
			TtPrint(tts->Param, tts->Print, tmp);

			Disconnect(ts->Sock);
			ReleaseSock(ts->Sock);

			Free(ts);
		}
	}
	UnlockList(w->TtsSockList);

	ReleaseList(o);
	ReleaseList(w->TtsSockList);
	ReleaseSockEvent(w->SockEvent);
	Free(send_buf_data);
	Free(recv_buf_data);
}

static void TtsAcceptProc(TTS *tts, SOCK *listen_socket)
{
	wchar_t tmp[MAX_SIZE];
	UINT seed = 0;
	if (tts == NULL || listen_socket == NULL)
	{
		return;
	}

	while (FlagRead(&tts->Halt) == false)
	{
		SOCK *s;
		s = Accept(listen_socket);

		if (s == NULL)
		{
			if (FlagRead(&tts->Halt) == false)
			{
				SleepThread(10);
			}
			continue;
		}
		else
		{
			UINT num, i;
			TTS_WORKER *w;

			AcceptInitEx(s, true);

			num = LIST_NUM(tts->WorkerList);

			i = seed % num;

			seed++;

			w = LIST_DATA(tts->WorkerList, i);

			w->NewSocketArrived = true;
			LockList(w->TtsSockList);
			{
				TTS_SOCK *ts = ZeroMalloc(sizeof(TTS_SOCK));

				ts->Id = (++tts->IdSeed);
				ts->Sock = s;

				ts->GiveupSpan = (UINT64)(10 * 60 * 1000);
				ts->LastCommTime = Tick64();

				UniFormat(tmp, sizeof(tmp), _UU("TTS_ACCEPTED"), ts->Id,
					s->RemoteHostname, s->RemotePort);
				TtPrint(tts->Param, tts->Print, tmp);

				Insert(w->TtsSockList, ts);
				w->NewSocketArrived = true;
			}
			UnlockList(w->TtsSockList);

			SetSockEvent(w->SockEvent);
		}
	}
}

static void TtsListenThread(THREAD *thread, void *param)
{
	TTS *tts;
	wchar_t tmp[MAX_SIZE];
	if (thread == NULL || param == NULL)
	{
		return;
	}

	tts = (TTS *)param;

	tts->ListenSocket = Listen(tts->Port, NULL, false);

	if (tts->ListenSocket == NULL)
	{
		UniFormat(tmp, sizeof(tmp), _UU("TT_LISTEN_FAILED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		NoticeThreadInit(thread);

		tts->ErrorCode = ERR_INTERNAL_ERROR;
	}
	else
	{
		UINT i, num_worker_threads;

		UniFormat(tmp, sizeof(tmp), _UU("TTS_LISTEN_STARTED"), tts->Port);
		TtPrint(tts->Param, tts->Print, tmp);

		AddRef(tts->ListenSocket->ref);

		num_worker_threads = GetNumberOfCpu();

		for (i = 0;i < num_worker_threads;i++)
		{
			TTS_WORKER *w = ZeroMalloc(sizeof(TTS_WORKER));

			w->Tts = tts;
			w->WorkThread = NewThread(TtsWorkerThread, w);
			WaitThreadInit(w->WorkThread);

			Add(tts->WorkerList, w);
		}

		NoticeThreadInit(thread);

		TtsAcceptProc(tts, tts->ListenSocket);

		TtPrint(tts->Param, tts->Print, _UU("TTS_LISTEN_STOP"));

		ReleaseSock(tts->ListenSocket);

		for (i = 0;i < LIST_NUM(tts->WorkerList);i++)
		{
			TTS_WORKER *w = LIST_DATA(tts->WorkerList, i);

			SetSockEvent(w->SockEvent);

			WaitThread(w->WorkThread, INFINITE);
			ReleaseThread(w->WorkThread);
			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}
	}
}

static wchar_t *GetTtcTypeStr(UINT type)
{
	switch (type)
	{
	case TRAFFIC_TYPE_DOWNLOAD:
		return _UU("TTC_TYPE_DOWNLOAD");

	case TRAFFIC_TYPE_UPLOAD:
		return _UU("TTC_TYPE_UPLOAD");

	default:
		return _UU("TTC_TYPE_FULL");
	}
}

static void TtcPrintSummary(TTC *ttc)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	wchar_t *tag = L"%-35s %s";
	if (ttc == NULL)
	{
		return;
	}

	TtPrint(ttc->Param, ttc->Print, L"");
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_TITLE"));
	TtPrint(ttc->Param, ttc->Print, L"");

	StrToUni(tmp2, sizeof(tmp2), ttc->Host);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_HOST"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniToStru(tmp2, ttc->Port);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_PORT"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniToStru(tmp2, ttc->NumTcp);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_NUMTCP"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_TYPE"), GetTtcTypeStr(ttc->Type));
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniFormat(tmp2, sizeof(tmp2), _UU("TTC_SPAN_STR"), (double)(ttc->Span) / 1000.0);
	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_SPAN"), tmp2);
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_ETHER"), ttc->Raw ? _UU("SEC_NO") : _UU("SEC_YES"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	UniFormat(tmp, sizeof(tmp), tag, _UU("TTC_SUMMARY_DOUBLE"), ttc->Double ? _UU("SEC_YES") : _UU("SEC_NO"));
	TtPrint(ttc->Param, ttc->Print, tmp);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_SUMMARY_BAR"));
	TtPrint(ttc->Param, ttc->Print, L"");
}

static void TtcGenerateResult(TTC *ttc)
{
	TT_RESULT *res;
	UINT i;
	if (ttc == NULL)
	{
		return;
	}

	res = &ttc->Result;

	Zero(res, sizeof(TT_RESULT));

	res->Raw = ttc->Raw;
	res->Double = ttc->Double;
	res->Span = ttc->RealSpan;

	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		if (ts->Download == false)
		{
			res->NumBytesUpload += ts->NumBytes;
		}
		else
		{
			res->NumBytesDownload += ts->NumBytes;
		}
	}

	if (res->Raw == false)
	{
		res->NumBytesDownload = (UINT64)((double)res->NumBytesDownload * 1514.0 / 1460.0);
		res->NumBytesUpload = (UINT64)((double)res->NumBytesUpload * 1514.0 / 1460.0);
	}

	res->NumBytesTotal = res->NumBytesDownload + res->NumBytesUpload;

	if (res->Span != 0)
	{
		res->BpsUpload = (UINT64)((double)res->NumBytesUpload * 8.0 / ((double)res->Span / 1000.0));
		res->BpsDownload = (UINT64)((double)res->NumBytesDownload * 8.0 / ((double)res->Span / 1000.0));
	}

	if (res->Double)
	{
		res->BpsUpload *= 2ULL;
		res->BpsDownload *= 2ULL;
	}

	res->BpsTotal = res->BpsUpload + res->BpsDownload;
}

static void TtcWorkerThread(THREAD *thread, void *param)
{
	TTC_WORKER *w;
	TTC *ttc;
	bool dont_block_next_time = false;
	bool halting = false;
	UINT64 halt_timeout = 0;
	bool all_sockets_blocked;
	wchar_t tmp[MAX_SIZE];
	UCHAR *send_buf_data, *recv_buf_data;
	UINT buf_size;
	UINT64 tmp64;

	if (thread == NULL || param == NULL)
	{
		return;
	}

	w = (TTC_WORKER *)param;
	ttc = w->Ttc;

	TtGenerateRandomData(&send_buf_data, &buf_size);
	TtGenerateRandomData(&recv_buf_data, &buf_size);

	NoticeThreadInit(thread);

	Wait(w->StartEvent, INFINITE);

	while (true)
	{
		UINT i;

		if (dont_block_next_time == false)
		{
			WaitSockEvent(w->SockEvent, 50);
		}

		dont_block_next_time = false;

		if (ttc->AbnormalTerminated)
		{
			break;
		}

		if (ttc->end_tick <= Tick64())
		{
			if (halting == false)
			{
				if ((ttc->flag2++) == 0)
				{
					UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_END"),
						(double)ttc->Span / 1000.0);
					TtPrint(ttc->Param, ttc->Print, tmp);
				}

				if (ttc->RealSpan == 0)
				{
					ttc->RealSpan = Tick64() - ttc->start_tick;
				}

				halting = true;

				halt_timeout = Tick64() + 60000ULL;
			}
		}

		if (halt_timeout != 0)
		{
			bool ok = true;

			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);

				if (ts->Download == false)
				{
					if (ts->ServerUploadReportReceived == false)
					{
						ok = false;
					}
				}
			}

			if (ok)
			{
				w->Ok = true;
				break;
			}
			else
			{
				if (halt_timeout <= Tick64())
				{
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					break;
				}
			}
		}

		all_sockets_blocked = false;

		while (all_sockets_blocked == false)
		{
			all_sockets_blocked = true;

			for (i = 0;i < LIST_NUM(w->SockList);i++)
			{
				UINT ret = SOCK_LATER;
				TTC_SOCK *ts = LIST_DATA(w->SockList, i);
				bool blocked_for_this_socket = false;
				UCHAR c = 0;
				UCHAR c_and_session_id[1 + sizeof(UINT64) + sizeof(UINT64)];

				if (halt_timeout != 0)
				{
					if (ts->State != 3 && ts->State != 4)
					{
						if (ts->Download == false)
						{
							if (ts->State != 0)
							{
								ts->State = 3;
							}
							else
							{
								ts->ServerUploadReportReceived = true;
								ts->State = 4;
							}
						}
						else
						{
							ts->State = 4;
						}
					}
				}

				switch (ts->State)
				{
				case 0:
					if (ts->Download)
					{
						c = 1;
					}
					else
					{
						c = 0;
					}

					c_and_session_id[0] = c;
					WRITE_UINT64(c_and_session_id + 1, ttc->session_id);
					WRITE_UINT64(c_and_session_id + sizeof(UINT64) + 1, ttc->Span);

					ret = Send(ts->Sock, c_and_session_id, 1 + sizeof(UINT64) + sizeof(UINT64), false);

					if (ret != 0 && ret != SOCK_LATER)
					{
						if (ts->Download)
						{
							ts->State = 1;
						}
						else
						{
							ts->State = 2;
						}
					}
					break;

				case 1:
					ret = Recv(ts->Sock, recv_buf_data, buf_size, false);
					break;

				case 2:
					ret = Send(ts->Sock, send_buf_data, buf_size, false);
					break;

				case 3:
					if (ts->NextSendRequestReportTick == 0 ||
						(Tick64() >= ts->NextSendRequestReportTick))
					{
						UCHAR suprise[MAX_SIZE];
						UINT i;

						ts->NextSendRequestReportTick = Tick64() + 200ULL;

						for (i = 0;i < sizeof(suprise);i++)
						{
							suprise[i] = '!';
						}

						(void)Send(ts->Sock, suprise, sizeof(suprise), false);
					}

					ret = Recv(ts->Sock, &tmp64, sizeof(tmp64), false);
					if (ret != 0 && ret != SOCK_LATER && ret == sizeof(tmp64))
					{
						ts->NumBytes = Endian64(tmp64);

						ts->ServerUploadReportReceived = true;

						ts->State = 4;
					}
					break;

				case 4:
					if (Recv(ts->Sock, recv_buf_data, buf_size, false) == SOCK_LATER)
					{
						ret = SOCK_LATER;
					}
					break;
				}

				if (ret == 0)
				{
					ttc->AbnormalTerminated = true;
					ttc->ErrorCode = ERR_PROTOCOL_ERROR;
					blocked_for_this_socket = true;
					dont_block_next_time = false;

					if (ts->HideErrMsg == false)
					{
						UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_DISCONNECTED"), ts->Id);
						TtPrint(ttc->Param, ttc->Print, tmp);
						ts->HideErrMsg = true;
					}
				}
				else if (ret == SOCK_LATER)
				{
					blocked_for_this_socket = true;
					dont_block_next_time = false;
				}
				else
				{
					if (ts->Download)
					{
						ts->NumBytes += (UINT64)ret;
					}
				}

				if (blocked_for_this_socket == false)
				{
					all_sockets_blocked = false;
				}
			}

			if (ttc->end_tick <= Tick64())
			{
				all_sockets_blocked = true;
				dont_block_next_time = true;
			}
		}
	}

	Free(send_buf_data);
	Free(recv_buf_data);
}

static void TtcThread(THREAD *thread, void *param)
{
	TTC *ttc;
	UINT i;
	wchar_t tmp[MAX_SIZE];
	bool ok = false;
	IP ip_ret;
	if (thread == NULL || param == NULL)
	{
		return;
	}

	ttc = (TTC *)param;

	NoticeThreadInit(thread);

	TtcPrintSummary(ttc);

	UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_START"),
		ttc->Host, ttc->Port, ttc->NumTcp);
	TtPrint(ttc->Param, ttc->Print, tmp);

	ttc->ItcSockList = NewList(NULL);

	ok = true;

	Zero(&ip_ret, sizeof(ip_ret));

	for (i = 0;i < ttc->NumTcp;i++)
	{
		SOCK *s;
		TTC_SOCK *ts = ZeroMalloc(sizeof(TTC_SOCK));
		char target_host[MAX_SIZE];

		ts->Id = i + 1;

		if (ttc->Type == TRAFFIC_TYPE_DOWNLOAD)
		{
			ts->Download = true;
		}
		else if (ttc->Type == TRAFFIC_TYPE_UPLOAD)
		{
			ts->Download = false;
		}
		else
		{
			ts->Download = ((i % 2) == 0) ? true : false;
		}

		StrCpy(target_host, sizeof(target_host), ttc->Host);

		if (IsZeroIP(&ip_ret) == false)
		{
			IPToStr(target_host, sizeof(target_host), &ip_ret);
		}

		s = ConnectEx4(target_host, ttc->Port, 0, NULL, &ip_ret);

		if (s == NULL)
		{
			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_FAILED"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);
			ok = false;
			Free(ts);
			break;
		}
		else
		{
			char buffer[TRAFFIC_VER_STR_SIZE];

			SetTimeout(s, 5000);

			Zero(buffer, sizeof(buffer));
			if (Recv(s, buffer, sizeof(buffer), false) != sizeof(buffer) || Cmp(buffer, TRAFFIC_VER_STR, TRAFFIC_VER_STR_SIZE) != 0)
			{
				TtPrint(ttc->Param, ttc->Print, _UU("TTC_CONNECT_NOT_SERVER"));
				ok = false;
				ReleaseSock(s);
				Free(ts);
				break;
			}

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK"), i + 1);
			TtPrint(ttc->Param, ttc->Print, tmp);

			UniFormat(tmp, sizeof(tmp), _UU("TTC_CONNECT_OK_2"), GetTtcTypeStr(ts->Download ? TRAFFIC_TYPE_DOWNLOAD : TRAFFIC_TYPE_UPLOAD));
			TtPrint(ttc->Param, ttc->Print, tmp);

			ts->Sock = s;

			SetTimeout(s, TIMEOUT_INFINITE);
		}

		Insert(ttc->ItcSockList, ts);
	}

	Set(ttc->InitedEvent);

	if (ok)
	{
		UINT64 start_tick, end_tick;
		wchar_t tmp1[MAX_SIZE], tmp2[MAX_SIZE];
		UINT64 session_id = Rand64();
		UINT i, num_cpu;
		bool all_ok = false;

		ttc->session_id = session_id;

		num_cpu = GetNumberOfCpu();

		ttc->WorkerThreadList = NewList(NULL);

		for (i = 0;i < num_cpu;i++)
		{
			TTC_WORKER *w = ZeroMalloc(sizeof(TTC_WORKER));

			w->Ttc = ttc;
			w->SockList = NewList(NULL);
			w->StartEvent = NewEvent();
			w->SockEvent = NewSockEvent();

			w->WorkerThread = NewThread(TtcWorkerThread, w);

			WaitThreadInit(w->WorkerThread);

			Add(ttc->WorkerThreadList, w);
		}

		for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
		{
			TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);
			UINT num = LIST_NUM(ttc->WorkerThreadList);
			UINT j = i % num;
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, j);

			Add(w->SockList, ts);

			JoinSockToSockEvent(ts->Sock, w->SockEvent);
		}

		start_tick = Tick64();
		end_tick = start_tick + ttc->Span;

		ttc->start_tick = start_tick;
		ttc->end_tick = end_tick;

		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			Set(w->StartEvent);
		}

		GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(Tick64ToTime64(start_tick)), NULL);
		GetDateTimeStrEx64(tmp2, sizeof(tmp2), SystemToLocal64(Tick64ToTime64(end_tick)), NULL);
		UniFormat(tmp, sizeof(tmp), _UU("TTC_COMM_START"), tmp1, tmp2);
		TtPrint(ttc->Param, ttc->Print, tmp);

		all_ok = true;
		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			WaitThread(w->WorkerThread, INFINITE);

			if (w->Ok == false)
			{
				all_ok = false;
			}
		}

		if (all_ok)
		{
			TtcGenerateResult(ttc);
		}

		for (i = 0;i < LIST_NUM(ttc->WorkerThreadList);i++)
		{
			TTC_WORKER *w = LIST_DATA(ttc->WorkerThreadList, i);

			ReleaseThread(w->WorkerThread);

			ReleaseEvent(w->StartEvent);
			ReleaseList(w->SockList);

			ReleaseSockEvent(w->SockEvent);

			Free(w);
		}

		ReleaseList(ttc->WorkerThreadList);
		ttc->WorkerThreadList = NULL;
	}
	else
	{
		TtPrint(ttc->Param, ttc->Print, _UU("TTC_ERROR_ABORTED"));
		ttc->ErrorCode = ERR_CONNECT_FAILED;
	}

	for (i = 0;i < LIST_NUM(ttc->ItcSockList);i++)
	{
		TTC_SOCK *ts = LIST_DATA(ttc->ItcSockList, i);

		Disconnect(ts->Sock);
		ReleaseSock(ts->Sock);
		Free(ts);
	}

	ReleaseList(ttc->ItcSockList);
}

static TTC *NewTtcEx(char *host, UINT port, UINT numtcp, UINT type, UINT64 span, bool dbl, bool raw, TT_PRINT_PROC *print_proc, void *param)
{
	TTC *ttc;

	ttc = ZeroMalloc(sizeof(TTC));
	ttc->InitedEvent = NewEvent();
	ttc->Port = port;
	StrCpy(ttc->Host, sizeof(ttc->Host), host);
	ttc->NumTcp = numtcp;
	ttc->Type = type;
	ttc->Span = span;
	ttc->Double = dbl;
	ttc->Raw = raw;

	if (ttc->Type == TRAFFIC_TYPE_FULL && ttc->NumTcp < 2)
	{
		ttc->NumTcp = 2;
	}

	ttc->Print = print_proc;
	ttc->Param = param;
	ttc->ErrorCode = ERR_NO_ERROR;

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_INIT"));

	ttc->Thread = NewThread(TtcThread, ttc);
	WaitThreadInit(ttc->Thread);

	return ttc;
}

static UINT FreeTtc(TTC *ttc, TT_RESULT *result)
{
	UINT ret;
	if (ttc == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	WaitThread(ttc->Thread, INFINITE);
	ReleaseThread(ttc->Thread);

	TtPrint(ttc->Param, ttc->Print, _UU("TTC_FREE"));

	ret = ttc->ErrorCode;

	if (ret == ERR_NO_ERROR)
	{
		if (result != NULL)
		{
			Copy(result, &ttc->Result, sizeof(TT_RESULT));
		}
	}

	ReleaseEvent(ttc->InitedEvent);

	Free(ttc);

	return ret;
}

static TTS *NewTts(UINT port, void *param, TT_PRINT_PROC *print_proc)
{
	TTS *tts;
	THREAD *t;

	tts = ZeroMalloc(sizeof(TTS));
	tts->Port = port;
	tts->Param = param;
	tts->Print = print_proc;

	TtPrint(param, print_proc, _UU("TTS_INIT"));

	tts->WorkerList = NewList(NULL);

	t = NewThread(TtsListenThread, tts);
	WaitThreadInit(t);

	tts->Thread = t;

	return tts;
}

static UINT FreeTts(TTS *tts)
{
	UINT ret;
	if (tts == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_INIT"));

	FlagWrite(&tts->Halt, true);
	Disconnect(tts->ListenSocket);
	ReleaseSock(tts->ListenSocket);

	WaitThread(tts->Thread, INFINITE);

	ReleaseThread(tts->Thread);

	TtPrint(tts->Param, tts->Print, _UU("TTS_STOP_FINISHED"));

	ret = tts->ErrorCode;

	ReleaseList(tts->WorkerList);

	Free(tts);

	return ret;
}

static void PtTrafficPrintProc(void *param, wchar_t *str)
{
	CONSOLE *c;
	if (param == NULL || str == NULL)
	{
		return;
	}

	c = (CONSOLE *)param;

	if (c->ConsoleType == CONSOLE_LOCAL)
	{
		Lock(c->OutputLock);
		{
			wchar_t tmp[MAX_SIZE];

			UniStrCpy(tmp, sizeof(tmp), str);
			if (UniEndWith(str, L"\n") == false)
			{
				UniStrCat(tmp, sizeof(tmp), L"\n");
			}
			UniPrint(L"%s", tmp);
		}
		Unlock(c->OutputLock);
	}
}

static void TtcPrintResult(CONSOLE *c, TT_RESULT *res)
{
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char str[MAX_SIZE];
	if (c == NULL || res == NULL)
	{
		return;
	}

	c->Write(c, _UU("TTC_RES_TITLE"));

	ct = CtNew();
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_2"), true);
	CtInsertColumn(ct, _UU("TTC_RES_COLUMN_3"), true);

	GetSpanStrMilli(str, sizeof(str), res->Span);
	StrToUni(tmp, sizeof(tmp), str);
	CtInsert(ct, _UU("TTC_RES_SPAN"), tmp, L"");

	CtInsert(ct, _UU("TTC_RES_ETHER"), res->Raw ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	ToStr3(str, sizeof(str), res->NumBytesDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesDownload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_DOWNLOAD"), tmp1, tmp2);

	ToStr3(str, sizeof(str), res->NumBytesUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesUpload);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_UPLOAD"), tmp1, tmp2);

	ToStr3(str, sizeof(str), res->NumBytesTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S Bytes", str);
	ToStrByte1000(str, sizeof(str), res->NumBytesTotal);
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BYTES_TOTAL"), tmp1, tmp2);

	CtInsert(ct, _UU("TTC_RES_DOUBLE"), (res->Double == false) ? _UU("SEC_NO") : _UU("SEC_YES"), L"");

	ToStr3(str, sizeof(str), res->BpsDownload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsDownload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_DOWNLOAD"), tmp1, tmp2);

	ToStr3(str, sizeof(str), res->BpsUpload);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsUpload);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_UPLOAD"), tmp1, tmp2);

	ToStr3(str, sizeof(str), res->BpsTotal);
	UniFormat(tmp1, sizeof(tmp1), L"%S bps", str);
	ToStrByte1000(str, sizeof(str), res->BpsTotal);
	ReplaceStr(str, sizeof(str), str, "Bytes", "bps");
	StrToUni(tmp2, sizeof(tmp2), str);
	CtInsert(ct, _UU("TTC_RES_BPS_TOTAL"), tmp1, tmp2);

	CtFree(ct, c);
}

static UINT PtTrafficServer(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	UINT port;
	bool nohup;
	TTS *tts;
	PARAM args[] =
	{
		{"[port]", NULL, NULL, NULL, NULL},
		{"NOHUP", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	port = GetParamInt(o, "[port]");
	if (port == 0)
	{
		port = TRAFFIC_DEFAULT_PORT;
	}

	nohup = GetParamYes(o, "nohup");

	tts = NewTts(port, c, PtTrafficPrintProc);

	if (nohup)
	{
		while (true)
		{
			SleepThread(10000);
		}
	}

	c->Write(c, _UU("TTS_ENTER_TO_EXIT"));

	Free(c->ReadLine(c, L"", true));

	ret = tts->ErrorCode;

	FreeTts(tts);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeParamValueList(o);

	return ret;
}

static UINT PtTrafficClient(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	TTC *ttc;
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	char *host = NULL;
	UINT port;
	UINT num, type;
	bool dbl = false, raw = false;
	UINT64 span;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_TrafficClient_EVAL_NUMTCP",
		0, TRAFFIC_NUMTCP_MAX,
	};
	PARAM args[] =
	{
		{"[host:port]", CmdPrompt, _UU("CMD_TrafficClient_PROMPT_HOST"), CmdEvalNotEmpty, NULL},
		{"NUMTCP", NULL, NULL, CmdEvalMinMax, &minmax},
		{"TYPE", NULL, NULL, NULL, NULL},
		{"SPAN", NULL, NULL, NULL, NULL},
		{"DOUBLE", NULL, NULL, NULL, NULL},
		{"RAW", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (ParseHostPort(GetParamStr(o, "[host:port]"), &host, &port, TRAFFIC_DEFAULT_PORT) == false)
	{
		c->Write(c, _UU("CMD_TrafficClient_ERROR_HOSTPORT"));
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		char *s;
		UINT i;

		Trim(host);

		num = GetParamInt(o, "NUMTCP");
		if (num == 0)
		{
			num = TRAFFIC_NUMTCP_DEFAULT;
		}
		s = GetParamStr(o, "TYPE");

		if (StartWith("download", s))
		{
			type = TRAFFIC_TYPE_DOWNLOAD;
		}
		else if (StartWith("upload", s))
		{
			type = TRAFFIC_TYPE_UPLOAD;
		}
		else
		{
			type = TRAFFIC_TYPE_FULL;
		}

		i = GetParamInt(o, "SPAN");

		if (i == 0)
		{
			i = TRAFFIC_SPAN_DEFAULT;
		}

		span = (UINT64)i * 1000ULL;

		dbl = GetParamYes(o, "DOUBLE");
		raw = GetParamYes(o, "RAW");

		if (type == TRAFFIC_TYPE_FULL)
		{
			if ((num % 2) != 0)
			{
				ret = ERR_INVALID_PARAMETER;
				c->Write(c, _UU("CMD_TrafficClient_ERROR_NUMTCP"));
			}
		}

		if (ret == ERR_NO_ERROR)
		{
			TT_RESULT result;
			ttc = NewTtcEx(host, port, num, type, span, dbl, raw, PtTrafficPrintProc, c);

			Zero(&result, sizeof(result));
			ret = FreeTtc(ttc, &result);

			if (ret == ERR_NO_ERROR)
			{
				TtcPrintResult(c, &result);
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeParamValueList(o);

	Free(host);

	return ret;
}

// A file could not be saved: print the reason and return the error the command exits with
static UINT CmdSaveFailed(CONSOLE *c, char *str_id)
{
	c->Write(c, _UU(str_id));

	return ERR_INTERNAL_ERROR;
}

static UINT PtMakeCert(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	UINT ret = ERR_NO_ERROR;
	X *x = NULL;
	K *pub = NULL;
	K *pri = NULL;
	NAME *n;
	X_SERIAL *x_serial = NULL;
	BUF *buf;
	UINT days;
	X *root_x = NULL;
	K *root_k = NULL;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_MakeCert_EVAL_EXPIRES",
		0,
		10950,
	};
	PARAM args[] =
	{
		{"CN", CmdPrompt, _UU("CMD_MakeCert_PROMPT_CN"), NULL, NULL},
		{"O", CmdPrompt, _UU("CMD_MakeCert_PROMPT_O"), NULL, NULL},
		{"OU", CmdPrompt, _UU("CMD_MakeCert_PROMPT_OU"), NULL, NULL},
		{"C", CmdPrompt, _UU("CMD_MakeCert_PROMPT_C"), NULL, NULL},
		{"ST", CmdPrompt, _UU("CMD_MakeCert_PROMPT_ST"), NULL, NULL},
		{"L", CmdPrompt, _UU("CMD_MakeCert_PROMPT_L"), NULL, NULL},
		{"SERIAL", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SERIAL"), NULL, NULL},
		{"EXPIRES", CmdPrompt, _UU("CMD_MakeCert_PROMPT_EXPIRES"), CmdEvalMinMax, &minmax},
		{"SIGNCERT", NULL, NULL, CmdEvalIsFile, NULL},
		{"SIGNKEY", NULL, NULL, CmdEvalIsFile, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
		{"SAVEKEY", CmdPrompt, _UU("CMD_MakeCert_PROMPT_SAVEKEY"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "SIGNCERT")) == false && IsEmptyStr(GetParamStr(o, "SIGNKEY")) == false)
	{
		root_x = FileToXW(GetParamUniStr(o, "SIGNCERT"));
		root_k = FileToKW(GetParamUniStr(o, "SIGNKEY"), true, NULL);

		if (root_x == NULL || root_k == NULL || CheckXandK(root_x, root_k) == false)
		{
			ret = ERR_INTERNAL_ERROR;

			c->Write(c, _UU("CMD_MakeCert_ERROR_SIGNKEY"));
		}
	}

	if (ret == ERR_NO_ERROR)
	{
		buf = StrToBin(GetParamStr(o, "SERIAL"));
		if (buf != NULL && buf->Size >= 1)
		{
			x_serial = NewXSerial(buf->Buf, buf->Size);
		}
		FreeBuf(buf);

		n = NewName(GetParamUniStr(o, "CN"), GetParamUniStr(o, "O"), GetParamUniStr(o, "OU"), 
			GetParamUniStr(o, "C"), GetParamUniStr(o, "ST"), GetParamUniStr(o, "L"));

		days = GetParamInt(o, "EXPIRES");
		if (days == 0)
		{
			days = 3650;
		}

		// MakeCert and MakeCert2048 both make a key of MAKECERT_RSA_BITS
		if (RsaGen(&pri, &pub, MAKECERT_RSA_BITS))
		{
			if (root_x == NULL)
			{
				x = NewRootX(pub, pri, n, days, x_serial);
			}
			else
			{
				x = NewX(pub, root_k, root_x, n, days, x_serial);
			}
		}

		FreeXSerial(x_serial);
		FreeName(n);

		if (x == NULL)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MakeCert_ERROR_GEN_FAILED"));
		}
		else
		{
			if (XToFileW(x, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				ret = CmdSaveFailed(c, "CMD_SAVECERT_FAILED");
			}
			else if (KToFileW(pri, GetParamUniStr(o, "SAVEKEY"), true, NULL) == false)
			{
				ret = CmdSaveFailed(c, "CMD_SAVEKEY_FAILED");
			}
		}
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeParamValueList(o);

	FreeX(root_x);
	FreeK(root_k);

	FreeX(x);
	FreeK(pri);
	FreeK(pub);

	return ret;
}

static void PsMain(PS *ps)
{
	char prompt[MAX_SIZE];
	wchar_t tmp[MAX_SIZE];
	if (ps == NULL)
	{
		return;
	}

	if(ps->Console->ConsoleType != CONSOLE_CSV)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED"),
			ps->ServerName, ps->ServerPort);
		ps->Console->Write(ps->Console, tmp);
		ps->Console->Write(ps->Console, L"");

		if (ps->HubName == NULL)
		{
			ps->Console->Write(ps->Console, _UU("CMD_VPNCMD_SERVER_CONNECTED_1"));
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_SERVER_CONNECTED_2"),
				ps->HubName);
			ps->Console->Write(ps->Console, tmp);
		}
		ps->Console->Write(ps->Console, L"");
	}

	ps->CapsList = ScGetCapsEx(ps->Rpc);

	if (ps->AdminHub != NULL)
	{
		RPC_HUB_STATUS t;
		UINT ret;
		wchar_t tmp[MAX_SIZE];

		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), ps->AdminHub);

		ret = ScGetHubStatus(ps->Rpc, &t);
		if (ret == ERR_NO_ERROR)
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);

			if (ps->HubName != NULL)
			{
				Free(ps->HubName);
			}
			ps->HubName = CopyStr(t.HubName);

			if( ps->Console->ConsoleType != CONSOLE_CSV)
			{
				ps->Console->Write(ps->Console, tmp);
			}
		}
		else
		{
			UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Select_Failed"), ps->AdminHub);

			ps->Console->Write(ps->Console, tmp);
			CmdPrintError(ps->Console, ret);
		}
	}

	if (ps->HubName == NULL)
	{
		RPC_KEY_PAIR t;

		Zero(&t, sizeof(t));

		if (ScGetServerCert(ps->Rpc, &t) == ERR_NO_ERROR)
		{
			if (t.Cert != NULL && t.Cert->has_basic_constraints == false)
			{
				if (t.Cert->root_cert)
				{
					ps->Console->Write(ps->Console, L"");
					ps->Console->Write(ps->Console, _UU("SM_CERT_MESSAGE_CLI"));
					ps->Console->Write(ps->Console, L"");
				}
			}

			FreeRpcKeyPair(&t);
		}
	}

	while (true)
	{
		CMD cmd[] =
		{
			{"About", PsAbout},
			{"Check", PtCheck},
			{"Crash", PsCrash},
			{"Flush", PsFlush},
			{"ServerInfoGet", PsServerInfoGet},
			{"ServerStatusGet", PsServerStatusGet},
			{"ListenerCreate", PsListenerCreate},
			{"ListenerDelete", PsListenerDelete},
			{"ListenerList", PsListenerList},
			{"ListenerEnable", PsListenerEnable},
			{"ListenerDisable", PsListenerDisable},
			{"ServerPasswordSet", PsServerPasswordSet},
			{"ServerCertGet", PsServerCertGet},
			{"ServerKeyGet", PsServerKeyGet},
			{"ServerCertSet", PsServerCertSet},
			{"ServerCipherGet", PsServerCipherGet},
			{"ServerCipherSet", PsServerCipherSet},
			{"SyslogGet", PsSyslogGet},
			{"SyslogDisable", PsSyslogDisable},
			{"SyslogEnable", PsSyslogEnable},
			{"ConnectionList", PsConnectionList},
			{"ConnectionGet", PsConnectionGet},
			{"ConnectionDisconnect", PsConnectionDisconnect},
			{"BridgeDeviceList", PsBridgeDeviceList},
			{"BridgeList", PsBridgeList},
			{"BridgeCreate", PsBridgeCreate},
			{"BridgeDelete", PsBridgeDelete},
			{"Caps", PsCaps},
			{"Reboot", PsReboot},
			{"ConfigGet", PsConfigGet},
			{"ConfigSet", PsConfigSet},
			{"LogFileList", PsLogFileList},
			{"LogFileGet", PsLogFileGet},
			{"HubCreate", PsHubCreate},
			{"HubDelete", PsHubDelete},
			{"HubList", PsHubList},
			{"Hub", PsHub},
			{"Online", PsOnline},
			{"Offline", PsOffline},
			{"SetMaxSession", PsSetMaxSession},
			{"SetHubPassword", PsSetHubPassword},
			{"SetEnumAllow", PsSetEnumAllow},
			{"SetEnumDeny", PsSetEnumDeny},
			{"OptionsGet", PsOptionsGet},
			{"StatusGet", PsStatusGet},
			{"LogGet", PsLogGet},
			{"LogEnable", PsLogEnable},
			{"LogDisable", PsLogDisable},
			{"LogSwitchSet", PsLogSwitchSet},
			{"LogPacketSaveType", PsLogPacketSaveType},
			{"CAList", PsCAList},
			{"CAAdd", PsCAAdd},
			{"CADelete", PsCADelete},
			{"CAGet", PsCAGet},
			{"CascadeList", PsCascadeList},
			{"CascadeCreate", PsCascadeCreate},
			{"CascadeSet", PsCascadeSet},
			{"CascadeGet", PsCascadeGet},
			{"CascadeDelete", PsCascadeDelete},
			{"CascadeUsernameSet", PsCascadeUsernameSet},
			{"CascadeAnonymousSet", PsCascadeAnonymousSet},
			{"CascadePasswordSet", PsCascadePasswordSet},
			{"CascadeCertSet", PsCascadeCertSet},
			{"CascadeCertGet", PsCascadeCertGet},
			{"CascadeEncryptEnable", PsCascadeEncryptEnable},
			{"CascadeEncryptDisable", PsCascadeEncryptDisable},
			{"CascadeCompressEnable", PsCascadeCompressEnable},
			{"CascadeCompressDisable", PsCascadeCompressDisable},
			{"CascadeProxyNone", PsCascadeProxyNone},
			{"CascadeHttpHeaderAdd", PsCascadeHttpHeaderAdd},
			{"CascadeHttpHeaderDelete", PsCascadeHttpHeaderDelete},
			{"CascadeHttpHeaderGet", PsCascadeHttpHeaderGet},
			{"CascadeProxyHttp", PsCascadeProxyHttp},
			{"CascadeProxySocks", PsCascadeProxySocks},
			{"CascadeProxySocks5", PsCascadeProxySocks5},
			{"CascadeServerCertEnable", PsCascadeServerCertEnable},
			{"CascadeServerCertDisable", PsCascadeServerCertDisable},
			{"CascadeDefaultCAEnable", PsCascadeDefaultCAEnable},
			{"CascadeDefaultCADisable", PsCascadeDefaultCADisable},
			{"CascadeServerCertSet", PsCascadeServerCertSet},
			{"CascadeServerCertDelete", PsCascadeServerCertDelete},
			{"CascadeServerCertGet", PsCascadeServerCertGet},
			{"CascadeDetailSet", PsCascadeDetailSet},
			{"CascadePolicySet", PsCascadePolicySet},
			{"PolicyList", PsPolicyList},
			{"CascadeStatusGet", PsCascadeStatusGet},
			{"CascadeRename", PsCascadeRename},
			{"CascadeOnline", PsCascadeOnline},
			{"CascadeOffline", PsCascadeOffline},
			{"AccessAdd", PsAccessAdd},
			{"AccessAddEx", PsAccessAddEx},
			{"AccessAdd6", PsAccessAdd6},
			{"AccessAddEx6", PsAccessAddEx6},
			{"AccessList", PsAccessList},
			{"AccessDelete", PsAccessDelete},
			{"AccessEnable", PsAccessEnable},
			{"AccessDisable", PsAccessDisable},
			{"UserList", PsUserList},
			{"UserCreate", PsUserCreate},
			{"UserSet", PsUserSet},
			{"UserDelete", PsUserDelete},
			{"UserGet", PsUserGet},
			{"UserAnonymousSet", PsUserAnonymousSet},
			{"UserPasswordSet", PsUserPasswordSet},
			{"UserCertSet", PsUserCertSet},
			{"UserCertGet", PsUserCertGet},
			{"UserSignedSet", PsUserSignedSet},
			{"UserNTLMSet", PsUserNTLMSet},
			{"UserPolicyRemove", PsUserPolicyRemove},
			{"UserPolicySet", PsUserPolicySet},
			{"UserExpiresSet", PsUserExpiresSet},
			{"GroupList", PsGroupList},
			{"GroupCreate", PsGroupCreate},
			{"GroupSet", PsGroupSet},
			{"GroupDelete", PsGroupDelete},
			{"GroupGet", PsGroupGet},
			{"GroupJoin", PsGroupJoin},
			{"GroupUnjoin", PsGroupUnjoin},
			{"GroupPolicyRemove", PsGroupPolicyRemove},
			{"GroupPolicySet", PsGroupPolicySet},
			{"SessionList", PsSessionList},
			{"SessionGet", PsSessionGet},
			{"SessionDisconnect", PsSessionDisconnect},
			{"MacTable", PsMacTable},
			{"MacDelete", PsMacDelete},
			{"IpTable", PsIpTable},
			{"IpDelete", PsIpDelete},
			{"AdminOptionList", PsAdminOptionList},
			{"AdminOptionSet", PsAdminOptionSet},
			{"ExtOptionList", PsExtOptionList},
			{"ExtOptionSet", PsExtOptionSet},
			{"CrlList", PsCrlList},
			{"CrlAdd", PsCrlAdd},
			{"CrlDel", PsCrlDel},
			{"CrlGet", PsCrlGet},
			{"AcList", PsAcList},
			{"AcAdd", PsAcAdd},
			{"AcAdd6", PsAcAdd6},
			{"AcDel", PsAcDel},
			{"MakeCert", PtMakeCert},
			{"MakeCert2048", PtMakeCert},
			{"TrafficClient", PtTrafficClient},
			{"TrafficServer", PtTrafficServer},
			{"ServerCertRegenerate", PsServerCertRegenerate},
		};

		if (ps->HubName == NULL)
		{
			Format(prompt, sizeof(prompt), "VPN Server>");
		}
		else
		{
			Format(prompt, sizeof(prompt), "VPN Server/%s>", ps->HubName);
		}

		if (DispatchNextCmdEx(ps->Console, ps->CmdLine, prompt, cmd, sizeof(cmd) / sizeof(cmd[0]), ps) == false)
		{
			break;
		}
		ps->LastError = ps->Console->RetCode;

		if (ps->LastError == ERR_NO_ERROR && ps->Console->ConsoleType != CONSOLE_CSV)
		{
			ps->Console->Write(ps->Console, _UU("CMD_MSG_OK"));
			ps->Console->Write(ps->Console, L"");
		}

		if (ps->CmdLine != NULL)
		{
			break;
		}
	}

	FreeCapsList(ps->CapsList);
	ps->CapsList = NULL;
}

// Eval parameter of CmdEvalHostAndPort; a NULL parameter is port 0 and the standard message
typedef struct CMD_EVAL_HOST_PORT
{
	UINT DefaultPort;			// Port taken when the text names none (0: the text must name a port)
	wchar_t *ErrorMessage;		// Message printed when the text is invalid (NULL: CMD_HOSTPORT_EVAL_FAILED)
} CMD_EVAL_HOST_PORT;

static bool CmdEvalHostAndPort(CONSOLE *c, wchar_t *str, void *param)
{
	CMD_EVAL_HOST_PORT *e = (CMD_EVAL_HOST_PORT *)param;
	char *tmp;
	bool ret = false;
	if (c == NULL || str == NULL)
	{
		return false;
	}

	tmp = CopyUniToStr(str);

	ret = ParseHostPort(tmp, NULL, NULL, e == NULL ? 0 : e->DefaultPort);

	if (ret == false)
	{
		c->Write(c, (e == NULL || e->ErrorMessage == NULL) ? _UU("CMD_HOSTPORT_EVAL_FAILED") : e->ErrorMessage);
	}

	Free(tmp);

	return ret;
}

static UINT PsServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	PARAM args[] =
	{
		{"[cert]", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (XToFileW(t.Cert, GetParamUniStr(o, "[cert]"), true) == false)
	{
		ret = CmdSaveFailed(c, "CMD_SAVECERT_FAILED");
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return ret;
}

static UINT PsServerKeyGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	PARAM args[] =
	{
		{"[key]", CmdPrompt, _UU("CMD_SAVEKEYPATH"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetServerCert(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Key != NULL)
	{
		if (KToFileW(t.Key, GetParamUniStr(o, "[key]"), true, NULL) == false)
		{
			ret = CmdSaveFailed(c, "CMD_SAVEKEY_FAILED");
		}
	}
	else
	{
		ret = ERR_NOT_ENOUGH_RIGHT;
		CmdPrintError(c, ret);
	}

	FreeRpcKeyPair(&t);

	FreeParamValueList(o);

	return ret;
}

static bool CmdLoadCertChainAndKey(CONSOLE *c, X **xx, K **kk, LIST **cc, wchar_t *cert_filename, wchar_t *key_filename)
{
	X *x = NULL;
	K *k;
	LIST *chain = NULL;
	if (c == NULL || cert_filename == NULL || key_filename == NULL || xx == NULL || kk == NULL)
	{
		return false;
	}

	BUF *b = ReadDumpW(cert_filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return false;
	}

	// DER-encoded X509 files can't hold multiple certificates
	if (cc == NULL || IsBase64(b) == false)
	{
		x = BufToX(b, IsBase64(b));
	}
	else
	{
		chain = BufToXList(b, true);
		if (LIST_NUM(chain) > 0)
		{
			x = LIST_DATA(chain, 0);
			Delete(chain, x);

			if (LIST_NUM(chain) == 0)
			{
				ReleaseList(chain);
				chain = NULL;
			}
		}
	}
	FreeBuf(b);
	if (x == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		FreeXList(chain);
		return false;
	}

	k = CmdLoadKey(c, key_filename);
	if (k == NULL)
	{
		c->Write(c, _UU("CMD_LOADKEY_FAILED"));
		FreeX(x);
		FreeXList(chain);
		return false;
	}

	if (CheckXandK(x, k) == false)
	{
		c->Write(c, _UU("CMD_KEYPAIR_FAILED"));
		FreeX(x);
		FreeK(k);
		FreeXList(chain);

		return false;
	}

	*xx = x;
	*kk = k;
	if (cc != NULL)
	{
		*cc = chain;
	}

	return true;
}

static K *CmdLoadKey(CONSOLE *c, wchar_t *filename)
{
	BUF *b;
	if (c == NULL || filename == NULL)
	{
		return NULL;
	}

	b = ReadDumpW(filename);
	if (b == NULL)
	{
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return NULL;
	}
	else
	{
		K *key;
		if (IsEncryptedK(b, true) == false)
		{
			key = BufToK(b, true, IsBase64(b), NULL);
		}
		else
		{
			c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_1"));

			while (true)
			{
				char *pass = c->ReadPassword(c, _UU("CMD_LOADKEY_ENCRYPTED_2"));

				if (pass == NULL)
				{
					FreeBuf(b);
					return NULL;
				}

				key = BufToK(b, true, IsBase64(b), pass);
				Free(pass);

				if (key != NULL)
				{
					break;
				}

				c->Write(c, _UU("CMD_LOADKEY_ENCRYPTED_3"));
			}
		}

		FreeBuf(b);

		return key;
	}
}

static UINT PsServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_KEY_PAIR t;
	PARAM args[] =
	{
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (CmdLoadCertChainAndKey(c, &t.Cert, &t.Key, &t.Chain,
		GetParamUniStr(o, "LOADCERT"),
		GetParamUniStr(o, "LOADKEY")))
	{
		ret = ScSetServerCert(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		if (t.Flag1 == 0)
		{
			c->Write(c, L"");
			c->Write(c, _UU("SM_CERT_NEED_ROOT"));
			c->Write(c, L"");
		}

		FreeRpcKeyPair(&t);
	}
	else
	{
		ret = ERR_INTERNAL_ERROR;
	}

	FreeParamValueList(o);

	return ret;
}

static UINT PsServerCipherGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	TOKEN_LIST *ciphers;
	UINT i;
	wchar_t tmp[4096];

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	UniFormat(tmp, sizeof(tmp), L" %S", t.String);
	FreeRpcStr(&t);
	Zero(&t, sizeof(RPC_STR));

	c->Write(c, _UU("CMD_ServerCipherGet_SERVER"));
	c->Write(c, tmp);

	ret = ScGetServerCipherList(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		ciphers = ParseToken(t.String, ";");

		FreeRpcStr(&t);

		c->Write(c, L"");
		c->Write(c, _UU("CMD_ServerCipherGet_CIPHERS"));

		for (i = 0; i < ciphers->NumTokens; i++)
		{
			UniFormat(tmp, sizeof(tmp), L" %S", ciphers->Token[i]);
			c->Write(c, tmp);
		}

		FreeToken(ciphers);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsServerCipherSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_STR t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ServerCipherSet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	t.String = CopyStr(GetParamStr(o, "[name]"));

	ret = ScSetServerCipher(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcStr(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsSyslogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;
	CMD_EVAL_MIN_MAX minmax = {"CMD_SyslogEnable_MINMAX", SYSLOG_SERVER_AND_HUB_SECURITY_LOG, SYSLOG_SERVER_AND_HUB_ALL_LOG};
	CMD_EVAL_HOST_PORT host_eval = {SYSLOG_PORT, NULL};
	char *host;
	UINT port;

	PARAM args[] =
	{
		{"[2|3]", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_23"), CmdEvalMinMax, &minmax},
		{"HOST", CmdPrompt, _UU("CMD_SyslogEnable_Prompt_HOST"), CmdEvalHostAndPort, &host_eval},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	if (ParseHostPort(GetParamStr(o, "HOST"), &host, &port, SYSLOG_PORT))
	{
		StrCpy(t.Hostname, sizeof(t.Hostname), host);
		t.Port = port;
		t.SaveType = GetParamInt(o, "[2|3]");

		Free(host);

		ret = ScSetSysLog(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSyslogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.SaveType = SYSLOG_NONE;

	ret = ScSetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSyslogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	SYSLOG_SETTING t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetSysLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_1"), GetSyslogSettingName(t.SaveType));

		if (t.SaveType != SYSLOG_NONE)
		{
			StrToUni(tmp, sizeof(tmp), t.Hostname);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_2"), tmp);

			UniToStru(tmp, t.Port);
			CtInsert(ct, _UU("CMD_SyslogGet_COLUMN_3"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

static wchar_t *GetSyslogSettingName(UINT n)
{
	char tmp[MAX_PATH];

	Format(tmp, sizeof(tmp), "SM_SYSLOG_%u", n);

	return _UU(tmp);
}

static wchar_t *GetConnectionTypeStr(UINT type)
{
	char tmp[MAX_SIZE];
	Format(tmp, sizeof(tmp), "SM_CONNECTION_TYPE_%u", type);

	return _UU(tmp);
}

static UINT PsConnectionList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_CONNECTION t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_CONN_COLUMN_4"), false);

	for (i = 0;i < t.NumConnection;i++)
	{
		wchar_t tmp[MAX_SIZE];
		wchar_t name[MAX_SIZE];
		wchar_t datetime[MAX_SIZE];
		RPC_ENUM_CONNECTION_ITEM *e = &t.Connections[i];

		StrToUni(name, sizeof(name), e->Name);
		UniFormat(tmp, sizeof(tmp), _UU("SM_HOSTNAME_AND_PORT"), e->Hostname, e->Port);
		GetDateTimeStrEx64(datetime, sizeof(datetime), SystemToLocal64(e->ConnectedTime), NULL);

		CtInsert(ct, name, tmp, datetime,
			GetConnectionTypeStr(e->Type));
	}

	CtFree(ct, c);

	FreeRpcEnumConnection(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsConnectionGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONNECTION_INFO t;
	CT *ct;
	wchar_t tmp[MAX_SIZE];
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetConnectionInfo(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("SM_CONNINFO_NAME"), tmp);

		CtInsert(ct, _UU("SM_CONNINFO_TYPE"), GetConnectionTypeStr(t.Type));

		StrToUni(tmp, sizeof(tmp), t.Hostname);
		CtInsert(ct, _UU("SM_CONNINFO_HOSTNAME"), tmp);

		UniToStru(tmp, t.Port);
		CtInsert(ct, _UU("SM_CONNINFO_PORT"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ConnectedTime), NULL);
		CtInsert(ct, _UU("SM_CONNINFO_TIME"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ServerStr);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_STR"), tmp);

		UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ServerVer / 100, t.ServerVer % 100);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_VER"), tmp);

		UniToStru(tmp, t.ServerBuild);
		CtInsert(ct, _UU("SM_CONNINFO_SERVER_BUILD"), tmp);

		if (StrLen(t.ClientStr) != 0)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientStr);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_STR"), tmp);

			UniFormat(tmp, sizeof(tmp), L"%u.%02u", t.ClientVer / 100, t.ClientVer % 100);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_VER"), tmp);

			UniToStru(tmp, t.ClientBuild);
			CtInsert(ct, _UU("SM_CONNINFO_CLIENT_BUILD"), tmp);
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsConnectionDisconnect(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DISCONNECT_CONNECTION t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_ConnectionDisconnect_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScDisconnectConnection(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsBridgeDeviceList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_ETH t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumEthernet(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_ENUM_ETH_ITEM *item = &t.Items[i];
		wchar_t tmp[MAX_SIZE * 2];

		StrToUni(tmp, sizeof(tmp), item->DeviceName);
		c->Write(c, tmp);
	}

	FreeRpcEnumEth(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsBridgeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOCALBRIDGE t;
	UINT i;
	CT *ct;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	ct = CtNew();

	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_3"), false);
	CtInsertColumn(ct, _UU("SM_BRIDGE_COLUMN_4"), false);

	for (i = 0;i < t.NumItem;i++)
	{
		RPC_LOCALBRIDGE *e = &t.Items[i];
		wchar_t name[MAX_SIZE];
		wchar_t nic[MAX_SIZE];
		wchar_t hub[MAX_SIZE];
		wchar_t *status = _UU("SM_BRIDGE_OFFLINE");

		UniToStru(name, i + 1);
		StrToUni(nic, sizeof(nic), e->DeviceName);
		StrToUni(hub, sizeof(hub), e->HubName);

		if (e->Online)
		{
			status = e->Active ? _UU("SM_BRIDGE_ONLINE") : _UU("SM_BRIDGE_ERROR");
		}

		CtInsert(ct, name, hub, nic, status);
	}

	CtFree(ct, c);

	FreeRpcEnumLocalBridge(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsBridgeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	PARAM args[] =
	{
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeCreate_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
		{"TAP", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.Active = true;
	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));
	t.Online = true;
	t.TapMode = GetParamYes(o, "TAP");

	ret = ScAddLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		c->Write(c, _UU("SM_BRIDGE_INTEL"));
		c->Write(c, L"");

		if (GetCapsBool(ps->CapsList, "b_is_in_vm"))
		{
			c->Write(c, _UU("D_SM_VMBRIDGE@CAPTION"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_1"));
			c->Write(c, _UU("D_SM_VMBRIDGE@S_2"));
			c->Write(c, L"");
		}
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsBridgeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LOCALBRIDGE t;
	PARAM args[] =
	{
		{"[hubname]", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_HUBNAME"), CmdEvalNotEmpty, NULL},
		{"DEVICE", CmdPrompt, _UU("CMD_BridgeDelete_PROMPT_DEVICE"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.DeviceName, sizeof(t.DeviceName), GetParamStr(o, "DEVICE"));
	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[hubname]"));

	ret = ScDeleteLocalBridge(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCaps(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	CAPSLIST *t;
	UINT i;
	CT *ct;


	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	t = ps->CapsList;
	if (t == NULL)
	{
		CmdPrintError(c, ERR_INTERNAL_ERROR);
		FreeParamValueList(o);
		return ERR_INTERNAL_ERROR;
	}

	ct = CtNewStandard();

	for (i = 0;i < LIST_NUM(t->CapsList);i++)
	{
		CAPS *c = LIST_DATA(t->CapsList, i);
		wchar_t title[MAX_SIZE];
		char name[256];

		Format(name, sizeof(name), "CT_%s", c->Name);

		UniStrCpy(title, sizeof(title), _UU(name));

		if (UniIsEmptyStr(title))
		{
			UniFormat(title, sizeof(title), L"%S", (StrLen(c->Name) >= 2) ? c->Name + 2 : c->Name);
		}

		if (StartWith(c->Name, "b_"))
		{
			CtInsert(ct, title, c->Value == 0 ? _UU("CAPS_NO") : _UU("CAPS_YES"));
		}
		else
		{
			wchar_t str[64];
			UniToStru(str, c->Value);
			CtInsert(ct, title, str);
		}
	}

	CtFree(ct, c);

	FreeParamValueList(o);

	return 0;
}

static UINT PsReboot(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_TEST t;
	PARAM args[] =
	{
		{"RESETCONFIG", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	t.IntValue = GetParamYes(o, "RESETCONFIG") ? 1 : 0;

	ret = ScRebootServer(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcTest(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsConfigGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	PARAM args[] =
	{
		{"[path]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScGetConfig(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t *filename = GetParamUniStr(o, "[path]");

		if (UniIsEmptyStr(filename))
		{
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *buf;
			UNI_TOKEN_LIST *lines;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_ConfigGet_FILENAME"), t.FileName,
				StrLen(t.FileData));
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)t.FileData, StrLen(t.FileData));
			buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(buf, buf_size, (BYTE *)t.FileData, StrLen(t.FileData));

			lines = UniGetLines(buf);
			if (lines != NULL)
			{
				UINT i;

				for (i = 0;i < lines->NumTokens;i++)
				{
					c->Write(c, lines->Token[i]);
				}

				UniFreeToken(lines);
			}

			c->Write(c, L"");

			Free(buf);
		}
		else
		{
			IO *io = FileCreateW(filename);

			if (io == NULL)
			{
				ret = CmdSaveFailed(c, "CMD_ConfigGet_FILE_SAVE_FAILED");
			}
			else
			{
				if (FileWrite(io, t.FileData, StrLen(t.FileData)) == false)
				{
					ret = CmdSaveFailed(c, "CMD_ConfigGet_FILE_SAVE_FAILED");
				}
				FileClose(io);
			}
		}
	}

	FreeRpcConfig(&t);

	FreeParamValueList(o);

	return ret;
}

static UINT PsConfigSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CONFIG t;
	wchar_t *filename;
	BUF *buf;
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_ConfigSet_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamUniStr(o, "[path]");

	buf = ReadDumpW(filename);
	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_ConfigSet_FILE_LOAD_FAILED"));
		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		Zero(&t, sizeof(t));

		t.FileData = ZeroMalloc(buf->Size + 1);
		Copy(t.FileData, buf->Buf, buf->Size);
		FreeBuf(buf);

		ret = ScSetConfig(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
		}

		FreeRpcConfig(&t);
	}

	FreeParamValueList(o);

	return ret;
}

static bool CmdEvalIpAndMask4(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	UINT ip, mask;
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask4(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1"));
		return false;
	}

	return true;
}
static bool CmdEvalIpAndMask6(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[MAX_SIZE];
	IP ip, mask;
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (ParseIpAndMask6(tmp, &ip, &mask) == false)
	{
		c->Write(c, _UU("CMD_PARSE_IP_MASK_ERROR_1_6"));
		return false;
	}

	return true;
}

static UINT PsLogFileList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LOG_FILE t;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	c->Write(c, _UU("CMD_LogFileList_START"));
	c->Write(c, L"");

	ret = ScEnumLogFile(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileList_NUM_LOGS"), t.NumItem);
		c->Write(c, tmp);

		ct = CtNew();

		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_2"), true);
		CtInsertColumn(ct, _UU("SM_LOG_FILE_COLUMN_3"), false);

		for (i = 0;i < t.NumItem;i++)
		{
			RPC_ENUM_LOG_FILE_ITEM *e = &t.Items[i];
			wchar_t tmp1[MAX_PATH], tmp2[128], tmp3[128];
			char tmp[MAX_SIZE];

			StrToUni(tmp1, sizeof(tmp1), e->FilePath);

			ToStrByte(tmp, sizeof(tmp), e->FileSize);
			StrToUni(tmp2, sizeof(tmp2), tmp);

			GetDateTimeStr64Uni(tmp3, sizeof(tmp3), SystemToLocal64(e->UpdatedTime));

			CtInsert(ct, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLogFile(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsLogFileGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	BUF *buf;
	char *filename = NULL;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_LogFileGet_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVEPATH", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	filename = GetParamStr(o, "SAVEPATH");

	c->Write(c, _UU("CMD_LogFileGet_START"));

	buf = DownloadFileFromServer(ps->Rpc,
		GetParamStr(o, "[name]"), 0, NULL, NULL);

	if (buf == NULL)
	{
		c->Write(c, _UU("CMD_LogFileGet_FAILED"));

		ret = ERR_INTERNAL_ERROR;
	}
	else
	{
		if (IsEmptyStr(filename) == false)
		{
			if (DumpBuf(buf, filename) == false)
			{
				ret = ERR_INTERNAL_ERROR;
				c->Write(c, _UU("CMD_LogFileGet_SAVE_FAILED"));
			}
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			UINT buf_size;
			wchar_t *uni_buf;

			UniFormat(tmp, sizeof(tmp), _UU("CMD_LogFileGet_FILESIZE"),
				buf->Size);
			c->Write(c, tmp);
			c->Write(c, L"");

			buf_size = CalcUtf8ToUni((BYTE *)buf->Buf, buf->Size);
			uni_buf = ZeroMalloc(buf_size + 32);

			Utf8ToUni(uni_buf, buf_size, (BYTE *)buf->Buf, buf->Size);

			c->Write(c, uni_buf);
			c->Write(c, L"");

			Free(uni_buf);
		}

		FreeBuf(buf);
	}

	FreeParamValueList(o);

	return ret;
}

static UINT PsHubCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pass = "";
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubCreate_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	if (IsEmptyStr(GetParamStr(o, "PASSWORD")) == false)
	{
		pass = GetParamStr(o, "PASSWORD");
	}

	Sha0(t.HashedPassword, pass, StrLen(pass));
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pass);
	t.Online = true;

	ret = ScCreateHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsHubDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_DELETE_HUB t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_HubDelete_PROMPT_NAME"), CmdEvalNotEmpty, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

	ret = ScDeleteHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

// Total bytes sent and received, broadcast and unicast
static UINT64 TrafficTotalBytes(const TRAFFIC *t)
{
	return t->Recv.BroadcastBytes + t->Recv.UnicastBytes +
		t->Send.BroadcastBytes + t->Send.UnicastBytes;
}

// Total packets sent and received, broadcast and unicast
static UINT64 TrafficTotalPackets(const TRAFFIC *t)
{
	return t->Recv.BroadcastCount + t->Recv.UnicastCount +
		t->Send.BroadcastCount + t->Send.UnicastCount;
}

static UINT PsHubList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_HUB t;
	UINT i;

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	ret = ScEnumHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_8"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_9"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_10"), false);
		CtInsertColumn(ct, _UU("SM_HUB_COLUMN_11"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumHub;i++)
		{
			RPC_ENUM_HUB_ITEM *e = &t.Hubs[i];
			wchar_t name[MAX_HUBNAME_LEN + 1];
			wchar_t s1[64], s2[64], s3[64], s4[64], s5[64];
			wchar_t s6[64], s7[128], s8[128];
			wchar_t s9[64], s10[64];

			UniToStru(s1, e->NumUsers);
			UniToStru(s2, e->NumGroups);
			UniToStru(s3, e->NumSessions);
			UniToStru(s4, e->NumMacTables);
			UniToStru(s5, e->NumIpTables);

			UniToStru(s6, e->NumLogin);

			if (e->LastLoginTime != 0)
			{
				GetDateTimeStr64Uni(s7, sizeof(s7), SystemToLocal64(e->LastLoginTime));
			}
			else
			{
				UniStrCpy(s7, sizeof(s7), _UU("COMMON_UNKNOWN"));
			}

			if (e->LastCommTime != 0)
			{
				GetDateTimeStr64Uni(s8, sizeof(s8), SystemToLocal64(e->LastCommTime));
			}
			else
			{
				UniStrCpy(s8, sizeof(s8), _UU("COMMON_UNKNOWN"));
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(s9, sizeof(s9), _UU("CM_ST_NONE"));
				UniStrCpy(s10, sizeof(s10), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(s9, sizeof(s9), TrafficTotalBytes(&e->Traffic));

				UniToStr3(s10, sizeof(s10), TrafficTotalPackets(&e->Traffic));
			}

			StrToUni(name, sizeof(name), e->HubName);

			CtInsert(ct,
				name,
				e->Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"),
				s1, s2, s3, s4, s5, s6, s7, s8, s9, s10);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumHub(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsHub(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;
	PARAM args[] =
	{
		{"[name]", NULL, NULL, NULL, NULL},
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (IsEmptyStr(GetParamStr(o, "[name]")) == false)
	{
		wchar_t tmp[MAX_SIZE];
		Zero(&t, sizeof(t));

		StrCpy(t.HubName, sizeof(t.HubName), GetParamStr(o, "[name]"));

		ret = ScGetHubStatus(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		if (ps->HubName != NULL)
		{
			Free(ps->HubName);
		}
		ps->HubName = CopyStr(t.HubName);

		UniFormat(tmp, sizeof(tmp), _UU("CMD_Hub_Selected"), t.HubName);
		c->Write(c, tmp);
	}
	else
	{
		if (ps->HubName != NULL)
		{
			c->Write(c, _UU("CMD_Hub_Unselected"));
			Free(ps->HubName);
		}
		ps->HubName = NULL;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsOnline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = true;

	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsOffline(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_HUB_ONLINE t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Online = false;

	ret = ScSetHubOnline(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSetMaxSession(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	PARAM args[] =
	{
		{"[max_session]", CmdPrompt, _UU("CMD_SetMaxSession_Prompt"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.MaxSession = GetParamInt(o, "[max_session]");

	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSetHubPassword(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;
	char *pw;
	PARAM args[] =
	{
		{"[password]", CmdPromptChoosePassword, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	pw = GetParamStr(o, "[password]");
	HashPassword(t.SecurePassword, ADMINISTRATOR_USERNAME, pw);
	Sha0(t.HashedPassword, pw, StrLen(pw));

	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSetEnumAllow(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = false;

	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsSetEnumDeny(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	ret = ScGetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.HubOption.NoEnum = true;

	ret = ScSetHub(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsOptionsGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_HUB t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHub(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct;
		wchar_t tmp[MAX_SIZE];

		UniFormat(tmp, sizeof(tmp), _UU("CMD_OptionsGet_TITLE"), ps->HubName);
		c->Write(c, tmp);

		ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_OptionsGet_ENUM"),
			t.HubOption.NoEnum ? _UU("CMD_MSG_DENY") : _UU("CMD_MSG_ALLOW"));

		if (t.HubOption.MaxSession == 0)
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		else
		{
			UniToStru(tmp, t.HubOption.MaxSession);
		}
		CtInsert(ct, _UU("CMD_OptionsGet_MAXSESSIONS"), tmp);

		CtInsert(ct, _UU("CMD_OptionsGet_STATUS"), t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsStatusGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_STATUS t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubStatus(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();
		wchar_t *s;
		wchar_t tmp[MAX_SIZE];

		s = CopyStrToUni(t.HubName);
		CtInsert(ct, _UU("SM_HUB_STATUS_HUBNAME"), s);
		Free(s);

		CtInsert(ct, _UU("SM_HUB_STATUS_ONLINE"),
			t.Online ? _UU("SM_HUB_ONLINE") : _UU("SM_HUB_OFFLINE"));

		UniToStru(tmp, t.NumSessions);
		CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS"), tmp);

		if (t.NumSessionsClient != 0 || t.NumSessionsBridge != 0)
		{
			UniToStru(tmp, t.NumSessionsClient);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_CLIENT"), tmp);
			UniToStru(tmp, t.NumSessionsBridge);
			CtInsert(ct, _UU("SM_HUB_NUM_SESSIONS_BRIDGE"), tmp);
		}

		UniToStru(tmp, t.NumAccessLists);
		CtInsert(ct, _UU("SM_HUB_NUM_ACCESSES"), tmp);

		UniToStru(tmp, t.NumUsers);
		CtInsert(ct, _UU("SM_HUB_NUM_USERS"), tmp);
		UniToStru(tmp, t.NumGroups);
		CtInsert(ct, _UU("SM_HUB_NUM_GROUPS"), tmp);

		UniToStru(tmp, t.NumMacTables);
		CtInsert(ct, _UU("SM_HUB_NUM_MAC_TABLES"), tmp);
		UniToStru(tmp, t.NumIpTables);
		CtInsert(ct, _UU("SM_HUB_NUM_IP_TABLES"), tmp);

		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_HUB_NUM_LOGIN"), tmp);

		if (t.LastLoginTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastLoginTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_LOGIN_TIME"), tmp);

		if (t.LastCommTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.LastCommTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_LAST_COMM_TIME"), tmp);

		if (t.CreatedTime != 0)
		{
			GetDateTimeStr64Uni(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime));
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("COMMON_UNKNOWN"));
		}
		CtInsert(ct, _UU("SM_HUB_CREATED_TIME"), tmp);

		CmdInsertTrafficInfo(ct, &t.Traffic);

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

static wchar_t *GetLogSwitchStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "SM_LOG_SWITCH_%u", i);

	return _UU(tmp);
}

static wchar_t *GetPacketLogNameStr(UINT i)
{
	char tmp[64];

	Format(tmp, sizeof(tmp), "CMD_Log_%u", i);

	return _UU(tmp);
}

static UINT PsLogGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubLog(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_Log_SecurityLog"),
			t.LogSetting.SaveSecurityLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SaveSecurityLog)
		{
			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.SecurityLogSwitchType));
		}

		CtInsert(ct, L"", L"");

		CtInsert(ct, _UU("CMD_Log_PacketLog"),
			t.LogSetting.SavePacketLog ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		if (t.LogSetting.SavePacketLog)
		{
			UINT i;

			CtInsert(ct, _UU("CMD_Log_SwitchType"), GetLogSwitchStr(t.LogSetting.PacketLogSwitchType));

			for (i = 0;i <= 7;i++)
			{
				wchar_t *tmp = NULL;

				switch (t.LogSetting.PacketLogConfig[i])
				{
				case PACKET_LOG_NONE:
					tmp = _UU("D_SM_LOG@B_PACKET_0_0");
					break;

				case PACKET_LOG_HEADER:
					tmp = _UU("D_SM_LOG@B_PACKET_0_1");
					break;

				case PACKET_LOG_ALL:
					tmp = _UU("D_SM_LOG@B_PACKET_0_2");
					break;
				}

				CtInsert(ct, GetPacketLogNameStr(i),
					tmp);
			}
		}

		CtFree(ct, c);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsLogEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = true;
	}
	else
	{
		t.LogSetting.SavePacketLog = true;
	}

	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsLogDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SaveSecurityLog = false;
	}
	else
	{
		t.LogSetting.SavePacketLog = false;
	}

	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT StrToLogSwitchType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (IsEmptyStr(str) || StartWith("none", str))
	{
		ret = LOG_SWITCH_NO;
	}
	else if (StartWith("second", str))
	{
		ret = LOG_SWITCH_SECOND;
	}
	else if (StartWith("minute", str))
	{
		ret = LOG_SWITCH_MINUTE;
	}
	else if (StartWith("hour", str))
	{
		ret = LOG_SWITCH_HOUR;
	}
	else if (StartWith("day", str))
	{
		ret = LOG_SWITCH_DAY;
	}
	else if (StartWith("month", str))
	{
		ret = LOG_SWITCH_MONTH;
	}

	return ret;
}

static UINT PsLogSwitchSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	bool packet_log = false;
	char *tmp;
	UINT new_switch_type = 0;
	PARAM args[] =
	{
		{"[security|packet]", CmdPrompt, _UU("CMD_LogEnable_Prompt"), CmdEvalNotEmpty, NULL},
		{"SWITCH", CmdPrompt, _UU("CMD_LogSwitchSet_Prompt"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	tmp = GetParamStr(o, "[security|packet]");

	if (StartWith(tmp, "p"))
	{
		packet_log = true;
	}
	else if (StartWith(tmp, "s") == false)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}
	
	new_switch_type = StrToLogSwitchType(GetParamStr(o, "SWITCH"));

	if (new_switch_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (packet_log == false)
	{
		t.LogSetting.SecurityLogSwitchType = new_switch_type;
	}
	else
	{
		t.LogSetting.PacketLogSwitchType = new_switch_type;
	}

	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT StrToPacketLogSaveInfoType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL)
	{
		return INFINITE;
	}

	if (StartWith("none", str) || IsEmptyStr(str))
	{
		ret = PACKET_LOG_NONE;
	}
	else if (StartWith("header", str))
	{
		ret = PACKET_LOG_HEADER;
	}
	else if (StartWith("full", str) || StartWith("all", str))
	{
		ret = PACKET_LOG_ALL;
	}

	return ret;
}

static UINT StrToPacketLogType(char *str)
{
	UINT ret = INFINITE;
	if (str == NULL || IsEmptyStr(str))
	{
		return INFINITE;
	}

	if (StartWith("tcpconn", str))
	{
		ret = PACKET_LOG_TCP_CONN;
	}
	else if (StartWith("tcpdata", str))
	{
		ret = PACKET_LOG_TCP;
	}
	else if (StartWith("dhcp", str))
	{
		ret = PACKET_LOG_DHCP;
	}
	else if (StartWith("udp", str))
	{
		ret = PACKET_LOG_UDP;
	}
	else if (StartWith("icmp", str))
	{
		ret = PACKET_LOG_ICMP;
	}
	else if (StartWith("ip", str))
	{
		ret = PACKET_LOG_IP;
	}
	else if (StartWith("arp", str))
	{
		ret = PACKET_LOG_ARP;
	}
	else if (StartWith("ethernet", str))
	{
		ret = PACKET_LOG_ETHERNET;
	}

	return ret;
}

static UINT PsLogPacketSaveType(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_LOG t;
	UINT packet_type = INFINITE;
	UINT packet_save_info_type = INFINITE;
	PARAM args[] =
	{
		{"TYPE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_TYPE"), NULL, NULL},
		{"SAVE", CmdPrompt, _UU("CMD_LogPacketSaveType_Prompt_SAVE"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	
	packet_type = StrToPacketLogType(GetParamStr(o, "TYPE"));
	packet_save_info_type = StrToPacketLogSaveInfoType(GetParamStr(o, "SAVE"));

	if (packet_type == INFINITE || packet_save_info_type == INFINITE)
	{
		c->Write(c, _UU("CMD_LogEnable_Prompt_Error"));
		FreeParamValueList(o);
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	t.LogSetting.PacketLogConfig[packet_type] = packet_save_info_type;

	ret = ScSetHubLog(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCAList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ENUM_CA t;
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNewStandard();

		for (i = 0;i < t.NumCa;i++)
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[64];
			RPC_HUB_ENUM_CA_ITEM *e = &t.Ca[i];

			GetDateStrEx64(tmp, sizeof(tmp), SystemToLocal64(e->Expires), NULL);

			UniToStru(tmp2, e->Key);

			CtInsert(ct, _UU("CMD_CAList_COLUMN_ID"), tmp2);
			CtInsert(ct, _UU("CM_CERT_COLUMN_1"), e->SubjectName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_2"), e->IssuerName);
			CtInsert(ct, _UU("CM_CERT_COLUMN_3"), tmp);

			if (i != (t.NumCa - 1))
			{
				CtInsert(ct, L"---", L"---");
			}
		}

		CtFree(ct, c);
	}

	FreeRpcHubEnumCa(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsCAAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_ADD_CA t;
	X *x;
	PARAM args[] =
	{
		{"[path]", CmdPrompt, _UU("CMD_CAAdd_PROMPT_PATH"), CmdEvalIsFile, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "[path]"));

	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_MSG_LOAD_CERT_FAILED"));
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Cert = x;

	ret = ScAddCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcHubAddCa(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsCADelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_DELETE_CA t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CADelete_PROMPT_ID"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScDeleteCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCAGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_HUB_GET_CA t;
	PARAM args[] =
	{
		{"[id]", CmdPrompt, _UU("CMD_CAGet_PROMPT_ID"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_CAGet_PROMPT_SAVECERT"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.Key = GetParamInt(o, "[id]");

	ret = ScGetCa(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (XToFileW(t.Cert, GetParamUniStr(o, "SAVECERT"), true) == false)
		{
			ret = ERR_INTERNAL_ERROR;
			c->Write(c, _UU("CMD_MSG_SAVE_CERT_FAILED"));
		}
	}

	FreeRpcHubGetCa(&t);

	FreeParamValueList(o);

	return ret;
}

static UINT PsCascadeList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_LINK t;
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		CT *ct = CtNew();
		UINT i;

		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_LINK_COLUMN_5"), false);

		for (i = 0;i < t.NumLink;i++)
		{
			RPC_ENUM_LINK_ITEM *e = &t.Links[i];
			wchar_t tmp1[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			wchar_t tmp3[MAX_SIZE];
			wchar_t tmp4[MAX_SIZE];

			GetDateTimeStrEx64(tmp1, sizeof(tmp1), SystemToLocal64(e->ConnectedTime), NULL);
			StrToUni(tmp2, sizeof(tmp2), e->Hostname);
			StrToUni(tmp3, sizeof(tmp3), e->HubName);

			if (e->Online == false)
			{
				UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_OFFLINE"));
			}
			else
			{
				if (e->Connected)
				{
					UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ONLINE"));
				}
				else
				{
					if (e->LastError != 0)
					{
						UniFormat(tmp4, sizeof(tmp4), _UU("SM_LINK_STATUS_ERROR"), e->LastError, _E(e->LastError));
					}
					else
					{
						UniStrCpy(tmp4, sizeof(tmp4), _UU("SM_LINK_CONNECTING"));
					}
				}
			}

			CtInsert(ct, e->AccountName, tmp4, tmp1, tmp2, tmp3);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumLink(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeCreate(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	Copy(&t.Policy, GetDefaultPolicy(), sizeof(POLICY));

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));
	t.ClientOption->MaxConnection = 8;
	t.ClientOption->UseEncrypt = true;
	t.ClientOption->AdditionalConnectionInterval = 1;

	t.ClientAuth = ZeroMalloc(sizeof(CLIENT_AUTH));
	t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;
	StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username), GetParamStr(o, "USERNAME"));

	Free(host);

	ret = ScCreateLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	char *host = NULL;
	UINT port = 443;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"HUB", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Hub"), CmdEvalSafe, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, 443);

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		Free(host);
		return ret;
	}

	t.ClientOption->Port = port;
	StrCpy(t.ClientOption->Hostname, sizeof(t.ClientOption->Hostname), host);
	StrCpy(t.ClientOption->HubName, sizeof(t.ClientOption->HubName), GetParamStr(o, "HUB"));

	Free(host);

	ret = ScSetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

static wchar_t *GetProxyTypeStr(UINT i)
{
	switch (i)
	{
	case PROXY_DIRECT:

		return _UU("PROTO_DIRECT_TCP");

	case PROXY_HTTP:
		return _UU("PROTO_HTTP_PROXY");

	case PROXY_SOCKS:
		return _UU("PROTO_SOCKS_PROXY");

	default:
		return _UU("PROTO_UNKNOWN");
	}
}

static wchar_t *GetClientAuthTypeStr(UINT i)
{
	char tmp[MAX_SIZE];

	Format(tmp, sizeof(tmp), "PW_TYPE_%u", i);

	return _UU(tmp);
}

static UINT PsCascadeGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName),
		GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];

		CT *ct = CtNewStandard();

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NAME"), t.ClientOption->AccountName);

		StrToUni(tmp, sizeof(tmp), t.ClientOption->Hostname);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HOSTNAME"), tmp);

		UniToStru(tmp, t.ClientOption->Port);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PORT"), tmp);

		StrToUni(tmp, sizeof(tmp), t.ClientOption->HubName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_HUBNAME"), tmp);

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_TYPE"), GetProxyTypeStr(t.ClientOption->ProxyType));

		if (t.ClientOption->ProxyType != PROXY_DIRECT)
		{
			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyName);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_HOSTNAME"), tmp);

			UniToStru(tmp, t.ClientOption->ProxyPort);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_PORT"), tmp);

			StrToUni(tmp, sizeof(tmp), t.ClientOption->ProxyUsername);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_PROXY_USERNAME"), tmp);
		}

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_USE"),
			t.CheckServerCert ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		if (t.ServerCert != NULL)
		{
			GetAllNameFromX(tmp, sizeof(tmp), t.ServerCert);
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_SERVER_CERT_NAME"), tmp);
		}

		if (t.CheckServerCert)
		{
			CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ADD_DEFAULT_CA"),
				t.AddDefaultCA ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));
		}

		StrToUni(tmp, sizeof(tmp), t.ClientOption->DeviceName);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_DEVICE_NAME"), tmp);

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_TYPE"), GetClientAuthTypeStr(t.ClientAuth->AuthType));

		StrToUni(tmp, sizeof(tmp), t.ClientAuth->Username);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_USERNAME"), tmp);

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_CERT)
		{
			if (t.ClientAuth->ClientX != NULL)
			{
				GetAllNameFromX(tmp, sizeof(tmp), t.ClientAuth->ClientX);
				CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_AUTH_CERT_NAME"), tmp);
			}
		}

		UniToStru(tmp, t.ClientOption->MaxConnection);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NUMTCP"), tmp);

		UniToStru(tmp, t.ClientOption->AdditionalConnectionInterval);
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_INTERVAL"), tmp);

		if (t.ClientOption->ConnectionDisconnectSpan != 0)
		{
			UniToStru(tmp, t.ClientOption->ConnectionDisconnectSpan);
		}
		else
		{
			UniStrCpy(tmp, sizeof(tmp), _UU("CMD_MSG_INFINITE"));
		}
		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_TTL"), tmp);

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_TCP_HALF"),
			t.ClientOption->HalfConnection ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_ENCRYPT"),
			t.ClientOption->UseEncrypt ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_COMPRESS"),
			t.ClientOption->UseCompress ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_BRIDGE_ROUTER"),
			t.ClientOption->RequireBridgeRoutingMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_MONITOR"),
			t.ClientOption->RequireMonitorMode ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_NO_TRACKING"),
			t.ClientOption->NoRoutingTracking ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtInsert(ct, _UU("CMD_ACCOUNT_COLUMN_QOS_DISABLE"),
			t.ClientOption->DisableQoS ? _UU("CMD_MSG_ENABLE") : _UU("CMD_MSG_DISABLE"));

		CtFree(ct, c);

		c->Write(c, L"");
		c->Write(c, _UU("CMD_CascadeGet_Policy"));
		PrintPolicy(c, &t.Policy, true);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	UniStrCpy(t.AccountName, sizeof(t.AccountName), GetParamUniStr(o, "[name]"));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScDeleteLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeUsernameSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"USERNAME", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Username"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		StrCpy(t.ClientAuth->Username, sizeof(t.ClientAuth->Username),
			GetParamStr(o, "USERNAME"));

		if (t.ClientAuth->AuthType == CLIENT_AUTHTYPE_PASSWORD)
		{
			c->Write(c, _UU("CMD_CascadeUsername_Notice"));
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeAnonymousSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_ANONYMOUS;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadePasswordSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"PASSWORD", CmdPromptChoosePassword, NULL, NULL, NULL},
		{"TYPE", CmdPrompt, _UU("CMD_CascadePasswordSet_Prompt_Type"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *typestr = GetParamStr(o, "TYPE");

		if (StartWith("standard", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PASSWORD;
			HashPassword(t.ClientAuth->HashedPassword, t.ClientAuth->Username,
				GetParamStr(o, "PASSWORD"));
		}
		else if (StartWith("ntdomain", typestr))
		{
			t.ClientAuth->AuthType = CLIENT_AUTHTYPE_PLAIN_PASSWORD;

			StrCpy(t.ClientAuth->PlainPassword, sizeof(t.ClientAuth->PlainPassword),
				GetParamStr(o, "PASSWORD"));
		}
		else
		{
			c->Write(c, _UU("CMD_CascadePasswordSet_Type_Invalid"));
			FreeRpcCreateLink(&t);
			ret = ERR_INVALID_PARAMETER;
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	K *k;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
		{"LOADKEY", CmdPrompt, _UU("CMD_LOADKEYPATH"), CmdEvalIsFile, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (CmdLoadCertChainAndKey(c, &x, &k, NULL, GetParamUniStr(o, "LOADCERT"), GetParamUniStr(o, "LOADKEY")) == false)
	{
		FreeParamValueList(o);
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		FreeX(x);
		FreeK(k);
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientAuth->AuthType = CLIENT_AUTHTYPE_CERT;
		if (t.ClientAuth->ClientX != NULL)
		{
			FreeX(t.ClientAuth->ClientX);
		}
		if (t.ClientAuth->ClientK != NULL)
		{
			FreeK(t.ClientAuth->ClientK);
		}

		t.ClientAuth->ClientX = x;
		t.ClientAuth->ClientK = k;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ClientAuth->AuthType != CLIENT_AUTHTYPE_CERT)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Not_Auth_Cert"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (t.ClientAuth->ClientX == NULL)
		{
			c->Write(c, _UU("CMD_CascadeCertSet_Cert_Not_Exists"));
			ret = ERR_INTERNAL_ERROR;
		}
		else if (XToFileW(t.ClientAuth->ClientX, GetParamUniStr(o, "SAVECERT"), true) == false)
		{
			ret = CmdSaveFailed(c, "CMD_SAVECERT_FAILED");
		}
		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

static UINT PsCascadeEncryptEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->UseEncrypt = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeEncryptDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->UseEncrypt = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeCompressEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->UseCompress = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeCompressDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->UseCompress = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeHttpHeaderAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"DATA", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Data"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		HTTP_HEADER *header = NULL;
		char *name = GetParamStr(o, "NAME");

		Trim(name);

		header = NewHttpHeader("", "", "");

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");
		for (i = 0; i < tokens->NumTokens; i++)
		{
			AddHttpValueStr(header, tokens->Token[i]);
		}
		FreeToken(tokens);

		if (GetHttpValue(header, name) == NULL)
		{
			char s[HTTP_CUSTOM_HEADER_MAX_SIZE];
			Format(s, sizeof(s), "%s: %s\r\n", name, GetParamStr(o, "DATA"));
			EnSafeHttpHeaderValueStr(s, ' ');

			if ((StrLen(s) + StrLen(t.ClientOption->CustomHttpHeader)) < sizeof(t.ClientOption->CustomHttpHeader)) {
				StrCat(t.ClientOption->CustomHttpHeader, sizeof(t.ClientOption->CustomHttpHeader), s);
				ret = ScSetLink(ps->Rpc, &t);
			}
			else
			{
				ret = ERR_TOO_MANT_ITEMS;
			}
		}
		else
		{
			ret = ERR_OBJECT_EXISTS;
		}

		FreeHttpHeader(header);
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return ret;
}

// Whether line is a header named name: the text before its first colon, trimmed, is name in any case
static bool IsHttpHeaderLineOf(char *line, char *name)
{
	char *tmp = CopyStr(line);
	UINT pos = SearchStr(tmp, ":", 0);
	bool ret;

	if (pos != INFINITE)
	{
		tmp[pos] = 0;
	}

	Trim(tmp);

	ret = (StrCmpi(tmp, name) == 0);

	Free(tmp);

	return ret;
}

static UINT PsCascadeHttpHeaderDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadeHttpHeader_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	if (ret == ERR_NO_ERROR)
	{
		UINT i = 0;
		TOKEN_LIST *tokens = NULL;
		char *headers = t.ClientOption->CustomHttpHeader;
		UINT headers_size = sizeof(t.ClientOption->CustomHttpHeader);
		char *name = GetParamStr(o, "NAME");

		Trim(name);

		// Parse the stored headers first, then rebuild the field from the ones kept
		tokens = ParseToken(headers, "\r\n");

		Zero(headers, headers_size);

		for (i = 0; i < tokens->NumTokens; i++)
		{
			if (IsHttpHeaderLineOf(tokens->Token[i], name) == false)
			{
				StrCat(headers, headers_size, tokens->Token[i]);
				StrCat(headers, headers_size, "\r\n");
			}
		}

		FreeToken(tokens);

		ret = ScSetLink(ps->Rpc, &t);
	}

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	FreeParamValueList(o);

	return ret;
}

static UINT PsCascadeHttpHeaderGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = ERR_NO_ERROR;
	RPC_CREATE_LINK t;

	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));
	ret = ScGetLink(ps->Rpc, &t);

	FreeParamValueList(o);

	if (ret == ERR_NO_ERROR)
	{
		wchar_t unistr[HTTP_CUSTOM_HEADER_MAX_SIZE];
		TOKEN_LIST *tokens = NULL;
		UINT i = 0;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);

		tokens = ParseToken(t.ClientOption->CustomHttpHeader, "\r\n");

		for (i = 0; i < tokens->NumTokens; i++)
		{
			StrToUni(unistr, sizeof(unistr), tokens->Token[i]);
			CtInsert(ct, unistr);
		}

		FreeToken(tokens);

		CtFreeEx(ct, c, false);
	}
	else
	{
		CmdPrintError(c, ret);
	}

	FreeRpcCreateLink(&t);

	return ret;
}

static UINT PsCascadeProxyNone(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->ProxyType = PROXY_DIRECT;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

// Set the proxy of a cascade connection: the shared body of CascadeProxyHttp, CascadeProxySocks and CascadeProxySocks5
static UINT PsCascadeProxySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param, UINT type, UINT default_port)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SERVER", CmdPrompt, _UU("CMD_CascadeProxyHttp_Prompt_Server"), CmdEvalHostAndPort, NULL},
		{"USERNAME", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		char *host;
		UINT port;

		if (ParseHostPort(GetParamStr(o, "SERVER"), &host, &port, default_port))
		{
			t.ClientOption->ProxyType = type;
			StrCpy(t.ClientOption->ProxyName, sizeof(t.ClientOption->ProxyName), host);
			t.ClientOption->ProxyPort = port;
			StrCpy(t.ClientOption->ProxyUsername, sizeof(t.ClientOption->ProxyUsername), GetParamStr(o, "USERNAME"));
			StrCpy(t.ClientOption->ProxyPassword, sizeof(t.ClientOption->ProxyPassword), GetParamStr(o, "PASSWORD"));
			Free(host);
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeProxyHttp(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	return PsCascadeProxySet(c, cmd_name, str, param, PROXY_HTTP, 8080);
}

static UINT PsCascadeProxySocks(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	return PsCascadeProxySet(c, cmd_name, str, param, PROXY_SOCKS, 1080);
}

static UINT PsCascadeProxySocks5(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	return PsCascadeProxySet(c, cmd_name, str, param, PROXY_SOCKS5, 1080);
}

static UINT PsCascadeServerCertEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.CheckServerCert = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeServerCertDisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.CheckServerCert = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeDefaultCAEnable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.AddDefaultCA = true;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeDefaultCADisable(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.AddDefaultCA = false;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeServerCertSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	X *x;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"LOADCERT", CmdPrompt, _UU("CMD_LOADCERTPATH"), CmdEvalIsFile, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	x = FileToXW(GetParamUniStr(o, "LOADCERT"));
	if (x == NULL)
	{
		FreeParamValueList(o);
		c->Write(c, _UU("CMD_LOADCERT_FAILED"));
		return ERR_INTERNAL_ERROR;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		FreeX(x);
		return ret;
	}
	else
	{
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = x;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeServerCertDelete(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ServerCert != NULL)
		{
			FreeX(t.ServerCert);
		}
		t.ServerCert = NULL;

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static UINT PsCascadeServerCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), CmdEvalNotEmpty, NULL},
	};
	
	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.ServerCert == NULL)
		{
			c->Write(c, _UU("CMD_CERT_NOT_EXISTS"));
			ret = ERR_INTERNAL_ERROR;
		}
		else
		{
			if (XToFileW(t.ServerCert, GetParamUniStr(o, "SAVECERT"), true) == false)
			{
				ret = CmdSaveFailed(c, "CMD_SAVECERT_FAILED");
			}
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return ret;
}

static UINT PsCascadeDetailSet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	CMD_EVAL_MIN_MAX mm_maxtcp =
	{
		"CMD_CascadeDetailSet_Eval_MaxTcp", 1, 32
	};
	CMD_EVAL_MIN_MAX mm_interval =
	{
		"CMD_CascadeDetailSet_Eval_Interval", 1, 4294967295UL
	};
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"MAXTCP", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_MaxTcp"), CmdEvalMinMax, &mm_maxtcp},
		{"INTERVAL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_Interval"), CmdEvalMinMax, &mm_interval},
		{"TTL", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_TTL"), NULL, NULL},
		{"HALF", CmdPrompt, _UU("CMD_CascadeDetailSet_Prompt_HALF"), NULL, NULL},
		{"NOQOS", CmdPrompt, _UU("CMD_AccountDetailSet_Prompt_NOQOS"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		t.ClientOption->MaxConnection = GetParamInt(o, "MAXTCP");
		t.ClientOption->AdditionalConnectionInterval = GetParamInt(o, "INTERVAL");
		t.ClientOption->ConnectionDisconnectSpan = GetParamInt(o, "TTL");
		t.ClientOption->HalfConnection = GetParamYes(o, "HALF");
		t.ClientOption->DisableQoS = GetParamYes(o, "NOQOS");

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static void PrintPolicy(CONSOLE *c, POLICY *pol, bool cascade_mode)
{
	UINT i;
	CT *ct;
	PACK *p;
	if (c == NULL || pol == NULL)
	{
		return;
	}

	ct = CtNew();
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);
	CtInsertColumn(ct, _UU("CMD_PolicyList_Column_3"), false);

	p = NewPack();
	OutRpcPolicy(p, pol);

	for (i = 0; i < PolicyNum();i++)
	{
		char name[64];
		wchar_t *tmp;

		if (cascade_mode == false || PolicyIsSupportedForCascade(i))
		{
			wchar_t value_str[256];
			UINT value;
			char tmp2[256];

			Format(tmp2, sizeof(tmp2), "policy:%s", PolicyIdToStr(i));
			value = PackGetInt(p, tmp2);

			tmp = CopyStrToUni(PolicyIdToStr(i));

			FormatPolicyValue(value_str, sizeof(value_str),
				i, value);

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name), value_str);

			Free(tmp);
		}
	}

	FreePack(p);

	CtFree(ct, c);
}

static void PrintPolicyList(CONSOLE *c, char *name)
{
	UINT id;
	if (c == NULL)
	{
		return;
	}
	if (IsEmptyStr(name))
	{
		name = NULL;
	}

	if (name != NULL)
	{
		id = PolicyStrToId(name);
		if (id == INFINITE)
		{
			c->Write(c, _UU("CMD_PolicyList_Invalid_Name"));
		}
		else
		{
			wchar_t tmp[MAX_SIZE];
			wchar_t tmp2[MAX_SIZE];
			char name1[64], name2[64];
			wchar_t *title, *descript;
			wchar_t policy_name[MAX_SIZE];

			Format(name1, sizeof(name1), "POL_%u", id);
			Format(name2, sizeof(name2), "POL_EX_%u", id);

			title = _UU(name1);
			descript = _UU(name2);

			StrToUni(policy_name, sizeof(policy_name), PolicyIdToStr(id));

			c->Write(c, _UU("CMD_PolicyList_Help_1"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", policy_name);
			c->Write(c, tmp2);
			c->Write(c, L"");

			c->Write(c, _UU("CMD_PolicyList_Help_2"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", title);
			c->Write(c, tmp2);
			c->Write(c, L"");

			GetPolicyValueRangeStr(tmp, sizeof(tmp), id);
			c->Write(c, _UU("CMD_PolicyList_Help_3"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			FormatPolicyValue(tmp, sizeof(tmp), id, GetPolicyItem(id)->DefaultValue);
			c->Write(c, _UU("CMD_PolicyList_Help_4"));
			UniFormat(tmp2, sizeof(tmp2), L" %s", tmp);
			c->Write(c, tmp2);
			c->Write(c, L"");

			c->Write(c, _UU("CMD_PolicyList_Help_5"));
			c->Write(c, descript);
			c->Write(c, L"");
		}
	}
	else
	{
		UINT i;
		CT *ct = CtNew();
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_1"), false);
		CtInsertColumn(ct, _UU("CMD_PolicyList_Column_2"), false);

		for (i = 0; i < PolicyNum();i++)
		{
			char name[64];
			wchar_t *tmp;

			tmp = CopyStrToUni(PolicyIdToStr(i));

			Format(name, sizeof(name), "POL_%u", i);
			CtInsert(ct, tmp, _UU(name));

			Free(tmp);
		}

		CtFree(ct, c);
	}
}

static bool EditPolicy(CONSOLE *c, POLICY *pol, char *name, char *value, bool cascade_mode)
{
	PACK *p;
	ELEMENT *e;
	POLICY_ITEM *item;
	UINT id;
	wchar_t tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	char pack_name[128];
	if (c == NULL || pol == NULL || name == NULL || value == NULL)
	{
		return false;
	}

	p = NewPack();

	OutRpcPolicy(p, pol);

	Format(pack_name, sizeof(pack_name), "policy:%s", PolicyIdToStr(PolicyStrToId(name)));

	if ((e = GetElement(p, pack_name, VALUE_INT)) == NULL || (id = PolicyStrToId(name)) == INFINITE)
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	if (cascade_mode && (PolicyIsSupportedForCascade(id) == false))
	{
		UniFormat(tmp, sizeof(tmp), _UU("CMD_CascadePolicySet_Invalid_Name_For_Cascade"), name);
		c->Write(c, tmp);
		FreePack(p);
		return false;
	}

	item = GetPolicyItem(id);

	if (item->TypeInt == false)
	{
		e->values[0]->IntValue = (
			StartWith(value, "y") || StartWith(value, "t") ||
			ToInt(value) != 0) ? 1 : 0;
	}
	else
	{
		UINT n = ToInt(value);
		bool b = true;

		GetPolicyValueRangeStr(tmp, sizeof(tmp), id);

		if (item->AllowZero == false)
		{
			if (n == 0)
			{
				b = false;
			}
		}

		if (n != 0 && (n < item->MinValue || n > item->MaxValue))
		{
			b = false;
		}

		if (b == false)
		{
			UniFormat(tmp2, sizeof(tmp2), _UU("CMD_CascadePolicySet_Invalid_Range"), PolicyIdToStr(id), tmp);
			c->Write(c, tmp2);
			FreePack(p);
			return false;
		}

		e->values[0]->IntValue = n;
	}

	Zero(pol, sizeof(POLICY));

	InRpcPolicy(pol, p);

	FreePack(p);

	return true;
}

static UINT PsPolicyList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PARAM args[] =
	{
		{"[name]", NULL, NULL, NULL, NULL}
	};

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	PrintPolicyList(c, GetParamStr(o, "[name]"));

	FreeParamValueList(o);

	return ERR_NO_ERROR;
}

static UINT PsCascadePolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_CREATE_LINK t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_CascadeCreate_Prompt_Name"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	t.ClientOption = ZeroMalloc(sizeof(CLIENT_OPTION));
	UniStrCpy(t.ClientOption->AccountName, sizeof(t.ClientOption->AccountName), GetParamUniStr(o, "[name]"));

	ret = ScGetLink(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (EditPolicy(c, &t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), true) == false)
		{
			FreeRpcCreateLink(&t);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}

		ret = ScSetLink(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}

		FreeRpcCreateLink(&t);
	}

	FreeParamValueList(o);

	return 0;
}

static bool StrToPassOrDiscard(char *str)
{
	if (str == NULL)
	{
		return false;
	}

	if (ToInt(str) != 0)
	{
		return true;
	}

	if (StartWith(str, "p") || StartWith(str, "y") || StartWith(str, "t"))
	{
		return true;
	}

	return false;
}

static UINT StrToProtocol(char *str)
{
	if (IsEmptyStr(str))
	{
		return 0;
	}

	if (StartWith("ip", str))
	{
		return 0;
	}
	else if (StartWith("tcp", str))
	{
		return IP_PROTO_TCP;
	}
	else if (StartWith("udp", str))
	{
		return IP_PROTO_UDP;
	}
	else if (StartWith("icmpv4", str))
	{
		return IP_PROTO_ICMPV4;
	}
	else if (StartWith("icmpv6", str))
	{
		return IP_PROTO_ICMPV6;
	}

	if (ToInt(str) == 0)
	{
		if (StrCmpi(str, "0") == 0)
		{
			return 0;
		}
		else
		{
			return INFINITE;
		}
	}

	if (ToInt(str) >= 256)
	{
		return INFINITE;
	}

	return ToInt(str);
}

static bool CmdEvalProtocol(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	if (c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if (StrToProtocol(tmp) == INFINITE)
	{
		c->Write(c, _UU("CMD_PROTOCOL_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Value of str when it is only decimal digits (no sign, no space) and at most max
static bool StrToUIntStrict(char *str, UINT max, UINT *value)
{
	UINT v = 0;
	UINT i;

	if (str == NULL || str[0] == 0)
	{
		return false;
	}

	for (i = 0;str[i] != 0;i++)
	{
		UINT d;

		if (str[i] < '0' || str[i] > '9')
		{
			return false;
		}

		d = (UINT)(str[i] - '0');

		// v * 10 + d must not pass max (nor wrap)
		if (d > max || v > (max - d) / 10)
		{
			return false;
		}

		v = v * 10 + d;
	}

	*value = v;

	return true;
}

// Port range of an access list rule: empty text is every port (0-0); otherwise one port or two joined by a
// hyphen, spaces around each allowed, each 1 to 65535 and the first not above the second. Anything else (a
// service name, a list, a sign, a third number) is refused instead of being stored as another range.
static bool ParsePortRange(char *str, UINT *start, UINT *end)
{
	UINT a = 0, b = 0;
	char *tmp;
	UINT pos;
	bool ok;

	if (str == NULL)
	{
		return false;
	}

	if (IsEmptyStr(str) == false)
	{
		tmp = CopyStr(str);

		pos = SearchStr(tmp, "-", 0);
		if (pos == INFINITE)
		{
			Trim(tmp);
			ok = StrToUIntStrict(tmp, 65535, &a);
			b = a;
		}
		else
		{
			char *second = tmp + pos + 1;

			tmp[pos] = 0;
			Trim(tmp);
			Trim(second);
			ok = StrToUIntStrict(tmp, 65535, &a) && StrToUIntStrict(second, 65535, &b);
		}

		Free(tmp);

		if (ok == false || a == 0 || a > b)
		{
			return false;
		}
	}

	if (start != NULL)
	{
		*start = a;
	}
	if (end != NULL)
	{
		*end = b;
	}

	return true;
}

static bool CmdEvalPortRange(CONSOLE *c, wchar_t *str, void *param)
{
	char *tmp;
	bool ok;
	if (c == NULL || str == NULL)
	{
		return false;
	}

	// The whole text: the AccessAdd commands parse it again from the parameter
	tmp = CopyUniToStr(str);
	ok = ParsePortRange(tmp, NULL, NULL);
	Free(tmp);

	if (ok == false)
	{
		c->Write(c, _UU("CMD_PORT_RANGE_EVAL_FAILED"));
		return false;
	}

	return true;
}

static bool ParseMacAddressAndMask(char *src, bool *check_mac, UCHAR *mac_bin, UCHAR *mask_bin)
{
	TOKEN_LIST *t;
	char *macstr, *maskstr;
	UCHAR mac[6], mask[6];
	bool ok = false;

	if (src == NULL)
	{
		return false;
	}

	if(check_mac != NULL && mac_bin != NULL && mask_bin != NULL)
	{
		ok = true;
	}
	if(IsEmptyStr(src) != false)
	{
		if(ok != false)
		{
			*check_mac = false;
			Zero(mac_bin, 6);
			Zero(mask_bin, 6);
		}
		return true;
	}

	t = ParseToken(src, "/");
	if(t->NumTokens != 2)
	{
		FreeToken(t);
		return false;
	}

	macstr = t->Token[0];
	maskstr = t->Token[1];

	Trim(macstr);
	Trim(maskstr);

	if(StrToMac(mac, macstr) == false || StrToMac(mask, maskstr) == false)
	{
		FreeToken(t);
		return false;
	}
	else
	{
		if(ok != false)
		{
			Copy(mac_bin, mac, 6);
			Copy(mask_bin, mask, 6);
			*check_mac = true;
		}
	}
	FreeToken(t);

	return true;
}

static bool CmdEvalMacAddressAndMask(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);


	if(ParseMacAddressAndMask(tmp, NULL, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_MAC_ADDRESS_AND_MASK_EVAL_FAILED"));
		return false;
	}

	return true;
}

// Whether input abbreviates word: a non-empty prefix of it in any case ("est" abbreviates "Established")
static bool IsAbbreviationOf(char *input, char *word)
{
	return StartWith(word, input);
}

static bool ParseTcpState(char *src, bool *check_tcp_state, bool *established)
{
	bool ok = false;
	if(src == NULL)
	{
		return false;
	}

	if(check_tcp_state != NULL && established != NULL)
	{
		ok = true;
	}

	if (IsEmptyStr(src) == false)
	{
		if (IsAbbreviationOf(src, "Established"))
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = true;
			}
		}
		else if (IsAbbreviationOf(src, "Unestablished"))
		{
			if(ok != false)
			{
				*check_tcp_state = true;
				*established = false;
			}
		}
		else
		{
			return false;
		}
	}
	else
	{
		if(ok != false)
		{
			*check_tcp_state = false;
			*established = false;
		}
	}

	return true;
}
static bool CmdEvalTcpState(CONSOLE *c, wchar_t *str, void *param)
{
	char tmp[64];
	if(c == NULL || str == NULL)
	{
		return false;
	}

	UniToStr(tmp, sizeof(tmp), str);

	if(ParseTcpState(tmp, NULL, NULL) == false)
	{
		c->Write(c, _UU("CMD_TCP_CONNECTION_STATE_EVAL_FAILED"));
		return false;
	}

	return true;
}

UINT PsAccessAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessAddEx(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCIP"), CmdEvalIpAndMask4, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTIP"), CmdEvalIpAndMask4, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);
	ParseIpAndMask4(GetParamStr(o, "SRCIP"), &a->SrcIpAddress, &a->SrcSubnetMask);
	ParseIpAndMask4(GetParamStr(o, "DESTIP"), &a->DestIpAddress, &a->DestSubnetMask);
	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);

	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}

UINT PsAccessAddEx6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ADD_ACCESS t;
	ACCESS *a;
	IP ip, mask;
	CMD_EVAL_MIN_MAX minmax =
	{
		"CMD_AccessAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	CMD_EVAL_MIN_MAX minmax_delay =
	{
		"CMD_AccessAddEx6_Eval_DELAY", 0, HUB_ACCESSLIST_DELAY_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_jitter =
	{
		"CMD_AccessAddEx6_Eval_JITTER", 0, HUB_ACCESSLIST_JITTER_MAX,
	};
	CMD_EVAL_MIN_MAX minmax_loss =
	{
		"CMD_AccessAddEx6_Eval_LOSS", 0, HUB_ACCESSLIST_LOSS_MAX,
	};
	PARAM args[] =
	{
		{"[pass|discard]", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TYPE"), CmdEvalNotEmpty, NULL},
		{"MEMO", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_MEMO"), NULL, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &minmax},
		{"SRCUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCUSERNAME"), NULL, NULL},
		{"DESTUSERNAME", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTUSERNAME"), NULL, NULL},
		{"SRCMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCMAC"), CmdEvalMacAddressAndMask, NULL},
		{"DESTMAC", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTMAC"), CmdEvalMacAddressAndMask, NULL},
		{"SRCIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCIP"), CmdEvalIpAndMask6, NULL},
		{"DESTIP", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTIP"), CmdEvalIpAndMask6, NULL},
		{"PROTOCOL", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_PROTOCOL"), CmdEvalProtocol, NULL},
		{"SRCPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_SRCPORT"), CmdEvalPortRange, NULL},
		{"DESTPORT", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_DESTPORT"), CmdEvalPortRange, NULL},
		{"TCPSTATE", CmdPrompt, _UU("CMD_AccessAdd6_Prompt_TCPSTATE"), CmdEvalTcpState, NULL},
		{"DELAY", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_DELAY"), CmdEvalMinMax, &minmax_delay},
		{"JITTER", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_JITTER"), CmdEvalMinMax, &minmax_jitter},
		{"LOSS", CmdPrompt, _UU("CMD_AccessAddEx6_Prompt_LOSS"), CmdEvalMinMax, &minmax_loss},
		{"REDIRECTURL", NULL, NULL, NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	a = &t.Access;

	a->IsIPv6 = true;

	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	UniStrCpy(a->Note, sizeof(a->Note), GetParamUniStr(o, "MEMO"));
	a->Active = true;
	a->Priority = GetParamInt(o, "PRIORITY");
	a->Discard = StrToPassOrDiscard(GetParamStr(o, "[pass|discard]")) ? false : true;
	StrCpy(a->SrcUsername, sizeof(a->SrcUsername), GetParamStr(o, "SRCUSERNAME"));
	StrCpy(a->DestUsername, sizeof(a->DestUsername), GetParamStr(o, "DESTUSERNAME"));
	ParseMacAddressAndMask(GetParamStr(o, "SRCMAC"), &a->CheckSrcMac, a->SrcMacAddress, a->SrcMacMask);
	ParseMacAddressAndMask(GetParamStr(o, "DESTMAC"), &a->CheckDstMac, a->DstMacAddress, a->DstMacMask);

	Zero(&ip, sizeof(ip));
	Zero(&mask, sizeof(mask));

	ParseIpAndMask6(GetParamStr(o, "SRCIP"), &ip, &mask);
	IPToIPv6Addr(&a->SrcIpAddress6, &ip);
	IPToIPv6Addr(&a->SrcSubnetMask6, &mask);

	ParseIpAndMask6(GetParamStr(o, "DESTIP"), &ip, &mask);
	IPToIPv6Addr(&a->DestIpAddress6, &ip);
	IPToIPv6Addr(&a->DestSubnetMask6, &mask);

	a->Protocol = StrToProtocol(GetParamStr(o, "PROTOCOL"));
	ParsePortRange(GetParamStr(o, "SRCPORT"), &a->SrcPortStart, &a->SrcPortEnd);
	ParsePortRange(GetParamStr(o, "DESTPORT"), &a->DestPortStart, &a->DestPortEnd);
	ParseTcpState(GetParamStr(o, "TCPSTATE"), &a->CheckTcpState, &a->Established);
	a->Delay = GetParamInt(o, "DELAY");
	a->Jitter = GetParamInt(o, "JITTER");
	a->Loss = GetParamInt(o, "LOSS");
	StrCpy(a->RedirectUrl, sizeof(a->RedirectUrl), GetParamStr(o, "REDIRECTURL"));

	ret = ScAddAccess(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	FreeParamValueList(o);

	return 0;
}


UINT PsUserList(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_ENUM_USER t;

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, NULL, 0);
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScEnumUser(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		UINT i;
		CT *ct = CtNew();

		CtInsertColumn(ct, _UU("SM_USER_COLUMN_1"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_2"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_3"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_4"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_USER_COLUMN_7"), false);
		CtInsertColumn(ct, _UU("SM_LICENSE_COLUMN_5"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_6"), false);
		CtInsertColumn(ct, _UU("SM_SESS_COLUMN_7"), false);

		for (i = 0;i < t.NumUser;i++)
		{
			RPC_ENUM_USER_ITEM *e = &t.Users[i];
			wchar_t name[MAX_SIZE];
			wchar_t group[MAX_SIZE];
			wchar_t num[MAX_SIZE];
			wchar_t time[MAX_SIZE];
			wchar_t exp[MAX_SIZE];
			wchar_t num1[64], num2[64];

			StrToUni(name, sizeof(name), e->Name);

			if (StrLen(e->GroupName) != 0)
			{
				StrToUni(group, sizeof(group), e->GroupName);
			}
			else
			{
				UniStrCpy(group, sizeof(group), _UU("SM_NO_GROUP"));
			}

			UniToStru(num, e->NumLogin);

			GetDateTimeStrEx64(time, sizeof(time), SystemToLocal64(e->LastLoginTime), NULL);

			if (e->IsExpiresFilled == false)
			{
				UniStrCpy(exp, sizeof(exp), _UU("CM_ST_NONE"));
			}
			else
			{
				if (e->Expires == 0)
				{
					UniStrCpy(exp, sizeof(exp), _UU("SM_LICENSE_NO_EXPIRES"));
				}
				else
				{
					GetDateTimeStrEx64(exp, sizeof(exp), SystemToLocal64(e->Expires), NULL);
				}
			}

			if (e->IsTrafficFilled == false)
			{
				UniStrCpy(num1, sizeof(num1), _UU("CM_ST_NONE"));
				UniStrCpy(num2, sizeof(num2), _UU("CM_ST_NONE"));
			}
			else
			{
				UniToStr3(num1, sizeof(num1), TrafficTotalBytes(&e->Traffic));

				UniToStr3(num2, sizeof(num2), TrafficTotalPackets(&e->Traffic));
			}

			CtInsert(ct,
				name, e->Realname, group, e->Note, GetAuthTypeStr(e->AuthType),
				num, time, exp, num1, num2);
		}

		CtFreeEx(ct, c, true);
	}

	FreeRpcEnumUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		CT *ct;

		ct = CtNewStandard();

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_UserGet_Column_Name"), tmp);

		CtInsert(ct, _UU("CMD_UserGet_Column_RealName"), t.Realname);

		CtInsert(ct, _UU("CMD_UserGet_Column_Note"), t.Note);

		if (IsEmptyStr(t.GroupName) == false)
		{
			StrToUni(tmp, sizeof(tmp), t.GroupName);
			CtInsert(ct, _UU("CMD_UserGet_Column_Group"), tmp);
		}

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.ExpireTime), NULL);
		CtInsert(ct, _UU("CMD_UserGet_Column_Expires"), tmp);

		CtInsert(ct, _UU("CMD_UserGet_Column_AuthType"), GetAuthTypeStr(t.AuthType));

		switch (t.AuthType)
		{
		case AUTHTYPE_USERCERT:
			if (t.AuthData != NULL)
			{
				AUTHUSERCERT *auc = (AUTHUSERCERT *)t.AuthData;

				if (auc != NULL && auc->UserX != NULL)
				{
					GetAllNameFromX(tmp, sizeof(tmp), auc->UserX);
					CtInsert(ct, _UU("CMD_UserGet_Column_UserCert"), tmp);
				}
			}
			break;

		case AUTHTYPE_ROOTCERT:
			if (t.AuthData != NULL)
			{
				AUTHROOTCERT *arc = (AUTHROOTCERT *)t.AuthData;

				if (UniIsEmptyStr(arc->CommonName) == false)
				{
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_CN"), arc->CommonName);
				}

				if (arc->Serial != NULL && arc->Serial->size >= 1)
				{
					char tmp2[MAX_SIZE];

					BinToStrEx(tmp2, sizeof(tmp2), arc->Serial->data, arc->Serial->size);
					StrToUni(tmp, sizeof(tmp), tmp2);
					CtInsert(ct, _UU("CMD_UserGet_Column_RootCert_SERIAL"), tmp);
				}
			}
			break;

		case AUTHTYPE_NT:
			if (t.AuthData != NULL)
			{
				AUTHNT *an = (AUTHNT *)t.AuthData;

				if (UniIsEmptyStr(an->NtUsername) == false)
				{
					CtInsert(ct, _UU("CMD_UserGet_Column_NtUsername"), an->NtUsername);
				}
			}
			break;
		}

		CtInsert(ct, L"---", L"---");

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.CreatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_CREATE"), tmp);

		GetDateTimeStrEx64(tmp, sizeof(tmp), SystemToLocal64(t.UpdatedTime), NULL);
		CtInsert(ct, _UU("SM_USERINFO_UPDATE"), tmp);

		CmdInsertTrafficInfo(ct, &t.Traffic);

		UniToStru(tmp, t.NumLogin);
		CtInsert(ct, _UU("SM_USERINFO_NUMLOGIN"), tmp);


		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_UserGet_Policy"));
			PrintPolicy(c, t.Policy, false);
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsUserCertGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	AUTHUSERCERT *a;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"SAVECERT", CmdPrompt, _UU("CMD_SAVECERTPATH"), NULL, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	a = (AUTHUSERCERT *)t.AuthData;

	if (t.AuthType != AUTHTYPE_USERCERT || a == NULL || a->UserX == NULL)
	{
		ret = ERR_INVALID_PARAMETER;

		c->Write(c, _UU("CMD_UserCertGet_Not_Cert"));
	}
	else
	{
		if (XToFileW(a->UserX, GetParamUniStr(o, "SAVECERT"), true) == false)
		{
			ret = CmdSaveFailed(c, "CMD_SAVECERT_FAILED");
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

UINT PsUserPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_USER t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_UserCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetUser(ps->Rpc, &t);
	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}

	if (t.Policy == NULL)
	{
		t.Policy = ClonePolicy(GetDefaultPolicy());
	}

	if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
	{
		ret = ERR_INVALID_PARAMETER;
	}
	else
	{
		ret = ScSetUser(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetUser(&t);

	FreeParamValueList(o);

	return ret;
}

UINT PsGroupGet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		wchar_t tmp[MAX_SIZE];
		char groupname[MAX_USERNAME_LEN + 1];
		CT *ct = CtNewStandard();

		StrCpy(groupname, sizeof(groupname), t.Name);

		StrToUni(tmp, sizeof(tmp), t.Name);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NAME"), tmp);
		CtInsert(ct, _UU("CMD_GroupGet_Column_REALNAME"), t.Realname);
		CtInsert(ct, _UU("CMD_GroupGet_Column_NOTE"), t.Note);

		CtFree(ct, c);

		if (t.Policy != NULL)
		{
			c->Write(c, L"");
			c->Write(c, _UU("CMD_GroupGet_Column_POLICY"));

			PrintPolicy(c, t.Policy, false);
		}

		{
			RPC_ENUM_USER t;
			bool b = false;

			Zero(&t, sizeof(t));

			StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

			if (ScEnumUser(ps->Rpc, &t) == ERR_NO_ERROR)
			{
				UINT i;

				for (i = 0;i < t.NumUser;i++)
				{
					RPC_ENUM_USER_ITEM *u = &t.Users[i];

					if (StrCmpi(u->GroupName, groupname) == 0)
					{
						if (b == false)
						{
							b = true;
							c->Write(c, L"");
							c->Write(c, _UU("CMD_GroupGet_Column_MEMBERS"));
						}

						UniFormat(tmp, sizeof(tmp), L" %S", u->Name);
						c->Write(c, tmp);
					}
				}
				FreeRpcEnumUser(&t);

				if (b)
				{
					c->Write(c, L"");
				}
			}
		}

	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsGroupPolicySet(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_SET_GROUP t;
	PARAM args[] =
	{
		{"[name]", CmdPrompt, _UU("CMD_GroupCreate_Prompt_NAME"), CmdEvalNotEmpty, NULL},
		{"NAME", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLNAME"), CmdEvalNotEmpty, NULL},
		{"VALUE", CmdPrompt, _UU("CMD_CascadePolicySet_PROMPT_POLVALUE"), CmdEvalNotEmpty, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);
	StrCpy(t.Name, sizeof(t.Name), GetParamStr(o, "[name]"));

	ret = ScGetGroup(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		if (t.Policy == NULL)
		{
			t.Policy = ClonePolicy(GetDefaultPolicy());
		}

		if (EditPolicy(c, t.Policy, GetParamStr(o, "NAME"), GetParamStr(o, "VALUE"), false) == false)
		{
			FreeRpcSetGroup(&t);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}

		ret = ScSetGroup(ps->Rpc, &t);

		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcSetGroup(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAcAdd(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd_Prompt_IP"), CmdEvalIpAndMask4, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		UINT u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask4(GetParamStr(o, "IP"), &u_ip, &u_mask);
		UINTToIP(&ac->IpAddress, u_ip);

		if (u_mask == 0xffffffff)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			UINTToIP(&ac->SubnetMask, u_mask);
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

UINT PsAcAdd6(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	PS *ps = (PS *)param;
	UINT ret = 0;
	RPC_AC_LIST t;
	CMD_EVAL_MIN_MAX mm =
	{
		"CMD_AcAdd6_Eval_PRIORITY", 1, 4294967295UL,
	};
	PARAM args[] =
	{
		{"[allow|deny]", CmdPrompt, _UU("CMD_AcAdd6_Prompt_AD"), CmdEvalNotEmpty, NULL},
		{"PRIORITY", CmdPrompt, _UU("CMD_AcAdd6_Prompt_PRIORITY"), CmdEvalMinMax, &mm},
		{"IP", CmdPrompt, _UU("CMD_AcAdd6_Prompt_IP"), CmdEvalIpAndMask6, NULL},
	};

	if (ps->HubName == NULL)
	{
		c->Write(c, _UU("CMD_Hub_Not_Selected"));
		return ERR_INVALID_PARAMETER;
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));
	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	Zero(&t, sizeof(t));
	StrCpy(t.HubName, sizeof(t.HubName), ps->HubName);

	ret = ScGetAcList(ps->Rpc, &t);

	if (ret != ERR_NO_ERROR)
	{
		CmdPrintError(c, ret);
		FreeParamValueList(o);
		return ret;
	}
	else
	{
		AC *ac = ZeroMalloc(sizeof(AC));
		char *test = GetParamStr(o, "[allow|deny]");
		IP u_ip, u_mask;

		if (StartWith("deny", test))
		{
			ac->Deny = true;
		}

		ParseIpAndMask6(GetParamStr(o, "IP"), &u_ip, &u_mask);
		Copy(&ac->IpAddress, &u_ip, sizeof(IP));

		if (SubnetMaskToInt6(&u_mask) == 128)
		{
			ac->Masked = false;
		}
		else
		{
			ac->Masked = true;
			Copy(&ac->SubnetMask, &u_mask, sizeof(IP));
		}

		ac->Priority = GetParamInt(o, "PRIORITY");

		Insert(t.o, ac);

		ret = ScSetAcList(ps->Rpc, &t);
		if (ret != ERR_NO_ERROR)
		{
			CmdPrintError(c, ret);
			FreeParamValueList(o);
			return ret;
		}
	}

	FreeRpcAcList(&t);

	FreeParamValueList(o);

	return 0;
}

static PS *NewPs(CONSOLE *c, RPC *rpc, char *servername, UINT serverport, char *hubname, char *adminhub, wchar_t *cmdline)
{
	PS *ps;
	if (c == NULL || rpc == NULL || servername == NULL)
	{
		return NULL;
	}

	if (IsEmptyStr(hubname))
	{
		hubname = NULL;
	}
	if (IsEmptyStr(adminhub))
	{
		adminhub = NULL;
	}
	if (UniIsEmptyStr(cmdline))
	{
		cmdline = NULL;
	}

	ps = ZeroMalloc(sizeof(PS));
	ps->ServerPort = serverport;
	ps->ServerName = CopyStr(servername);
	ps->Console = c;
	ps->Rpc = rpc;
	ps->HubName = CopyStr(hubname);
	ps->LastError = 0;
	ps->AdminHub = CopyStr(adminhub);
	ps->CmdLine = CopyUniStr(cmdline);

	return ps;
}

static void FreePs(PS *ps)
{
	if (ps == NULL)
	{
		return;
	}

	Free(ps->HubName);
	Free(ps->AdminHub);
	Free(ps->CmdLine);
	Free(ps->ServerName);

	Free(ps);
}

static UINT PsConnect(CONSOLE *c, char *host, UINT port, char *hub, char *adminhub, wchar_t *cmdline, char *password)
{
	UINT retcode = 0;
	RPC *rpc = NULL;
	CEDAR *cedar;
	CLIENT_OPTION o;
	UCHAR hashed_password[SHA1_SIZE];
	bool b = false;
	if (c == NULL || host == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}
	if (port == 0)
	{
		port = 443;
	}
	if (hub != NULL)
	{
		adminhub = NULL;
	}

	cedar = NewCedar(NULL, NULL);

	Zero(&o, sizeof(o));
	UniStrCpy(o.AccountName, sizeof(o.AccountName), L"VPNCMD");
	StrCpy(o.Hostname, sizeof(o.Hostname), host);
	o.Port = port;
	o.ProxyType = PROXY_DIRECT;

	Sha0(hashed_password, password, StrLen(password));

	if (IsEmptyStr(password) == false)
	{
		b = true;
	}

	while (true)
	{
		UINT err;

		rpc = AdminConnectEx(cedar, &o, hub, hashed_password, &err, CEDAR_CUI_STR);
		if (rpc == NULL)
		{
			retcode = err;

			if (err == ERR_ACCESS_DENIED && c->ProgrammingMode == false)
			{
				char *pass;
				if (b)
				{
					c->Write(c, _UU("CMD_VPNCMD_PASSWORD_1"));
				}

				b = true;

				pass = c->ReadPassword(c, _UU("CMD_VPNCMD_PASSWORD_2"));
				c->Write(c, L"");

				if (pass != NULL)
				{
					Sha0(hashed_password, pass, StrLen(pass));
					Free(pass);
				}
				else
				{
					break;
				}
			}
			else
			{
				CmdPrintError(c, err);
				break;
			}
		}
		else
		{
			PS *ps;

			ps = NewPs(c, rpc, o.Hostname, port, hub, adminhub, cmdline);
			PsMain(ps);
			retcode = ps->LastError;
			FreePs(ps);
			AdminDisconnect(rpc);
			break;
		}
	}

	ReleaseCedar(cedar);

	return retcode;
}

void CmdPrintError(CONSOLE *c, UINT err)
{
	wchar_t tmp[MAX_SIZE];
	if (c == NULL)
	{
		return;
	}

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ERROR"),
		err, GetUniErrorStr(err));
	c->Write(c, tmp);

	if (err == ERR_DISCONNECTED)
	{
		c->Write(c, _UU("CMD_DISCONNECTED_MSG"));
	}
}

void CmdPrintAbout(CONSOLE *c)
{
	CEDAR *cedar;
	wchar_t tmp[MAX_SIZE];
	if (c == NULL)
	{
		return;
	}

	cedar = NewCedar(NULL, NULL);

	UniFormat(tmp, sizeof(tmp), _UU("CMD_VPNCMD_ABOUT"),
		cedar->VerString, cedar->BuildInfo);

	c->Write(c, tmp);

	ReleaseCedar(cedar);
}

// Split src at separator into host and optional port: the shared tail of ParseHostPort
static bool ParseHostPortTokens(char *src, char *separator, char **host, UINT *port, UINT default_port)
{
	TOKEN_LIST *t;
	bool ret = false;
	if (src == NULL)
	{
		return false;
	}

	t = ParseToken(src, separator);
	if (t == NULL)
	{
		return false;
	}

	if (port != NULL)
	{
		*port = 0;
	}

	if (default_port == 0)
	{
		if (t->NumTokens < 2)
		{
			FreeToken(t);
			return false;
		}

		if (ToInt(t->Token[1]) == 0)
		{
			FreeToken(t);
			return false;
		}
	}

	if (t->NumTokens >= 2 && ToInt(t->Token[1]) == 0)
	{
		FreeToken(t);
		return false;
	}

	if (t->NumTokens >= 1 && IsEmptyStr(t->Token[0]) == false)
	{
		ret = true;

		if (host != NULL)
		{
			*host = CopyStr(t->Token[0]);
			Trim(*host);
		}

		if (t->NumTokens >= 2)
		{
			if (port != NULL)
			{
				*port = ToInt(t->Token[1]);
			}
		}
	}

	if (port != NULL)
	{
		if (*port == 0)
		{
			*port = default_port;
		}
	}

	FreeToken(t);

	return ret;
}

bool ParseHostPort(char *src, char **host, UINT *port, UINT default_port)
{
	if (src == NULL)
	{
		return false;
	}

	if (StartWith(src, "["))
	{
		if (InStr(src, "]"))
		{
			// Format of [target]:port
			UINT i, n;
			char tmp[MAX_SIZE];

			StrCpy(tmp, sizeof(tmp), src);

			n = SearchStrEx(tmp, "]", 0, false);
			if (n != INFINITE)
			{
				UINT len = StrLen(tmp);

				for (i = n;i < len;i++)
				{
					if (tmp[i] == ':')
					{
						tmp[i] = '@';
					}
				}
			}

			return ParseHostPortTokens(tmp, "@", host, port, default_port);
		}
	}

	if (InStr(src, "@"))
	{
		return ParseHostPortTokens(src, "@", host, port, default_port);
	}

	return ParseHostPortTokens(src, ":", host, port, default_port);
}

static UINT VpnCmdProc(CONSOLE *c, char *cmd_name, wchar_t *str, void *param)
{
	LIST *o;
	char *target;
	bool server = false;
	bool tools = false;
	char *hostname = NULL;
	char *password;
	wchar_t *cmdline;
	bool host_inputted = false;
	UINT port = 0;
	UINT retcode = 0;
	PARAM args[] =
	{
		{"[host:port]", NULL, NULL, NULL, NULL},
		{"SERVER", NULL, NULL, NULL, NULL},
		{"TOOLS", NULL, NULL, NULL, NULL},
		{"HUB", NULL, NULL, NULL, NULL},
		{"ADMINHUB", NULL, NULL, NULL, NULL},
		{"PASSWORD", NULL, NULL, NULL, NULL},
		{"IN", NULL, NULL, NULL, NULL},
		{"OUT", NULL, NULL, NULL, NULL},
		{"CMD", NULL, NULL, NULL, NULL},
		{"CSV", NULL, NULL, NULL, NULL},
		{"PROGRAMMING", NULL, NULL, NULL, NULL},
	};

	if(c->ConsoleType != CONSOLE_CSV)
	{
		CmdPrintAbout(c);
		c->Write(c, L"");
	}

	o = ParseCommandList(c, cmd_name, str, args, sizeof(args) / sizeof(args[0]));

	if (o == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	if (GetParamStr(o, "SERVER") == NULL && GetParamStr(o, "TOOLS") == NULL)
	{
		wchar_t *ret;
		UINT code;
		c->Write(c, _UU("CMD_VPNCMD_CS_1"));

		ret = c->ReadLine(c, _UU("CMD_VPNCMD_CS_2"), true);

		code = UniToInt(ret);
		Free(ret);

		switch (code)
		{
		case 1:
			server = true;
			break;

		case 3:
			tools = true;
			break;

		default:
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		c->Write(c, L"");
	}
	else
	{
		if (GetParamStr(o, "SERVER") != NULL)
		{
			server = true;
		}
		else
		{
			tools = true;
		}
	}

	target = CopyStr(GetParamStr(o, "[host:port]"));

	if (target == NULL && tools == false)
	{
		wchar_t *str;
		if (server)
		{
			c->Write(c, _UU("CMD_VPNCMD_HOST_1"));
		}

		str = c->ReadLine(c, _UU("CMD_VPNCMD_HOST_3"), true);
		c->Write(c, L"");
		target = CopyUniToStr(str);
		Free(str);

		if (target == NULL)
		{
			FreeParamValueList(o);
			return ERR_USER_CANCEL;
		}

		if (IsEmptyStr(target))
		{
			Free(target);
			target = CopyStr("localhost");
		}
	}
	else
	{
		host_inputted = true;
	}

	if (tools == false)
	{
		if (ParseHostPort(target, &hostname, &port, 443) == false)
		{
			c->Write(c, _UU("CMD_MSG_INVALID_HOSTNAME"));
			Free(target);
			FreeParamValueList(o);
			return ERR_INVALID_PARAMETER;
		}
	}

	password = GetParamStr(o, "PASSWORD");
	if (password == NULL)
	{
		password = "";
	}

	cmdline = GetParamUniStr(o, "CMD");

	if (server)
	{
		char *hub;
		char *adminhub = NULL;

		hub = CopyStr(GetParamStr(o, "HUB"));
		adminhub = GetParamStr(o, "ADMINHUB");

		if (hub == NULL)
		{
			if (host_inputted == false)
			{
				wchar_t *s;
				c->Write(c, _UU("CMD_VPNCMD_HUB_1"));

				s = c->ReadLine(c, _UU("CMD_VPNCMD_HUB_2"), true);

				hub = CopyUniToStr(s);
				Free(s);
			}
		}

		if (IsEmptyStr(hub))
		{
			Free(hub);
			hub = NULL;
		}
		if (IsEmptyStr(adminhub))
		{
			adminhub = NULL;
		}

		retcode = PsConnect(c, hostname, port, hub, adminhub, cmdline, password);

		Free(hub);
	}
	else if (tools)
	{
		retcode = PtConnect(c, cmdline);
	}

	Free(hostname);
	Free(target);
	FreeParamValueList(o);

	return retcode;
}

UINT CommandMain(wchar_t *command_line)
{
	UINT ret = 0;
	wchar_t *infile, *outfile;
	wchar_t *csvmode;
	wchar_t *programming_mode;
	CONSOLE *c;

	if (command_line == NULL)
	{
		return ERR_INVALID_PARAMETER;
	}

	infile = ParseCommandEx(command_line, L"in", NULL);
	outfile = ParseCommandEx(command_line, L"out", NULL);
	if (UniIsEmptyStr(infile))
	{
		Free(infile);
		infile = NULL;
	}
	if (UniIsEmptyStr(outfile))
	{
		Free(outfile);
		outfile = NULL;
	}

	c = NewLocalConsole(infile, outfile);
	if (c != NULL)
	{
		CMD cmd[] =
		{
			{"vpncmd", VpnCmdProc},
		};

		csvmode = ParseCommandEx(command_line, L"csv", NULL);
		if(csvmode != NULL)
		{
			Free(csvmode);
			c->ConsoleType = CONSOLE_CSV;
		}

		programming_mode = ParseCommandEx(command_line, L"programming", NULL);
		if (programming_mode != NULL)
		{
			Free(programming_mode);
			c->ProgrammingMode = true;
		}

		if (DispatchNextCmdEx(c, command_line, ">", cmd, sizeof(cmd) / sizeof(cmd[0]), NULL) == false)
		{
			ret = ERR_INVALID_PARAMETER;
		}
		else
		{
			ret = c->RetCode;
		}

		c->Free(c);
	}
	else
	{
		// The /IN file cannot be read or the /OUT file cannot be created
		Print("Error: Couldn't open local console.\n");
		ret = ERR_INVALID_PARAMETER;
	}

	Free(infile);
	Free(outfile);

	return ret;
}

