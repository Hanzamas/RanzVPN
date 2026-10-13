// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module
// © 2020 Nokia

// CommandCheck.c
// vpncmd system check (Check*): network, threads, file system, strings, memory and kernel self-tests

#include "Command.h"

#include "Admin.h"
#include "Connection.h"
#include "Console.h"
#include "Database.h"
#include "Server.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Network.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/OS.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/TcpIp.h"
#include "Mayaqua/Tick64.h"

#include "Mayaqua/Crypto/Key.h"

#include <stdlib.h>
#include "CommandInternal.h"

// System checker definition
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

// Accept thread
void CheckNetworkAcceptThread(THREAD *thread, void *param)
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

// Listen thread
void CheckNetworkListenThread(THREAD *thread, void *param)
{
	CHECK_NETWORK_1 *c = (CHECK_NETWORK_1 *)param;
	SOCK *s;
	UINT i, rsa_bits = 1024;
	K *pub, *pri;
	X *x;
	LIST *o = NewList(NULL);
	NAME *name = NewName(L"Test", L"Test", L"Test", L"JP", L"Ibaraki", L"Tsukuba");

	// Set RSA bits considering OpenSSL security Level
	// Security level 4 needs 7680 bits
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
		s = Listen(i);
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

// Network function check
bool CheckNetwork()
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
					Print("Recv Failed (Disconnected).\n", ret);
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

// Test thread 1
void CheckThread1(THREAD *thread, void *param)
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

// Test thread 2
void CheckThread2(THREAD *thread, void *param)
{
	EVENT *e = (EVENT *)param;
	Wait(e, INFINITE);
}

typedef struct CHECK_THREAD_3
{
	UINT num, a;
} CHECK_THREAD_3;

// Test thread 3
void CheckThread3(THREAD *thread, void *param)
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

// Thread check
bool CheckThread()
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

// File system check
bool CheckFileSystem()
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

// String check
bool CheckStrings()
{
	wchar_t *numstr = _UU("CHECK_TEST_123456789");
	char tmp[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	UINT i;
	UINT sum, sum2;
	UNI_TOKEN_LIST *t;

	UniStrCpy(tmp2, sizeof(tmp2), L"");

	sum2 = 0;
	for (i = 0;i < 64;i++)
	{
		sum2 += i;
		UniFormat(tmp2, sizeof(tmp2), L"%s,%u", tmp2, i);
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

// Memory check
bool CheckMemory()
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

// Function that do not do anything
void InputToNull(void *p)
{
	if (RetZero() == 1)
	{
		UCHAR *c = (UCHAR *)p;
		c[0] = 0x32;
	}
}

// Function that returns 0
UINT RetZero()
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

// Kernel check
bool CheckKernel()
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
	else if (false)
	{
		UINT64 tick1 = Tick64();
		UINT64 time1;
		UINT64 time2;

		SleepThread(1000);

		time2 = LocalTime64();
		time1 = SystemToLocal64(TickToTime(tick1));

		if (time2 > time1)
		{
			s = time2 - time1;
		}
		else
		{
			s = time1 - time2;
		}

		if (s <= 500 || s >= 2000)
		{
			Print("TickToTime Failed.\n");
			return false;
		}
	}

	return true;
}

// System checker
bool SystemCheck()
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
