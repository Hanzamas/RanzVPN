// Eraser.c
// Eraser: deletes the oldest log files while the free disk space is below the minimum

#include "Eraser.h"

#include "Cedar.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Platform.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

static char *delete_targets[] =
{
	"backup.ranz_server.config",
	HUB_PACKET_LOG_DIR,
	HUB_SECURITY_LOG_DIR,
	SERVER_LOG_DIR,
};

static UINT eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;

static bool CheckEraserDiskFreeSpace(ERASER *e)
{
	wchar_t *dir_w;
	wchar_t dir[MAX_SIZE];
	UINT len;
	ULARGE_INTEGER free_size;
	if (e == NULL)
	{
		return true;
	}

	// Ask the directory's own volume, so a mount point, junction or subst
	// drive reports its target and not the drive root
	dir_w = CopyStrToUni(e->DirName);
	InnerFilePathW(dir, sizeof(dir), dir_w);
	Free(dir_w);

	// A UNC path needs the trailing backslash
	len = UniStrLen(dir);
	if (len != 0 && dir[len - 1] != L'\\')
	{
		UniStrCat(dir, sizeof(dir), L"\\");
	}

	if (GetDiskFreeSpaceExW(dir, &free_size, NULL, NULL) == FALSE)
	{
		return true;
	}

	if (e->MinFreeSpace > free_size.QuadPart)
	{
		return false;
	}

	return true;
}

static void FreeEraseFileList(LIST *o)
{
	UINT i;
	if (o == NULL)
	{
		return;
	}

	for (i = 0; i < LIST_NUM(o); i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);
		Free(f->FullPath);
		Free(f);
	}

	ReleaseList(o);
}

static void EnumEraseFile(LIST *o, char *dirname)
{
	DIRLIST *dir;
	UINT i;
	char tmp[MAX_PATH];
	if (o == NULL || dirname == NULL)
	{
		return;
	}

	dir = EnumDir(dirname);

	for (i = 0; i < dir->NumFiles; i++)
	{
		DIRENT *e = dir->File[i];
		Format(tmp, sizeof(tmp), "%s/%s", dirname, e->FileName);
		NormalizePath(tmp, sizeof(tmp), tmp);

		if (e->Folder == false)
		{
			ERASE_FILE *f;

			if (EndWith(tmp, ".log") || EndWith(tmp, ".config") || EndWith(tmp, ".old"))
			{
				f = ZeroMalloc(sizeof(ERASE_FILE));
				f->FullPath = CopyStr(tmp);
				f->UpdateTime = e->UpdateDate;

				Add(o, f);
			}
		}
		else
		{
			EnumEraseFile(o, tmp);
		}
	}

	FreeDir(dir);
}

static LIST *GenerateEraseFileList(ERASER *e)
{
	LIST *o;
	UINT i;
	if (e == NULL)
	{
		return NULL;
	}

	o = NewListFast(CompareEraseFile);

	for (i = 0; i < sizeof(delete_targets) / sizeof(delete_targets[0]); i++)
	{
		char dirname[MAX_PATH];
		Format(dirname, sizeof(dirname), "%s/%s", e->DirName, delete_targets[i]);

		EnumEraseFile(o, dirname);
	}

	Sort(o);

	return o;
}

static void EraserMain(ERASER *e)
{
	LIST *o;
	UINT i;
	bool ok = false;
	char bs[64];
	if (e == NULL)
	{
		return;
	}

	if (CheckEraserDiskFreeSpace(e))
	{
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);

	o = GenerateEraseFileList(e);

	for (i = 0; i < LIST_NUM(o); i++)
	{
		ERASE_FILE *f = LIST_DATA(o, i);

		if (FileDelete(f->FullPath))
		{
			ELog(e, "LE_DELETE", bs, f->FullPath);
		}

		if (CheckEraserDiskFreeSpace(e))
		{
			ok = true;
			break;
		}
	}

	FreeEraseFileList(o);

	if (e->LastFailed == false && ok == false)
	{
		ELog(e, "LE_NOT_ENOUGH_FREE", bs);
	}

	e->LastFailed = ok ? false : true;
}

int CompareEraseFile(void *p1, void *p2)
{
	ERASE_FILE *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ERASE_FILE **)p1;
	f2 = *(ERASE_FILE **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	if (f1->UpdateTime > f2->UpdateTime)
	{
		return 1;
	}
	else if (f1->UpdateTime == f2->UpdateTime)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static void EraserThread(THREAD *t, void *p)
{
	ERASER *e = (ERASER *)p;
	char bs[64];
	if (t == NULL || e == NULL)
	{
		return;
	}

	ToStrByte(bs, sizeof(bs), e->MinFreeSpace);
	ELog(e, "LE_START", e->DirName, bs);

	while (e->Halt == false)
	{
		EraserMain(e);
		e->NumChecks++;

		// The interval in milliseconds (at least 1 s, as the seconds of GetEraserCheckInterval for the configuration)
		Wait(e->HaltEvent, MAX(eraser_check_interval, 1000));
	}
}

void SetEraserCheckInterval(UINT interval)
{
	if (interval == 0)
	{
		eraser_check_interval = DISK_FREE_CHECK_INTERVAL_DEFAULT;
	}
	else
	{
		eraser_check_interval = interval * 1000;
	}
}

UINT GetEraserCheckInterval()
{
	UINT ret = eraser_check_interval / 1000;

	if (ret == 0)
	{
		ret = 1;
	}

	return ret;
}

ERASER *NewEraser(LOG *log, UINT64 min_size)
{
	ERASER *e;
	char dir[MAX_PATH];

	if (min_size == 0)
	{
		min_size = DISK_FREE_SPACE_DEFAULT_WINDOWS;
	}

	if (min_size < DISK_FREE_SPACE_MIN)
	{
		min_size = DISK_FREE_SPACE_MIN;
	}

	e = ZeroMalloc(sizeof(ERASER));

	GetExeDir(dir, sizeof(dir));

	e->Log = log;
	e->MinFreeSpace = min_size;
	e->DirName = CopyStr(dir);
	e->HaltEvent = NewEvent();

	e->Thread = NewThread(EraserThread, e);

	return e;
}

void FreeEraser(ERASER *e)
{
	if (e == NULL)
	{
		return;
	}

	e->Halt = true;
	Set(e->HaltEvent);
	WaitThread(e->Thread, INFINITE);
	ReleaseThread(e->Thread);
	ReleaseEvent(e->HaltEvent);

	Free(e->DirName);
	Free(e);
}

void ELog(ERASER *e, char *name, ...)
{
	wchar_t buf[MAX_SIZE * 2];
	va_list args;
	if (name == NULL)
	{
		return;
	}

	va_start(args, name);
	LogFormat(buf, sizeof(buf), name, args);

	InsertUnicodeRecord(e->Log, buf);

	if (IsDebug())
	{
		UniPrint(L"LOG: %s\n", buf);
	}
	va_end(args);
}
