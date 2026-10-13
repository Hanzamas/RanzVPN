// AdminLog.c
// Admin RPC area: log files (enumerate and read the server log files)

#include "Admin.h"

#include "Account.h"
#include "BridgeWin32.h"
#include "Connection.h"
#include "Link.h"
#include "Listener.h"
#include "MsChapV2.h"
#include "Remote.h"
#include "Protocol.h"
#include "Sam.h"
#include "Server.h"
#include "Session.h"
#include "Wpc.h"

#include "Mayaqua/Cfg.h"
#include "Mayaqua/FileIO.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/HTTP.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"
#include "AdminInternal.h"

UINT StReadLogFile(ADMIN *a, RPC_READ_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	char logfilename[MAX_PATH];
	char servername[MAX_HOST_NAME_LEN + 1];
	UINT offset;

	if (IsEmptyStr(t->FilePath))
	{
		return ERR_INVALID_PARAMETER;
	}

	StrCpy(logfilename, sizeof(logfilename), t->FilePath);
	offset = t->Offset;

	GetMachineName(servername, sizeof(servername));

	// Check the permission to read the log file
	if (a->LogFileList == NULL)
	{
		RPC_ENUM_LOG_FILE elf;
		UINT elf_ret;

		Zero(&elf, sizeof(elf));

		elf_ret = StEnumLogFile(a, &elf);

		FreeRpcEnumLogFile(&elf);

		if (elf_ret != ERR_NO_ERROR)
		{
			return elf_ret;
		}
	}
	if (CheckLogFileNameFromEnumList(a->LogFileList, logfilename) == false)
	{
		return ERR_OBJECT_NOT_FOUND;
	}

	FreeRpcReadLogFile(t);
	Zero(t, sizeof(RPC_READ_LOG_FILE));

	SiReadLocalLogFile(s, logfilename, offset, t);

	if (offset == 0)
	{
		ALog(a, NULL, "LA_READ_LOG_FILE", servername, logfilename);
	}

	StrCpy(t->FilePath, sizeof(t->FilePath), logfilename);
	t->Offset = offset;

	return ERR_NO_ERROR;
}

UINT StEnumLogFile(ADMIN *a, RPC_ENUM_LOG_FILE *t)
{
	SERVER *s = a->Server;
	CEDAR *c = s->Cedar;
	UINT i;
	bool no_access = false;

	HUB *h;

	if (a->ServerAdmin == false)
	{
		h = GetHub(c, a->HubName);

		if (a->ServerAdmin == false && GetHubAdminOption(h, "no_read_log_file") != 0)
		{
			no_access = true;
		}

		ReleaseHub(h);
	}

	if (no_access)
	{
		return ERR_NOT_ENOUGH_RIGHT;
	}

	FreeRpcEnumLogFile(t);
	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	SiEnumLocalLogFileList(s, a->ServerAdmin ? NULL : a->HubName, t);

	// Cache the log file list on the RPC session
	if (a->LogFileList != NULL)
	{
		FreeEnumLogFile(a->LogFileList);
	}

	a->LogFileList = NewListFast(CmpLogFile);

	for (i = 0;i < t->NumItem;i++)
	{
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];
		LOG_FILE *f = ZeroMalloc(sizeof(LOG_FILE));

		f->FileSize = e->FileSize;
		f->UpdatedTime = e->UpdatedTime;
		StrCpy(f->Path, sizeof(f->Path), e->FilePath);

		Insert(a->LogFileList, f);
	}

	return ERR_NO_ERROR;
}

void SiReadLocalLogFile(SERVER *s, char *filepath, UINT offset, RPC_READ_LOG_FILE *t)
{
	char exe_dir[MAX_PATH], full_path[MAX_PATH];
	IO *o;
	if (s == NULL || t == NULL || filepath == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_READ_LOG_FILE));

	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(full_path, sizeof(full_path), "%s/%s", exe_dir, filepath);

	o = FileOpenEx(full_path, false, false);
	if (o != NULL)
	{
		UINT filesize = FileSize(o);

		if (offset < filesize)
		{
			UINT readsize = MIN(filesize - offset, FTP_BLOCK_SIZE);
			void *buf = ZeroMalloc(readsize);

			FileSeek(o, FILE_BEGIN, offset);
			FileRead(o, buf, readsize);

			t->Buffer = NewBuf();
			WriteBuf(t->Buffer, buf, readsize);
			Free(buf);
		}

		FileClose(o);
	}
}

void SiEnumLocalLogFileList(SERVER *s, char *hubname, RPC_ENUM_LOG_FILE *t)
{
	LIST *o;
	UINT i;
	if (s == NULL || t == NULL)
	{
		return;
	}

	Zero(t, sizeof(RPC_ENUM_LOG_FILE));

	o = EnumLogFile(hubname);

	t->NumItem = LIST_NUM(o);
	t->Items = ZeroMalloc(sizeof(RPC_ENUM_LOG_FILE_ITEM) * t->NumItem);

	for (i = 0;i < LIST_NUM(o);i++)
	{
		LOG_FILE *f = LIST_DATA(o, i);
		RPC_ENUM_LOG_FILE_ITEM *e = &t->Items[i];

		StrCpy(e->FilePath, sizeof(e->FilePath), f->Path);
		e->FileSize = f->FileSize;
		e->UpdatedTime = f->UpdatedTime;
	}

	FreeEnumLogFile(o);
}
