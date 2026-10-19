// Cfg.c
// Configuration information manipulation module

#include "Cfg.h"

#include "FileIO.h"
#include "Internat.h"
#include "Memory.h"
#include "Network.h"
#include "Object.h"
#include "Str.h"

static void BackupCfgWEx(CFG_RW *rw, FOLDER *f, wchar_t *original, UINT revision_number)
{
	wchar_t dirname[MAX_PATH];
	wchar_t filename[MAX_PATH];
	wchar_t fullpath[MAX_PATH];
	wchar_t datestr[MAX_PATH];
	SYSTEMTIME st;
	if (f == NULL || rw == NULL)
	{
		return;
	}

	UniFormat(dirname, sizeof(dirname), L"$backup.%s", original[0] == L'$' ? original + 1 : original);

	LocalTime(&st);
	UniFormat(datestr, sizeof(datestr), L"%04u%02u%02u%02u_%s",
		st.wYear, st.wMonth, st.wDay, st.wHour, original[0] == L'$' ? original + 1 : original);

	if (revision_number == INFINITE)
	{
		UniStrCpy(filename, sizeof(filename), datestr);
	}
	else
	{
		UniFormat(filename, sizeof(filename), L"%08u_%s",
			revision_number, original[0] == L'$' ? original + 1 : original);
	}

	if (UniStrCmpi(datestr, rw->LastSavedDateStr) == 0)
	{
		return;
	}

	UniStrCpy(rw->LastSavedDateStr, sizeof(rw->LastSavedDateStr), datestr);

	if (IsFileExistsW(filename))
	{
		return;
	}

	MakeDirW(dirname);

	UniFormat(fullpath, sizeof(fullpath), L"%s/%s", dirname, filename);
	CfgSaveW(f, fullpath);
}

void FreeCfgRw(CFG_RW *rw)
{
	if (rw == NULL)
	{
		return;
	}

	if (rw->Io != NULL)
	{
		FileClose(rw->Io);
	}

	DeleteLock(rw->lock);
	Free(rw->FileNameW);
	Free(rw->FileName);
	Free(rw);
}

UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number)
{
	UINT ret = 0;
	if (rw == NULL || f == NULL)
	{
		return 0;
	}

	Lock(rw->lock);
	{
		if (rw->Io != NULL)
		{
			FileClose(rw->Io);
			rw->Io = NULL;
		}

		if (CfgSaveExW2(rw, f, rw->FileNameW, &ret))
		{
			if (rw->DontBackup == false)
			{
				BackupCfgWEx(rw, f, rw->FileNameW, revision_number);
			}
		}
		else
		{
			ret = 0;
		}

		rw->Io = FileOpenW(rw->FileNameW, false);
	}
	Unlock(rw->lock);

	return ret;
}

CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a)
{
	CFG_RW *ret;
	wchar_t *cfg_name_w = CopyStrToUni(cfg_name_a);
	wchar_t *template_name_w = CopyStrToUni(template_name_a);

	ret = NewCfgRwEx2W(root, cfg_name_w, dont_backup, template_name_w);

	Free(cfg_name_w);
	Free(template_name_w);

	return ret;
}
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name)
{
	CFG_RW *rw;
	FOLDER *f;
	bool loaded_from_template = false;
	if (cfg_name == NULL || root == NULL)
	{
		return NULL;
	}

	f = CfgReadW(cfg_name);
	if (f == NULL)
	{
		if (UniIsEmptyStr(template_name) == false)
		{
			f = CfgReadW(template_name);
			if (f != NULL)
			{
				loaded_from_template = true;

				goto LABEL_CONTINUE;
			}
		}

		rw = ZeroMalloc(sizeof(CFG_RW));
		rw->lock = NewLock();
		rw->FileNameW = CopyUniStr(cfg_name);
		rw->FileName = CopyUniToStr(cfg_name);
		rw->Io = FileCreateW(cfg_name);
		*root = NULL;
		rw->DontBackup = dont_backup;

		return rw;
	}

LABEL_CONTINUE:
	rw = ZeroMalloc(sizeof(CFG_RW));
	rw->FileNameW = CopyUniStr(cfg_name);
	rw->FileName = CopyUniToStr(cfg_name);
	if (loaded_from_template == false)
	{
		rw->Io = FileOpenW(cfg_name, false);
	}
	else
	{
		rw->Io = FileCreateW(cfg_name);
	}
	rw->lock = NewLock();

	*root = f;

	rw->DontBackup = dont_backup;

	return rw;
}

bool FileCopy(char *src, char *dst)
{
	BUF *b;
	bool ret = false;
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDump(src);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBuf(b, dst);

	FreeBuf(b);

	return ret;
}
bool FileCopyW(wchar_t *src, wchar_t *dst)
{
	return FileCopyExW(src, dst, true);
}
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock)
{
	BUF *b;
	bool ret = false;
	if (src == NULL || dst == NULL)
	{
		return false;
	}

	b = ReadDumpExW(src, false);
	if (b == NULL)
	{
		return false;
	}

	SeekBuf(b, 0, 0);

	ret = DumpBufW(b, dst);

	FreeBuf(b);

	return ret;
}
// Writes data to <name>.tmp in the same directory, flushes it to disk and replaces name with it
// in one step, so a reader sees either the old file or the whole new one
static bool CfgWriteFileReplace(wchar_t *name, void *data, UINT size)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t inner_tmp[MAX_SIZE];
	wchar_t inner_name[MAX_SIZE];
	IO *o;
	bool ok;
	if (name == NULL || data == NULL)
	{
		return false;
	}

	UniFormat(tmp, sizeof(tmp), L"%s.tmp", name);

	o = FileCreateW(tmp);
	if (o == NULL)
	{
		return false;
	}
	ok = FileWrite(o, data, size);
	// FileClose flushes a writer with FlushFileBuffers
	FileClose(o);

	if (ok)
	{
		InnerFilePathW(inner_tmp, sizeof(inner_tmp), tmp);
		InnerFilePathW(inner_name, sizeof(inner_name), name);
		ok = MoveFileExW(inner_tmp, inner_name, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
	}

	if (ok == false)
	{
		FileDeleteW(tmp);
	}

	return ok;
}

bool CfgStageNewFile(CFG_RW *rw, void *data, UINT size)
{
	wchar_t newfile[MAX_SIZE];
	if (rw == NULL || data == NULL)
	{
		return false;
	}

	// CfgReadW loads <name>.new in place of the live file on the next read
	UniFormat(newfile, sizeof(newfile), L"%s.new", rw->FileNameW);

	return CfgWriteFileReplace(newfile, data, size);
}

void CfgGetDisplayFileName(CFG_RW *rw, char *dst, UINT size)
{
	if (dst == NULL)
	{
		return;
	}
	if (rw == NULL)
	{
		ClearStr(dst, size);
		return;
	}

	// A leading '@' only marks a path relative to the executable directory
	StrCpy(dst, size, rw->FileName + (rw->FileName[0] == '@' ? 1 : 0));
}

void CfgSaveW(FOLDER *f, wchar_t *name)
{
	CfgSaveExW(NULL, f, name);
}
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name)
{
	return CfgSaveExW2(rw, f, name, NULL);
}
bool CfgSaveExW2(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size)
{
	return CfgSaveExW3(rw, f, name, written_size, IsFileExistsW(SAVE_BINARY_FILE_NAME_SWITCH));
}
bool CfgSaveExW3(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size, bool write_binary)
{
	bool text = !write_binary;
	UCHAR hash[SHA1_SIZE];
	BUF *b;
	bool ret = true;
	UINT dummy_int = 0;
	if (name == NULL || f == NULL)
	{
		return false;
	}
	if (written_size == NULL)
	{
		written_size = &dummy_int;
	}

	b = CfgFolderToBuf(f, text);
	if (b == NULL)
	{
		return false;
	}
	Sha0(hash, b->Buf, b->Size);

	if (rw != NULL)
	{
		if (Cmp(hash, rw->LashHash, SHA1_SIZE) == 0)
		{
			ret = false;
		}
		else
		{
			Copy(rw->LashHash, hash, SHA1_SIZE);
		}
	}

	if (ret || OS_IS_UNIX(GetOsInfo()->OsType))
	{
		// A failed write keeps the live file; the next save writes again
		if (CfgWriteFileReplace(name, b->Buf, b->Size))
		{
			wchar_t log_name[MAX_SIZE];

			// CfgReadW prefers a <name>.log left by an older save; the new file supersedes it
			UniFormat(log_name, sizeof(log_name), L"%s.log", name);
			FileDeleteW(log_name);
		}
		else if (rw != NULL)
		{
			Zero(rw->LashHash, sizeof(rw->LashHash));
		}
	}

	*written_size = b->Size;

	FreeBuf(b);

	return ret;
}

FOLDER *CfgReadW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	wchar_t newfile[MAX_SIZE];
	BUF *b;
	IO *o;
	UINT size;
	void *buf;
	FOLDER *f;
	bool delete_new = false;
	bool binary_file = false;
	UCHAR header[8];
	bool has_eof = false;
	if (name == NULL)
	{
		return NULL;
	}

	UniFormat(newfile, sizeof(newfile), L"%s.new", name);
	UniFormat(tmp, sizeof(tmp), L"%s.log", name);

	o = FileOpenW(newfile, false);
	if (o == NULL)
	{
		UINT size;
		o = FileOpenW(tmp, false);

		if (o != NULL)
		{
			size = FileSize(o);
			if (size >= 2)
			{
				char c;

				if (FileSeek(o, FILE_BEGIN, size - 1) && FileRead(o, &c, 1) && c == 0x1A && FileSeek(o, FILE_BEGIN, 0))
				{
					has_eof = true;
				}
				else
				{
					FileClose(o);
					o = NULL;
				}
			}
		}
	}
	else
	{
		delete_new = true;
	}
	if (o == NULL)
	{
		o = FileOpenW(name, false);
	}
	else
	{
		if (FileSize(o) == 0)
		{
			FileClose(o);
			o = FileOpenW(name, false);
		}
	}
	if (o == NULL)
	{
		return NULL;
	}

	size = FileSize(o);
	if (has_eof)
	{
		size -= 1;
	}
	buf = Malloc(size);
	FileRead(o, buf, size);
	b = NewBuf();
	WriteBuf(b, buf, size);
	SeekBuf(b, 0, 0);

	FileClose(o);

	if (delete_new)
	{
		FileDeleteW(newfile);
	}

	// A buffer starting with "SEVPN_DB" is the binary format
	ReadBuf(b, header, sizeof(header));
	if (Cmp(header, TAG_BINARY, 8) == 0)
	{
		UCHAR hash1[SHA1_SIZE], hash2[SHA1_SIZE];
		binary_file = true;

		ReadBuf(b, hash1, sizeof(hash1));

		Sha0(hash2, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE);

		if (Cmp(hash1, hash2, SHA1_SIZE) != 0)
		{
			FreeBuf(b);
			return NULL;
		}
	}

	SeekBuf(b, 0, 0);

	if (binary_file)
	{
		SeekBuf(b, 8 + SHA1_SIZE, 0);
	}

	if (binary_file == false)
	{
		f = CfgBufTextToFolder(b);
	}
	else
	{
		f = CfgBufBinToFolder(b);
	}

	Free(buf);
	FreeBuf(b);

	FileDeleteW(newfile);

	return f;
}

char *CfgReadNextLine(BUF *b)
{
	char *tmp;
	char *buf;
	UINT len;
	if (b == NULL)
	{
		return NULL;
	}

	tmp = (char *)b->Buf + b->Current;
	if ((b->Size - b->Current) == 0)
	{
		return NULL;
	}
	len = 0;
	while (true)
	{
		if (tmp[len] == 13 || tmp[len] == 10)
		{
			if (tmp[len] == 13)
			{
				if (len < (b->Size - b->Current))
				{
					len++;
				}
			}
			break;
		}
		len++;
		if (len >= (b->Size - b->Current))
		{
			break;
		}
	}

	buf = ZeroMalloc(len + 1);
	ReadBuf(b, buf, len);
	SeekBuf(b, 1, 1);

	if (StrLen(buf) >= 1)
	{
		if (buf[StrLen(buf) - 1] == 13)
		{
			buf[StrLen(buf) - 1] = 0;
		}
	}

	return buf;
}

static bool CfgReadNextTextBUF(BUF *b, FOLDER *current)
{
	char *buf;
	TOKEN_LIST *token;
	char *name;
	char *string;
	char *data;
	bool ret;
	FOLDER *f;

	if (b == NULL || current == NULL)
	{
		return false;
	}

	ret = true;

	buf = CfgReadNextLine(b);
	if (buf == NULL)
	{
		return false;
	}

	token = ParseToken(buf, "\t ");
	if (token == NULL)
	{
		Free(buf);
		return false;
	}

	if (token->NumTokens >= 1)
	{
		if (!StrCmpi(token->Token[0], TAG_DECLARE))
		{
			if (token->NumTokens >= 2)
			{
				name = CfgUnescape(token->Token[1]);

				f = CfgCreateFolder(current, name);

				while (true)
				{
					if (CfgReadNextTextBUF(b, f) == false)
					{
						break;
					}
				}

				Free(name);
			}
		}
		if (!StrCmpi(token->Token[0], "}"))
		{
			ret = false;
		}
		if (token->NumTokens >= 3)
		{
			name = CfgUnescape(token->Token[1]);
			data = token->Token[2];

			if (!StrCmpi(token->Token[0], TAG_STRING))
			{
				wchar_t *uni;
				UINT uni_size;
				string = CfgUnescape(data);
				uni_size = CalcUtf8ToUni(string, StrLen(string));
				if (uni_size != 0)
				{
					uni = Malloc(uni_size);
					Utf8ToUni(uni, uni_size, string, StrLen(string));
					CfgAddUniStr(current, name, uni);
					Free(uni);
				}
				Free(string);
			}
			if (!StrCmpi(token->Token[0], TAG_INT))
			{
				CfgAddInt(current, name, ToInt(data));
			}
			if (!StrCmpi(token->Token[0], TAG_INT64))
			{
				CfgAddInt64(current, name, ToInt64(data));
			}
			if (!StrCmpi(token->Token[0], TAG_BOOL))
			{
				bool b = false;
				if (!StrCmpi(data, TAG_TRUE))
				{
					b = true;
				}
				else if (ToInt(data) != 0)
				{
					b = true;
				}
				CfgAddBool(current, name, b);
			}
			if (!StrCmpi(token->Token[0], TAG_BYTE))
			{
				char *base64 = CfgUnescape(data);
				const UINT base64_size = StrLen(base64);

				UINT bin_size;
				void *bin = Base64ToBin(&bin_size, base64, base64_size);
				if (bin != NULL)
				{
					CfgAddByte(current, name, bin, bin_size);
					Free(bin);
				}

				Free(base64);
			}

			Free(name);
		}
	}

	FreeToken(token);

	Free(buf);

	return ret;
}

FOLDER *CfgBufTextToFolder(BUF *b)
{
	FOLDER *f, *c;
	if (b == NULL)
	{
		return NULL;
	}

	c = CfgCreateFolder(NULL, "tmp");

	while (true)
	{
		if (CfgReadNextTextBUF(b, c) == false)
		{
			break;
		}
	}

	f = CfgFindFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		CfgDeleteFolder(c);
		return NULL;
	}

	Delete(c->Folders, f);
	f->Parent = NULL;

	CfgDeleteFolder(c);

	return f;
}

// Smallest encoding of one folder or one item in the binary format: a folder is a name length and
// two counts, an item a name length, a type and a value of at least 4 bytes
#define	CFG_BIN_MIN_ENTRY_SIZE		12

// Read one big-endian UINT of the binary format; false at the end of the data, where ReadBufInt()
// returns 0
static bool CfgReadBinInt(BUF *b, UINT *value)
{
	UINT v;

	if (ReadBuf(b, &v, sizeof(v)) != sizeof(v))
	{
		return false;
	}

	*value = Endian32(v);

	return true;
}

// Read a folder or item count; false when that many entries cannot fit in the bytes left
static bool CfgReadBinCount(BUF *b, UINT *count)
{
	if (CfgReadBinInt(b, count) == false)
	{
		return false;
	}

	return (*count <= ReadBufRemainSize(b) / CFG_BIN_MIN_ENTRY_SIZE);
}

// Read one folder of the binary format into parent. Every count and size is checked against the
// bytes left before it is used: false on a short or malformed input, which leaves a partial tree
// under parent for the caller to delete
static bool CfgReadNextFolderBin(BUF *b, FOLDER *parent)
{
	char name[MAX_SIZE];
	FOLDER *f;
	UINT n, i;
	UINT size;
	UINT value;
	UCHAR *buf;
	wchar_t *string;
	if (b == NULL || parent == NULL)
	{
		return false;
	}

	if (ReadBufStr(b, name, sizeof(name)) == false)
	{
		return false;
	}
	f = CfgCreateFolder(parent, name);

	if (CfgReadBinCount(b, &n) == false)
	{
		return false;
	}
	for (i = 0;i < n;i++)
	{
		if (CfgReadNextFolderBin(b, f) == false)
		{
			return false;
		}
	}

	if (CfgReadBinCount(b, &n) == false)
	{
		return false;
	}
	for (i = 0;i < n;i++)
	{
		UINT type;

		if (ReadBufStr(b, name, sizeof(name)) == false || CfgReadBinInt(b, &type) == false)
		{
			return false;
		}

		switch (type)
		{
		case ITEM_TYPE_INT:
			if (CfgReadBinInt(b, &value) == false)
			{
				return false;
			}
			CfgAddInt(f, name, value);
			break;

		case ITEM_TYPE_INT64:
			if (ReadBufRemainSize(b) < sizeof(UINT64))
			{
				return false;
			}
			CfgAddInt64(f, name, ReadBufInt64(b));
			break;

		case ITEM_TYPE_BYTE:
			// The size is bounded by the bytes left before it allocates
			if (CfgReadBinInt(b, &size) == false || size > ReadBufRemainSize(b))
			{
				return false;
			}
			buf = ZeroMalloc(size);
			ReadBuf(b, buf, size);
			CfgAddByte(f, name, buf, size);
			Free(buf);
			break;

		case ITEM_TYPE_STRING:
			// Bounded by the bytes left, so size + 1 does not wrap
			if (CfgReadBinInt(b, &size) == false || size > ReadBufRemainSize(b))
			{
				return false;
			}
			buf = ZeroMalloc(size + 1);
			ReadBuf(b, buf, size);
			string = ZeroMalloc(CalcUtf8ToUni(buf, StrLen(buf)) + 4);
			Utf8ToUni(string, 0, buf, StrLen(buf));
			CfgAddUniStr(f, name, string);
			Free(string);
			Free(buf);
			break;

		case ITEM_TYPE_BOOL:
			if (CfgReadBinInt(b, &value) == false)
			{
				return false;
			}
			CfgAddBool(f, name, value == 0 ? false : true);
			break;

		default:
			// The size of an unknown value is unknown: the rest cannot be read
			return false;
		}
	}

	return true;
}

FOLDER *CfgBufBinToFolder(BUF *b)
{
	FOLDER *f, *c;
	if (b == NULL)
	{
		return NULL;
	}

	c = CfgCreateFolder(NULL, "tmp");

	if (CfgReadNextFolderBin(b, c) == false)
	{
		CfgDeleteFolder(c);
		return NULL;
	}

	f = CfgFindFolder(c, TAG_ROOT);
	if (f == NULL)
	{
		CfgDeleteFolder(c);
		return NULL;
	}

	Delete(c->Folders, f);
	f->Parent = NULL;

	CfgDeleteFolder(c);

	return f;
}

static BUF *CfgFolderToBufBin(FOLDER *f)
{
	BUF *b;
	UCHAR hash[SHA1_SIZE];
	if (f == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	WriteBuf(b, TAG_BINARY, 8);

	Zero(hash, sizeof(hash));
	WriteBuf(b, hash, sizeof(hash));

	CfgOutputFolderBin(b, f);

	Sha0(((UCHAR *)b->Buf) + 8, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE);

	return b;
}

static BUF *CfgFolderToBufTextEx(FOLDER *f, bool no_banner)
{
	BUF *b;
	if (f == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	if (no_banner == false)
	{
		WriteBuf(b, TAG_CPYRIGHT, StrLen(TAG_CPYRIGHT));
	}

	CfgOutputFolderText(b, f, 0);

	return b;
}

static bool CfgEnumFolderProc(FOLDER *f, void *param)
{
	CFG_ENUM_PARAM *p;
	if (f == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	CfgOutputFolderText(p->b, f, p->depth);

	return true;
}

static bool CfgEnumItemProc(ITEM *t, void *param)
{
	CFG_ENUM_PARAM *p;
	if (t == NULL || param == NULL)
	{
		return false;
	}

	p = (CFG_ENUM_PARAM *)param;
	CfgAddItemText(p->b, t, p->depth);

	return true;
}

void CfgOutputFolderBin(BUF *b, FOLDER *f)
{
	UINT i;
	if (b == NULL || f == NULL)
	{
		return;
	}

	WriteBufStr(b, f->Name);

	WriteBufInt(b, LIST_NUM(f->Folders));

	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *sub = LIST_DATA(f->Folders, i);
		CfgOutputFolderBin(b, sub);

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}

	WriteBufInt(b, LIST_NUM(f->Items));

	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		char *utf8;
		UINT utf8_size;
		ITEM *t = LIST_DATA(f->Items, i);

		WriteBufStr(b, t->Name);

		WriteBufInt(b, t->Type);

		switch (t->Type)
		{
		case ITEM_TYPE_INT:
			WriteBufInt(b, *((UINT *)t->Buf));
			break;

		case ITEM_TYPE_INT64:
			WriteBufInt64(b, *((UINT64 *)t->Buf));
			break;

		case ITEM_TYPE_BYTE:
			WriteBufInt(b, t->size);
			WriteBuf(b, t->Buf, t->size);
			break;

		case ITEM_TYPE_STRING:
			utf8_size = CalcUniToUtf8((wchar_t *)t->Buf) + 1;
			utf8 = ZeroMalloc(utf8_size);
			UniToUtf8(utf8, utf8_size, (wchar_t *)t->Buf);
			WriteBufInt(b, StrLen(utf8));
			WriteBuf(b, utf8, StrLen(utf8));
			Free(utf8);
			break;

		case ITEM_TYPE_BOOL:
			if (*((bool *)t->Buf) == false)
			{
				WriteBufInt(b, 0);
			}
			else
			{
				WriteBufInt(b, 1);
			}
			break;
		}
	}
}

void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth)
{
	CFG_ENUM_PARAM p;
	if (b == NULL || f == NULL)
	{
		return;
	}

	CfgAddDeclare(b, f->Name, depth);
	depth++;

	Zero(&p, sizeof(CFG_ENUM_PARAM));
	p.depth = depth;
	p.b = b;

	CfgEnumItem(f, CfgEnumItemProc, &p);

	if (LIST_NUM(f->Folders) != 0 && LIST_NUM(f->Items) != 0)
	{
		WriteBuf(b, "\r\n", 2);
	}

	CfgEnumFolder(f, CfgEnumFolderProc, &p);
	depth--;
	CfgAddEnd(b, depth);

}

void CfgAddItemText(BUF *b, ITEM *t, UINT depth)
{
	char *data;
	char *sub = NULL;
	UINT size;
	char *utf8;
	UINT utf8_size;
	wchar_t *string;
	if (b == NULL || t == NULL)
	{
		return;
	}

	data = NULL;
	switch (t->Type)
	{
	case ITEM_TYPE_INT:
		data = Malloc(32);
		ToStr(data, *((UINT *)t->Buf));
		break;

	case ITEM_TYPE_INT64:
		data = Malloc(64);
		ToStr64(data, *((UINT64 *)t->Buf));
		break;

	case ITEM_TYPE_BYTE:
		data = Base64FromBin(NULL, t->Buf, t->size);
		break;

	case ITEM_TYPE_STRING:
		string = t->Buf;
		utf8_size = CalcUniToUtf8(string);
		utf8_size++;
		utf8 = ZeroMalloc(utf8_size);
		utf8[0] = 0;
		UniToUtf8(utf8, utf8_size, string);
		size = utf8_size;
		data = utf8;
		break;

	case ITEM_TYPE_BOOL:
		size = 32;
		data = Malloc(size);
		if (*((bool *)t->Buf) == false)
		{
			StrCpy(data, size, TAG_FALSE);
		}
		else
		{
			StrCpy(data, size, TAG_TRUE);
		}
		break;
	}
	if (data == NULL)
	{
		return;
	}

	CfgAddData(b, t->Type, t->Name, data, sub, depth);

	Free(data);
}

void CfgAddData(BUF *b, UINT type, char *name, char *data, char *sub, UINT depth)
{
	char *tmp;
	char *name2;
	char *data2;
	char *sub2 = NULL;
	UINT tmp_size;
	if (b == NULL || type == 0 || name == NULL || data == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);
	data2 = CfgEscape(data);
	if (sub != NULL)
	{
		sub2 = CfgEscape(sub);
	}

	tmp_size = StrLen(name2) + StrLen(data2) + 2 + 64 + 1;
	tmp = Malloc(tmp_size);

	if (sub2 != NULL)
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, sub2);
	}
	else
	{
		StrCpy(tmp, tmp_size, CfgTypeToStr(type));
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, name2);
		StrCat(tmp, tmp_size, " ");
		StrCat(tmp, tmp_size, data2);
	}

	Free(name2);
	Free(data2);
	if (sub2 != NULL)
	{
		Free(sub2);
	}
	CfgAddLine(b, tmp, depth);
	Free(tmp);
}

char *CfgTypeToStr(UINT type)
{
	switch (type)
	{
	case ITEM_TYPE_INT:
		return TAG_INT;
	case ITEM_TYPE_INT64:
		return TAG_INT64;
	case ITEM_TYPE_BYTE:
		return TAG_BYTE;
	case ITEM_TYPE_STRING:
		return TAG_STRING;
	case ITEM_TYPE_BOOL:
		return TAG_BOOL;
	}
	return NULL;
}

void CfgAddEnd(BUF *b, UINT depth)
{
	if (b == NULL)
	{
		return;
	}

	CfgAddLine(b, "}", depth);
}

void CfgAddDeclare(BUF *b, char *name, UINT depth)
{
	char *tmp;
	char *name2;
	UINT tmp_size;
	if (b == NULL || name == NULL)
	{
		return;
	}

	name2 = CfgEscape(name);

	tmp_size = StrLen(name2) + 2 + StrLen(TAG_DECLARE);
	tmp = Malloc(tmp_size);

	Format(tmp, 0, "%s %s", TAG_DECLARE, name2);
	CfgAddLine(b, tmp, depth);
	CfgAddLine(b, "{", depth);
	Free(tmp);
	Free(name2);
}

void CfgAddLine(BUF *b, char *str, UINT depth)
{
	UINT i;
	if (b == NULL)
	{
		return;
	}

	for (i = 0;i < depth;i++)
	{
		WriteBuf(b, "\t", 1);
	}
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);
}

BUF *CfgFolderToBuf(FOLDER *f, bool textmode)
{
	return CfgFolderToBufEx(f, textmode, false);
}
BUF *CfgFolderToBufEx(FOLDER *f, bool textmode, bool no_banner)
{
	if (f == NULL)
	{
		return NULL;
	}

	if (textmode)
	{
		return CfgFolderToBufTextEx(f, no_banner);
	}
	else
	{
		return CfgFolderToBufBin(f);;
	}
}

char *CfgUnescape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len, wp, i;
	UINT code;
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len + 1);
	wp = 0;
	if (len == 1 && str[0] == '$')
	{
		tmp[0] = 0;
	}
	else
	{
		for (i = 0;i < len;i++)
		{
			if (str[i] != '$')
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp2[0] = '0';
				tmp2[1] = 'x';
				tmp2[2] = str[i + 1];
				// A '$' at the end of the string has no digits: do not read past its null
				tmp2[3] = (tmp2[2] != 0) ? str[i + 2] : 0;
				i += 2;
				tmp2[4] = 0;
				code = ToInt(tmp2);
				tmp[wp++] = (char)code;
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, StrLen(tmp) + 1, tmp);
	Free(tmp);
	return ret;
}

char *CfgEscape(char *str)
{
	char *tmp;
	char *ret;
	char tmp2[16];
	UINT len;
	UINT wp, i;
	if (str == NULL)
	{
		return NULL;
	}

	len = StrLen(str);
	tmp = ZeroMalloc(len * 3 + 2);
	if (len == 0)
	{
		StrCpy(tmp, (len * 3 + 2), "$");
	}
	else
	{
		wp = 0;
		for (i = 0;i < len;i++)
		{
			if (CfgCheckCharForName(str[i]))
			{
				tmp[wp++] = str[i];
			}
			else
			{
				tmp[wp++] = '$';
				Format(tmp2, sizeof(tmp2), "%02X", (UINT)str[i]);
				tmp[wp++] = tmp2[0];
				tmp[wp++] = tmp2[1];
			}
		}
	}
	ret = Malloc(StrLen(tmp) + 1);
	StrCpy(ret, 0, tmp);
	Free(tmp);
	return ret;
}

bool CfgCheckCharForName(char c)
{
	if (c >= 0 && c <= 31)
	{
		return false;
	}
	if (c == ' ' || c == '\t')
	{
		return false;
	}
	if (c == '$')
	{
		return false;
	}
	return true;
}

bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size)
{
	wchar_t *tmp;
	UINT tmp_size;
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	tmp_size = size * 4 + 10;
	tmp = Malloc(tmp_size);
	if (CfgGetUniStr(f, name, tmp, tmp_size) == false)
	{
		Free(tmp);
		return false;
	}

	UniToStr(str, size, tmp);
	Free(tmp);

	return true;
}

bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size)
{
	ITEM *t;
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}
	if (t->Type != ITEM_TYPE_STRING)
	{
		return false;
	}
	UniStrCpy(str, size, t->Buf);
	return true;
}

bool CfgIsItem(FOLDER *f, char *name)
{
	ITEM *t;
	if (f == NULL || name == NULL)
	{
		return false;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return false;
	}

	return true;
}

BUF *CfgGetBuf(FOLDER *f, char *name)
{
	ITEM *t;
	BUF *b;
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return NULL;
	}

	b = NewBuf();
	WriteBuf(b, t->Buf, t->size);
	SeekBuf(b, 0, 0);

	return b;
}

UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size)
{
	ITEM *t;
	if (f == NULL || name == NULL || buf == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BYTE)
	{
		return 0;
	}
	if (t->size <= size)
	{
		Copy(buf, t->Buf, t->size);
		return t->size;
	}
	else
	{
		Copy(buf, t->Buf, size);
		return t->size;
	}
}

UINT64 CfgGetInt64(FOLDER *f, char *name)
{
	ITEM *t;
	UINT64 *ret;
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT64)
	{
		return 0;
	}
	if (t->size != sizeof(UINT64))
	{
		return 0;
	}

	ret = (UINT64 *)t->Buf;
	return *ret;
}

bool CfgGetBool(FOLDER *f, char *name)
{
	ITEM *t;
	bool *ret;
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_BOOL)
	{
		return 0;
	}
	if (t->size != sizeof(bool))
	{
		return 0;
	}

	ret = (bool *)t->Buf;
	if (*ret == false)
	{
		return false;
	}
	else
	{
		return true;
	}
}

UINT CfgGetInt(FOLDER *f, char *name)
{
	ITEM *t;
	UINT *ret;
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	t = CfgFindItem(f, name);
	if (t == NULL)
	{
		return 0;
	}
	if (t->Type != ITEM_TYPE_INT)
	{
		return 0;
	}
	if (t->size != sizeof(UINT))
	{
		return 0;
	}

	ret = (UINT *)t->Buf;
	return *ret;
}

ITEM *CfgFindItem(FOLDER *parent, char *name)
{
	ITEM *t, tt;
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	tt.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(tt.Name, 0, name);
	t = Search(parent->Items, &tt);
	Free(tt.Name);

	return t;
}

FOLDER *CfgFindFolder(FOLDER *parent, char *name)
{
	FOLDER *f, ff;
	if (parent == NULL || name == NULL)
	{
		return NULL;
	}

	ff.Name = ZeroMalloc(StrLen(name) + 1);
	StrCpy(ff.Name, 0, name);
	f = Search(parent->Folders, &ff);
	Free(ff.Name);

	return f;
}

ITEM *CfgAddStr(FOLDER *f, char *name, char *str)
{
	wchar_t *tmp;
	UINT tmp_size;
	ITEM *t;
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	tmp_size = CalcStrToUni(str);
	if (tmp_size == 0)
	{
		return NULL;
	}
	tmp = Malloc(tmp_size);
	StrToUni(tmp, tmp_size, str);
	t = CfgAddUniStr(f, name, tmp);
	Free(tmp);

	return t;
}

ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str)
{
	if (f == NULL || name == NULL || str == NULL)
	{
		return NULL;
	}

	return CfgCreateItem(f, name, ITEM_TYPE_STRING, str, UniStrSize(str));
}

ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b)
{
	if (f == NULL || name == NULL || b == NULL)
	{
		return NULL;
	}
	return CfgAddByte(f, name, b->Buf, b->Size);
}

ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size)
{
	if (f == NULL || name == NULL || buf == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_BYTE, buf, size);
}

ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i)
{
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT64, &i, sizeof(UINT64));
}

bool CfgGetIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	if (f == NULL || name == NULL || ip == NULL)
	{
		return false;
	}

	Zero(ip, sizeof(IP));

	if (CfgGetStr(f, name, tmp, sizeof(tmp)) == false)
	{
		return false;
	}

	if (StrToIP(ip, tmp) == false)
	{
		return false;
	}

	return true;
}
UINT CfgGetIp32(FOLDER *f, char *name)
{
	IP p;
	if (f == NULL || name == NULL)
	{
		return 0;
	}

	if (CfgGetIp(f, name, &p) == false)
	{
		return 0;
	}

	return IPToUINT(&p);
}
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	Zero(addr, sizeof(IPV6_ADDR));
	if (f == NULL || name == NULL || addr == NULL)
	{
		return false;
	}

	if (CfgGetIp(f, name, &ip) == false)
	{
		return false;
	}

	if (IsIP6(&ip) == false)
	{
		return false;
	}

	if (IPToIPv6Addr(addr, &ip) == false)
	{
		return false;
	}

	return true;
}

ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip)
{
	char tmp[MAX_SIZE];
	if (f == NULL || name == NULL || ip == NULL)
	{
		return NULL;
	}

	IPToStr(tmp, sizeof(tmp), ip);

	return CfgAddStr(f, name, tmp);
}
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip)
{
	IP p;
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	UINTToIP(&p, ip);

	return CfgAddIp(f, name, &p);
}
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr)
{
	IP ip;
	if (f == NULL || name == NULL || addr == NULL)
	{
		return NULL;
	}

	IPv6AddrToIP(&ip, addr);

	return CfgAddIp(f, name, &ip);
}

ITEM *CfgAddInt(FOLDER *f, char *name, UINT i)
{
	if (f == NULL || name == NULL)
	{
		return NULL;
	}
	return CfgCreateItem(f, name, ITEM_TYPE_INT, &i, sizeof(UINT));
}

ITEM *CfgAddBool(FOLDER *f, char *name, bool b)
{
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	return CfgCreateItem(f, name, ITEM_TYPE_BOOL, &b, sizeof(bool));
}

static int CmpItemName(void *p1, void *p2)
{
	ITEM *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(ITEM **)p1;
	f2 = *(ITEM **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

static int CmpFolderName(void *p1, void *p2)
{
	FOLDER *f1, *f2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	f1 = *(FOLDER **)p1;
	f2 = *(FOLDER **)p2;
	if (f1 == NULL || f2 == NULL)
	{
		return 0;
	}
	return StrCmpi(f1->Name, f2->Name);
}

void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param)
{
	UINT i;
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		ITEM *tt = LIST_DATA(f->Items, i);
		if (proc(tt, param) == false)
		{
			break;
		}
	}
}

TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Folders);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f)
{
	TOKEN_LIST *t, *ret;
	UINT i;
	if (f == NULL)
	{
		return NULL;
	}

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->NumTokens = LIST_NUM(f->Items);
	t->Token = ZeroMalloc(sizeof(char *) * t->NumTokens);

	for (i = 0;i < t->NumTokens;i++)
	{
		FOLDER *ff = LIST_DATA(f->Items, i);
		t->Token[i] = CopyStr(ff->Name);
	}

	ret = UniqueToken(t);
	FreeToken(t);

	return ret;
}

void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param)
{
	UINT i;
	if (f == NULL || proc == NULL)
	{
		return;
	}
	
	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		FOLDER *ff = LIST_DATA(f->Folders, i);
		if (proc(ff, param) == false)
		{
			break;
		}

		if ((i % 100) == 99)
		{
			YieldCpu();
		}
	}
}

ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size)
{
	UINT name_size;
	ITEM *t;
	if (parent == NULL || name == NULL || type == 0 || buf == NULL)
	{
		return NULL;
	}

	name_size = StrLen(name) + 1;

	t = ZeroMalloc(sizeof(ITEM));
	t->Buf = Malloc(size);
	Copy(t->Buf, buf, size);
	t->Name = ZeroMalloc(name_size);
	StrCpy(t->Name, 0, name);
	t->Type = type;
	t->size = size;
	t->Parent = parent;
	
	Insert(parent->Items, t);

	return t;
}

static void CfgDeleteItem(ITEM *t)
{
	if (t == NULL)
	{
		return;
	}

	Delete(t->Parent->Items, t);

	Free(t->Buf);
	Free(t->Name);
	Free(t);
}


void CfgDeleteFolder(FOLDER *f)
{
	FOLDER **ff;
	ITEM **tt;
	UINT num, i;
	if (f == NULL)
	{
		return;
	}

	if(f->Folders == NULL)
	{
		return;
	}

	num = LIST_NUM(f->Folders);
	if (num  != 0)
	{
		ff = Malloc(sizeof(FOLDER *) * num);
		Copy(ff, f->Folders->p, sizeof(FOLDER *) * num);
		for (i = 0;i < num;i++)
		{
			CfgDeleteFolder(ff[i]);
		}
		Free(ff);
	}

	num = LIST_NUM(f->Items);
	if (num != 0)
	{
		tt = Malloc(sizeof(ITEM *) * num);
		Copy(tt, f->Items->p, sizeof(ITEM *) * num);
		for (i = 0;i < num;i++)
		{
			CfgDeleteItem(tt[i]);
		}
		Free(tt);
	}

	Free(f->Name);
	if (f->Parent != NULL)
	{
		Delete(f->Parent->Folders, f);
	}
	ReleaseList(f->Folders);
	ReleaseList(f->Items);

	Free(f);
}

FOLDER *CfgCreateFolder(FOLDER *parent, char *name)
{
	UINT size;
	FOLDER *f;
	if (name == NULL)
	{
		return NULL;
	}

	size = StrLen(name) + 1;

	f = ZeroMalloc(sizeof(FOLDER));
	f->Items = NewListFast(CmpItemName);
	f->Folders = NewListFast(CmpFolderName);
	f->Name = ZeroMalloc(size);
	StrCpy(f->Name, 0, name);
	f->Parent = parent;

	if (f->Parent != NULL)
	{
		Insert(f->Parent->Folders, f);
	}
	return f;
}

