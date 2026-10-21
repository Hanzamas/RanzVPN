// Cfg.c
// Configuration information manipulation module

#include "Cfg.h"

#include "FileIO.h"
#include "Internat.h"
#include "IpAddr.h"
#include "Memory.h"
#include "Object.h"
#include "Str.h"

// Folders nest at most this deep. The text and binary readers recurse once per level, so a deeper
// file is rejected instead of running the stack out
#define	CFG_MAX_DEPTH				64

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
	CfgSaveExW(NULL, f, fullpath, NULL);
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

// True when the file exists and is not empty, also when another process holds it locked
static bool CfgFileHasDataW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	WIN32_FILE_ATTRIBUTE_DATA data;

	InnerFilePathW(tmp, sizeof(tmp), name);

	if (GetFileAttributesExW(tmp, GetFileExInfoStandard, &data) == FALSE)
	{
		return false;
	}

	return data.nFileSizeHigh != 0 || data.nFileSizeLow != 0;
}

// Rename a pending unreadable file to <name>.bad, replacing an older one. False while the file stays in place
static bool CfgRwRenameBadFile(CFG_RW *rw)
{
	wchar_t bad[MAX_SIZE];
	wchar_t src[MAX_SIZE];
	wchar_t dst[MAX_SIZE];

	if (rw->BadFilePending == false)
	{
		return true;
	}

	if (CfgFileHasDataW(rw->FileNameW))
	{
		UniFormat(bad, sizeof(bad), L"%s.bad", rw->FileNameW);
		InnerFilePathW(src, sizeof(src), rw->FileNameW);
		InnerFilePathW(dst, sizeof(dst), bad);

		if (MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == FALSE)
		{
			return false;
		}

		rw->BadFileRenamed = true;
	}

	rw->BadFilePending = false;

	return true;
}

// The file of rw exists but holds no usable configuration: rename it to <name>.bad before anything writes the
// file. When the rename fails, every save tries it again and writes nothing until it succeeds
void CfgRwSetAsideBadFile(CFG_RW *rw)
{
	if (rw == NULL)
	{
		return;
	}

	Lock(rw->lock);
	{
		if (rw->Io != NULL)
		{
			FileClose(rw->Io);
			rw->Io = NULL;
		}

		rw->BadFilePending = true;
		CfgRwRenameBadFile(rw);
	}
	Unlock(rw->lock);
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

		rw->SaveFailed = false;

		if (CfgRwRenameBadFile(rw) == false)
		{
			// The unreadable file is still in place: write nothing over it
			rw->SaveFailed = true;
		}
		else if (CfgSaveExW(rw, f, rw->FileNameW, &ret))
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
	if (cfg_name == NULL || root == NULL)
	{
		return NULL;
	}

	f = CfgReadW(cfg_name);

	rw = ZeroMalloc(sizeof(CFG_RW));
	rw->lock = NewLock();
	rw->FileNameW = CopyUniStr(cfg_name);
	rw->FileName = CopyUniToStr(cfg_name);
	rw->DontBackup = dont_backup;

	if (f != NULL)
	{
		rw->Io = FileOpenW(cfg_name, false);
		*root = f;

		return rw;
	}

	// A file with data that could not be read is renamed to <name>.bad before anything creates the file
	rw->BadFilePending = true;
	CfgRwRenameBadFile(rw);

	if (UniIsEmptyStr(template_name) == false)
	{
		f = CfgReadW(template_name);
	}

	if (rw->BadFilePending == false)
	{
		rw->Io = FileCreateW(cfg_name);
	}

	*root = f;

	return rw;
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

	b = ReadDumpExW(src, false, 0);
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

// Save the folder as a text configuration file. With rw, an unchanged tree (same hash as the
// last save) is not written again and false is returned.
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size)
{
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

	b = CfgFolderToBuf(f);
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

	if (ret)
	{
		// A failed write keeps the live file; the next save writes again
		if (CfgWriteFileReplace(name, b->Buf, b->Size))
		{
			wchar_t log_name[MAX_SIZE];

			// CfgReadW prefers a <name>.log left by an older save; the new file supersedes it
			UniFormat(log_name, sizeof(log_name), L"%s.log", name);
			FileDeleteW(log_name);
		}
		else
		{
			ret = false;

			if (rw != NULL)
			{
				Zero(rw->LashHash, sizeof(rw->LashHash));
				rw->SaveFailed = true;
			}
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
	bool read_ok;
	FOLDER *f;
	bool delete_new = false;
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
	// Read straight into the BUF; a failed read loads nothing, as a missing file does
	b = NewBuf();
	AdjustBufSize(b, size);
	read_ok = (size == 0 || FileRead(o, b->Buf, size));
	b->Size = size;

	FileClose(o);

	if (read_ok == false)
	{
		FreeBuf(b);
		return NULL;
	}

	if (delete_new)
	{
		FileDeleteW(newfile);
	}

	f = CfgBufToFolder(b, false);

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

// Read one line of the text format into current, a folder depth levels below the top. false at
// the closing brace of current or at the end of the data; *error set when a folder nests deeper
// than CFG_MAX_DEPTH. *open counts the declared folders whose closing brace has not been read yet.
static bool CfgReadNextTextBUF(BUF *b, FOLDER *current, UINT depth, bool *error, UINT *open)
{
	char *buf;
	TOKEN_LIST *token;
	char *name;
	char *string;
	char *data;
	bool ret;
	FOLDER *f;

	if (b == NULL || current == NULL || error == NULL || open == NULL)
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
				if (depth >= CFG_MAX_DEPTH)
				{
					*error = true;
				}
				else
				{
					name = CfgUnescape(token->Token[1]);

					f = CfgCreateFolder(current, name);
					(*open)++;

					while (true)
					{
						if (CfgReadNextTextBUF(b, f, depth + 1, error, open) == false)
						{
							break;
						}
					}

					Free(name);
				}

				if (*error)
				{
					FreeToken(token);
					Free(buf);
					return false;
				}
			}
		}
		if (!StrCmpi(token->Token[0], "}"))
		{
			if (*open != 0)
			{
				(*open)--;
			}
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

// Parse a text configuration. With require_closed, a folder whose closing brace is missing, as in a
// truncated file, gives NULL.
static FOLDER *CfgBufTextToFolderEx(BUF *b, bool require_closed)
{
	FOLDER *f, *c;
	UINT open = 0;
	bool error = false;
	if (b == NULL)
	{
		return NULL;
	}

	c = CfgCreateFolder(NULL, "tmp");

	while (true)
	{
		if (CfgReadNextTextBUF(b, c, 0, &error, &open) == false)
		{
			break;
		}
	}

	if (error)
	{
		CfgDeleteFolder(c);
		return NULL;
	}

	f = CfgFindFolder(c, TAG_ROOT);
	if (f == NULL || (require_closed && open != 0))
	{
		CfgDeleteFolder(c);
		return NULL;
	}

	Delete(c->Folders, f);
	f->Parent = NULL;

	CfgDeleteFolder(c);

	return f;
}

FOLDER *CfgBufTextToFolder(BUF *b)
{
	return CfgBufTextToFolderEx(b, false);
}

// Parse a configuration in either format. A buffer starting with "SEVPN_DB" is the binary format,
// whose stored SHA-0 must match the body; anything else is text, where require_closed rejects a
// truncated file. NULL when it does not parse.
FOLDER *CfgBufToFolder(BUF *b, bool require_closed)
{
	UCHAR hash[SHA1_SIZE];
	if (b == NULL)
	{
		return NULL;
	}

	if (b->Size < 8 || Cmp(b->Buf, TAG_BINARY, 8) != 0)
	{
		SeekBuf(b, 0, 0);
		return CfgBufTextToFolderEx(b, require_closed);
	}

	if (b->Size < 8 + SHA1_SIZE)
	{
		return NULL;
	}

	Sha0(hash, ((UCHAR *)b->Buf) + 8 + SHA1_SIZE, b->Size - 8 - SHA1_SIZE);
	if (Cmp(((UCHAR *)b->Buf) + 8, hash, SHA1_SIZE) != 0)
	{
		return NULL;
	}

	SeekBuf(b, 8 + SHA1_SIZE, 0);
	return CfgBufBinToFolder(b);
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

// Read one folder of the binary format into parent, a folder depth levels below the top. Every
// count and size is checked against the bytes left before it is used: false on a short or
// malformed input or a folder nested deeper than CFG_MAX_DEPTH, which leaves a partial tree under
// parent for the caller to delete
static bool CfgReadNextFolderBin(BUF *b, FOLDER *parent, UINT depth)
{
	char name[MAX_SIZE];
	FOLDER *f;
	UINT n, i;
	UINT size;
	UINT value;
	char *buf;
	wchar_t *string;
	if (b == NULL || parent == NULL || depth >= CFG_MAX_DEPTH)
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
		if (CfgReadNextFolderBin(b, f, depth + 1) == false)
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

	if (CfgReadNextFolderBin(b, c, 0) == false)
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

	CfgAddData(b, t->Type, t->Name, data, depth);

	Free(data);
}

// The escaped form of c, a character CfgCheckCharForName refuses: '$' and two upper-case hex digits
static void CfgEscapeChar(char c, char *dst)
{
	static char hex[] = "0123456789ABCDEF";

	dst[0] = '$';
	dst[1] = hex[((UCHAR)c >> 4) & 0x0F];
	dst[2] = hex[(UCHAR)c & 0x0F];
}

// Write str to b as CfgEscape escapes it, without a copy of the escaped string
static void CfgWriteEscaped(BUF *b, char *str)
{
	char esc[3];
	UINT len, start, i;

	len = StrLen(str);
	if (len == 0)
	{
		WriteBuf(b, "$", 1);
		return;
	}

	start = 0;
	for (i = 0;i < len;i++)
	{
		if (CfgCheckCharForName(str[i]) == false)
		{
			WriteBuf(b, str + start, i - start);
			CfgEscapeChar(str[i], esc);
			WriteBuf(b, esc, sizeof(esc));
			start = i + 1;
		}
	}
	WriteBuf(b, str + start, len - start);
}

static void CfgAddIndent(BUF *b, UINT depth)
{
	UINT i;

	for (i = 0;i < depth;i++)
	{
		WriteBuf(b, "\t", 1);
	}
}

// The line "<type> <name> <data>" with the escaped name and data written straight into b
void CfgAddData(BUF *b, UINT type, char *name, char *data, UINT depth)
{
	char *type_str;
	if (b == NULL || type == 0 || name == NULL || data == NULL)
	{
		return;
	}

	type_str = CfgTypeToStr(type);

	CfgAddIndent(b, depth);
	WriteBuf(b, type_str, StrLen(type_str));
	WriteBuf(b, " ", 1);
	CfgWriteEscaped(b, name);
	WriteBuf(b, " ", 1);
	CfgWriteEscaped(b, data);
	WriteBuf(b, "\r\n", 2);
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
	if (b == NULL)
	{
		return;
	}

	CfgAddIndent(b, depth);
	WriteBuf(b, str, StrLen(str));
	WriteBuf(b, "\r\n", 2);
}

// Write the folder as a text configuration: the banner, then the tree
BUF *CfgFolderToBuf(FOLDER *f)
{
	BUF *b;
	if (f == NULL)
	{
		return NULL;
	}

	b = NewBuf();

	WriteBuf(b, TAG_CPYRIGHT, StrLen(TAG_CPYRIGHT));

	CfgOutputFolderText(b, f, 0);

	return b;
}

// Unescape str into dst when dst is not NULL, without a terminator. Returns the length of the
// result, which ends at the first character that unescapes to 0. A lone '$' is the empty string.
static UINT CfgUnescapeTo(char *str, char *dst)
{
	char tmp2[8];
	UINT len, wp, i;
	char c;

	len = StrLen(str);
	if (len == 1 && str[0] == '$')
	{
		return 0;
	}

	wp = 0;
	for (i = 0;i < len;i++)
	{
		c = str[i];
		if (c == '$')
		{
			tmp2[0] = '0';
			tmp2[1] = 'x';
			tmp2[2] = str[i + 1];
			// A '$' at the end of the string has no digits: do not read past its null
			tmp2[3] = (tmp2[2] != 0) ? str[i + 2] : 0;
			i += 2;
			tmp2[4] = 0;
			c = (char)ToInt(tmp2);
			if (c == 0)
			{
				break;
			}
		}
		if (dst != NULL)
		{
			dst[wp] = c;
		}
		wp++;
	}

	return wp;
}

char *CfgUnescape(char *str)
{
	char *ret;
	UINT len;
	if (str == NULL)
	{
		return NULL;
	}

	// Size the result in a first pass, then allocate it once
	len = CfgUnescapeTo(str, NULL);
	ret = Malloc(len + 1);
	CfgUnescapeTo(str, ret);
	ret[len] = 0;

	return ret;
}

// Escape str into dst when dst is not NULL, without a terminator, and return the escaped length.
// A character CfgCheckCharForName refuses becomes '$' and two hex digits; "" becomes a lone '$'.
static UINT CfgEscapeTo(char *str, char *dst)
{
	UINT len, wp, i;

	len = StrLen(str);
	if (len == 0)
	{
		if (dst != NULL)
		{
			dst[0] = '$';
		}
		return 1;
	}

	wp = 0;
	for (i = 0;i < len;i++)
	{
		if (CfgCheckCharForName(str[i]))
		{
			if (dst != NULL)
			{
				dst[wp] = str[i];
			}
			wp++;
		}
		else
		{
			if (dst != NULL)
			{
				CfgEscapeChar(str[i], dst + wp);
			}
			wp += 3;
		}
	}

	return wp;
}

char *CfgEscape(char *str)
{
	char *ret;
	UINT len;
	if (str == NULL)
	{
		return NULL;
	}

	// Size the result in a first pass, then allocate it once
	len = CfgEscapeTo(str, NULL);
	ret = Malloc(len + 1);
	CfgEscapeTo(str, ret);
	ret[len] = 0;

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
	ITEM *t;
	if (f == NULL || name == NULL || str == NULL)
	{
		return false;
	}

	str[0] = 0;

	t = CfgFindItem(f, name);
	if (t == NULL || t->Type != ITEM_TYPE_STRING)
	{
		return false;
	}

	// Convert the stored string straight into the caller's buffer
	UniToStr(str, size, t->Buf);

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

// The value of the item called name when it has the given type and size, else NULL
static void *CfgFindValue(FOLDER *f, char *name, UINT type, UINT size)
{
	ITEM *t;
	if (f == NULL || name == NULL)
	{
		return NULL;
	}

	t = CfgFindItem(f, name);
	if (t == NULL || t->Type != type || t->size != size)
	{
		return NULL;
	}

	return t->Buf;
}

UINT64 CfgGetInt64(FOLDER *f, char *name)
{
	UINT64 *ret = CfgFindValue(f, name, ITEM_TYPE_INT64, sizeof(UINT64));
	if (ret == NULL)
	{
		return 0;
	}

	return *ret;
}

bool CfgGetBool(FOLDER *f, char *name)
{
	bool *ret = CfgFindValue(f, name, ITEM_TYPE_BOOL, sizeof(bool));
	if (ret == NULL || *ret == false)
	{
		return false;
	}

	return true;
}

UINT CfgGetInt(FOLDER *f, char *name)
{
	UINT *ret = CfgFindValue(f, name, ITEM_TYPE_INT, sizeof(UINT));
	if (ret == NULL)
	{
		return 0;
	}

	return *ret;
}

// The entry called name in an Items or Folders list. The key is a char * that CfgCmpName reads
// as it reads the Name, the first member of an ITEM and a FOLDER.
static void *CfgFindByName(LIST *o, char *name)
{
	if (o == NULL || name == NULL)
	{
		return NULL;
	}

	// The caller's pointer is the key: the search only reads it
	return Search(o, &name);
}

ITEM *CfgFindItem(FOLDER *parent, char *name)
{
	if (parent == NULL)
	{
		return NULL;
	}

	return CfgFindByName(parent->Items, name);
}

FOLDER *CfgFindFolder(FOLDER *parent, char *name)
{
	if (parent == NULL)
	{
		return NULL;
	}

	return CfgFindByName(parent->Folders, name);
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

// The Name of an entry of an Items or Folders list. Name is the first member of both ITEM and
// FOLDER, and a pointer to a structure points to its first member, so this reads either.
static char *CfgEntryName(void *p)
{
	return *(char **)p;
}

// Comparator of the Items and the Folders lists: case-insensitive by Name
static int CfgCmpName(void *p1, void *p2)
{
	void *e1, *e2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	e1 = *(void **)p1;
	e2 = *(void **)p2;
	if (e1 == NULL || e2 == NULL)
	{
		return 0;
	}
	return StrCmpi(CfgEntryName(e1), CfgEntryName(e2));
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

// The names of an Items or Folders list, each case-insensitive name once. Insert() keeps the list
// sorted by CfgCmpName, so names equal but for case are adjacent: one pass against the last kept
// name drops them and keeps the first, as the old O(N^2) scan did.
static TOKEN_LIST *CfgNamesToTokenList(LIST *o)
{
	TOKEN_LIST *t;
	char *last = NULL;
	UINT i;

	t = ZeroMalloc(sizeof(TOKEN_LIST));
	t->Token = ZeroMalloc(sizeof(char *) * LIST_NUM(o));

	for (i = 0;i < LIST_NUM(o);i++)
	{
		char *name = CfgEntryName(LIST_DATA(o, i));
		if (last != NULL && StrCmpi(last, name) == 0)
		{
			continue;
		}

		t->Token[t->NumTokens++] = CopyStr(name);
		last = name;
	}

	return t;
}

TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f)
{
	if (f == NULL)
	{
		return NULL;
	}

	return CfgNamesToTokenList(f->Folders);
}

TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f)
{
	if (f == NULL)
	{
		return NULL;
	}

	return CfgNamesToTokenList(f->Items);
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

// Free f with its subfolders and items. The children are not taken out of f's lists one by
// one: the lists go whole with f, so freeing n children costs O(n). The caller detaches f.
static void CfgFreeFolderTree(FOLDER *f)
{
	UINT i;

	for (i = 0;i < LIST_NUM(f->Folders);i++)
	{
		CfgFreeFolderTree(LIST_DATA(f->Folders, i));
	}

	for (i = 0;i < LIST_NUM(f->Items);i++)
	{
		ITEM *t = LIST_DATA(f->Items, i);

		Free(t->Buf);
		Free(t->Name);
		Free(t);
	}

	ReleaseList(f->Folders);
	ReleaseList(f->Items);
	Free(f->Name);
	Free(f);
}

void CfgDeleteFolder(FOLDER *f)
{
	if (f == NULL)
	{
		return;
	}

	if(f->Folders == NULL)
	{
		return;
	}

	if (f->Parent != NULL)
	{
		Delete(f->Parent->Folders, f);
	}

	CfgFreeFolderTree(f);
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
	f->Items = NewListFast(CfgCmpName);
	f->Folders = NewListFast(CfgCmpName);
	f->Name = ZeroMalloc(size);
	StrCpy(f->Name, 0, name);
	f->Parent = parent;

	if (f->Parent != NULL)
	{
		Insert(f->Parent->Folders, f);
	}
	return f;
}

