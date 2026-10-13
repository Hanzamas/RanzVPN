// SoftEther VPN Source Code - Developer Edition Master Branch
// Mayaqua Kernel


// FileIO.c
// File Input / Output code

#include "FileIO.h"

#include "Cfg.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Str.h"
#include "Tick64.h"
#include "Tracking.h"
#include "Win32.h"

#include <Hamcore.h>

static char exe_file_name[MAX_SIZE] = "/tmp/a.out";
static wchar_t exe_file_name_w[MAX_SIZE] = L"/tmp/a.out";
static LIST *hamcore = NULL;
static HAMCORE *hamcore_io = NULL;

#define	NUM_CRC32_TABLE	256
static UINT crc32_table[NUM_CRC32_TABLE];

// Append a file footer
void ZipAddFileFooter(ZIP_PACKER *p)
{
	ZIP_DATA_FOOTER f;
	// Validate arguments
	if (p == NULL)
	{
		return;
	}

	Zero(&f, sizeof(f));
	WriteZipDataFooter(p->CurrentFile, &f);

	WriteFifo(p->Fifo, &f, sizeof(f));
}

// Creating a ZIP data header
void WriteZipDataHeader(ZIP_FILE *f, ZIP_DATA_HEADER *h, bool write_sizes)
{
	// Validate arguments
	if (f == NULL || h ==NULL)
	{
		return;
	}

	h->Signature = Endian32(Swap32(ZIP_SIGNATURE));
	h->NeedVer = Endian16(Swap16(ZIP_VERSION));
	h->CompType = 0;
	h->FileDate = Endian16(Swap16(System64ToDosDate(f->DateTime)));
	h->FileTime = Endian16(Swap16(System64ToDosTime(f->DateTime)));
	h->Option = Endian16(Swap16(8)); // bit3: Set the file-size and the CRC in local header to 0

	if (write_sizes == false)
	{
		h->CompSize = h->UncompSize = 0;
		h->Crc32 = 0;
	}
	else
	{
		h->CompSize = h->UncompSize = Endian32(Swap32(f->Size));
		h->Crc32 = Endian32(Swap32(f->Crc32));
	}

	h->FileNameLen = Endian16(Swap16(StrLen(f->Name)));
	h->ExtraLen = 0;
}

// Creating a ZIP data footer
void WriteZipDataFooter(ZIP_FILE *f, ZIP_DATA_FOOTER *h)
{
	// Validate arguments
	if (f == NULL || h ==NULL)
	{
		return;
	}

	h->Signature = Endian32(Swap32(0x08074B50));
	h->CompSize = h->UncompSize = Endian32(Swap32(f->Size));
	h->Crc32 = Endian32(Swap32(f->Crc32));
}

// Initialize the common table of CRC32
void InitCrc32()
{
	UINT poly = 0xEDB88320;
	UINT u, i, j;

	for (i = 0;i < 256;i++)
	{
		u = i;

		for (j = 0;j < 8;j++)
		{
			if ((u & 0x1) != 0)
			{
				u = (u >> 1) ^ poly;
			}
			else
			{
				u >>= 1;
			}
		}

		crc32_table[i] = u;
	}
}

// CRC32 arithmetic processing
UINT Crc32(void *buf, UINT pos, UINT len)
{
	return Crc32Finish(Crc32Next(buf, pos, len, 0xffffffff));
}
UINT Crc32Next(void *buf, UINT pos, UINT len, UINT last_crc32)
{
	UINT ret = last_crc32;
	UINT i;

	for (i = 0;i < len;i++)
	{
		ret = (ret >> 8) ^ crc32_table[((UCHAR *)buf)[pos + i] ^ (ret & 0xff)];
	}

	return ret;
}
UINT Crc32Finish(UINT last_crc32)
{
	return ~last_crc32;
}

// Check whether the file exists
bool IsFile(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileW(wchar_t *name)
{
	IO *io;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	io = FileOpenExW(name, false, false);
	if (io == NULL)
	{
		return false;
	}

	FileClose(io);

	return true;
}

// Make the file name safe
void ConvertSafeFileName(char *dst, UINT size, char *src)
{
	UINT i;
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	StrCpy(dst, size, src);
	for (i = 0;i < StrLen(dst);i++)
	{
		if (IsSafeChar(dst[i]) == false)
		{
			dst[i] = '_';
		}
	}
}

// Get the free disk space
bool GetDiskFree(char *path, UINT64 *free_size, UINT64 *used_size, UINT64 *total_size)
{
	bool ret;
	// Validate arguments
	if (path == NULL)
	{
		path = "./";
	}

	ret = Win32GetDiskFree(path, free_size, used_size, total_size);

	return ret;
}

// Enumeration of directory
DIRLIST *EnumDirEx(char *dirname, COMPARE *compare)
{
	wchar_t *dirname_w = CopyStrToUni(dirname);
	DIRLIST *ret = EnumDirExW(dirname_w, compare);

	Free(dirname_w);

	return ret;
}
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare)
{
	DIRLIST *d = NULL;
	// Validate arguments
	if (dirname == NULL)
	{
		dirname = L"./";
	}

	if (compare == NULL)
	{
		compare = CompareDirListByName;
	}

	d = Win32EnumDirExW(dirname, compare);

	return d;
}
DIRLIST *EnumDir(char *dirname)
{
	return EnumDirEx(dirname, NULL);
}
DIRLIST *EnumDirW(wchar_t *dirname)
{
	return EnumDirExW(dirname, NULL);
}

// Comparison of DIRLIST list entry
int CompareDirListByName(void *p1, void *p2)
{
	DIRENT *d1, *d2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	d1 = *(DIRENT **)p1;
	d2 = *(DIRENT **)p2;
	if (d1 == NULL || d2 == NULL)
	{
		return 0;
	}
	return UniStrCmpi(d1->FileNameW, d2->FileNameW);
}

// Release the enumeration of the directory 
void FreeDir(DIRLIST *d)
{
	UINT i;
	// Validate arguments
	if (d == NULL)
	{
		return;
	}

	for (i = 0;i < d->NumFiles;i++)
	{
		DIRENT *f = d->File[i];
		Free(f->FileName);
		Free(f->FileNameW);
		Free(f);
	}
	Free(d->File);
	Free(d);
}


// Read HamCore file
BUF *ReadHamcoreW(wchar_t *filename)
{
	char *filename_a = CopyUniToStr(filename);
	BUF *ret;

	ret = ReadHamcore(filename_a);

	Free(filename_a);

	return ret;
}
BUF *ReadHamcore(char *name)
{
	if (name == NULL || MayaquaIsMinimalMode())
	{
		return NULL;
	}

	if (name[0] == '/')
	{
		++name;
	}

	char path[MAX_PATH];
	GetExeDir(path, sizeof(path));
	Format(path, sizeof(path), "%s/%s/%s", path, HAMCORE_DIR_NAME, name);

	BUF *buf = ReadDump(path);
	if (buf != NULL)
	{
		return buf;
	}

	LockList(hamcore);
	{
		HC t = {0};
		t.Path = name;
		HC *c = Search(hamcore, &t);
		if (c == NULL)
		{
			const HAMCORE_FILE *file = HamcoreFind(hamcore_io, name);
			if (file)
			{
				c = Malloc(sizeof(HC));
				c->Size = file->OriginalSize;
				c->Path = CopyStr(name);
				c->Buffer = Malloc(c->Size);

				if (HamcoreRead(hamcore_io, c->Buffer, file))
				{
					Add(hamcore, c);
				}
				else
				{
					Free(c->Buffer);
					Free(c->Path);
					Free(c);

					c = NULL;
				}
			}
		}

		if (c != NULL)
		{
			buf = NewBuf();
			WriteBuf(buf, c->Buffer, c->Size);
			SeekBuf(buf, 0, 0);
			c->LastAccess = Tick64();
		}

		LIST *to_delete = NewListFast(NULL);

		for (UINT i = 0; i < LIST_NUM(hamcore); ++i)
		{
			HC *c = LIST_DATA(hamcore, i);
			if (c->LastAccess + HAMCORE_CACHE_EXPIRES <= Tick64())
			{
				Add(to_delete, c);
			}
		}

		for (UINT i = 0; i < LIST_NUM(to_delete); ++i)
		{
			HC *c = LIST_DATA(to_delete, i);

			Delete(hamcore, c);

			Free(c->Buffer);
			Free(c->Path);
			Free(c);
		}

		ReleaseList(to_delete);
	}
	UnlockList(hamcore);

	return buf;
}

// Initialization of HamCore file system
void InitHamcore()
{
	if (MayaquaIsMinimalMode())
	{
		return;
	}

	hamcore = NewList(CompareHamcore);
#ifdef HAMCORE_FILE_PATH
	hamcore_io = HamcoreOpen(HAMCORE_FILE_PATH);
	if (hamcore_io != NULL)
	{
		return;
	}
#endif
	char path[MAX_PATH];
	GetExeDir(path, sizeof(path));
	Format(path, sizeof(path), "%s/%s", path, HAMCORE_FILE_NAME);

	hamcore_io = HamcoreOpen(path);
	if (hamcore_io != NULL)
	{
	}
}

// Release of HamCore file system
void FreeHamcore()
{
	for (UINT i = 0; i < LIST_NUM(hamcore); ++i)
	{
		HC *c = LIST_DATA(hamcore, i);

		Free(c->Buffer);
		Free(c->Path);
		Free(c);
	}
	ReleaseList(hamcore);

	HamcoreClose(hamcore_io);
	hamcore_io = NULL;
	hamcore = NULL;
}

// Comparison of the HCs
int CompareHamcore(void *p1, void *p2)
{
	HC *c1, *c2;
	if (p1 == NULL || p2 == NULL)
	{
		return 0;
	}
	c1 = *(HC **)p1;
	c2 = *(HC **)p2;
	if (c1 == NULL || c2 == NULL)
	{
		return 0;
	}
	return StrCmpi(c1->Path, c2->Path);
}

// Getting the name of the directory where the EXE file is in
void GetExeDir(char *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePath(name, size, exe_file_name);
}
void GetExeDirW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	GetDirNameFromFilePathW(name, size, exe_file_name_w);
}

// Get the EXE file name
void GetExeName(char *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	StrCpy(name, size, exe_file_name);
}
void GetExeNameW(wchar_t *name, UINT size)
{
	// Validate arguments
	if (name == NULL)
	{
		return;
	}

	UniStrCpy(name, size, exe_file_name_w);
}

void GetLogDir(char *name, UINT size)
{
	GetExeDir(name, size);
}

void GetDbDirW(wchar_t *name, UINT size)
{
	GetExeDirW(name, size);
}

// Initialization of the acquisition of the EXE file name
void InitGetExeName(char *arg)
{
	wchar_t *arg_w = NULL;
	// Validate arguments
	if (arg == NULL)
	{
		arg = "./a.out";
	}

	arg_w = CopyUtfToUni(arg);

	Win32GetExeNameW(exe_file_name_w, sizeof(exe_file_name_w));

	UniToStr(exe_file_name, sizeof(exe_file_name), exe_file_name_w);

	Free(arg_w);
}

// Get the file name from the file path
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT i, len, wp;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	len = MIN(StrLen(filepath), (MAX_SIZE - 2));
	wp = 0;

	for (i = 0;i < (len + 1);i++)
	{
		char c = filepath[i];

		switch (c)
		{
		case '\\':
		case '/':
		case 0:
			tmp[wp] = 0;
			wp = 0;
			break;

		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}

	StrCpy(dst, size, tmp);
}
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath)
{
	wchar_t tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	UniStrCpy(tmp, sizeof(tmp), filepath);
	if (UniEndWith(tmp, L"\\") || UniEndWith(tmp, L"/"))
	{
		tmp[UniStrLen(tmp) - 1] = 0;
	}

	len = UniStrLen(tmp);

	UniStrCpy(dst, size, L"");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		wchar_t c = tmp[i];
		if (c == L'/' || c == L'\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (UniStrLen(dst) == 0)
	{
		UniStrCpy(dst, size, L"/");
	}

	NormalizePathW(dst, size, dst);
}

// Get the directory name from the file path
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath)
{
	char tmp[MAX_SIZE];
	UINT wp;
	UINT i;
	UINT len;
	// Validate arguments
	if (dst == NULL || filepath == NULL)
	{
		return;
	}

	StrCpy(tmp, sizeof(tmp), filepath);
	if (EndWith(tmp, "\\") || EndWith(tmp, "/"))
	{
		tmp[StrLen(tmp) - 1] = 0;
	}

	len = StrLen(tmp);

	StrCpy(dst, size, "");

	wp = 0;

	for (i = 0;i < len;i++)
	{
		char c = tmp[i];
		if (c == '/' || c == '\\')
		{
			tmp[wp++] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			tmp[wp++] = c;
		}
		else
		{
			tmp[wp++] = c;
		}
	}

	if (StrLen(dst) == 0)
	{
		StrCpy(dst, size, "/");
	}

	NormalizePath(dst, size, dst);
}

// Combine the two paths
void ConbinePath(char *dst, UINT size, char *dirname, char *filename)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *dirname_w = CopyStrToUni(dirname);
	wchar_t *filename_w = CopyStrToUni(filename);

	ConbinePathW(dst_w, sizeof(dst_w), dirname_w, filename_w);

	Free(dirname_w);
	Free(filename_w);

	UniToStr(dst, size, dst_w);
}
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	bool is_full_path;
	wchar_t tmp[MAX_SIZE];
	wchar_t filename_ident[MAX_SIZE];
	// Validate arguments
	if (dst == NULL || dirname == NULL || filename == NULL)
	{
		return;
	}

	NormalizePathW(filename_ident, sizeof(filename_ident), filename);

	is_full_path = false;

	if (UniStartWith(filename_ident, L"\\") || UniStartWith(filename_ident, L"/"))
	{
		is_full_path = true;
	}

	filename = &filename_ident[0];

	if (UniStrLen(filename) >= 2)
	{
		if ((L'a' <= filename[0] && filename[0] <= L'z') || (L'A' <= filename[0] && filename[0] <= L'Z'))
		{
			if (filename[1] == L':')
			{
				is_full_path = true;
			}
		}
	}

	if (is_full_path == false)
	{
		UniStrCpy(tmp, sizeof(tmp), dirname);
		if (UniEndWith(tmp, L"/") == false && UniEndWith(tmp, L"\\") == false)
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
		UniStrCat(tmp, sizeof(tmp), filename);
	}
	else
	{
		UniStrCpy(tmp, sizeof(tmp), filename);
	}

	NormalizePathW(dst, size, tmp);
}
void CombinePath(char *dst, UINT size, char *dirname, char *filename)
{
	ConbinePath(dst, size, dirname, filename);
}
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename)
{
	ConbinePathW(dst, size, dirname, filename);
}

// Check whether the file exists
bool IsFileExists(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return IsFileExistsInnerW(tmp);
}
bool IsFileExistsInnerW(wchar_t *name)
{
	IO *o;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	o = FileOpenInnerW(name, false, false);
	if (o == NULL)
	{
		return false;
	}

	FileClose(o);

	return true;
}

// Normalize the file path
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	wchar_t tmp[MAX_SIZE];
	UNI_TOKEN_LIST *t;
	bool first_double_slash = false;
	bool first_single_slash = false;
	wchar_t win32_drive_char = 0;
	bool is_full_path = false;
	UINT i;
	SK *sk;
	// Validate arguments
	if (dst == NULL || src == 0)
	{
		return;
	}

	// Convert the path (Win32, UNIX conversion)
	UniStrCpy(tmp, sizeof(tmp), src);
	ConvertPathW(tmp);
	UniTrim(tmp);

	// If the path begins with "./ " or " ../", replace it to the current directory
	if (UniStartWith(tmp, L"./") || UniStartWith(tmp, L".\\") ||
		UniStartWith(tmp, L"../") || UniStartWith(tmp, L"..\\") ||
		UniStrCmpi(tmp, L".") == 0 || UniStrCmpi(tmp, L"..") == 0)
	{
		wchar_t cd[MAX_SIZE];
		Zero(cd, sizeof(cd));

		Win32GetCurrentDirW(cd, sizeof(cd));

		if (UniStartWith(tmp, L".."))
		{
			UniStrCat(cd, sizeof(cd), L"/../");
			UniStrCat(cd, sizeof(cd), tmp + 2);
		}
		else
		{
			UniStrCat(cd, sizeof(cd), L"/");
			UniStrCat(cd, sizeof(cd), tmp);
		}

		UniStrCpy(tmp, sizeof(tmp), cd);
	}

	// If the path starts with "~/", replace it with the home directory
	if (UniStartWith(tmp, L"~/") || UniStartWith(tmp, L"~\\"))
	{
		wchar_t tmp2[MAX_SIZE];
		GetHomeDirW(tmp2, sizeof(tmp2));
		UniStrCat(tmp2, sizeof(tmp2), L"/");
		UniStrCat(tmp2, sizeof(tmp2), tmp + 2);
		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	if (UniStartWith(tmp, L"//") || UniStartWith(tmp, L"\\\\"))
	{
        // Begin with "//" or "\\"
		first_double_slash = true;
		is_full_path = true;
	}
	else if (UniStartWith(tmp, L"/") || UniStartWith(tmp, L"\\"))
	{
		// Begin with "\"
		first_single_slash = true;
		is_full_path = true;
	}

	if (UniStrLen(tmp) >= 2)
	{
		if (tmp[1] == L':')
		{
			// The drive string representation of the Win32
			wchar_t tmp2[MAX_SIZE];
			is_full_path = true;
			win32_drive_char = tmp[0];
			UniStrCpy(tmp2, sizeof(tmp2), tmp + 2);
			UniStrCpy(tmp, sizeof(tmp), tmp2);
		}
	}

	if (UniStrLen(tmp) == 1 && (tmp[0] == L'/' || tmp[0] == L'\\'))
	{
		tmp[0] = 0;
	}

	// Tokenize
	t = UniParseToken(tmp, L"/\\");

	sk = NewSk();

	for (i = 0;i < t->NumTokens;i++)
	{
		wchar_t *s = t->Token[i];

		if (UniStrCmpi(s, L".") == 0)
		{
			continue;
		}
		else if (UniStrCmpi(s, L"..") == 0)
		{
			if (sk->num_item >= 1 && (first_double_slash == false || sk->num_item >= 2))
			{
				Pop(sk);
			}
		}
		else
		{
			Push(sk, s);
		}
	}

	// Token concatenation
	UniStrCpy(tmp, sizeof(tmp), L"");

	if (first_double_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"//");
	}
	else if (first_single_slash)
	{
		UniStrCat(tmp, sizeof(tmp), L"/");
	}

	if (win32_drive_char != 0)
	{
		wchar_t d[2];
		d[0] = win32_drive_char;
		d[1] = 0;
		UniStrCat(tmp, sizeof(tmp), d);
		UniStrCat(tmp, sizeof(tmp), L":/");
	}

	for (i = 0;i < sk->num_item;i++)
	{
		UniStrCat(tmp, sizeof(tmp), (wchar_t *)sk->p[i]);
		if (i != (sk->num_item - 1))
		{
			UniStrCat(tmp, sizeof(tmp), L"/");
		}
	}

	ReleaseSk(sk);

	UniFreeToken(t);

	ConvertPathW(tmp);

	UniStrCpy(dst, size, tmp);
}
void NormalizePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_SIZE];
	wchar_t *src_w = CopyStrToUni(src);

	NormalizePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// Rename the file
bool FileRenameW(wchar_t *old_name, wchar_t *new_name)
{
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp1, sizeof(tmp1), old_name);
	InnerFilePathW(tmp2, sizeof(tmp2), new_name);

	return FileRenameInnerW(tmp1, tmp2);
}
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name)
{
	// Validate arguments
	if (old_name == NULL || new_name == NULL)
	{
		return false;
	}

	return OSFileRenameW(old_name, new_name);
}

// Convert the path
void ConvertPathW(wchar_t *path)
{
	UINT i, len;
	wchar_t new_char = L'\\';

	len = UniStrLen(path);
	for (i = 0;i < len;i++)
	{
		if (path[i] == L'\\' || path[i] == L'/')
		{
			path[i] = new_char;
		}
	}
}

// Delete the directory
bool DeleteDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = DeleteDirW(name_w);

	Free(name_w);

	return ret;
}
bool DeleteDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return DeleteDirInnerW(tmp);
}
bool DeleteDirInnerW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return OSDeleteDirW(name);
}

// Generation of internal file path
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src)
{
	// Validate arguments
	if (dst == NULL || src == NULL)
	{
		return;
	}

	if (src[0] == L'@')
	{
		wchar_t dir[MAX_SIZE];
		GetExeDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
	else if (src[0] == L'$')
	{
		wchar_t dir[MAX_SIZE];
		GetDbDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	}
	else
	{
		NormalizePathW(dst, size, src);
	}
}
void InnerFilePath(char *dst, UINT size, char *src)
{
	wchar_t dst_w[MAX_PATH];
	wchar_t *src_w = CopyStrToUni(src);

	InnerFilePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

// Recursive directory creation
bool MakeDirEx(char *name)
{
	bool ret;
	wchar_t *name_w = CopyStrToUni(name);

	ret = MakeDirExW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirExW(wchar_t *name)
{
	LIST *o;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	UINT i;
	bool ret = false;
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	o = NewListFast(NULL);

	UniStrCpy(tmp, sizeof(tmp), name);
	while (true)
	{
		wchar_t *s = CopyUniStr(tmp);

		Add(o, s);

		GetDirNameFromFilePathW(tmp2, sizeof(tmp2), tmp);

		if (UniStrCmpi(tmp2, tmp) == 0)
		{
			break;
		}

		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	for (i = 0;i < LIST_NUM(o);i++)
	{
		UINT j = LIST_NUM(o) - i - 1;
		wchar_t *s = LIST_DATA(o, j);

		if (UniStrCmpi(s, L"\\") != 0 && UniStrCmpi(s, L"/") != 0)
		{
			ret = MakeDirW(s);
		}
	}

	UniFreeStrList(o);

	return ret;
}

// Create a directory
bool MakeDir(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return MakeDirInnerW(tmp);
}
bool MakeDirInnerW(wchar_t *name)
{
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	return OSMakeDirW(name);
}

// Delete the file
bool FileDelete(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileDeleteInnerW(tmp);
}
bool FileDeleteInnerW(wchar_t *name)
{
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return false;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	return OSFileDeleteW(name2);
}

// Seek the file
bool FileSeek(IO *o, UINT mode, int offset)
{
	// Validate arguments
	if (o == NULL)
	{
		return false;
	}

	if (o->HamMode == false)
	{
		return OSFileSeek(o->pData, mode, offset);
	}
	else
	{
		return false;
	}
}

// Get the file size
UINT64 FileSize64(IO *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return 0;
	}

	if (o->HamMode == false)
	{
		return OSFileSize(o->pData);
	}
	else
	{
		return (UINT64)o->HamBuf->Size;
	}
}
UINT FileSize(IO *o)
{
	UINT64 size = (UINT)(FileSize64(o));

	if (size >= 4294967296ULL)
	{
		size = 4294967295ULL;
	}

	return (UINT)size;
}

// Read from a file
bool FileRead(IO *o, void *buf, UINT size)
{
	// Validate arguments
	if (o == NULL || buf == NULL)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_READ_COUNT);
	KS_ADD(KS_IO_TOTAL_READ_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	if (o->HamMode == false)
	{
		return OSFileRead(o->pData, buf, size);
	}
	else
	{
		return ReadBuf(o->HamBuf, buf, size) == size ? true : false;
	}
}

// Write to a file
bool FileWrite(IO *o, void *buf, UINT size)
{
	// Validate arguments
	if (o == NULL || buf == NULL)
	{
		return false;
	}
	if (o->WriteMode == false)
	{
		return false;
	}

	// KS
	KS_INC(KS_IO_WRITE_COUNT);
	KS_ADD(KS_IO_TOTAL_WRITE_SIZE, size);

	if (size == 0)
	{
		return true;
	}

	return OSFileWrite(o->pData, buf, size);
}

// Flush the file
void FileFlush(IO *o)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode)
	{
		return;
	}

	OSFileFlush(o->pData);
}

// Close the file
void FileClose(IO *o)
{
	FileCloseEx(o, false);
}
void FileCloseEx(IO *o, bool no_flush)
{
	// Validate arguments
	if (o == NULL)
	{
		return;
	}

	if (o->HamMode == false)
	{
		if (o->WriteMode)
		{
			Win32FileSetDate(o->pData, o->SetCreateTime, o->SetUpdateTime);
		}

		OSFileClose(o->pData, no_flush);
	}
	else
	{
		FreeBuf(o->HamBuf);
	}
	Free(o);

	// KS
	KS_INC(KS_IO_CLOSE_COUNT);
}

// Create a file
IO *FileCreateInnerW(wchar_t *name)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileCreateW(name2);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = true;

	// KS
	KS_INC(KS_IO_CREATE_COUNT);

	return o;
}
IO *FileCreate(char *name)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateW(wchar_t *name)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileCreateInnerW(tmp);
}

// Open the file
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock)
{
	IO *o;
	void *p;
	wchar_t name2[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	p = OSFileOpenW(name2, write_mode, read_lock);
	if (p == NULL)
	{
		return NULL;
	}

	o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = write_mode;

	Win32FileGetDate(p, &o->GetCreateTime, &o->GetUpdateTime, &o->GetAccessTime);

	// KS
	KS_INC(KS_IO_OPEN_COUNT);

	return o;
}
IO *FileOpen(char *name, bool write_mode)
{
	return FileOpenEx(name, write_mode, true);
}
IO *FileOpenW(wchar_t *name, bool write_mode)
{
	return FileOpenExW(name, write_mode, true);
}
IO *FileOpenEx(char *name, bool write_mode, bool read_lock)
{
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenExW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}

// Replace the specified character in the string with a new character
wchar_t *UniReplaceCharW(wchar_t *src, UINT size, wchar_t c, wchar_t  newc) {
	if (src == NULL)
	{
		return NULL;
	}
	for (; *src; src++, size -= sizeof(wchar_t)) {
		if (size < sizeof(wchar_t)) {
			break;
		}
		if (*src == c) {
			*src = newc;
		}
	}
	return (wchar_t *)src;
}

IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock)
{
	wchar_t tmp[MAX_SIZE];
	// Validate arguments
	if (name == NULL)
	{
		return NULL;
	}

	InnerFilePathW(tmp, sizeof(tmp), name);

	if (name[0] == L'|')
	{
		IO *o = ZeroMalloc(sizeof(IO));
		name++;
		UniStrCpy(o->NameW, sizeof(o->NameW), name);
		UniReplaceCharW(o->NameW, sizeof(o->NameW), L'\\', L'/');		// Path separator "/" is used.
		UniToStr(o->Name, sizeof(o->Name), o->NameW);
		o->HamMode = true;
		o->HamBuf = ReadHamcoreW(o->NameW);
		if (o->HamBuf == NULL)
		{
			Free(o);
			return NULL;
		}
		return o;
	}
	else
	{
		return FileOpenInnerW(tmp, write_mode, read_lock);
	}
}


