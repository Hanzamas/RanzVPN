// FileIO.c
// File Input / Output code

#include "FileIO.h"

#include "Cfg.h"
#include "GlobalConst.h"
#include "Internat.h"
#include "Memory.h"
#include "Microsoft.h"
#include "Str.h"
#include "Tracking.h"
#include "Win32.h"

#include <stdlib.h>

#include <winioctl.h>

static char exe_file_name[MAX_SIZE];
static wchar_t exe_file_name_w[MAX_SIZE];

// File I/O data of a disk file (IO pData), from the raw OS allocator
typedef struct WIN32IO {
	HANDLE hFile;
	bool WriteMode;
} WIN32IO;

bool IsFile(char *name) {
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileW(wchar_t *name) {
	if (name == NULL)
		return false;

	IO *io = FileOpenExW(name, false, false);
	if (io == NULL)
		return false;

	FileClose(io);

	return true;
}

void ConvertSafeFileName(char *dst, UINT size, char *src) {
	if (dst == NULL || src == NULL)
		return;

	StrCpy(dst, size, src);
	for (UINT i = 0; i < StrLen(dst); i++)
		if (IsSafeChar(dst[i]) == false)
			dst[i] = '_';
}

static DIRLIST *EnumDirEx(const char *dirname, COMPARE *compare) {
	wchar_t *dirname_w = CopyStrToUni(dirname);
	DIRLIST *ret = EnumDirExW(dirname_w, compare);

	Free(dirname_w);

	return ret;
}
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare) {
	DIRLIST *d = NULL;
	if (dirname == NULL)
		dirname = L"./";

	if (compare == NULL)
		compare = CompareDirListByName;

	d = Win32EnumDirExW(dirname, compare);

	return d;
}
DIRLIST *EnumDir(char *dirname) {
	return EnumDirEx(dirname, NULL);
}
DIRLIST *EnumDirW(wchar_t *dirname) {
	return EnumDirExW(dirname, NULL);
}

int CompareDirListByName(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	DIRENT *d1 = *(DIRENT **)p1;
	DIRENT *d2 = *(DIRENT **)p2;
	if (d1 == NULL || d2 == NULL)
		return 0;
	return UniStrCmpi(d1->FileNameW, d2->FileNameW);
}

void FreeDir(DIRLIST *d) {
	if (d == NULL)
		return;

	for (UINT i = 0; i < d->NumFiles; i++) {
		DIRENT *f = d->File[i];
		Free(f->FileName);
		Free(f->FileNameW);
		Free(f);
	}
	Free(d->File);
	Free(d);
}

// The built-in hamcore files are resources of the executable (module NULL: Mayaqua is linked
// into it), of type HAMCORE_RESOURCE_TYPE (cmake/RanzResources.cmake). The resource
// HAMCORE_RESOURCE_INDEX names them, one per line; the file on line n is the resource with the
// integer ID n.

// Bytes of the resource <id> of type HAMCORE_RESOURCE_TYPE, mapped with the image (read-only).
// False when the executable has no such resource.
static bool HamcoreResource(char *id, void **data, UINT *size) {
	HRSRC res = FindResourceA(NULL, id, HAMCORE_RESOURCE_TYPE);
	if (res == NULL)
		return false;

	*size = SizeofResource(NULL, res);
	*data = LockResource(LoadResource(NULL, res));

	return (*data != NULL || *size == 0);
}

// The line of the index text that starts at *pos: its start and its length without the line
// end (LF, or CR LF). Moves *pos past the line. False when *pos is at the end of the text.
static bool HamcoreIndexLine(const char *text, UINT size, UINT *pos, UINT *start, UINT *len) {
	UINT n = 0;

	if (*pos >= size)
		return false;

	while (*pos + n < size && text[*pos + n] != '\n')
		++n;

	*start = *pos;
	*pos = *pos + n + 1;

	// A line may end with CR LF
	if (n != 0 && text[*start + n - 1] == '\r')
		--n;

	*len = n;

	return true;
}

// Resource ID of the built-in hamcore file <name> (compared byte by byte): its line in the
// index, from 1, or 0 when the index does not name it. <num> (optional) receives the number of
// lines: 0 when the executable has no index.
static UINT HamcoreResourceId(const char *name, UINT *num) {
	char *text;
	UINT size, pos, start, len, line = 0, id = 0;
	UINT name_len = (name == NULL ? 0 : StrLen(name));

	if (num != NULL)
		*num = 0;

	if (HamcoreResource(HAMCORE_RESOURCE_INDEX, (void **)&text, &size) == false)
		return 0;

	for (pos = 0; HamcoreIndexLine(text, size, &pos, &start, &len);) {
		++line;
		if (id == 0 && name != NULL && len == name_len && Cmp(text + start, name, len) == 0)
			id = line;
	}

	if (num != NULL)
		*num = line;

	return id;
}

// Name of the built-in hamcore file with the resource ID <id>: line <id> of the index, cut to
// fit <name>. Empty when the index has no such line.
static void HamcoreResourceName(UINT id, char *name, UINT name_size) {
	char *text;
	UINT size, pos, start, len, line = 0;

	if (name_size == 0)
		return;
	name[0] = 0;

	if (HamcoreResource(HAMCORE_RESOURCE_INDEX, (void **)&text, &size) == false)
		return;

	for (pos = 0; HamcoreIndexLine(text, size, &pos, &start, &len);) {
		if (++line == id) {
			len = MIN(len, name_size - 1);
			Copy(name, text + start, len);
			name[len] = 0;
			return;
		}
	}
}

static BUF *ReadHamcoreW(const wchar_t *filename) {
	char *filename_a = CopyUniToStr(filename);

	BUF *ret = ReadHamcore(filename_a);

	Free(filename_a);

	return ret;
}
BUF *ReadHamcore(char *name) {
	if (name == NULL || MayaquaIsMinimalMode())
		return NULL;

	if (name[0] == '/')
		++name;

	// A loose file in the "hamcore" folder next to the executable wins over the built-in one
	char exe_dir[MAX_PATH];
	char path[MAX_PATH];
	GetExeDir(exe_dir, sizeof(exe_dir));
	Format(path, sizeof(path), "%s/%s/%s", exe_dir, HAMCORE_DIR_NAME, name);

	BUF *buf = ReadDump(path);
	if (buf != NULL)
		return buf;

	// The built-in file, copied into a new buffer at offset 0
	UINT id = HamcoreResourceId(name, NULL);
	void *data;
	UINT size;
	if (id == 0 || HamcoreResource(MAKEINTRESOURCEA(id), &data, &size) == false)
		return NULL;

	return MemToBuf(data, size);
}

// The built-in hamcore files are mapped with the image: there is no archive to open and no
// cache to fill. An executable without them, or whose index names a file it does not hold,
// stops here, at start, instead of failing on the first read.
void InitHamcore() {
	UINT i, num, size;
	void *data;

	if (MayaquaIsMinimalMode())
		return;

	HamcoreResourceId(NULL, &num);
	for (i = 1; i <= num; ++i)
		if (HamcoreResource(MAKEINTRESOURCEA(i), &data, &size) == false)
			break;

	if (num == 0 || i <= num) {
		char tmp[MAX_SIZE];

		if (num == 0) {
			StrCpy(tmp, sizeof(tmp), "Fatal Error: This executable holds no hamcore files (no resource " HAMCORE_RESOURCE_TYPE " " HAMCORE_RESOURCE_INDEX ").");
		} else {
			char name[MAX_PATH];

			HamcoreResourceName(i, name, sizeof(name));
			Format(tmp, sizeof(tmp), "Fatal Error: This executable lacks the hamcore file \"%s\" (file %u of %u, resource " HAMCORE_RESOURCE_TYPE " %u).", name, i, num, i);
		}
		StrCat(tmp, sizeof(tmp), "\r\nThe build embeds src/bin/hamcore with cmake/RanzResources.cmake.\r\n\r\n(If this problem occurs again, please reinstall VPN software files.)");

		MayaFatalExit(1, tmp);
	}
}

// Nothing to free: the built-in hamcore files belong to the image of the executable
void FreeHamcore() {
}

int CompareHamcore(void *p1, void *p2) {
	if (p1 == NULL || p2 == NULL)
		return 0;
	HC *c1 = *(HC **)p1;
	HC *c2 = *(HC **)p2;
	if (c1 == NULL || c2 == NULL)
		return 0;
	return StrCmpi(c1->Path, c2->Path);
}

void GetExeDir(char *name, UINT size) {
	if (name == NULL)
		return;

	GetDirNameFromFilePath(name, size, exe_file_name);
}
void GetExeDirW(wchar_t *name, UINT size) {
	if (name == NULL)
		return;

	GetDirNameFromFilePathW(name, size, exe_file_name_w);
}

void GetExeName(char *name, UINT size) {
	if (name == NULL)
		return;

	StrCpy(name, size, exe_file_name);
}
void GetExeNameW(wchar_t *name, UINT size) {
	if (name == NULL)
		return;

	UniStrCpy(name, size, exe_file_name_w);
}

void InitGetExeName() {
	Win32GetExeNameW(exe_file_name_w, ARRAYSIZE(exe_file_name_w));

	UniToStr(exe_file_name, sizeof(exe_file_name), exe_file_name_w);
}

void GetFileNameFromFilePath(char *dst, UINT size, char *filepath) {
	char tmp[MAX_SIZE];
	if (dst == NULL || filepath == NULL)
		return;

	UINT len = MIN(StrLen(filepath), (MAX_SIZE - 2));
	UINT wp = 0;

	for (UINT i = 0; i < (len + 1); i++) {
		char c = filepath[i];

		switch (c) {
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
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath) {
	wchar_t tmp[MAX_SIZE];
	if (dst == NULL || filepath == NULL)
		return;

	UniStrCpy(tmp, sizeof(tmp), filepath);
	if (UniEndWith(tmp, L"\\") || UniEndWith(tmp, L"/"))
		tmp[UniStrLen(tmp) - 1] = 0;

	UINT len = UniStrLen(tmp);

	UniStrCpy(dst, size, L"");

	UINT wp = 0;

	for (UINT i = 0; i < len; i++) {
		wchar_t c = tmp[i];
		if (c == L'/' || c == L'\\') {
			tmp[wp++] = 0;
			wp = 0;
			UniStrCat(dst, size, tmp);
			tmp[wp++] = c;
		} else {
			tmp[wp++] = c;
		}
	}

	if (UniStrLen(dst) == 0)
		UniStrCpy(dst, size, L"/");

	NormalizePathW(dst, size, dst);
}

void GetDirNameFromFilePath(char *dst, UINT size, char *filepath) {
	char tmp[MAX_SIZE];
	if (dst == NULL || filepath == NULL)
		return;

	StrCpy(tmp, sizeof(tmp), filepath);
	if (EndWith(tmp, "\\") || EndWith(tmp, "/"))
		tmp[StrLen(tmp) - 1] = 0;

	UINT len = StrLen(tmp);

	StrCpy(dst, size, "");

	UINT wp = 0;

	for (UINT i = 0; i < len; i++) {
		char c = tmp[i];
		if (c == '/' || c == '\\') {
			tmp[wp++] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			tmp[wp++] = c;
		} else {
			tmp[wp++] = c;
		}
	}

	if (StrLen(dst) == 0)
		StrCpy(dst, size, "/");

	NormalizePath(dst, size, dst);
}

void ConbinePath(char *dst, UINT size, char *dirname, char *filename) {
	wchar_t dst_w[MAX_PATH];
	wchar_t *dirname_w = CopyStrToUni(dirname);
	wchar_t *filename_w = CopyStrToUni(filename);

	ConbinePathW(dst_w, sizeof(dst_w), dirname_w, filename_w);

	Free(dirname_w);
	Free(filename_w);

	UniToStr(dst, size, dst_w);
}
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename) {
	wchar_t tmp[MAX_SIZE];
	wchar_t filename_ident[MAX_SIZE];
	if (dst == NULL || dirname == NULL || filename == NULL)
		return;

	NormalizePathW(filename_ident, sizeof(filename_ident), filename);

	bool is_full_path = false;

	if (UniStartWith(filename_ident, L"\\") || UniStartWith(filename_ident, L"/"))
		is_full_path = true;

	filename = &filename_ident[0];

	if (UniStrLen(filename) >= 2) {
		if ((L'a' <= filename[0] && filename[0] <= L'z') || (L'A' <= filename[0] && filename[0] <= L'Z')) {
			if (filename[1] == L':')
				is_full_path = true;
		}
	}

	if (is_full_path == false) {
		UniStrCpy(tmp, sizeof(tmp), dirname);
		if (UniEndWith(tmp, L"/") == false && UniEndWith(tmp, L"\\") == false)
			UniStrCat(tmp, sizeof(tmp), L"/");
		UniStrCat(tmp, sizeof(tmp), filename);
	} else {
		UniStrCpy(tmp, sizeof(tmp), filename);
	}

	NormalizePathW(dst, size, tmp);
}
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename) {
	ConbinePathW(dst, size, dirname, filename);
}

bool IsFileExists(char *name) {
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = IsFileExistsW(name_w);

	Free(name_w);

	return ret;
}
bool IsFileExistsW(wchar_t *name) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return false;

	InnerFilePathW(tmp, sizeof(tmp), name);

	return IsFileExistsInnerW(tmp);
}
// A file exists when it has attributes and is not a directory (a locked file exists too)
bool IsFileExistsInnerW(wchar_t *name) {
	wchar_t name2[MAX_SIZE];
	if (name == NULL)
		return false;

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	DWORD attr = GetFileAttributesW(name2);
	if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY) != 0)
		return false;

	return true;
}

void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src) {
	wchar_t tmp[MAX_SIZE];
	bool first_double_slash = false;
	bool first_single_slash = false;
	wchar_t win32_drive_char = 0;
	bool is_full_path = false;
	if (dst == NULL || src == 0)
		return;

	UniStrCpy(tmp, sizeof(tmp), src);
	ConvertPathW(tmp);
	UniTrim(tmp);

	if (UniStartWith(tmp, L"./") || UniStartWith(tmp, L".\\") ||
	    UniStartWith(tmp, L"../") || UniStartWith(tmp, L"..\\") ||
	    UniStrCmpi(tmp, L".") == 0 || UniStrCmpi(tmp, L"..") == 0) {
		wchar_t cd[MAX_SIZE];
		Zero(cd, sizeof(cd));

		Win32GetCurrentDirW(cd, ARRAYSIZE(cd));

		if (UniStartWith(tmp, L"..")) {
			UniStrCat(cd, sizeof(cd), L"/../");
			UniStrCat(cd, sizeof(cd), tmp + 2);
		} else {
			UniStrCat(cd, sizeof(cd), L"/");
			UniStrCat(cd, sizeof(cd), tmp);
		}

		UniStrCpy(tmp, sizeof(tmp), cd);
	}

	if (UniStartWith(tmp, L"//") || UniStartWith(tmp, L"\\\\")) {
		first_double_slash = true;
		is_full_path = true;
	} else if (UniStartWith(tmp, L"/") || UniStartWith(tmp, L"\\")) {
		first_single_slash = true;
		is_full_path = true;
	}

	if (UniStrLen(tmp) >= 2) {
		if (tmp[1] == L':') {
			wchar_t tmp2[MAX_SIZE];
			is_full_path = true;
			win32_drive_char = tmp[0];
			UniStrCpy(tmp2, sizeof(tmp2), tmp + 2);
			UniStrCpy(tmp, sizeof(tmp), tmp2);
		}
	}

	if (UniStrLen(tmp) == 1 && (tmp[0] == L'/' || tmp[0] == L'\\'))
		tmp[0] = 0;

	UNI_TOKEN_LIST *t = UniParseToken(tmp, L"/\\");

	SK *sk = NewSk();

	for (UINT i = 0; i < t->NumTokens; i++) {
		wchar_t *s = t->Token[i];

		if (UniStrCmpi(s, L".") == 0) {
			continue;
		} else if (UniStrCmpi(s, L"..") == 0) {
			if (sk->num_item >= 1 && (first_double_slash == false || sk->num_item >= 2))
				Pop(sk);
		} else {
			Push(sk, s);
		}
	}

	UniStrCpy(tmp, sizeof(tmp), L"");

	if (first_double_slash)
		UniStrCat(tmp, sizeof(tmp), L"//");
	else if (first_single_slash)
		UniStrCat(tmp, sizeof(tmp), L"/");

	if (win32_drive_char != 0) {
		wchar_t d[2];
		d[0] = win32_drive_char;
		d[1] = 0;
		UniStrCat(tmp, sizeof(tmp), d);
		UniStrCat(tmp, sizeof(tmp), L":/");
	}

	for (UINT i = 0; i < sk->num_item; i++) {
		UniStrCat(tmp, sizeof(tmp), (wchar_t *)sk->p[i]);
		if (i != (sk->num_item - 1))
			UniStrCat(tmp, sizeof(tmp), L"/");
	}

	ReleaseSk(sk);

	UniFreeToken(t);

	ConvertPathW(tmp);

	UniStrCpy(dst, size, tmp);
}
void NormalizePath(char *dst, UINT size, char *src) {
	wchar_t dst_w[MAX_SIZE];
	wchar_t *src_w = CopyStrToUni(src);

	NormalizePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

bool FileRenameW(wchar_t *old_name, wchar_t *new_name) {
	wchar_t tmp1[MAX_SIZE];
	wchar_t tmp2[MAX_SIZE];
	if (old_name == NULL || new_name == NULL)
		return false;

	InnerFilePathW(tmp1, sizeof(tmp1), old_name);
	InnerFilePathW(tmp2, sizeof(tmp2), new_name);

	return FileRenameInnerW(tmp1, tmp2);
}
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name) {
	if (old_name == NULL || new_name == NULL)
		return false;

	// Rename
	if (MoveFileW(old_name, new_name) == FALSE)
		return false;

	return true;
}

void ConvertPathW(wchar_t *path) {
	wchar_t new_char = L'\\';

	UINT len = UniStrLen(path);
	for (UINT i = 0; i < len; i++)
		if (path[i] == L'\\' || path[i] == L'/')
			path[i] = new_char;
}

bool DeleteDirW(wchar_t *name) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return false;

	InnerFilePathW(tmp, sizeof(tmp), name);

	return DeleteDirInnerW(tmp);
}
bool DeleteDirInnerW(wchar_t *name) {
	if (name == NULL)
		return false;

	if (RemoveDirectoryW(name) == FALSE)
		return false;

	return true;
}

void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src) {
	if (dst == NULL || src == NULL)
		return;

	if (src[0] == L'@') {
		wchar_t dir[MAX_SIZE];
		GetExeDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	} else if (src[0] == L'$') {
		wchar_t dir[MAX_SIZE];
		GetExeDirW(dir, sizeof(dir));
		ConbinePathW(dst, size, dir, &src[1]);
	} else {
		NormalizePathW(dst, size, src);
	}
}
void InnerFilePath(char *dst, UINT size, char *src) {
	wchar_t dst_w[MAX_PATH];
	wchar_t *src_w = CopyStrToUni(src);

	InnerFilePathW(dst_w, sizeof(dst_w), src_w);

	Free(src_w);

	UniToStr(dst, size, dst_w);
}

bool MakeDirEx(char *name) {
	wchar_t *name_w = CopyStrToUni(name);

	bool ret = MakeDirExW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirExW(wchar_t *name) {
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	bool ret = false;
	if (name == NULL)
		return false;

	LIST *o = NewListFast(NULL);

	UniStrCpy(tmp, sizeof(tmp), name);
	while (true) {
		wchar_t *s = CopyUniStr(tmp);

		Add(o, s);

		GetDirNameFromFilePathW(tmp2, sizeof(tmp2), tmp);

		if (UniStrCmpi(tmp2, tmp) == 0)
			break;

		UniStrCpy(tmp, sizeof(tmp), tmp2);
	}

	for (UINT i = 0; i < LIST_NUM(o); i++) {
		UINT j = LIST_NUM(o) - i - 1;
		wchar_t *s = LIST_DATA(o, j);

		if (UniStrCmpi(s, L"\\") != 0 && UniStrCmpi(s, L"/") != 0)
			ret = MakeDirW(s);
	}

	UniFreeStrList(o);

	return ret;
}

bool MakeDir(char *name) {
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = MakeDirW(name_w);

	Free(name_w);

	return ret;
}
bool MakeDirW(wchar_t *name) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return false;

	InnerFilePathW(tmp, sizeof(tmp), name);

	return MakeDirInnerW(tmp);
}
bool MakeDirInnerW(wchar_t *name) {
	if (name == NULL)
		return false;

	if (CreateDirectoryW(name, NULL) == FALSE)
		return false;

	return true;
}

bool FileDelete(char *name) {
	wchar_t *name_w = CopyStrToUni(name);
	bool ret = FileDeleteW(name_w);

	Free(name_w);

	return ret;
}
bool FileDeleteW(wchar_t *name) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return false;

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileDeleteInnerW(tmp);
}
bool FileDeleteInnerW(wchar_t *name) {
	wchar_t name2[MAX_SIZE];
	if (name == NULL)
		return false;

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	if (DeleteFileW(name2) == FALSE)
		return false;

	return true;
}

// Seek the file (a 64-bit offset; a hamcore file cannot seek)
bool FileSeek(IO *o, UINT mode, INT64 offset) {
	LARGE_INTEGER distance;
	if (o == NULL)
		return false;

	if (o->HamMode)
		return false;

	if (mode != FILE_BEGIN && mode != FILE_END && mode != FILE_CURRENT)
		return false;

	WIN32IO *p = (WIN32IO *)o->pData;
	distance.QuadPart = offset;
	if (SetFilePointerEx(p->hFile, distance, NULL, mode) == FALSE)
		return false;

	return true;
}

UINT64 FileSize64(IO *o) {
	LARGE_INTEGER size;
	if (o == NULL)
		return 0;

	if (o->HamMode)
		return (UINT64)o->HamBuf->Size;

	WIN32IO *p = (WIN32IO *)o->pData;
	if (GetFileSizeEx(p->hFile, &size) == FALSE || size.QuadPart < 0)
		return 0;

	return (UINT64)size.QuadPart;
}
// The size clamped to 4 GiB - 1
UINT FileSize(IO *o) {
	UINT64 size = FileSize64(o);

	if (size >= 4294967296ULL)
		size = 4294967295ULL;

	return (UINT)size;
}

// Read from a file (all or nothing: a short read fails)
bool FileRead(IO *o, void *buf, UINT size) {
	DWORD read_size;
	if (o == NULL || buf == NULL)
		return false;

	KS_INC(KS_IO_READ_COUNT);
	KS_ADD(KS_IO_TOTAL_READ_SIZE, size);

	if (size == 0)
		return true;

	if (o->HamMode)
		return ReadBuf(o->HamBuf, buf, size) == size ? true : false;

	WIN32IO *p = (WIN32IO *)o->pData;
	if (ReadFile(p->hFile, buf, size, &read_size, NULL) == FALSE)
		return false;

	if (read_size != size)
		return false;

	return true;
}

// Write to a file (all or nothing: a short write fails)
bool FileWrite(IO *o, void *buf, UINT size) {
	DWORD write_size;
	if (o == NULL || buf == NULL)
		return false;
	if (o->WriteMode == false)
		return false;

	KS_INC(KS_IO_WRITE_COUNT);
	KS_ADD(KS_IO_TOTAL_WRITE_SIZE, size);

	if (size == 0)
		return true;

	WIN32IO *p = (WIN32IO *)o->pData;
	if (WriteFile(p->hFile, buf, size, &write_size, NULL) == FALSE)
		return false;

	if (write_size != size)
		return false;

	return true;
}

// Read the dates of a disk file (on open)
static bool FileGetDate(void *pData, UINT64 *created_time, UINT64 *updated_time, UINT64 *accessed_date) {
	BY_HANDLE_FILE_INFORMATION info;
	// Validate arguments
	if (pData == NULL)
		return false;

	WIN32IO *p = (WIN32IO *)pData;

	Zero(&info, sizeof(info));

	if (GetFileInformationByHandle(p->hFile, &info) == false)
		return false;

	if (created_time != NULL)
		*created_time = FileTimeToUINT64(&info.ftCreationTime);

	if (updated_time != NULL)
		*updated_time = FileTimeToUINT64(&info.ftLastWriteTime);

	if (accessed_date != NULL)
		*accessed_date = FileTimeToUINT64(&info.ftLastAccessTime);

	return true;
}

// Write the dates of a disk file (on close of a writer); nothing to do when both are 0
static bool FileSetDate(void *pData, UINT64 created_time, UINT64 updated_time) {
	FILETIME ft_created_time, ft_updated_time;
	FILETIME *p_created_time = NULL, *p_updated_time = NULL;
	// Validate arguments
	if (pData == NULL || (created_time == 0 && updated_time == 0))
		return false;

	WIN32IO *p = (WIN32IO *)pData;

	if (created_time != 0) {
		UINT64ToFileTime(&ft_created_time, created_time);

		p_created_time = &ft_created_time;
	}

	if (updated_time != 0) {
		UINT64ToFileTime(&ft_updated_time, updated_time);

		p_updated_time = &ft_updated_time;
	}

	return SetFileTime(p->hFile, p_created_time, NULL, p_updated_time);
}

void FileFlush(IO *o) {
	if (o == NULL)
		return;

	if (o->HamMode)
		return;

	WIN32IO *p = (WIN32IO *)o->pData;
	if (p->WriteMode)
		FlushFileBuffers(p->hFile);
}

// Close the file; false when the flush or the close of a disk file fails
bool FileClose(IO *o) {
	return FileCloseEx(o, false);
}
bool FileCloseEx(IO *o, bool no_flush) {
	bool ret = true;
	if (o == NULL)
		return false;

	if (o->HamMode == false) {
		WIN32IO *p = (WIN32IO *)o->pData;

		if (o->WriteMode)
			FileSetDate(p, o->SetCreateTime, o->SetUpdateTime);

		// A writer is flushed unless no_flush is set
		if (p->WriteMode && no_flush == false) {
			if (FlushFileBuffers(p->hFile) == FALSE)
				ret = false;
		}
		if (CloseHandle(p->hFile) == FALSE)
			ret = false;

		Win32MemoryFree(p);
	} else {
		FreeBuf(o->HamBuf);
	}
	Free(o);

	KS_INC(KS_IO_CLOSE_COUNT);

	return ret;
}

static IO *FileCreateInnerW(const wchar_t *name) {
	wchar_t name2[MAX_SIZE];
	if (name == NULL)
		return NULL;

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	// Replace an existing file, read-write, sharing read. An existing hidden file denies
	// FILE_ATTRIBUTE_NORMAL, so retry with FILE_ATTRIBUTE_HIDDEN.
	HANDLE h = CreateFileW(name2, GENERIC_READ | GENERIC_WRITE,
	                       FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
	                       NULL);
	if (h == INVALID_HANDLE_VALUE) {
		h = CreateFileW(name2, GENERIC_READ | GENERIC_WRITE,
		                FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN,
		                NULL);
		if (h == INVALID_HANDLE_VALUE)
			return NULL;
	}

	WIN32IO *p = Win32MemoryAlloc(sizeof(WIN32IO));
	p->hFile = h;
	p->WriteMode = true;

	IO *o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = true;

	KS_INC(KS_IO_CREATE_COUNT);

	return o;
}
IO *FileCreate(char *name) {
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileCreateW(name_w);

	Free(name_w);

	return ret;
}
IO *FileCreateW(wchar_t *name) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return NULL;

	InnerFilePathW(tmp, sizeof(tmp), name);

	return FileCreateInnerW(tmp);
}

IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock) {
	DWORD lock_mode;
	wchar_t name2[MAX_SIZE];
	if (name == NULL)
		return NULL;

	UniStrCpy(name2, sizeof(name2), name);
	ConvertPathW(name2);

	// A writer opens read-write and shares read. A reader shares read, and also write
	// when it does not take the read lock.
	if (write_mode)
		lock_mode = FILE_SHARE_READ;
	else if (read_lock == false)
		lock_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	else
		lock_mode = FILE_SHARE_READ;

	HANDLE h = CreateFileW(name2,
	                       (write_mode ? GENERIC_READ | GENERIC_WRITE : GENERIC_READ),
	                       lock_mode,
	                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
		return NULL;

	WIN32IO *p = Win32MemoryAlloc(sizeof(WIN32IO));
	p->hFile = h;
	p->WriteMode = write_mode;

	IO *o = ZeroMalloc(sizeof(IO));
	o->pData = p;
	UniStrCpy(o->NameW, sizeof(o->NameW), name2);
	UniToStr(o->Name, sizeof(o->Name), o->NameW);
	o->WriteMode = write_mode;

	FileGetDate(p, &o->GetCreateTime, &o->GetUpdateTime, &o->GetAccessTime);

	KS_INC(KS_IO_OPEN_COUNT);

	return o;
}
IO *FileOpen(char *name, bool write_mode) {
	return FileOpenEx(name, write_mode, true);
}
IO *FileOpenW(wchar_t *name, bool write_mode) {
	return FileOpenExW(name, write_mode, true);
}
IO *FileOpenEx(char *name, bool write_mode, bool read_lock) {
	wchar_t *name_w = CopyStrToUni(name);
	IO *ret = FileOpenExW(name_w, write_mode, read_lock);

	Free(name_w);

	return ret;
}

static wchar_t *UniReplaceCharW(wchar_t *src, UINT size, wchar_t c, wchar_t newc) {
	if (src == NULL)
		return NULL;
	for (; *src; src++, size -= sizeof(wchar_t)) {
		if (size < sizeof(wchar_t))
			break;
		if (*src == c)
			*src = newc;
	}
	return (wchar_t *)src;
}

IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock) {
	wchar_t tmp[MAX_SIZE];
	if (name == NULL)
		return NULL;

	InnerFilePathW(tmp, sizeof(tmp), name);

	if (name[0] == L'|') {
		IO *o = ZeroMalloc(sizeof(IO));
		name++;
		UniStrCpy(o->NameW, sizeof(o->NameW), name);
		UniReplaceCharW(o->NameW, sizeof(o->NameW), L'\\', L'/');
		UniToStr(o->Name, sizeof(o->Name), o->NameW);
		o->HamMode = true;
		o->HamBuf = ReadHamcoreW(o->NameW);
		if (o->HamBuf == NULL) {
			Free(o);
			return NULL;
		}
		return o;
	} else {
		return FileOpenInnerW(tmp, write_mode, read_lock);
	}
}


bool Win32SetFolderCompress(char *path, bool compressed) {
	DWORD retsize = 0;
	char tmp[MAX_PATH];
	if (path == NULL)
		return false;

	InnerFilePath(tmp, sizeof(tmp), path);

	HANDLE h = CreateFile(tmp, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

	if (h == INVALID_HANDLE_VALUE)
		return false;

	USHORT flag = compressed ? COMPRESSION_FORMAT_DEFAULT : COMPRESSION_FORMAT_NONE;

	bool ret = (DeviceIoControl(h, FSCTL_SET_COMPRESSION, &flag, sizeof(USHORT),
	                            NULL, 0, &retsize, NULL) != FALSE);

	CloseHandle(h);

	return ret;
}

DIRLIST *Win32EnumDirExW(wchar_t *dirname, COMPARE *compare) {
	WIN32_FIND_DATAW data_w;
	wchar_t tmp[MAX_PATH];
	wchar_t tmp2[MAX_PATH];
	wchar_t dirname2[MAX_PATH];

	UniStrCpy(tmp2, sizeof(tmp2), dirname);

	if (UniStrLen(tmp2) >= 1 && tmp2[UniStrLen(tmp2) - 1] == L'\\')
		tmp2[UniStrLen(tmp2) - 1] = 0;

	UniFormat(tmp, sizeof(tmp), L"%s\\*.*", tmp2);
	NormalizePathW(tmp, sizeof(tmp), tmp);
	NormalizePathW(dirname2, sizeof(dirname2), tmp2);

	LIST *o = NewListFast(compare);

	Zero(&data_w, sizeof(data_w));

	HANDLE h = FindFirstFileW(tmp, &data_w);

	if (h != INVALID_HANDLE_VALUE) {
		bool b = true;

		do {
			if (UniStrCmpi(data_w.cFileName, L"..") != 0 &&
			    UniStrCmpi(data_w.cFileName, L".") != 0) {
				DIRENT *f = ZeroMalloc(sizeof(DIRENT));
				wchar_t fullpath[MAX_SIZE];
				bool ok = false;

				f->FileNameW = CopyUniStr(data_w.cFileName);
				f->FileName = CopyUniToStr(f->FileNameW);
				f->Folder = (data_w.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? true : false;

				CombinePathW(fullpath, sizeof(fullpath), dirname2, f->FileNameW);

				HANDLE hfile = CreateFileW(fullpath, 0,
				                           FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				                           NULL, OPEN_EXISTING, 0, NULL);

				if (hfile != INVALID_HANDLE_VALUE) {
					BY_HANDLE_FILE_INFORMATION info;

					Zero(&info, sizeof(info));

					if (GetFileInformationByHandle(hfile, &info)) {
						f->UpdateDate = FileTimeToUINT64(&info.ftLastWriteTime);

						if (f->Folder == false)
							f->FileSize = ((UINT64)info.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)info.nFileSizeLow;

						ok = true;
					}

					CloseHandle(hfile);
				}

				if (ok == false) {
					f->UpdateDate = FileTimeToUINT64(&data_w.ftLastWriteTime);

					if (f->Folder == false)
						f->FileSize = ((UINT64)data_w.nFileSizeHigh * (UINT64)((UINT64)MAXDWORD + (UINT64)1)) + (UINT64)data_w.nFileSizeLow;
				}

				Add(o, f);
			}

			Zero(&data_w, sizeof(data_w));

			b = FindNextFileW(h, &data_w);
		} while (b);

		FindClose(h);
	}

	Sort(o);

	DIRLIST *d = ZeroMalloc(sizeof(DIRLIST));
	d->NumFiles = LIST_NUM(o);
	d->File = ToArray(o);

	ReleaseList(o);

	return d;
}

// The path of the executable; num_chars counts wide characters, not bytes. Empty when it fails or
// does not fit.
void Win32GetExeNameW(wchar_t *name, UINT num_chars) {
	if (name == NULL || num_chars == 0)
		return;

	DWORD ret = GetModuleFileNameW(NULL, name, num_chars);
	if (ret == 0 || ret >= num_chars)
		name[0] = 0;
}

// The current directory; num_chars counts wide characters, not bytes. Empty when it fails or does
// not fit.
void Win32GetCurrentDirW(wchar_t *dir, UINT num_chars) {
	if (dir == NULL || num_chars == 0)
		return;

	DWORD ret = GetCurrentDirectoryW(num_chars, dir);
	if (ret == 0 || ret >= num_chars)
		dir[0] = 0;
}

void Win32NukuEnW(wchar_t *dst, UINT size, wchar_t *src) {
	wchar_t str[MAX_SIZE];
	if (src)
		UniStrCpy(str, sizeof(str), src);
	else
		UniStrCpy(str, sizeof(str), dst);
	int i = UniStrLen(str);
	if (i > 0 && str[i - 1] == L'\\')
		str[i - 1] = 0;
	UniStrCpy(dst, size, str);
}
void Win32NukuEn(char *dst, UINT size, char *src) {
	char str[MAX_SIZE];
	if (src)
		StrCpy(str, sizeof(str), src);
	else
		StrCpy(str, sizeof(str), dst);
	int i = StrLen(str);
	if (i > 0 && str[i - 1] == '\\')
		str[i - 1] = 0;
	StrCpy(dst, size, str);
}

void Win32GetDirFromPath(char *dst, UINT size, char *src) {
	char str[MAX_SIZE];
	char c;
	char tmp[MAX_SIZE];
	if (src)
		StrCpy(str, sizeof(str), src);
	else
		StrCpy(str, sizeof(str), dst);
	Win32NukuEn(str, sizeof(str), NULL);
	int wp = 0;
	int len = StrLen(str);
	dst[0] = 0;
	for (int i = 0; i < len; i++) {
		c = str[i];
		switch (c) {
		case '\\':
			tmp[wp] = 0;
			wp = 0;
			StrCat(dst, size, tmp);
			StrCat(dst, size, "\\");
			break;
		default:
			tmp[wp] = c;
			wp++;
			break;
		}
	}
	Win32NukuEn(dst, size, NULL);
}

bool Win32DeleteDirW(wchar_t *name) {
	if (name == NULL)
		return false;

	if (RemoveDirectoryW(name) == FALSE)
		return false;
	return true;
}

