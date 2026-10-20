// FileIO.h
// Header of FileIO.c

#ifndef	FILEIO_H
#define	FILEIO_H

#include "Mayaqua.h"

#define	HAMCORE_DIR_NAME			"hamcore"
#define	HAMCORE_RESOURCE_TYPE		"HAMCORE"		// Resource type of the built-in hamcore files
#define	HAMCORE_RESOURCE_INDEX		"INDEX"			// Resource that names them (cmake/RanzResources.cmake)

struct IO
{
	char Name[MAX_SIZE];
	wchar_t NameW[MAX_SIZE];
	void *pData;
	bool WriteMode;
	bool HamMode;
	BUF *HamBuf;
	UINT64 SetUpdateTime, SetCreateTime;
	UINT64 GetUpdateTime, GetCreateTime, GetAccessTime;
};

typedef struct HC
{
	char *Path;
	void *Buffer;
	size_t Size;
	UINT64 LastAccess;
} HC;

struct DIRENT
{
	bool Folder;
	char *FileName;
	wchar_t *FileNameW;
	UINT64 FileSize;
	UINT64 UpdateDate;
};

struct DIRLIST
{
	UINT NumFiles;
	struct DIRENT **File;
};

bool DeleteDirInnerW(wchar_t *name);
bool DeleteDirW(wchar_t *name);
bool MakeDirInnerW(wchar_t *name);
bool MakeDir(char *name);
bool MakeDirW(wchar_t *name);
bool MakeDirEx(char *name);
bool MakeDirExW(wchar_t *name);
bool FileDeleteInnerW(wchar_t *name);
bool FileDelete(char *name);
bool FileDeleteW(wchar_t *name);
bool FileSeek(IO *o, UINT mode, INT64 offset);
UINT FileSize(IO *o);
UINT64 FileSize64(IO *o);
bool FileRead(IO *o, void *buf, UINT size);
bool FileWrite(IO *o, void *buf, UINT size);
void FileFlush(IO *o);
bool FileClose(IO *o);
bool FileCloseEx(IO *o, bool no_flush);
IO *FileCreate(char *name);
IO *FileCreateW(wchar_t *name);
IO *FileOpenInnerW(wchar_t *name, bool write_mode, bool read_lock);
IO *FileOpen(char *name, bool write_mode);
IO *FileOpenW(wchar_t *name, bool write_mode);
IO *FileOpenEx(char *name, bool write_mode, bool read_lock);
IO *FileOpenExW(wchar_t *name, bool write_mode, bool read_lock);
void ConvertPathW(wchar_t *path);
bool FileRenameInnerW(wchar_t *old_name, wchar_t *new_name);
bool FileRenameW(wchar_t *old_name, wchar_t *new_name);
void NormalizePath(char *dst, UINT size, char *src);
void NormalizePathW(wchar_t *dst, UINT size, wchar_t *src);
bool IsFileExistsInnerW(wchar_t *name);
bool IsFileExists(char *name);
bool IsFileExistsW(wchar_t *name);
void InnerFilePath(char *dst, UINT size, char *src);
void InnerFilePathW(wchar_t *dst, UINT size, wchar_t *src);
void ConbinePath(char *dst, UINT size, char *dirname, char *filename);
void ConbinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void CombinePathW(wchar_t *dst, UINT size, wchar_t *dirname, wchar_t *filename);
void GetDirNameFromFilePath(char *dst, UINT size, char *filepath);
void GetDirNameFromFilePathW(wchar_t *dst, UINT size, wchar_t *filepath);
void GetFileNameFromFilePath(char *dst, UINT size, char *filepath);
void InitGetExeName();
void GetExeName(char *name, UINT size);
void GetExeNameW(wchar_t *name, UINT size);
void GetExeDir(char *name, UINT size);
void GetExeDirW(wchar_t *name, UINT size);
int CompareHamcore(void *p1, void *p2);
void InitHamcore();
void FreeHamcore();
BUF *ReadHamcore(char *name);
DIRLIST *EnumDir(char *dirname);
DIRLIST *EnumDirW(wchar_t *dirname);
DIRLIST *EnumDirExW(wchar_t *dirname, COMPARE *compare);
void FreeDir(DIRLIST *d);
int CompareDirListByName(void *p1, void *p2);
void ConvertSafeFileName(char *dst, UINT size, char *src);
bool IsFile(char *name);
bool IsFileW(wchar_t *name);

#endif	// FILEIO_H
