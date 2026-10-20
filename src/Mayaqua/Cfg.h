// Cfg.h
// Header of Cfg.c

#ifndef	CFG_H
#define	CFG_H

#include "Encrypt.h"


#define	TAG_DECLARE			"declare"
#define	TAG_STRING			"string"
#define	TAG_INT				"uint"
#define	TAG_INT64			"uint64"
#define	TAG_BOOL			"bool"
#define	TAG_BYTE			"byte"
#define	TAG_TRUE			"true"
#define	TAG_FALSE			"false"
#define	TAG_ROOT			"root"

#define	TAG_CPYRIGHT		"\xef\xbb\xbf# Software Configuration File\r\n# ---------------------------\r\n# \r\n# You may edit this file when the VPN Server / Client / Bridge program is not running.\r\n# \r\n# In prior to edit this file manually by your text editor,\r\n# shutdown the VPN Server / Client / Bridge background service.\r\n# Otherwise, all changes will be lost.\r\n# \r\n"
#define	TAG_BINARY			"SEVPN_DB"

#define	ITEM_TYPE_INT		1
#define	ITEM_TYPE_INT64		2
#define	ITEM_TYPE_BYTE		3
#define	ITEM_TYPE_STRING	4
#define	ITEM_TYPE_BOOL		5

struct FOLDER
{
	char *Name;
	LIST *Items;
	LIST *Folders;
	struct FOLDER *Parent;
};

struct ITEM
{
	char *Name;
	UINT Type;
	void *Buf;
	UINT size;
	FOLDER *Parent;
};

struct CFG_RW
{
	LOCK *lock;
	char *FileName;
	wchar_t *FileNameW;
	IO *Io;
	UCHAR LashHash[SHA1_SIZE];
	bool DontBackup;
	wchar_t LastSavedDateStr[MAX_SIZE];
	bool SaveFailed;			// The last SaveCfgRwEx could not write the file
	bool BadFilePending;		// An unreadable file is still in place: no save writes over it
	bool BadFileRenamed;		// An unreadable file has been renamed to <name>.bad
};

typedef bool (*ENUM_FOLDER)(FOLDER *f, void *param);
typedef bool (*ENUM_ITEM)(ITEM *t, void *param);

struct CFG_ENUM_PARAM
{
	BUF *b;
	UINT depth;
};

ITEM *CfgCreateItem(FOLDER *parent, char *name, UINT type, void *buf, UINT size);
void CfgDeleteFolder(FOLDER *f);
FOLDER *CfgCreateFolder(FOLDER *parent, char *name);
void CfgEnumFolder(FOLDER *f, ENUM_FOLDER proc, void *param);
TOKEN_LIST *CfgEnumFolderToTokenList(FOLDER *f);
TOKEN_LIST *CfgEnumItemToTokenList(FOLDER *f);
void CfgEnumItem(FOLDER *f, ENUM_ITEM proc, void *param);
FOLDER *CfgFindFolder(FOLDER *parent, char *name);
ITEM *CfgFindItem(FOLDER *parent, char *name);
ITEM *CfgAddInt(FOLDER *f, char *name, UINT i);
ITEM *CfgAddBool(FOLDER *f, char *name, bool b);
ITEM *CfgAddInt64(FOLDER *f, char *name, UINT64 i);
ITEM *CfgAddByte(FOLDER *f, char *name, void *buf, UINT size);
ITEM *CfgAddBuf(FOLDER *f, char *name, BUF *b);
ITEM *CfgAddStr(FOLDER *f, char *name, char *str);
ITEM *CfgAddUniStr(FOLDER *f, char *name, wchar_t *str);
UINT CfgGetInt(FOLDER *f, char *name);
bool CfgGetBool(FOLDER *f, char *name);
UINT64 CfgGetInt64(FOLDER *f, char *name);
UINT CfgGetByte(FOLDER *f, char *name, void *buf, UINT size);
BUF *CfgGetBuf(FOLDER *f, char *name);
bool CfgGetStr(FOLDER *f, char *name, char *str, UINT size);
bool CfgGetUniStr(FOLDER *f, char *name, wchar_t *str, UINT size);
bool CfgIsItem(FOLDER *f, char *name);
char *CfgEscape(char *name);
bool CfgCheckCharForName(char c);
char *CfgUnescape(char *str);
BUF *CfgFolderToBuf(FOLDER *f);
void CfgOutputFolderText(BUF *b, FOLDER *f, UINT depth);
void CfgAddLine(BUF *b, char *str, UINT depth);
void CfgAddDeclare(BUF *b, char *name, UINT depth);
void CfgAddEnd(BUF *b, UINT depth);
void CfgAddData(BUF *b, UINT type, char *name, char *data, UINT depth);
char *CfgTypeToStr(UINT type);
void CfgAddItemText(BUF *b, ITEM *t, UINT depth);
FOLDER *CfgBufTextToFolder(BUF *b);
FOLDER *CfgBufBinToFolder(BUF *b);
FOLDER *CfgBufToFolder(BUF *b, bool require_closed);
char *CfgReadNextLine(BUF *b);
bool CfgSaveExW(CFG_RW *rw, FOLDER *f, wchar_t *name, UINT *written_size);
FOLDER *CfgReadW(wchar_t *name);
bool CfgStageNewFile(CFG_RW *rw, void *data, UINT size);
void CfgGetDisplayFileName(CFG_RW *rw, char *dst, UINT size);
CFG_RW *NewCfgRwEx2W(FOLDER **root, wchar_t *cfg_name, bool dont_backup, wchar_t *template_name);
CFG_RW *NewCfgRwEx2A(FOLDER **root, char *cfg_name_a, bool dont_backup, char *template_name_a);
UINT SaveCfgRwEx(CFG_RW *rw, FOLDER *f, UINT revision_number);
void CfgRwSetAsideBadFile(CFG_RW *rw);
void FreeCfgRw(CFG_RW *rw);
ITEM *CfgAddIp32(FOLDER *f, char *name, UINT ip);
UINT CfgGetIp32(FOLDER *f, char *name);
bool CfgGetIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
ITEM *CfgAddIp6Addr(FOLDER *f, char *name, IPV6_ADDR *addr);
bool FileCopyW(wchar_t *src, wchar_t *dst);
bool FileCopyExW(wchar_t *src, wchar_t *dst, bool read_lock);

bool CfgGetIp(FOLDER *f, char *name, struct IP *ip);
ITEM *CfgAddIp(FOLDER *f, char *name, struct IP *ip);

#endif

