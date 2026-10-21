// Eraser.h
// Header of Eraser.c

#ifndef	ERASER_H
#define	ERASER_H

#include "LogWriter.h"

typedef struct ERASER ERASER;

#define	DISK_FREE_SPACE_MIN			1048576
#define	DISK_FREE_SPACE_DEFAULT		(DISK_FREE_SPACE_MIN * 100)
#define	DISK_FREE_SPACE_DEFAULT_WINDOWS	((UINT64)(8ULL * 1024ULL * 1024ULL * 1024ULL))

#define	DISK_FREE_CHECK_INTERVAL_DEFAULT	(5 * 60 * 1000)

struct ERASER
{
	LOG *Log;
	UINT64 MinFreeSpace;
	char *DirName;
	volatile bool Halt;
	THREAD *Thread;
	bool LastFailed;
	EVENT *HaltEvent;
	volatile UINT NumChecks;			// Free space checks made so far (EraserMain passes)
	UINT CheckInterval;					// Milliseconds between two free space checks
	TOKEN_LIST *Targets;				// Files and directories under DirName whose files may be deleted, in this order
};

typedef struct ERASE_FILE
{
	char *FullPath;
	UINT64 UpdateTime;
} ERASE_FILE;

ERASER *NewEraser(LOG *log, UINT64 min_size, UINT interval, char **targets, UINT num_targets);
void FreeEraser(ERASER *e);
void ELog(ERASER *e, char *name, ...);
int CompareEraseFile(void *p1, void *p2);
UINT GetEraserCheckInterval(ERASER *e);

#endif
