// golden.h
// The golden files of vpntest (golden.c): a test writes its output into the output directory of its golden family and
// compares it with the golden file of the family (tests/golden/<family>), or records it in update mode

#ifndef	GOLDEN_H
#define	GOLDEN_H

#include "Mayaqua/MayaType.h"

// The checks of a test that compares golden files: a test zeroes it, and HarnessCheck counts the failures
typedef struct HARNESS
{
	UINT NumFail;				// Failed checks
} HARNESS;

bool HarnessCheck(HARNESS *h, bool ok, char *what);
char *HarnessBufToStr(BUF *b);
bool HarnessDirHasFiles(char *dir);
void HarnessGetFamilyDirs(char *family, char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update);
void HarnessCompareGolden(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, char *actual, bool update);

#endif	// GOLDEN_H
