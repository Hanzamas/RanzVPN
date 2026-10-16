// WaterMark.c
// SoftEther protocol digital watermark data

#include "WaterMark.h"

#include "Mayaqua/Encrypt.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

#include <stdlib.h>

// Digital watermark image data (GIF89a), loaded from hamcore by InitWaterMark()
BYTE *WaterMark = NULL;
UINT WaterMarkSize = 0;

BUF *LoadWaterMark()
{
	BUF *b;
	UCHAR hash[SHA256_SIZE];
	char hash_str[SHA256_SIZE * 2 + 1];

	b = ReadDump(WATERMARK_FILENAME);
	if (b == NULL)
	{
		return NULL;
	}

	Sha2_256(hash, b->Buf, b->Size);
	BinToStr(hash_str, sizeof(hash_str), hash, sizeof(hash));

	if (b->Size != WATERMARK_SIZE || StrCmpi(hash_str, WATERMARK_SHA256) != 0)
	{
		FreeBuf(b);
		return NULL;
	}

	return b;
}

// Load the watermark at startup (the program cannot run without it)
void InitWaterMark()
{
	BUF *b = LoadWaterMark();

	if (b == NULL)
	{
		Alert("Error: Can't read the watermark data (watermark.bin is missing or corrupt).\r\nPlease check the hamcore files: the resources of the executable, and a hamcore folder next to it.\r\n\r\n(First, reboot the computer. If this problem occurs again, please reinstall VPN software files.)", NULL);
		exit(-1);
	}

	WaterMarkSize = b->Size;
	WaterMark = Clone(b->Buf, b->Size);

	FreeBuf(b);
}

void FreeWaterMark()
{
	Free(WaterMark);
	WaterMark = NULL;
	WaterMarkSize = 0;
}



