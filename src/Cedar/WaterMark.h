// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module


// WaterMark.h
// Header of WaterMark.c

#ifndef WATERMARK_H
#define WATERMARK_H

#include "Mayaqua/MayaType.h"

// Hamcore file that holds the digital watermark (a GIF89a image)
#define WATERMARK_FILENAME "|watermark.bin"
#define WATERMARK_SIZE     1411                                                               // Size of the watermark file
#define WATERMARK_SHA256   "96A706BBAB378EC37DFEF21E02B1A3C177FBEBEFFA039EB0EFAC918630DF12A0" // SHA-256 of the watermark file

// Digital watermark
extern BYTE *WaterMark;
extern UINT WaterMarkSize;

BUF *LoadWaterMark();
void InitWaterMark();
void FreeWaterMark();

#define MAX_WATERMARK_SIZE (WaterMarkSize + HTTP_PACK_RAND_SIZE_MAX * 2)

#endif // WATERMARK_H

