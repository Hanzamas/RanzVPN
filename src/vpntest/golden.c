// golden.c
// The golden files of vpntest: a test writes its output into the output directory of its golden family and compares it
// with the golden file of the family (tests/golden/<family>), or records it in update mode

#include "harness_int.h"

#include "Mayaqua/FileIO.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"

// Print a check result and count the failures
bool HarnessCheck(HARNESS *h, bool ok, char *what)
{
	Print("  [%s] %s\n", ok ? "PASS" : "FAIL", what);

	if (ok == false)
	{
		h->NumFail++;
	}

	return ok;
}

// Copy a buffer into a newly allocated NUL-terminated string
char *HarnessBufToStr(BUF *b)
{
	if (b == NULL)
	{
		return CopyStr("");
	}

	char *ret = ZeroMalloc(b->Size + 1);
	Copy(ret, b->Buf, b->Size);

	return ret;
}

// Skip a UTF-8 byte order mark
static char *HarnessSkipBom(char *s)
{
	if (s != NULL && (UCHAR)s[0] == 0xEF && (UCHAR)s[1] == 0xBB && (UCHAR)s[2] == 0xBF)
	{
		return s + 3;
	}

	return s;
}

// Split a text into lines (CR removed, no empty entry after the final LF)
static LIST *HarnessSplitLines(char *text)
{
	LIST *o = NewListFast(NULL);
	UINT start = 0;

	if (text == NULL)
	{
		return o;
	}

	UINT len = StrLen(text);

	for (UINT i = 0;i <= len;i++)
	{
		if (i == len || text[i] == '\n')
		{
			UINT n = i - start;

			if (i == len && n == 0)
			{
				break;
			}

			char *line = ZeroMalloc(n + 1);
			Copy(line, text + start, n);
			if (n >= 1 && line[n - 1] == '\r')
			{
				line[n - 1] = 0;
			}

			Add(o, line);
			start = i + 1;
		}
	}

	return o;
}

// Release a line list
static void HarnessFreeLines(LIST *o)
{
	if (o == NULL)
	{
		return;
	}

	for (UINT i = 0;i < LIST_NUM(o);i++)
	{
		Free(LIST_DATA(o, i));
	}

	ReleaseList(o);
}

// Compare two texts line by line (line endings and a final newline do not matter)
static bool HarnessTextEqual(char *a, char *b)
{
	LIST *la = HarnessSplitLines(HarnessSkipBom(a));
	LIST *lb = HarnessSplitLines(HarnessSkipBom(b));
	bool ret = true;

	if (LIST_NUM(la) != LIST_NUM(lb))
	{
		ret = false;
	}
	else
	{
		for (UINT i = 0;i < LIST_NUM(la);i++)
		{
			if (StrCmp(LIST_DATA(la, i), LIST_DATA(lb, i)) != 0)
			{
				ret = false;
				break;
			}
		}
	}

	HarnessFreeLines(la);
	HarnessFreeLines(lb);

	return ret;
}

// Print a unified-diff-like report (LCS based, with context lines)
static void HarnessPrintDiff(char *name, char *expected, char *actual)
{
	LIST *a = HarnessSplitLines(HarnessSkipBom(expected));
	LIST *b = HarnessSplitLines(HarnessSkipBom(actual));
	UINT n = LIST_NUM(a);
	UINT m = LIST_NUM(b);

	Print("--- golden/%s\n", name);
	Print("+++ actual/%s\n", name);

	if (n > HARNESS_DIFF_MAX_LINES || m > HARNESS_DIFF_MAX_LINES)
	{
		// Too large for the LCS table: report the first difference only
		for (UINT i = 0;i < MAX(n, m);i++)
		{
			char *x = (i < n) ? LIST_DATA(a, i) : NULL;
			char *y = (i < m) ? LIST_DATA(b, i) : NULL;

			if (x == NULL || y == NULL || StrCmp(x, y) != 0)
			{
				Print("@@ line %u @@\n", i + 1);
				if (x != NULL)
				{
					Print("-%s\n", x);
				}
				if (y != NULL)
				{
					Print("+%s\n", y);
				}
				break;
			}
		}
	}
	else
	{
		UINT w = m + 1;
		UINT *dp = ZeroMalloc(sizeof(UINT) * (n + 1) * w);
		UINT num_ops = 0;
		char *op_type = ZeroMalloc(n + m + 1);
		char **op_line = ZeroMalloc(sizeof(char *) * (n + m + 1));
		bool *visible = ZeroMalloc(sizeof(bool) * (n + m + 1));
		UINT i, j;
		bool gap = false;

		// dp[i][j] = length of the LCS of a[i..] and b[j..]
		for (i = n;i-- > 0;)
		{
			for (j = m;j-- > 0;)
			{
				if (StrCmp(LIST_DATA(a, i), LIST_DATA(b, j)) == 0)
				{
					dp[i * w + j] = dp[(i + 1) * w + (j + 1)] + 1;
				}
				else
				{
					dp[i * w + j] = MAX(dp[(i + 1) * w + j], dp[i * w + (j + 1)]);
				}
			}
		}

		i = 0;
		j = 0;
		while (i < n || j < m)
		{
			if (i < n && j < m && StrCmp(LIST_DATA(a, i), LIST_DATA(b, j)) == 0)
			{
				op_type[num_ops] = ' ';
				op_line[num_ops++] = LIST_DATA(a, i);
				i++;
				j++;
			}
			else if (j < m && (i >= n || dp[i * w + (j + 1)] >= dp[(i + 1) * w + j]))
			{
				op_type[num_ops] = '+';
				op_line[num_ops++] = LIST_DATA(b, j);
				j++;
			}
			else
			{
				op_type[num_ops] = '-';
				op_line[num_ops++] = LIST_DATA(a, i);
				i++;
			}
		}

		for (UINT k = 0;k < num_ops;k++)
		{
			if (op_type[k] != ' ')
			{
				UINT from = (k >= HARNESS_DIFF_CONTEXT) ? (k - HARNESS_DIFF_CONTEXT) : 0;
				UINT to = MIN(k + HARNESS_DIFF_CONTEXT, num_ops - 1);

				for (UINT x = from;x <= to;x++)
				{
					visible[x] = true;
				}
			}
		}

		for (UINT k = 0;k < num_ops;k++)
		{
			if (visible[k])
			{
				if (gap)
				{
					Print("@@ ... @@\n");
				}
				gap = false;
				Print("%c%s\n", op_type[k], op_line[k]);
			}
			else
			{
				gap = true;
			}
		}

		Free(visible);
		Free(op_line);
		Free(op_type);
		Free(dp);
	}

	HarnessFreeLines(a);
	HarnessFreeLines(b);
}

// Whether a directory contains at least one file
bool HarnessDirHasFiles(char *dir)
{
	DIRLIST *d = EnumDir(dir);
	bool ret = false;

	if (d == NULL)
	{
		return false;
	}

	for (UINT i = 0;i < d->NumFiles;i++)
	{
		if (d->File[i]->Folder == false)
		{
			ret = true;
			break;
		}
	}

	FreeDir(d);

	return ret;
}

// Output and golden directories of another golden family (for example "pack") and its update mode: the output
// directory is <harness output directory>/<family>, the golden directory is the sibling <family> of the harness
// golden directory (tests/golden/<family>). Update mode when that directory has no file or RANZ_UPDATE_GOLDEN=1.
void HarnessGetFamilyDirs(char *family, char *out_dir, UINT out_size, char *golden_dir, UINT golden_size, bool *update)
{
	char exe_dir[MAX_SIZE];
	char tmp[MAX_SIZE];
	char path[MAX_SIZE];

	GetExeDir(exe_dir, sizeof(exe_dir));

	// RANZ_HARNESS_OUT overrides <exe dir>/harness-out, as for the harness family
	if (GetEnv("RANZ_HARNESS_OUT", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false)
	{
		Format(out_dir, out_size, "%s/%s", tmp, family);
	}
	else
	{
		Format(out_dir, out_size, "%s/harness-out/%s", exe_dir, family);
	}

	// RANZ_GOLDEN_DIR names the harness family directory: the family directory is its sibling
	if (GetEnv("RANZ_GOLDEN_DIR", tmp, sizeof(tmp)) && IsEmptyStr(tmp) == false)
	{
		Format(path, sizeof(path), "%s/../%s", tmp, family);
	}
	else
	{
		Format(path, sizeof(path), "%s/../tests/golden/%s", exe_dir, family);
	}
	NormalizePath(golden_dir, golden_size, path);

	*update = false;

	if (GetEnv("RANZ_UPDATE_GOLDEN", tmp, sizeof(tmp)) && StrCmp(tmp, "1") == 0)
	{
		*update = true;
	}

	if (HarnessDirHasFiles(golden_dir) == false)
	{
		*update = true;
	}
}

// Write the actual output, then compare it with the golden file (or print it in update mode)
void HarnessCompareGolden(HARNESS *h, char *out_dir, char *golden_dir, char *file_name, char *actual, bool update)
{
	char path[MAX_SIZE];
	char tmp[MAX_SIZE];
	BUF *b = NewBuf();

	WriteBuf(b, actual, StrLen(actual));
	Format(path, sizeof(path), "%s/%s", out_dir, file_name);
	if (DumpBuf(b, path) == false)
	{
		Format(tmp, sizeof(tmp), "write %s", path);
		HarnessCheck(h, false, tmp);
	}
	FreeBuf(b);

	if (update)
	{
		LIST *lines = HarnessSplitLines(actual);

		Print("=== BEGIN GOLDEN %s ===\n", file_name);
		for (UINT i = 0;i < LIST_NUM(lines);i++)
		{
			Print("%s\n", (char *)LIST_DATA(lines, i));
		}
		Print("=== END GOLDEN %s ===\n", file_name);
		HarnessFreeLines(lines);

		Format(tmp, sizeof(tmp), "%s written (update mode, not compared)", file_name);
		HarnessCheck(h, true, tmp);
	}
	else
	{
		Format(path, sizeof(path), "%s/%s", golden_dir, file_name);
		BUF *g = ReadDump(path);
		char *golden = HarnessBufToStr(g);

		Format(tmp, sizeof(tmp), "%s matches the golden file", file_name);
		if (g == NULL)
		{
			Format(tmp, sizeof(tmp), "%s matches the golden file (golden file missing: %s)", file_name, path);
			HarnessCheck(h, false, tmp);
		}
		else if (HarnessCheck(h, HarnessTextEqual(golden, actual), tmp) == false)
		{
			HarnessPrintDiff(file_name, golden, actual);
		}

		Free(golden);
		FreeBuf(g);
	}
}
