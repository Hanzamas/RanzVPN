// CommandTable.c
// vpncmd console table output (Ct*): standard and CSV table printing

#include "Command.h"

#include "Admin.h"
#include "Console.h"

#include "Mayaqua/Internat.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"

#include <stdlib.h>
#include "CommandInternal.h"

static void CtPrintRow(CONSOLE *c, UINT num, UINT *widths, wchar_t **strings, bool *rights, char separate_char)
{
	wchar_t *buf;
	UINT buf_size;
	bool is_sep_line = true;
	if (c == NULL || num == 0 || widths == NULL || strings == NULL || rights == NULL)
	{
		return;
	}

	buf_size = 32;
	for (UINT i = 0;i < num;i++)
	{
		buf_size += sizeof(wchar_t) * widths[i] + 6;
	}

	buf = ZeroMalloc(buf_size);

	for (UINT i = 0;i < num;i++)
	{
		char *tmp;
		wchar_t *space_string;
		UINT w;
		UINT space = 0;
		wchar_t *string = strings[i];
		wchar_t *tmp_line = NULL;

		if (UniStrCmpi(string, L"---") == 0)
		{
			char *s = MakeCharArray('-', widths[i]);
			tmp_line = string = CopyStrToUni(s);

			Free(s);
		}
		else
		{
			is_sep_line = false;
		}

		w = UniStrWidth(string);

		if (widths[i] >= w)
		{
			space = widths[i] - w;
		}

		tmp = MakeCharArray(' ', space);
		space_string = CopyStrToUni(tmp);

		if (rights[i] != false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		UniStrCat(buf, buf_size, string);

		if (rights[i] == false)
		{
			UniStrCat(buf, buf_size, space_string);
		}

		Free(space_string);
		Free(tmp);

		if (i < (num - 1))
		{
			wchar_t tmp[4];
			char str[2];

			if (UniStrCmpi(strings[i], L"---") == 0)
			{
				str[0] = '+';
			}
			else
			{
				str[0] = separate_char;
			}
			str[1] = 0;

			StrToUni(tmp, sizeof(tmp), str);

			UniStrCat(buf, buf_size, tmp);
		}

		if (tmp_line != NULL)
		{
			Free(tmp_line);
		}
	}

	UniTrimRight(buf);

	if (is_sep_line)
	{
		if (UniStrLen(buf) > (c->GetWidth(c) - 1))
		{
			buf[c->GetWidth(c) - 1] = 0;
		}
	}

	c->Write(c, buf);

	Free(buf);
}

static void CtPrintStandard(CT *ct, CONSOLE *c)
{
	CT *t;
	if (ct == NULL || c == NULL)
	{
		return;
	}

	t = CtNewStandard();
	for (UINT i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		CTR *row = LIST_DATA(ct->Rows, i);

		for (UINT j = 0;j < LIST_NUM(ct->Columns);j++)
		{
			CTC *column = LIST_DATA(ct->Columns, j);

			CtInsert(t, column->String, row->Strings[j]);
		}

		if (i != (LIST_NUM(ct->Rows) - 1))
		{
			CtInsert(t, L"---", L"---");
		}
	}

	CtFree(t, c);
}

static void CtPrint(CT *ct, CONSOLE *c)
{
	UINT *widths;
	UINT num;
	wchar_t **header_strings;
	bool *rights;
	if (ct == NULL || c == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);
	widths = ZeroMalloc(sizeof(UINT) * num);

	for (UINT i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		UINT w;

		w = UniStrWidth(ctc->String);
		widths[i] = MAX(widths[i], w);
	}
	for (UINT j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		for (UINT i = 0;i < num;i++)
		{
			UINT w;

			w = UniStrWidth(ctr->Strings[i]);
			widths[i] = MAX(widths[i], w);
		}
	}

	header_strings = ZeroMalloc(sizeof(wchar_t *) * num);
	rights = ZeroMalloc(sizeof(bool) * num);

	for (UINT i = 0;i < num;i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		header_strings[i] = ctc->String;
		rights[i] = ctc->Right;
	}

	CtPrintRow(c, num, widths, header_strings, rights, '|');

	for (UINT i = 0;i < num;i++)
	{
		char *s;

		s = MakeCharArray('-', widths[i]);
		header_strings[i] = CopyStrToUni(s);
		Free(s);
	}

	CtPrintRow(c, num, widths, header_strings, rights, '+');

	for (UINT i = 0;i < num;i++)
	{
		Free(header_strings[i]);
	}

	for (UINT j = 0;j < LIST_NUM(ct->Rows);j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);

		CtPrintRow(c, num, widths, ctr->Strings, rights, '|');
	}

	Free(rights);
	Free(header_strings);
	Free(widths);
}

static void CtEscapeCsv(wchar_t *dst, UINT size, wchar_t *src){
	UINT len = UniStrLen(src);
	UINT idx;
	bool need_to_escape = false;
	wchar_t tmp[2]=L"*";

	if (src==NULL || dst==NULL)
	{
		return;
	}

	for (UINT i=0; i<len; i++)
	{
		tmp[0] = src[i];
		if (tmp[0] == L","[0] || tmp[0] == L"\n"[0] || tmp[0] == L"\""[0])
		{
			need_to_escape = true;
		}
	}
	if (need_to_escape == false)
	{
		UniStrCpy(dst,size,src);
		return;
	}

	// CSV: quote fields that contain a newline, comma or double quote
	UniStrCpy(dst, size, L"\"");
	idx = UniStrLen(dst);
	if(idx<size-1)
	{
		for (UINT i=0; i<len; i++)
		{
			tmp[0] = src[i];
			if (tmp[0] == L"\""[0])
			{
				UniStrCat(dst, size, tmp);
			}
			UniStrCat(dst, size, tmp);
		}
	}
	UniStrCat(dst, size, L"\"");
	return;
}

static void CtPrintCsv(CT *ct, CONSOLE *c)
{
	UINT num_columns = LIST_NUM(ct->Columns);
	wchar_t buf[MAX_SIZE*4];
	wchar_t fmtbuf[MAX_SIZE*4];

	buf[0] = 0;
	for(UINT i=0; i<num_columns; i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);
		CtEscapeCsv(fmtbuf, sizeof(fmtbuf), ctc->String);
		UniStrCat(buf, sizeof(buf), fmtbuf);
		if(i != num_columns-1)
			UniStrCat(buf, sizeof(buf), L",");
	}
	c->Write(c, buf);

	for(UINT j=0; j<LIST_NUM(ct->Rows); j++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, j);
		buf[0] = 0;
		for(UINT i=0; i<num_columns; i++)
		{
			CtEscapeCsv(fmtbuf, sizeof(fmtbuf), ctr->Strings[i]);
			UniStrCat(buf, sizeof(buf), fmtbuf);
			if(i != num_columns-1)
				UniStrCat(buf, sizeof(buf), L",");
		}
		c->Write(c, buf);
	}
}

void CtFreeEx(CT *ct, CONSOLE *c, bool standard_view)
{
	UINT num;
	if (ct == NULL)
	{
		return;
	}

	if (c != NULL)
	{
		if (c->ConsoleType == CONSOLE_CSV)
		{
			CtPrintCsv(ct, c);
		}
		else
		{
			if (standard_view == false)
			{
				CtPrint(ct, c);
			}
			else
			{
				CtPrintStandard(ct, c);
			}
		}
	}

	num = LIST_NUM(ct->Columns);

	for (UINT i = 0;i < LIST_NUM(ct->Rows);i++)
	{
		CTR *ctr = LIST_DATA(ct->Rows, i);

		for (UINT j = 0;j < num;j++)
		{
			Free(ctr->Strings[j]);
		}

		Free(ctr->Strings);
		Free(ctr);
	}

	for (UINT i = 0;i < LIST_NUM(ct->Columns);i++)
	{
		CTC *ctc = LIST_DATA(ct->Columns, i);

		Free(ctc->String);
		Free(ctc);
	}

	ReleaseList(ct->Columns);
	ReleaseList(ct->Rows);

	Free(ct);
}
void CtFree(CT *ct, CONSOLE *c)
{
	CtFreeEx(ct, c, false);
}

void CtInsert(CT *ct, ...)
{
	CTR *ctr;
	UINT num;
	va_list va;
	if (ct == NULL)
	{
		return;
	}

	num = LIST_NUM(ct->Columns);

	va_start(va, ct);

	ctr = ZeroMalloc(sizeof(CTR));
	ctr->Strings = ZeroMalloc(sizeof(wchar_t *) * num);

	for (UINT i = 0;i < num;i++)
	{
		wchar_t *s = va_arg(va, wchar_t *);

		ctr->Strings[i] = CopyUniStr(s);
	}

	va_end(va);

	Insert(ct->Rows, ctr);
}

void CtInsertColumn(CT *ct, wchar_t *str, bool right)
{
	CTC *ctc;
	if (ct == NULL)
	{
		return;
	}
	if (str == NULL)
	{
		str = L"";
	}

	ctc = ZeroMalloc(sizeof(CTC));
	ctc->String = CopyUniStr(str);
	ctc->Right = right;

	Insert(ct->Columns, ctc);
}

CT *CtNew()
{
	CT *ct;

	ct = ZeroMalloc(sizeof(CT));
	ct->Columns = NewList(NULL);
	ct->Rows = NewList(NULL);

	return ct;
}

CT *CtNewStandard()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);

	return ct;
}
CT *CtNewStandardEx()
{
	CT *ct = CtNew();

	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_1"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_2"), false);
	CtInsertColumn(ct, _UU("CMD_CT_STD_COLUMN_3"), false);

	return ct;
}
