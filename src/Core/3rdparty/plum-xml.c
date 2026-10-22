/**
 * Copyright (c) 2021 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

// plum-xml.c
// xml_find_matching_child of libplum 0.6.0 (libplum/src/util.c), changed for Ranz VPN (CORE-S5-3, #79): the
// original searches a copy of the document without the attributes of its tags, frees that copy and returns a
// pointer into it, which the UPnP code then reads the control URL from. This one searches the same copy, keeps
// where each of its characters is in the document, and returns the place in the document itself. The search is
// the original's: case-insensitive for the tags, and a child matches when child_value starts with its text.
// src/Core/3rdparty/CMakeLists.txt builds util.c with its own function renamed, so libplum calls this one.

#include "util.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PATTERN_BUFFER_SIZE 256

// Case-insensitive strstr(), as my_stristr of util.c
static const char *xml_stristr(const char *haystack, const char *needle) {
	size_t len = strlen(needle);

	for (const char *p = haystack; *p != '\0'; ++p) {
		size_t i = 0;
		while (i < len && p[i] != '\0' && toupper((unsigned char)p[i]) == toupper((unsigned char)needle[i]))
			++i;
		if (i == len)
			return p;
	}

	return NULL;
}

// The document without the attributes of its tags, as xml_remove_attributes of util.c makes it, and in *where the
// position in str of each of its characters (one more for its end). NULL when there is no memory.
static char *xml_strip(const char *str, size_t **where) {
	size_t len = strlen(str);
	char *out = malloc(len + 1);
	size_t *map = malloc((len + 1) * sizeof(size_t));
	bool inside_tag = false;
	bool skip_chars = false;
	size_t n = 0;

	if (!out || !map) {
		free(out);
		free(map);
		return NULL;
	}

	for (size_t i = 0; i < len; ++i) {
		if (str[i] == '<')
			inside_tag = true;
		else if (str[i] == ' ' && inside_tag)
			skip_chars = true;
		else if (str[i] == '>')
			inside_tag = skip_chars = false;

		if (!skip_chars) {
			out[n] = str[i];
			map[n] = i;
			++n;
		}
	}

	out[n] = '\0';
	map[n] = len;
	*where = map;

	return out;
}

const char *xml_find_matching_child(const char *str, const char *tag, const char *child_tag, const char *child_value) {
	char before[PATTERN_BUFFER_SIZE];
	char after[PATTERN_BUFFER_SIZE];
	char child_before[PATTERN_BUFFER_SIZE];
	char child_after[PATTERN_BUFFER_SIZE];
	size_t *where = NULL;
	const char *found = NULL;

	if (*tag == '\0' || *child_tag == '\0')
		return NULL;

	int ret = snprintf(before, PATTERN_BUFFER_SIZE, "<%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;
	ret = snprintf(after, PATTERN_BUFFER_SIZE, "</%s>", tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;
	ret = snprintf(child_before, PATTERN_BUFFER_SIZE, "<%s>", child_tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;
	ret = snprintf(child_after, PATTERN_BUFFER_SIZE, "</%s>", child_tag);
	if (ret < 0 || ret >= PATTERN_BUFFER_SIZE)
		return NULL;

	char *str2 = xml_strip(str, &where);
	if (!str2)
		return NULL;

	const char *pos = str2;
	while (!found && (pos = xml_stristr(pos, before)) != NULL) {
		pos += strlen(before);

		const char *end = xml_stristr(pos, after);
		if (!end)
			end = pos + strlen(pos);

		const char *child_pos = pos;
		while (!found && (child_pos = xml_stristr(child_pos, child_before)) != NULL && child_pos < end) {
			child_pos += strlen(child_before);

			const char *child_end = xml_stristr(child_pos, child_after);
			if (!child_end)
				child_end = end;

			if (strncmp(child_value, child_pos, (size_t)(child_end - child_pos)) == 0)
				found = str + where[pos - str2];
		}
	}

	free(where);
	free(str2);

	return found;
}
