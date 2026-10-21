

#ifndef	HTTP_INTERNAL_H
#define	HTTP_INTERNAL_H

void FreeHttpValue(HTTP_VALUE *value);
int CompareHttpValue(void *p1, void *p2);
char *RecvLine(SOCK *s, UINT max_size);

#endif	// HTTP_INTERNAL_H
