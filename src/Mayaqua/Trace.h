// Trace.h
// Header of Trace.c

#ifndef TRACE_H
#define TRACE_H

#include "MayaType.h"

#include <stdarg.h>

void InitTrace();
void FreeTrace();
bool IsTraceEnabled();
void TraceDebugArgs(const char *fmt, va_list args);

#endif // TRACE_H
