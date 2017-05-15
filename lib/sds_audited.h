/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

#include "sds.h"

#ifdef __GNUC__
#define sdsBanned __attribute__ ((error("Banned: Insecure")))
#define sdsWarning __attribute__ ((warning("Warning: Insecure")))
sds sdscatvprintf(sds s, const char *fmt, va_list ap) sdsBanned ;
sds sdscatprintf(sds s, const char *fmt, ...) sdsBanned ;
sds sdscatfmt(sds s, char const *fmt, ...) sdsBanned ;
void sdsrange(sds s, int start, int end) sdsBanned ;
void sdsupdatelen(sds s) sdsBanned ;
sds *sdssplitlen(const char *s, int len, const char *sep, int seplen, int *count) sdsBanned ;
void sdsfreesplitres(sds *tokens, int count) sdsBanned;
sds sdsfromlonglong(long long value) sdsWarning;
sds sdscatrepr(sds s, const char *p, size_t len) sdsBanned;
sds *sdssplitargs(const char *line, int *argc) sdsBanned;
sds sdsjoin(char **argv, int argc, char *sep) sdsBanned;
sds sdsjoinsds(sds *argv, int argc, const char *sep, size_t seplen) sdsBanned;
#undef sdsBanned
#undef sdsWarning
#endif

