/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

#include <string.h>

size_t strlen_p(const char* str, size_t len);
size_t strlen_n(const char* str, size_t len);
size_t strlen_l(const char* str, size_t len);

char *strcpy_p( char *dest, const char *src , size_t dlen);
char *strcpy_n( char *dest, const char *src , size_t dlen);
char *strcpy_l( char *dest, const char *src , size_t dlen);

char *strcat_p( char *dest, const char *src , size_t dlen);
char *strcat_n( char *dest, const char *src , size_t dlen);
char *strcat_l( char *dest, const char *src , size_t dlen);

size_t memcpy_p( void *dest, const void *src, size_t dcount, size_t scount );
size_t memcpy_n( void *dest, const void *src, size_t dcount, size_t scount );
size_t memcpy_l( void *dest, const void *src, size_t dcount, size_t scount );

size_t moveback_n(void *buffer,size_t buflen,size_t offset);
size_t strfind_n(const char* str, size_t len,char c);


