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

extern size_t (*slam_read)(void*,size_t);
extern size_t (*slam_write)(const void*,size_t);
extern void (*slam_close)();

void slam_init();
int slam_readline(sds s);
int slam_readline_ptr(const char** ptr,size_t* size);
void slam_skip(size_t f);

/**
 * For debug only.
 * Must be called after slam_init().
 * Dumps all inputs and outputs to stderr. Must be repeated after starttls.
 * Be careful!
 */
void slam_debug();


void outc(char c);
void outdata(const void* p,size_t l);
void outsds(sds s);
void out(const char* s);

void slam_flush();

