/*
 * Copyright (C) 2017-2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

#include "common.h"

struct password* find_password(const char* fn,const char* name);
int append_password(const char* fn,const char* user,const char* passhash);

