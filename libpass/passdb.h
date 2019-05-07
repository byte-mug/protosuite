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

struct password* passdb_find_account(const char* db,const char* name);
int passdb_upsert_account(const char* db,const char* user,const char* passhash);
int passdb_delete_account(const char* db,const char* user);

