/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

#include "safe_strings.h"

size_t memeqlower_l(const void* checked,size_t clen,const void* pattern,size_t plen);
size_t memeqlower_n(const void* checked,size_t clen,const void* pattern,size_t plen);
size_t memeqlower_p(const void* checked,size_t clen,const void* pattern,size_t plen);

