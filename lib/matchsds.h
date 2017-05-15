/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

#include "match.h"
#include "sds_audited.h"

static inline size_t sdseqlower_l(sds checked,const char* pattern){
	return memeqlower_l(checked,sdslen(checked),pattern,strlen(pattern));
}
static inline size_t sdseqlower_n(sds checked,const char* pattern){
	return memeqlower_n(checked,sdslen(checked),pattern,strlen(pattern));
}
static inline size_t sdseqlower_p(sds checked,const char* pattern){
	return memeqlower_p(checked,sdslen(checked),pattern,strlen(pattern));
}
