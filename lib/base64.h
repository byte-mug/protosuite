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

//void build_base64_table();
sds base64_encode(const unsigned char *data, size_t input_length);
sds base64_decode(const unsigned char *data, size_t input_length);

