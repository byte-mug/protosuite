/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include "lspf.h"

LSPF_CTX lspf_init(void){ return 0; }
int lspf_init_failed(LSPF_CTX ctx) { return 0; }
void lspf_release(LSPF_CTX ctx) {}

int lspf_check_mailfrom(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from){ return LSPF_UNKNOWN; }
int lspf_check_rcptto(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from,const char* to){ return LSPF_UNKNOWN; }
