/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once

typedef struct lspf_ctx_s* LSPF_CTX;

enum {
#if 0
	/* This was previously defined. */
	LSPF_OK,
	LSPF_INTERNAL,
	LSPF_REJECT,
#endif
	LSPF_NONE,
	LSPF_NEUTRAL,
	LSPF_PASS,
	LSPF_FAIL,
	LSPF_SOFTFAIL,
	LSPF_TEMP_ERR,
	LSPF_PERM_ERR,
	LSPF_UNKNOWN,
};

LSPF_CTX lspf_init(void);
int lspf_init_failed(LSPF_CTX ctx);
void lspf_release(LSPF_CTX ctx);

int lspf_check_mailfrom(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from);
int lspf_check_rcptto(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from,const char* to);
/**/
