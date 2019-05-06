/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#pragma once
#include "common.h"
#include "lspf.h"

typedef struct decision_config *DECISION_CFG;
typedef struct decision_ctx *DECISION_CTX;

#define N_SUFFIXES 16

struct decision_perm {
	unsigned
		local2local : 1,
		local2remote : 1,
		remote2local : 1,
		remote2remote : 1;
};

struct decision_config {
	struct {
		mta_sds suffix[N_SUFFIXES];
		unsigned suffix_max;
	} local;
	struct {
		mta_sds spf;
	} mta2me;
	struct decision_perm perm_login,perm_anon;
};

DECISION_CFG deccfg_new();
int  deccfg_parse(DECISION_CFG cfg,const char* file);
void deccfg_free(DECISION_CFG cfg);

DECISION_CTX decctx_new();
void decctx_free(DECISION_CTX ctx);

/*
 * This function is called, if the other client is proven to be
 * A sibling-MTA in our network.
 */
void decctx_bypass_login(DECISION_CTX ctx,DECISION_CFG cfg);

/*
 * This function is called after a successfull user-login.
 * This usually indicates, that the client is a MUA.
 */
void decctx_on_login(DECISION_CTX ctx,DECISION_CFG cfg);

/*
 * Returns:
 *	0 on success.
 *	550 for errorcode 550.
 *	450 for errorcode 450.
 *      530 for "530 5.7.0  Authentication required"
 */
int  decctx_mailfrom(DECISION_CTX ctx,DECISION_CFG cfg,const char* ip,const char* helodom, mta_sds from);
int  decctx_rcptto(DECISION_CTX ctx,DECISION_CFG cfg,const char* ip,const char* helodom, mta_sds from, mta_sds to);

/**/

