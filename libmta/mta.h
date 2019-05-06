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

typedef struct mta_acl_s* MTA_ACL;
typedef struct mta_ace_s* MTA_ACEs;
typedef struct mta_ace_s  MTA_ACE;
typedef struct mta_eval_state MTA_STATE;

/* sds without including "sds.h" */
//typedef char* mta_sds;

enum {
	MTA_NONE,
	MTA_DEFER,
	MTA_PASS,
	MTA_REJECT,
};
enum {
	/* Mail goes to MBOX. */
	MTAF_MBOX = 0x01,
	MTAF_RUN1 = 0x02,
	MTAF_RUN2 = 0x04,
	MTAF_RUN3 = 0x08,
};
#define MTAF_RUN (MTAF_RUN1|MTAF_RUN2|MTAF_RUN3)

enum {
	MFUNC_NONE,
	MFUNC_TRUE,
	MFUNC_SPF_MAILFROM,
	MFUNC_SPF_RCPTTO,
	MFUNC_QUERY_FLAG,
	MFUNC_QUERY_STAGE,
	MFUNC_QUERY_DECISION,
};
enum {
	MTASTAGE_MAILFROM,
	MTASTAGE_RCPTTO,
	MTASTAGE_DATA,
};

struct mta_acl_s {
	MTA_ACEs array;
	int len;
	int cap;
	int caplog;
};

struct mta_ace_s {
	mta_sds decision,function,argument;
	
	int dec_value,dec_nvalue;
	unsigned dec_flags,dec_nflags;
	
	int func_value;
	
	int arg_value;
	unsigned arg_flags,arg_nflags;
};

struct mta_eval_state {
	unsigned flags;
	int decision;
};

MTA_ACL mta_acl_new(void);
int     mta_acl_load(MTA_ACL acl,int fd);

void    mta_free_ace(MTA_ACE* ace);
void    mta_free(MTA_ACL acl);

int     mta_acl_append(MTA_ACL acl,MTA_ACEs aces,int count);

void    mta_ace_init    (MTA_STATE* state);
int     mta_ace_evaluate(MTA_STATE* state, MTA_ACE* ace,int stage);
void    mta_ace_positive(MTA_STATE* state, MTA_ACE* ace);
int     mta_ace_continue(MTA_STATE* state);

/**/

