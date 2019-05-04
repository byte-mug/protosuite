/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
//
#include <unistd.h>
#include <stdlib.h>
#include "../lib/sds_audited.h"
#include "../lib/safe_strings.h"
#include "mta.h"

enum {
	FILEBUF_SZ = 1<<14,
};

static char buffer[1<<14];
static size_t pos;
static int g_fd;

static size_t local_read (void* v,size_t s){
	ssize_t r = read(g_fd,v,s);
	if(r<0)r=0;
	return r;
}
int local_readline(sds s){
	int i;
	size_t f = strfind_n(buffer,pos,'\n');
	size_t m = sdsalloc(s);
	if(!m)return 0;
	m--;
	while(!f){
		if(pos>=sizeof buffer) return 0; /* Buffer full. */
		f = local_read(buffer+pos,(sizeof buffer)-pos);
		if(!f) return 0; /* Read failed. */
		pos += f;
		f = strfind_n(buffer,pos,'\n');
	}
	if(!f)return 0;
	m = memcpy_l(s,buffer,m,f);
	sdssetlen(s,m);
	s[m] = 0;
	pos = moveback_n(buffer,pos,f);
	return 1;
}

MTA_ACL mta_acl_new(void) {
	size_t elem;
	MTA_ACL acl = malloc(sizeof(struct mta_acl_s));
	if(!acl) return acl;
	acl->caplog = 8;
	elem = sizeof(MTA_ACE) << acl->caplog;
	acl->len = 0;
	acl->cap = 1 << acl->caplog;
	acl->array = malloc(elem);
	if(!acl->array) {
		free(acl);
		return 0;
	}
	return acl;
}

static int decision_value(const char* dec) {
	if(!strcmp(dec,"defer")) return MTA_DEFER;
	if(!strcmp(dec,"pass")) return MTA_PASS;
	if(!strcmp(dec,"reject")) return MTA_REJECT;
	return 0;
}
static unsigned decision_flags(const char* dec) {
	if(!strcmp(dec,"mbox")) return MTAF_MBOX;
	if(!strcmp(dec,"run1")) return MTAF_RUN1;
	if(!strcmp(dec,"run2")) return MTAF_RUN2;
	if(!strcmp(dec,"run3")) return MTAF_RUN3;
	if(!strcmp(dec,"run")) return MTAF_RUN;
	return 0;
}
static int function_value(const char* func,const char* arg) {
	if(!strcmp(func,"=")) {
		if(!strcmp(arg,"0")) return MFUNC_NONE;
		if(!strcmp(arg,"1")) return MFUNC_TRUE;
		return MFUNC_QUERY_DECISION;
	}
	if(!strcmp(func,"SPF")) return MFUNC_SPF_MAILFROM;
	if(!strcmp(func,"SPFto")) return MFUNC_SPF_RCPTTO;
	if(!strcmp(func,"?")) return MFUNC_QUERY_FLAG;
	if(!strcmp(func,"stage")) return MFUNC_QUERY_STAGE;
	return MFUNC_NONE;
}

/* Parse ACE (ACL Entry) from string. */
static int mta_ace_parse(const char* line,size_t len,MTA_ACE* ace) {
	size_t f;
	
	f = strfind_n(line,len,'\t');
	if(!f) goto fail_1;
	ace->decision = sdsnewlen(line,f-1);
	if(!ace->decision) goto fail_1;
	line+=f; len-=f;
	
	f = strfind_n(line,len,'\t');
	if(!f) goto fail_2;
	ace->function = sdsnewlen(line,f-1);
	if(!ace->function) goto fail_2;
	line+=f; len-=f;
	
	f = strfind_n(line,len,'\n');
	if(!f) goto fail_3;
	ace->argument = sdsnewlen(line,f-1);
	if(!ace->argument) goto fail_3;
	
	ace->dec_value = 0;
	ace->dec_flags = 0;
	ace->dec_nvalue = 0;
	ace->dec_nflags = 0;
	
	if(*(ace->decision)=='!') {
		ace->dec_nvalue = decision_value(ace->decision+1);
		ace->dec_nflags = decision_flags(ace->decision+1);
	} else {
		ace->dec_value = decision_value(ace->decision);
		ace->dec_flags = decision_flags(ace->decision);
	}
	ace->func_value = function_value(ace->function,ace->argument);
	switch(ace->func_value){
	case MFUNC_QUERY_FLAG:
		ace->arg_flags = ace->arg_nflags = 0;
		if(*(ace->argument)=='!') {
			ace->arg_nflags = decision_flags(ace->argument+1);
		} else {
			ace->arg_flags = decision_flags(ace->argument);
		}
		break;
	case MFUNC_QUERY_STAGE:
		ace->arg_value = -1;
		if(!strcmp(ace->argument,"mail-from")) ace->arg_value = MTASTAGE_MAILFROM;
		if(!strcmp(ace->argument,"rcpt-to"))   ace->arg_value = MTASTAGE_RCPTTO;
		if(!strcmp(ace->argument,"data"))      ace->arg_value = MTASTAGE_DATA;
		break;
	case MFUNC_QUERY_DECISION:
		ace->arg_value = decision_value(ace->argument);
		if(!ace->arg_value) ace->arg_value = -1;
		break;
	}
	
	return 1;
	
fail_4:
	sdsfree(ace->argument);
fail_3:
	sdsfree(ace->function);
fail_2:
	sdsfree(ace->decision);
fail_1:
	return 0;
}

/* Load ACLs from file. */
int     mta_acl_load(MTA_ACL acl,int fd) {
	MTA_ACE ace;
	sds line;
	line = sdsempty();
	if(!line) return 0;
	line = sdsMakeRoomFor(line,256);
	if(!line) return 0;
	pos = 0;
	g_fd = fd;
	while(local_readline(line)){
		if(!mta_ace_parse(line,sdslen(line),&ace)) return 0;
		if(!mta_acl_append(acl,&ace,1)) return 0;
	}
	return 1;
}

void    mta_free_ace(MTA_ACE* ace){
	if(ace->decision) sdsfree(ace->decision);
	if(ace->function) sdsfree(ace->function);
	if(ace->argument) sdsfree(ace->argument);
}

void    mta_free(MTA_ACL acl) {
	int i,n;
	for(i=0,n=acl->len;i<n;++i)
		mta_free_ace(&(acl->array[i]));
}


static inline int grow(MTA_ACL acl) {
	MTA_ACEs aces;
	size_t elem;
	
	if(acl->len < acl->cap) return 1;
	
	acl->caplog++;
	
	elem = sizeof(MTA_ACE) << acl->caplog;
	aces = realloc(acl->array,elem);
	if(!aces) goto fail;
	acl->array = aces;
	acl->cap <<= 1;
	return 1;
fail:
	acl->caplog--;
	return 0;
}

int     mta_acl_append(MTA_ACL acl,MTA_ACEs aces,int count) {
	for(;count>0;--count,++aces){
		if(!grow(acl)) return 0;
		acl->array[acl->len] = *aces;
	}
	return 1;
}

void    mta_ace_init    (MTA_STATE* state){
	state->flags = MTAF_RUN;
	state->decision = MTA_NONE;
}

int     mta_ace_evaluate(MTA_STATE* state, MTA_ACE* ace,int stage){
	switch(ace->func_value) {
	case MFUNC_NONE: return 0;
	case MFUNC_TRUE: return 1;
	case MFUNC_QUERY_FLAG:
		return
			((state->flags&ace->arg_flags)==ace->arg_flags) ||
			((state->flags&ace->arg_nflags)==0);
	case MFUNC_QUERY_STAGE:
		return ace->arg_value == stage;
	case MFUNC_QUERY_DECISION:
		return ace->arg_value == state->decision;
	}
	
	return 0;
}

void    mta_ace_positive(MTA_STATE* state, MTA_ACE* ace){
	state->flags |= ace->dec_flags;
	state->flags &= ~(ace->dec_nflags);
	if(ace->dec_value)
		state->decision = ace->dec_value;
	
	if(ace->dec_nvalue==state->decision)
		state->decision = MTA_NONE;
}

int     mta_ace_continue(MTA_STATE* state){
	return state->flags & MTAF_RUN;
}

