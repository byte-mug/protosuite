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
#include "decision.h"
#include "ini.h"

struct decision_ctx {
	unsigned
		login_user : 1,
		bypass_login : 1,
		from_local : 1,
		from_remote : 1
	;
	LSPF_CTX spf_ctx;
	int      spf_mailfrom;
};

DECISION_CFG deccfg_new(void){
	int i;
	DECISION_CFG cfg;
	cfg = malloc(sizeof(*cfg));
	if(!cfg) return cfg;
	memset(cfg,0,sizeof(*cfg));
	/*
	 * Default settings:
	 *  MUA may send *@local -> *@local
	 *  MUA may send *@local -> *@remote
	 *  MTA may send *@remote -> *@local
	 */
	cfg->perm_login.local2remote = 1;
	cfg->perm_login.local2local = 1;
	cfg->perm_anon.remote2local = 1;
	
	return cfg;
}

static inline int str0eq(const char* str0,const char* check) {
	if(str0) return !strcmp(str0,check);
	return 0;
}

static inline int perm(const char* value){
	if(!strcmp(value,"1")) return 1;
	if(!strcmp(value,"grant")) return 1;
	if(!strcmp(value,"granted")) return 1;
	if(!strcmp(value,"0")) return 0;
	if(!strcmp(value,"deny")) return 0;
	if(!strcmp(value,"denied")) return 0;
	return 0;
}
//#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
static sds convert(const char* value){
	sds s = sdsnew(value);
	if(!s)return s;
	sdstrim(s," \r\n\t");
	return s;
}

/*
 * Warning: This function is ugly because of the macro definitions.
 * In german language, we would call it "Kraut-und-Rueben-Code".
 */
static int handler(
	void* user,
	const char* section,
	const char* name,
	const char* value
#if INI_HANDLER_LINENO
	,int lineno
#endif
	){
	sds c;
	DECISION_CFG cfg = user;
#define CONVERT c = convert(value); if(!c) return 0
#define CONVSET(x) if(x) return 0; c = convert(value); if(!c) return 0; x=c
#define XXPERM(xxfld) do { \
	if(!strcmp(name,"local2local")) { cfg->xxfld.local2local = perm(value); } \
	if(!strcmp(name,"local2remote")) { cfg->xxfld.local2remote = perm(value); } \
	if(!strcmp(name,"remote2local")) { cfg->xxfld.remote2local = perm(value); } \
	if(!strcmp(name,"remote2remote")) { cfg->xxfld.remote2remote = perm(value); } \
	}while(0)
	if(!strcmp(section, "local")) {
		if(!strcmp(name, "suffix")) {
			if(cfg->local.suffix_max<N_SUFFIXES) {
				CONVERT;
				cfg->local.suffix[cfg->local.suffix_max++] = c;
			} else return 0; /* Out of Slots: error! */
		}
	} else if(!strcmp(section, "user2me")) {
		XXPERM(perm_login);
	} else if(!strcmp(section, "mta2me")) {
		if(!strcmp(name,"spf")) { CONVSET(cfg->mta2me.spf); }
		XXPERM(perm_anon);
	//} else if(!strcmp(section, "forward")) {
		/* ... */
	}
	
#undef XXPERM
#undef CONVERT
#undef CONVSET
	return 1;
}

int deccfg_parse(DECISION_CFG cfg,const char* file){
	return ini_parse(file,handler, cfg);
}

#define FREESDS(x) if(x) sdsfree(x)
void deccfg_free(DECISION_CFG cfg) {
	unsigned i,n;
	for(i=0,n=cfg->local.suffix_max;i<n;++i)
		FREESDS(cfg->local.suffix[i]);
	FREESDS(cfg->mta2me.spf);
	free(cfg);
}
#undef FREESDS

DECISION_CTX decctx_new(void){
	DECISION_CTX ctx;
	ctx = malloc(sizeof(*ctx));
	if(!ctx) return ctx;
	memset(ctx,0,sizeof(*ctx));
	ctx->spf_ctx = lspf_init();
	if(lspf_init_failed(ctx->spf_ctx)) goto failed;
	
	return ctx;
failed:
	free(ctx);
	return 0;
}

void decctx_free(DECISION_CTX ctx) {
	if(ctx->spf_ctx) lspf_release(ctx->spf_ctx);
	/* TODO: ... */
}

void decctx_bypass_login(DECISION_CTX ctx,DECISION_CFG cfg){
	ctx->bypass_login = 1;
}

void decctx_on_login(DECISION_CTX ctx,DECISION_CFG cfg) {
	ctx->login_user = 1;
	ctx->bypass_login = 0;
}

static int islocal(DECISION_CFG cfg, sds addr) {
	sds c;
	unsigned i,n;
	size_t addrlen,clen,rest;
	addrlen = sdslen(addr);
	for(i=0,n=cfg->local.suffix_max;i<n;++i){
		c = cfg->local.suffix[i];
		if(!c) continue;
		clen = sdslen(c);
		if(clen>addrlen) continue;
		rest = addrlen-clen;
		if(!memcmp(c,addr+rest,clen)) return 1;
	}
	return 0;
}

static inline void idecctx_reset(DECISION_CTX ctx) {
	ctx->spf_mailfrom = 0;
	ctx->from_local = 0;
	ctx->from_remote = 0;
}

static inline int x2x_denied(DECISION_CTX ctx){
	/*
	 * If the user is anonymous and the address is local, Authentication is required.
	 */
	if(ctx->from_local && !ctx->login_user) return 530;
	
	/*
	 * Otherwise, it's just, that the Mail is rejected.
	 */
	return 550;
}

int  decctx_mailfrom(DECISION_CTX ctx,DECISION_CFG cfg,const char* ip,const char* helodom, mta_sds from) {
	struct decision_perm perm;
	int result;
	idecctx_reset(ctx);
	
	if(islocal(cfg,from)) {
		ctx->from_local = 1;
	} else {
		ctx->from_remote = 1;
	}
	
	/* If the other MTA (if any) is ours, PASS */
	if(ctx->bypass_login) return 0;
	
	/*
	 * Client is another MTA.
	 */
	if(!ctx->login_user) {
		
		if(str0eq(cfg->mta2me.spf,"on")){
			result = lspf_check_mailfrom(ctx->spf_ctx,ip,helodom,from);
			ctx->spf_mailfrom = result;
			switch(result) {
			case LSPF_FAIL: return 550;
			case LSPF_TEMP_ERR: return 450;
			}
		}
		
		perm = cfg->perm_anon;
	} else {
		perm = cfg->perm_login;
	}
	
	if(ctx->from_local) {
		/* Make sure we can send from local. */
		if(!(perm.local2local||perm.local2remote)) return x2x_denied(ctx);
	} else if(ctx->from_remote) {
		/* Make sure we can send from remote. */
		if(!(perm.remote2local||perm.remote2remote)) return x2x_denied(ctx);
	}
	
	return 0;
}
int  decctx_rcptto(DECISION_CTX ctx,DECISION_CFG cfg,const char* ip,const char* helodom, mta_sds from, mta_sds to) {
	struct decision_perm perm;
	int result;
	
	/* If the other MTA (if any) is ours, PASS */
	if(ctx->bypass_login) return 0;
	
	if(ctx->login_user) {
		perm = cfg->perm_login;
	} else {
		perm = cfg->perm_anon;
	}
	
	if(islocal(cfg,to)) {
		if(ctx->from_local&&!perm.local2local) return x2x_denied(ctx);
		if(ctx->from_remote&&!perm.remote2local) return x2x_denied(ctx);
	} else {
		if(ctx->from_local&&!perm.local2remote) return x2x_denied(ctx);
		if(ctx->from_remote&&!perm.remote2remote) return x2x_denied(ctx);
	}
	return 0;
}

