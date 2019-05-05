/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <spf2/spf.h>

#include "lspf.h"

struct lspf_ctx_s {
	SPF_server_t  *spf_server;
};


LSPF_CTX lspf_init(void){
	LSPF_CTX ctx = malloc(sizeof(struct lspf_ctx_s));
	if(!ctx) return 0;
	ctx->spf_server = SPF_server_new(SPF_DNS_CACHE, 0);
	if(!ctx->spf_server) goto errCtx;
	return ctx;
errCtx:
	free(ctx);
	return 0;
}
int lspf_init_failed(LSPF_CTX ctx) { return !ctx; }
void lspf_release(LSPF_CTX ctx) {
	if(!ctx) return;
	if(ctx->spf_server) SPF_server_free(ctx->spf_server);
	free(ctx);
}

static inline int is6(const char* ip) {
	for(;*ip;++ip)
		if(*ip==':') return 1;
	return 0;
}

#define caser(x,y) case x: return y
#define caseof(x,y) case x: y; break
#define otherwise(y) default: y; break

/*
 * spf2l(error-code,spf-response) -> LSPF_*
 *
 * Convert a Response into a local return code.
 */
static inline int
spf2l(SPF_errcode_t errc,SPF_response_t *spf_response) {
	/*
	 * malloc failed.
	 */
	if(!spf_response) return LSPF_TEMP_ERR;
	
	switch(errc) {
	case SPF_E_NOT_SPF:
	case SPF_E_SYNTAX:
	case SPF_E_RESULT_UNKNOWN:
	/* START SMALL PIECES */
	/* ..... */
	/* END SMALL PIECES */
		return LSPF_UNKNOWN;
	}
	switch(SPF_response_reason(spf_response)) {
	caser(SPF_REASON_FAILURE, LSPF_UNKNOWN);
	}
	switch(SPF_response_result(spf_response)) {
	caser(SPF_RESULT_NONE     , LSPF_NONE    );
	caser(SPF_RESULT_NEUTRAL  , LSPF_NEUTRAL );
	caser(SPF_RESULT_PASS     , LSPF_PASS    );
	caser(SPF_RESULT_FAIL     , LSPF_FAIL    );
	caser(SPF_RESULT_SOFTFAIL , LSPF_SOFTFAIL);
	caser(SPF_RESULT_TEMPERROR, LSPF_TEMP_ERR);
	caser(SPF_RESULT_PERMERROR, LSPF_PERM_ERR);
	}
	return LSPF_UNKNOWN;
}

/*
 * spfin(spf-request,ip,helodom,from) -> LSPF_UNKNOWN or LSPF_TEMP_ERR or LSPF_PERM_ERR
 *
 * Fill a SPF request with data.
 */
static inline int
spfin(SPF_request_t *spf_request,const char* ip,const char* helodom,const char* from) {
	if(spf_request) return LSPF_TEMP_ERR;
	if(ip){
		if(is6(ip))
			SPF_request_set_ipv6_str(spf_request, ip);
		else
			SPF_request_set_ipv4_str(spf_request, ip);
	}
	if(from)    SPF_request_set_env_from(spf_request, from);
	if(helodom) SPF_request_set_helo_dom(spf_request, helodom);
	return LSPF_UNKNOWN;
}

int lspf_check_mailfrom(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from) {
	SPF_request_t   *spf_request = 0;
	SPF_response_t  *spf_response = 0;
	SPF_errcode_t    errc;
	int res;
	spf_request = SPF_request_new(ctx->spf_server);
	
	res = spfin(spf_request,ip,helodom,from);
	if(res!=LSPF_UNKNOWN) return res;
	
	errc = SPF_request_query_mailfrom(spf_request, &spf_response);
	res = spf2l(errc,spf_response);
	
	if(spf_response) SPF_response_free(spf_response);
	if(spf_request) SPF_request_free(spf_request);
	return res;
}

int lspf_check_rcptto(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from,const char* to) {
	SPF_request_t   *spf_request = 0;
	SPF_response_t  *spf_response = 0;
	SPF_errcode_t    errc;
	int res;
	spf_request = SPF_request_new(ctx->spf_server);
	
	res = spfin(spf_request,ip,helodom,from);
	if(res!=LSPF_UNKNOWN) return res;
	
	errc = SPF_request_query_rcptto(spf_request, &spf_response,to);
	res = spf2l(errc,spf_response);
	
	if(spf_response) SPF_response_free(spf_response);
	if(spf_request) SPF_request_free(spf_request);
	return res;
}

