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
static inline int evaluate_err(SPF_errcode_t errc,int* res) {
	switch(errc) {
	case SPF_E_SUCCESS: return 1;
	case SPF_E_NO_MEMORY:
	case SPF_E_INTERNAL_ERROR: /* TODO: LSPF_TEMP_ERR or LSPF_UNKNOWN? */
		*res = LSPF_TEMP_ERR; break;
#if 0
	case SPF_E_NOT_SPF:
	case SPF_E_SYNTAX:
		/*
		 * If an SPF client encounters a syntax error in an SPF record,
		 * it must terminate processing and return a result of "unknown".
		 */
	case SPF_E_RESULT_UNKNOWN:
#endif
	default: *res = LSPF_UNKNOWN;
	}
	return 0;
}

#define caseof(x,y) case x: y; break;
#define otherwise(y) default: y; break;
int lspf_check_mailfrom(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from){
	SPF_request_t   *spf_request = 0;
	SPF_response_t  *spf_response = 0;
	int res = LSPF_UNKNOWN;
	spf_request = SPF_request_new(ctx->spf_server);
	if(spf_request) return LSPF_TEMP_ERR;
        if(ip){
		if(is6(ip))
			SPF_request_set_ipv6_str(spf_request, ip);
		else
			SPF_request_set_ipv4_str(spf_request, ip);
	}
	if(from)    SPF_request_set_env_from(spf_request, from);
	if(helodom) SPF_request_set_helo_dom(spf_request, helodom);
	if(!evaluate_err(SPF_request_query_mailfrom(spf_request, &spf_response),&res)) goto failed;
	if(!evaluate_err(SPF_response_errcode(spf_response),&res)) goto failed;
	
	switch(SPF_response_result(spf_response)) {
	caseof(SPF_RESULT_NONE     , res = LSPF_NONE    );
	caseof(SPF_RESULT_NEUTRAL  , res = LSPF_NEUTRAL );
	caseof(SPF_RESULT_PASS     , res = LSPF_PASS    );
	caseof(SPF_RESULT_FAIL     , res = LSPF_FAIL    );
	caseof(SPF_RESULT_SOFTFAIL , res = LSPF_SOFTFAIL);
	caseof(SPF_RESULT_TEMPERROR, res = LSPF_TEMP_ERR);
	caseof(SPF_RESULT_PERMERROR, res = LSPF_PERM_ERR);
	otherwise(                   res = LSPF_UNKNOWN );
	}
	
	
failed:
	if(spf_response) SPF_response_free(spf_response);
	if(spf_request) SPF_request_free(spf_request);
	return res;
}

int lspf_check_rcptto(LSPF_CTX ctx,const char* ip,const char* helodom,const char* from,const char* to){
	SPF_request_t   *spf_request = 0;
	SPF_response_t  *spf_response = 0;
	int res = LSPF_UNKNOWN;
	spf_request = SPF_request_new(ctx->spf_server);
	if(spf_request) return LSPF_TEMP_ERR;
        if(ip){
		if(is6(ip))
			SPF_request_set_ipv6_str(spf_request, ip);
		else
			SPF_request_set_ipv4_str(spf_request, ip);
	}
	if(from)    SPF_request_set_env_from(spf_request, from);
	if(helodom) SPF_request_set_helo_dom(spf_request, helodom);
	if(!evaluate_err(SPF_request_query_rcptto(spf_request, &spf_response,to),&res)) goto failed;
	if(!evaluate_err(SPF_response_errcode(spf_response),&res)) goto failed;
	
	switch(SPF_response_result(spf_response)) {
	caseof(SPF_RESULT_NONE     , res = LSPF_NONE    );
	caseof(SPF_RESULT_NEUTRAL  , res = LSPF_NEUTRAL );
	caseof(SPF_RESULT_PASS     , res = LSPF_PASS    );
	caseof(SPF_RESULT_FAIL     , res = LSPF_FAIL    );
	caseof(SPF_RESULT_SOFTFAIL , res = LSPF_SOFTFAIL);
	caseof(SPF_RESULT_TEMPERROR, res = LSPF_TEMP_ERR);
	caseof(SPF_RESULT_PERMERROR, res = LSPF_PERM_ERR);
	otherwise(                   res = LSPF_UNKNOWN );
	}
	
	
failed:
	if(spf_response) SPF_response_free(spf_response);
	if(spf_request) SPF_request_free(spf_request);
	return res;
}

