/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <nss/nss.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../lib/slam.h"
#include "tls_lib.h"

//static SSL *server_ctx;
//static SSL *client_ctx;
static const char* certificate;
static const char* keyforcert;
int nfd;

static size_t slamtls_read (void* v,size_t s){
	//ssize_t r = SSL_read(client_ctx,v,s);
	//if(r<0)r=0;
	//return r;
}
static size_t slamtls_write (const void* v,size_t s){
	//ssize_t r = SSL_write(client_ctx,(void*)v,s);
	//if(r<0)r=0;
	//return r;
}
static void slamtls_close (){
	//SSL_shutdown(client_ctx);
	close(nfd);
	//SSL_free(client_ctx);
}

static const char* nss_certdir;
static const char* cert_prefix;
static const char* key_prefix;
static const char* nss_secmod;

#define failon(x) if(x) return 0
#define failon2(x) do{ if(x) { NSS_Shutdown(); return 0; }}while(0)
int slamtls_init(){
	int i;
	struct stat statbuf;
	failon(fstat(0, &statbuf));
	failon(!S_ISSOCK(statbuf.st_mode));
	failon(fstat(1, &statbuf));
	failon(!S_ISSOCK(statbuf.st_mode));
	
	nss_certdir = getenv("NSS_CERTDIR");
	failon(!nss_certdir);
#if 0
	cert_prefix = getenv("NSS_CERT");
	if(!cert_prefix) cert_prefix = "";
	key_prefix  = getenv("NSS_KEY");
	if(!key_prefix) key_prefix = "";
	nss_secmod  = getenv("NSS_SECMOD");
	if(!nss_secmod) nss_secmod = "secmod.db";
#endif
	
	certificate = getenv("TLS_CERT");
	keyforcert = getenv("TLS_KEY");
	failon(!certificate);
	failon(!keyforcert);
	
	return 1;
}

/*
Informations:
	https://github.com/tiran/mod_nss
	https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Reference
	https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc.html
	https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Reference/NSS_functions#SSL_functions
*/

int slamtls_starttls(){
	//SECStatus status;
	int status;
	
	nfd = dup(1);
	failon(nfd<0);
	close(0);
	close(1);
	
	
	//server_ctx = SSL_CTX_new(SSLv3_server_method()); failon(!server_ctx);
	//SSL_CTX_use_certificate_file(server_ctx, certificate, SSL_SERVER_RSA_CERT);
	//SSL_CTX_use_PrivateKey_file(server_ctx, keyforcert, SSL_SERVER_RSA_KEY);
	//failon(!SSL_CTX_check_private_key(server_ctx));
	
	/*
	 XXX consider NSS_Init(nss_certdir)
	 https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc.html#1022864
	 */
	status = NSS_Initialize(nss_certdir,cert_prefix,key_prefix,nss_secmod,NSS_INIT_READONLY);
	//status = NSS_Init(nss_certdir);
	
	failon2(status != SECSuccess);
	
	status = NSS_SetDomesticPolicy();
	failon2(status != SECSuccess);
	
	//PK11_FindCertFromNickname();
	
	return 0;
	
	//client_ctx = SSL_new(server_ctx); failon(!client_ctx);
	//SSL_set_fd(client_ctx, nfd);
	//failon(!SSL_accept(client_ctx));
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

