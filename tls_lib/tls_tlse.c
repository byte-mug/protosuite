/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../lib/slam.h"
#include "tls_lib.h"
#define TLS_AMALGAMATION 1
#define TLS_CURVE25519 1
#include "tlse.c"

static SSL *server_ctx;
static SSL *client_ctx;
static const char* certificate;
static const char* keyforcert;
int nfd;

static size_t slamtls_read (void* v,size_t s){
	ssize_t r = SSL_read(client_ctx,v,s);
	if(r<0)r=0;
	return r;
}
static size_t slamtls_write (const void* v,size_t s){
	ssize_t r = SSL_write(client_ctx,(void*)v,s);
	if(r<0)r=0;
	return r;
}
static void slamtls_close (){
	SSL_shutdown(client_ctx);
	close(nfd);
	SSL_free(client_ctx);
}

#define failon(x) if(x) return 0
int slamtls_init(){
	int i;
	struct stat statbuf;
	failon(fstat(0, &statbuf));
	failon(!S_ISSOCK(statbuf.st_mode));
	failon(fstat(1, &statbuf));
	failon(!S_ISSOCK(statbuf.st_mode));
	
	certificate = getenv("TLS_CERT");
	keyforcert = getenv("TLS_KEY");
	failon(!certificate);
	failon(!keyforcert);
	
	return 1;
}

int slamtls_starttls(){
	nfd = dup(1);
	failon(nfd<0);
	close(0);
	close(1);
	
	server_ctx = SSL_CTX_new(SSLv3_server_method()); failon(!server_ctx);
	SSL_CTX_use_certificate_file(server_ctx, certificate, SSL_SERVER_RSA_CERT);
	SSL_CTX_use_PrivateKey_file(server_ctx, keyforcert, SSL_SERVER_RSA_KEY);
	failon(!SSL_CTX_check_private_key(server_ctx));
	
	client_ctx = SSL_new(server_ctx); failon(!client_ctx);
	SSL_set_fd(client_ctx, nfd);
	failon(!SSL_accept(client_ctx));
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

