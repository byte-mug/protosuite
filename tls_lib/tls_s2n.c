/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../lib/slam.h"
#include "tls_lib.h"
#include <s2n.h>

static struct s2n_connection *client_ctx;
static const char* certificate;
static const char* keyforcert;
static int nfd;
static s2n_blocked_status blocked;

static size_t slamtls_read (void* v,size_t s){
	ssize_t r = s2n_recv(client_ctx,v,s, &blocked);
	if(r<0)r=0;
	return r;
}
static size_t slamtls_write (const void* v,size_t s){
	ssize_t r = s2n_send(client_ctx,v,s, &blocked);
	if(r<0)r=0;
	return r;
}
static void slamtls_close (){
	s2n_shutdown(client_ctx,&blocked);
	close(nfd);
	s2n_connection_free(client_ctx);
	s2n_cleanup();
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

static const char* s2n_e2s(){
	switch(s2n_errno){
	case S2N_ERR_T_OK:       return "No error";
	case S2N_ERR_T_IO:       return "Underlying I/O operation failed, check system errno";
	case S2N_ERR_T_CLOSED:   return "EOF";
	case S2N_ERR_T_BLOCKED:  return "Underlying I/O operation would block";
	case S2N_ERR_T_ALERT:    return "Incoming Alert";
	case S2N_ERR_T_PROTO:    return "Failure in some part of the TLS protocol. Ex: CBC verification failure";
	case S2N_ERR_T_INTERNAL: return "Error internal to s2n. A precondition could have failed.";
	case S2N_ERR_T_USAGE:    return "User input error. Ex: Providing an invalid cipher preference version";
	}
	return "????";
}
#define PUT(x) (fprintf(stderr,"%s\n", #x),fflush(stderr))
#define failonX(x) if(x){ \
	fprintf(stderr,"s2n_errno = %s\n",s2n_e2s()); fflush(stderr); \
	return 0;\
}
int slamtls_starttls(){
	nfd = dup(1);
	failon(nfd<0);
	close(0);
	close(1);
	
	failon(s2n_init()<0);
	/*
	s2n_errno = S2N_ERR_T_OK;
	struct s2n_config * config = s2n_config_new(); failon(!config);
	
	PUT(s2n_config_set_cipher_preferences(config, "default"); );
	s2n_config_set_cipher_preferences(config, "default");
	
	PUT(failonX(s2n_config_add_cert_chain_and_key(config,certificate,keyforcert)<0););
	failonX(s2n_config_add_cert_chain_and_key(config,certificate,keyforcert)<0);
	*/
	
	PUT(client_ctx = s2n_connection_new(S2N_SERVER); failonX(!client_ctx););
	client_ctx = s2n_connection_new(S2N_SERVER); failonX(!client_ctx);
	
	//PUT(s2n_connection_set_config(client_ctx, config););
	//s2n_connection_set_config(client_ctx, config);
	
	PUT(failonX(s2n_connection_set_fd(client_ctx, nfd) < 0););
	failonX(s2n_connection_set_fd(client_ctx, nfd) < 0);
	
	PUT(failonX(s2n_negotiate(client_ctx, &blocked) < 0););
	failonX(s2n_negotiate(client_ctx, &blocked) < 0);
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

