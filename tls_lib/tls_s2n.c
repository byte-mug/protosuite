/*
 * Copyright (C) 2017-2019 Simon Schmidt
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
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include "../lib/slam.h"
#include "tls_lib.h"
#include <s2n.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MAP_FIXED
#define MAP_FIXED 0
#endif

static struct s2n_connection *client_ctx;
static const char* certificate;
static const char* keyforcert;
static int nfd;
static s2n_blocked_status blocked;

static const char* certmmap;
static const char* keymmap;

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

static char* filemapf(const char* fn) {
	struct stat sb;
	char* ret = 0;
	int mod = getpagesize();
	off_t size;
	int fd = open(fn,O_RDONLY,0);
	if(fd<0) return 0;
	if(fstat(fd,&sb)) goto failed;
	
	/* Empty file: Failed. */
	if(sb.st_size==0) goto failed;
	
	size = (sb.st_size+(mod-1))/mod;
	ret = mmap(0,size*mod,PROT_READ|PROT_WRITE,MAP_FILE|MAP_PRIVATE,fd,0);
	if(ret==MAP_FAILED) { ret=0; goto failed; }
	
	if(sb.st_size%mod) {
		/*
		 * Set a trailing NUL terminator.
		 * Since our mapping is MAP_PRIVATE, we will trigger a COW-event this way.
		 */
		ret[sb.st_size] = 0;
	} else {
		/*
		 * If we are here, we got a file that exactly fits into the boundaries of N Pages.
		 *
		 * Allocate a Page behind the memory mapped file to have a NUL-character behind it.
		 */
		void* x = mmap(ret+sb.st_size,mod,PROT_READ|PROT_WRITE,MAP_ANONYMOUS|MAP_FIXED,0,0);
		ret[sb.st_size] = 0;
	}
	
failed:
	close(fd);
	return ret;
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
	
	certmmap = filemapf(certificate);
	keymmap = filemapf(keyforcert);
	failon(!certmmap);
	failon(!keymmap);
	
	return 1;
}

static const char* s2n_e2s(){
#define SPLAIN(x) fprintf(stderr,"%s : %d\n",#x,(int)(x))
static char buffer [25];
	switch(s2n_error_get_type(s2n_errno)){
	case S2N_ERR_T_OK:       return "No error";
	case S2N_ERR_T_IO:       return "Underlying I/O operation failed, check system errno";
	case S2N_ERR_T_CLOSED:   return "EOF";
	case S2N_ERR_T_BLOCKED:  return "Underlying I/O operation would block";
	case S2N_ERR_T_ALERT:    return "Incoming Alert";
	case S2N_ERR_T_PROTO:    return "Failure in some part of the TLS protocol. Ex: CBC verification failure";
	case S2N_ERR_T_INTERNAL: return "Error internal to s2n. A precondition could have failed.";
	case S2N_ERR_T_USAGE:    return "User input error. Ex: Providing an invalid cipher preference version";
	}
	sprintf(buffer,"%d",s2n_error_get_type(s2n_errno));
	return buffer;
	//return "????";
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
	
	SPLAIN(S2N_ERR_T_OK);
	SPLAIN(S2N_ERR_T_IO);
	SPLAIN(S2N_ERR_T_CLOSED);
	SPLAIN(S2N_ERR_T_BLOCKED);
	SPLAIN(S2N_ERR_T_ALERT);
	SPLAIN(S2N_ERR_T_PROTO);
	SPLAIN(S2N_ERR_T_INTERNAL);
	SPLAIN(S2N_ERR_T_USAGE);
	
	failon(s2n_init()<0);
	s2n_errno = S2N_ERR_T_OK;
	/*
	*/
	struct s2n_config * config = s2n_config_new(); failon(!config);
	
	PUT(s2n_config_set_cipher_preferences(config, "default"); );
	s2n_config_set_cipher_preferences(config, "default");
	
	PUT(failonX(s2n_config_add_cert_chain_and_key(config,certmmap,keymmap)<0););
	failonX(s2n_config_add_cert_chain_and_key(config,certmmap,keymmap)<0);
	
	PUT(client_ctx = s2n_connection_new(S2N_SERVER); failonX(!client_ctx););
	client_ctx = s2n_connection_new(S2N_SERVER); failonX(!client_ctx);
	
	PUT(s2n_connection_set_config(client_ctx, config););
	s2n_connection_set_config(client_ctx, config);
	
	PUT(failonX(s2n_connection_set_fd(client_ctx, nfd) < 0););
	failonX(s2n_connection_set_fd(client_ctx, nfd) < 0);
	
	PUT(failonX(s2n_negotiate(client_ctx, &blocked) < 0););
	failonX(s2n_negotiate(client_ctx, &blocked) < 0);
	
	fprintf(stderr,"s2n_errno = %s\n",s2n_e2s()); fflush(stderr);
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

