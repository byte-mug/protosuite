/*
 * Copyright (C) 2019 Simon Schmidt
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/*
 * This file contains portions of the BearSSL example code, hence attribution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <bearssl.h>
#include "../lib/slam.h"
#include "../lib/sds_audited.h"
#include "tls_lib.h"

static br_ssl_server_context server_ctx;
static br_sslio_context io_ctx;
static const char* certificate;
static const char* keyforcert;
static int nfd;

#define CHNL 128
static br_x509_certificate cert_chain[CHNL];
static unsigned cert_chain_len = 0;
static br_x509_certificate cert_single;

static sds certbuf = 0;

static const br_rsa_private_key * RSAp = 0;
static const br_ec_private_key * ECp = 0;

static char buffer[1<<14];

static size_t slamtls_read (void* v,size_t s) {
	int r = br_sslio_read(&io_ctx,v,s);
	if(r<0) r = 0;
	return r;
}

/* XXX, maybe, we should seperate write() and flush() */
static size_t slamtls_write (const void* v,size_t s) {
	int r = br_sslio_write(&io_ctx,(void*)v,s);
	if(br_sslio_flush(&io_ctx)) r = 0;
	if(r<0) r = 0;
	return r;
}
static void slamtls_close () {
	br_sslio_close(&io_ctx);
	close(nfd);
}

#define printf(...) fprintf(stderr,__VA_ARGS__)

static void cb_skeypush(void *dest_ctx, const void *src, size_t len) {
	br_skey_decoder_push(dest_ctx,src,len);
}
static void cb_sdsappend(void *dest_ctx, const void *src, size_t len) {
	sds *cur = dest_ctx;
	if(*cur)
		*cur = sdscatlen(*cur,src,len);
	else
		*cur = sdsnewlen(src,len);
	if(!*cur) abort();
}

static int loadcert(const char* fn) {
	size_t R,L,I;
	int r,e;
	int fd = open(fn,O_RDONLY,0);
	if(fd<0) return 0;
	e = BR_PEM_ERROR;
	br_pem_decoder_context ctx;
	br_pem_decoder_init(&ctx);
	br_pem_decoder_setdest(&ctx,cb_sdsappend,&certbuf);
	
	for(;;) {
		r = read(fd,buffer,-1+sizeof buffer);
		if(r<1) break;
		R = r;
		L = 0;
		do {
			I = br_pem_decoder_push(&ctx,buffer+L,R-L);
			L += I;
			e = br_pem_decoder_event(&ctx);
			//printf("e -> %d\n",e);
			switch(e) {
			case BR_PEM_END_OBJ:
				cert_single.data = certbuf;
				cert_single.data_len = sdslen(certbuf);
				if(cert_chain_len>=CHNL) {
					close(fd);
					return 0; /* Chain full! */
				}
				cert_chain[++cert_chain_len] = cert_single;
				certbuf = 0;
				/* Fallthrough! */
			case BR_PEM_BEGIN_OBJ: break;
			default:
				close(fd);
				return 0; /* Error! */
			}
		} while(R>L);
	}
	
	close(fd);
	
	return !!cert_chain_len;
}

static br_skey_decoder_context skc;
static int loadkey(const char* fn) {
	size_t R,L,I;
	int r,e,ok;
	int fd = open(fn,O_RDONLY,0);
	if(fd<0) return 0;
	ok = 0;
	e = BR_PEM_ERROR;
	br_pem_decoder_context ctx;
	br_pem_decoder_init(&ctx);
	br_skey_decoder_init(&skc);
	br_pem_decoder_setdest(&ctx,cb_skeypush,&skc);
	
	for(;;) {
		r = read(fd,buffer,sizeof buffer);
		if(r<1) break;
		R = r;
		L = 0;
		do {
			I = br_pem_decoder_push(&ctx,buffer+L,R-L);
			L += I;
			e = br_pem_decoder_event(&ctx);
			switch(e){
			case BR_PEM_BEGIN_OBJ: continue; /* Skip. */
			case BR_PEM_END_OBJ: break; /* Go ahead. */
			default: /* Error! */
				close(fd);
				return 0;
			}
			ok = 1;
		} while(R>L);
	}
	
	close(fd);
	
	if(!ok) { return 0; }
	if(br_skey_decoder_last_error(&skc)) { return 0; }
	
	switch(br_skey_decoder_key_type(&skc)) {
	case BR_KEYTYPE_RSA: RSAp = br_skey_decoder_get_rsa(&skc); break;
	case BR_KEYTYPE_EC: ECp = br_skey_decoder_get_ec(&skc); break;
	}
	
	return (RSAp||ECp)?1:0;
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
	failon(!loadcert(certificate));
	failon(!loadkey(keyforcert));
	
	printf("RSAp %p; ECp %p\n",RSAp,ECp);
	
	return 1;
}

static unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t rlen;

		rlen = read(*(int *)ctx, buf, len);
		if (rlen <= 0) {
			if (rlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)rlen;
	}
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
	for (;;) {
		ssize_t wlen;

		wlen = write(*(int *)ctx, buf, len);
		if (wlen <= 0) {
			if (wlen < 0 && errno == EINTR) {
				continue;
			}
			return -1;
		}
		return (int)wlen;
	}
}

int slamtls_starttls(){
	nfd = dup(1);
	failon(nfd<0);
	close(0);
	close(1);
	
	if(RSAp) br_ssl_server_init_full_rsa(&server_ctx,cert_chain,cert_chain_len,RSAp);
	if(ECp) br_ssl_server_init_full_ec(&server_ctx,cert_chain,cert_chain_len,BR_KEYTYPE_EC,ECp);
	
	br_ssl_engine_set_buffer(&server_ctx.eng, iobuf, sizeof iobuf, 1);
	
	br_ssl_server_reset(&server_ctx);
	
	br_sslio_init(&io_ctx, &server_ctx.eng, sock_read, &nfd, sock_write, &nfd);
	
	printf("SSL READY\n"); fflush(stderr);
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

