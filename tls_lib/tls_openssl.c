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
#include <openssl/ssl.h>

#ifndef HEADER_DH_H
#include <openssl/dh.h>
#endif

static SSL_CTX *server_ctx;
static SSL *client_ctx;
static const char* certificate;
static const char* keyforcert;
int nfd;

/* openssl dhparam -C 2236 */
DH *get_dh2236()
{
    static unsigned char dhp_2236[] = {
	0x0B, 0xC8, 0x36, 0xBF, 0x29, 0xF7, 0x8E, 0x4A, 0x56, 0x8B, 
	0x21, 0xC4, 0x7F, 0x6E, 0x8F, 0x37, 0xF9, 0x13, 0xCE, 0x3D, 
	0x84, 0x8D, 0x11, 0x09, 0xCF, 0x00, 0x64, 0x4C, 0xF3, 0xA9, 
	0x6F, 0x85, 0xAE, 0x7D, 0xDD, 0x67, 0x39, 0x21, 0x75, 0x7B, 
	0xC7, 0x47, 0x45, 0x14, 0x41, 0x59, 0x6E, 0x15, 0xD0, 0x84, 
	0xA0, 0x37, 0x98, 0x7E, 0x70, 0x06, 0xFA, 0xF0, 0x67, 0x33, 
	0x8A, 0x32, 0x60, 0x9B, 0xBF, 0x52, 0xFF, 0x73, 0x46, 0xD6, 
	0x58, 0x71, 0xBE, 0xF7, 0xAD, 0x82, 0x36, 0xF2, 0x74, 0x32, 
	0x68, 0x46, 0x8C, 0xEB, 0xBE, 0x2A, 0x14, 0xA8, 0x01, 0x3A, 
	0x40, 0x3A, 0x95, 0x35, 0x5B, 0xC6, 0xBF, 0x19, 0xAB, 0x81, 
	0xD6, 0xCF, 0xB2, 0x67, 0xDE, 0xD6, 0xB3, 0xD7, 0x4A, 0x1C, 
	0x85, 0x92, 0x24, 0x4F, 0xF6, 0x74, 0x5B, 0x1F, 0x37, 0x8E, 
	0x03, 0x75, 0x81, 0xE5, 0x68, 0x49, 0x3F, 0x95, 0x38, 0x5B, 
	0xE2, 0xFE, 0x6C, 0xDB, 0xE3, 0xCC, 0xA4, 0xEC, 0xCF, 0x54, 
	0x45, 0x03, 0x85, 0x70, 0x78, 0x3A, 0xD9, 0xB6, 0x1A, 0x0A, 
	0xEC, 0xFC, 0x52, 0x5F, 0xAA, 0x1D, 0x45, 0xC1, 0xA2, 0x72, 
	0xBD, 0xA0, 0x2D, 0xCA, 0x38, 0x97, 0x0D, 0xBC, 0x81, 0x56, 
	0x05, 0xC8, 0x0F, 0x56, 0x79, 0x48, 0xE6, 0xDA, 0xA7, 0x39, 
	0x1E, 0x69, 0x58, 0x31, 0x36, 0x6F, 0x59, 0x8F, 0x4D, 0x63, 
	0x20, 0xA5, 0x60, 0xEF, 0x13, 0x8A, 0xA3, 0xAB, 0x1F, 0x21, 
	0x4B, 0x2C, 0xF7, 0xB2, 0xC8, 0x04, 0xD2, 0xED, 0xB8, 0x71, 
	0x76, 0xF4, 0xED, 0x06, 0xB8, 0xBC, 0x1B, 0x55, 0x6B, 0x06, 
	0xC1, 0xAB, 0x6D, 0xEA, 0xA5, 0x88, 0x09, 0x40, 0xB7, 0x5E, 
	0xFA, 0x06, 0x4F, 0x6A, 0x83, 0x33, 0xCE, 0x5F, 0xE9, 0x75, 
	0x2F, 0xE0, 0xEA, 0x5D, 0xE7, 0xD1, 0xC1, 0xE9, 0x99, 0xD9, 
	0xB6, 0x3C, 0xB1, 0x65, 0x43, 0xD1, 0x0B, 0x0B, 0xD5, 0xF5, 
	0x1F, 0x81, 0x69, 0x46, 0xA9, 0x64, 0x7E, 0x1D, 0x84, 0x63, 
	0xF1, 0xB9, 0xD4, 0x2A, 0xDA, 0xCC, 0x72, 0x46, 0xE0, 0x23
    };
    static unsigned char dhg_2236[] = {
	0x02
    };
    DH *dh = DH_new();
    BIGNUM *dhp_bn, *dhg_bn;

    if (dh == NULL)
        return NULL;
    dhp_bn = BN_bin2bn(dhp_2236, sizeof (dhp_2236), NULL);
    dhg_bn = BN_bin2bn(dhg_2236, sizeof (dhg_2236), NULL);
    if (dhp_bn == NULL || dhg_bn == NULL
            || !DH_set0_pqg(dh, dhp_bn, NULL, dhg_bn)) {
        DH_free(dh);
        BN_free(dhp_bn);
        BN_free(dhg_bn);
        return NULL;
    }
    return dh;
}
/*
-----BEGIN DH PARAMETERS-----
MIIBHwKCARgLyDa/KfeOSlaLIcR/bo83+RPOPYSNEQnPAGRM86lvha593Wc5IXV7
x0dFFEFZbhXQhKA3mH5wBvrwZzOKMmCbv1L/c0bWWHG+962CNvJ0MmhGjOu+KhSo
ATpAOpU1W8a/GauB1s+yZ97Ws9dKHIWSJE/2dFsfN44DdYHlaEk/lThb4v5s2+PM
pOzPVEUDhXB4Otm2Ggrs/FJfqh1FwaJyvaAtyjiXDbyBVgXID1Z5SObapzkeaVgx
Nm9Zj01jIKVg7xOKo6sfIUss97LIBNLtuHF29O0GuLwbVWsGwatt6qWICUC3XvoG
T2qDM85f6XUv4Opd59HB6ZnZtjyxZUPRCwvV9R+BaUapZH4dhGPxudQq2sxyRuAj
AgEC
-----END DH PARAMETERS-----
*/

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
	const SSL_METHOD * method;
	DH *dh = 0;
	EC_KEY *ecdh = 0;
	dh = get_dh2236();
	ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
	
	SSL_library_init();
	
	method = SSLv23_server_method(); failon(!method);
	server_ctx = SSL_CTX_new(method); failon(!server_ctx);
	/* SSL_CTX_set_ecdh_auto(server_ctx, 1); */
	if(dh) SSL_CTX_set_tmp_dh (server_ctx, dh);
	if(ecdh) SSL_CTX_set_tmp_ecdh (server_ctx, ecdh);
	
	SSL_CTX_use_certificate_file(server_ctx, certificate, SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(server_ctx, keyforcert, SSL_FILETYPE_PEM);
	failon(!SSL_CTX_check_private_key(server_ctx));
	
	client_ctx = SSL_new(server_ctx); failon(!client_ctx);
	SSL_set_fd(client_ctx, nfd);
	failon(!SSL_accept(client_ctx));
	
	slam_read = slamtls_read;
	slam_write = slamtls_write;
	slam_close = slamtls_close;
	return 1;
}

