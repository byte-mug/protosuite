/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <unistd.h>
#include <stdlib.h>
#include "slam.h"
#include "safe_strings.h"

#include "sds_audited.h"

size_t (*slam_read)(void*,size_t);
size_t (*slam_write)(const void*,size_t);
void (*slam_close)();

char buffer[1<<14];
size_t pos;

char outbuf[1<<14];
size_t outpos;

static size_t stdio_read (void* v,size_t s){
	ssize_t r = read(0,v,s);
	if(r<0)r=0;
	return r;
}
static size_t stdio_write (const void* v,size_t s){
	ssize_t r = write(1,v,s);
	if(r<0)r=0;
	return r;
}
static void stdio_close (){
	close(0);
	close(1);
}

static size_t (*oslam_read)(void*,size_t);
static size_t (*oslam_write)(const void*,size_t);

static size_t nslam_read (void* v,size_t s){
	size_t r = oslam_read(v,s);
	if(r)write(2,v,r);
	return r;
}
static size_t nslam_write (const void* v,size_t s){
	size_t r = oslam_write(v,s);
	if(r)write(2,v,r);
	return r;
}

void slam_init(){
	slam_read = stdio_read;
	slam_write = stdio_write;
	slam_close = stdio_close;
	pos = 0;
	outpos = 0;
}

void slam_debug(){
	oslam_read  = slam_read;
	oslam_write = slam_write;
	slam_read   = nslam_read;
	slam_write  = nslam_write;
}

int slam_readline(sds s){
	int i;
	size_t f = strfind_n(buffer,pos,'\n');
	size_t m = sdsalloc(s);
	if(!m)return 0;
	m--;
	while(!f){
		if(pos>=sizeof buffer) return 0; /* Buffer full. */
		f = slam_read(buffer+pos,(sizeof buffer)-pos);
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
int slam_readline_ptr(const char** ptr,size_t* size){
	int i;
	size_t f = strfind_n(buffer,pos,'\n');
	while(!f){
		if(pos>=sizeof buffer) return 0; /* Buffer full. */
		f = slam_read(buffer+pos,(sizeof buffer)-pos);
		if(!f) return 0; /* Read failed. */
		pos += f;
		f = strfind_n(buffer,pos,'\n');
	}
	if(!f)return 0;
	*ptr = buffer;
	*size = f;
	
	return 1;
}
void slam_skip(size_t f){
	pos = moveback_n(buffer,pos,f);
}

static void flush_if_full(){
	size_t x;
	if(outpos >= sizeof outbuf){
		x = slam_write(outbuf, sizeof outbuf);
		if(!x) abort();
		outpos = moveback_n(outbuf,sizeof outbuf,x);
	}
}

void outc(char c){
	flush_if_full();
	outbuf[outpos++]=c;
}

void outdata(const void* p,size_t l){
	size_t w;
restart:
	flush_if_full();
	w = memcpy_l(outbuf+outpos,p,(sizeof outbuf)-outpos,l);
	outpos+=w;
	p+=w;
	l-=w;
	if(l) goto restart;
}

void outsds(sds s){ outdata(s,sdslen(s)); }
void out(const char* s){ outdata(s,strlen(s)); }

void slam_flush(){
	size_t x;
	if(outpos >= sizeof outbuf) outpos = sizeof outbuf;
	if(!outpos)return;
	x = slam_write(outbuf, outpos);
	if(!x) abort();
	outpos = moveback_n(outbuf,outpos,x);
}


