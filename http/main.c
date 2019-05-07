/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include "../lib/sds_audited.h"
#include "../lib/slam.h"
#include "../lib/matchsds.h"
#include "../lib/safe_strings.h"
#include "../lib/servername.h"
#include "../tls_lib/tls_lib.h"
#define LN "\r\n"

static int flags = 0;
#define HTTP_FLAGS_TLS 1

static const char* server_name;

static void cleanup(void){
	slam_close();
}

static sds line,method,url,rest;

#define DEBUG(...) fprintf(stderr,__VA_ARGS__)

static void lineup(void) {
	method = sdsempty();
	if(!method) abort();
	method = sdsMakeRoomFor(method,10);
	if(!method) abort();
	
	url = sdsempty();
	if(!url) abort();
	url = sdsMakeRoomFor(url,256);
	if(!url) abort();
	
	rest = sdsempty();
	if(!rest) abort();
	rest = sdsMakeRoomFor(rest,10);
	if(!rest) abort();
	
	line = sdsempty();
	if(!line) abort();
	line = sdsMakeRoomFor(line,256);
	if(!line) abort();
}

static int emplace(sds target,const char* src,size_t len) {
	size_t s = memcpy_n(target,src,sdsalloc(target)-1,len);
	target[s]=0;
	sdssetlen(target,s);
	return !!s;
}

static void die_eof(void)      { slam_flush(); cleanup(); _exit(1); }

static inline int isNewLine(char c){
	switch(c){
	case '\r':
	case '\n':return 1;
	}
	return 0;
}

static int decode_line(void) {
	size_t len,f;
	len = sdslen(line);
	f = strfind_n(line,len,' ');
	if(!f) return 1;
	if(!emplace(method,line,f-1)) return 2;
	len = moveback_n(line,len,f);
	
	f = strfind_n(line,len,' ');
	if(!f) return 1;
	if(!emplace(url,line,f-1)) return 2;
	len = moveback_n(line,len,f);
	
	if(!emplace(rest,line,len)) return 2;
	sdstrim(rest," \r\n\t");
	return 0;
}

static int read_header(void) {
	for(;;) {
		if(!slam_readline(line)) die_eof();
		if(isNewLine(*line)||!*line) return 0;
	}
	return 1;
}

static void commands(void) {
	for(;;) {
		
		if(!slam_readline(line)) die_eof();
		
		if(decode_line()) die_eof();
		
		DEBUG("method='%s' url='%s' rest='%s'\n",method,url,rest);
		
		if(read_header()) die_eof();
		
		out("HTTP/1.1 200 OK" LN LN);
		out("Hello world!" LN);
		
		die_eof();
	}
}

#define caseof(a,b) case a: b; break
static void parseflags(void) {
	const char* env = getenv("HTTP_FLAGS");
	if(!env)return;
	if(!*env)return;
	do{switch(*env){
		caseof('S',flags |= HTTP_FLAGS_TLS);
	}}while(*++env);
}

/*
Further reading:
	https://www.tutorialspoint.com/de/http/http_requests.htm
	https://www.tutorialspoint.com/de/http/http_responses.htm
*/


int main(void) {
	parseflags();
	server_name = getenv("HTTP_SERVER_NAME");
	if(!server_name)
		server_name = "server_http/0.0 (UNIX)";
	
	lineup();
	
	slam_init();
	if(flags&HTTP_FLAGS_TLS){
		if(!slamtls_init()) return 1;
		if(!slamtls_starttls()) return 1;
	}
	commands();
	
	return 1;
}
