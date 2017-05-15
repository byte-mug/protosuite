/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include "safe_strings.h"

size_t strlen_p(const char* str, size_t len){
	size_t i;
	for(i=0;i<len;++i){
		if( str[i] ) continue;
		if( i != (len-1)) return 0;
		return i;
	}
	return 0;
}
size_t strlen_n(const char* str, size_t len){
	size_t i;
	for(i=0;i<len;++i){
		if(! str[i] ) return i;
	}
	return 0;
}
size_t strlen_l(const char* str, size_t len){
	size_t i;
	for(i=0;i<len;++i){
		if(! str[i] ) return i;
	}
	return len;
}

char *strcpy_p( char *dest, const char *src , size_t dlen){
	size_t slen = strlen(src)+1;
	if(slen!=dlen) return 0;
	memcpy(dest,src,slen);
	return dest;
}
char *strcpy_n( char *dest, const char *src , size_t dlen){
	size_t slen = strlen(src)+1;
	if(slen>dlen) return 0;
	memcpy(dest,src,slen);
	return dest;
}
char *strcpy_l( char *dest, const char *src , size_t dlen){
	size_t slen = strlen(src);
	if(slen<dlen){
		memcpy(dest,src,slen+1);
	}else{
		dlen--;
		memcpy(dest,src,dlen);
		dest[dlen] = 0;
	}
	return dest;
}

char *strcat_p( char *dest, const char *src , size_t dlen){
	size_t dsl = strlen_l(dest,dlen);
	size_t slen = strlen(src)+1;
	dlen-=dsl;
	if(slen!=dlen) return 0;
	memcpy(dest+dsl,src,slen);
	return dest;
}
char *strcat_n( char *dest, const char *src , size_t dlen){
	size_t dsl = strlen_l(dest,dlen);
	size_t slen = strlen(src)+1;
	dlen-=dsl;
	if(slen>dlen) return 0;
	memcpy(dest+dsl,src,slen);
	return dest;
}
char *strcat_l( char *dest, const char *src , size_t dlen){
	size_t dsl = strlen_l(dest,dlen);
	size_t slen = strlen(src);
	dlen-=dsl;
	if(slen<dlen){
		memcpy(dest+dsl,src,slen+1);
	}else{
		dlen--;
		memcpy(dest+dsl,src,dlen);
		dest[dlen+dsl] = 0;
	}
	return dest;
}

size_t memcpy_p( void *dest, const void *src, size_t dcount, size_t scount ){
	if(dcount!=scount) return 0;
	memcpy(dest,src,scount);
	return scount;
}
size_t memcpy_n( void *dest, const void *src, size_t dcount, size_t scount ){
	if(dcount<scount) return 0;
	memcpy(dest,src,scount);
	return scount;
}
size_t memcpy_l( void *dest, const void *src, size_t dcount, size_t scount ){
	if(dcount<scount) scount = dcount;
	memcpy(dest,src,scount);
	return scount;
}

size_t moveback_n(void *buffer,size_t buflen,size_t offset){
	if(offset>=buflen)return 0;
	memmove(buffer,buffer+offset,buflen-offset);
	return buflen-offset;
}
size_t strfind_n(const char* str, size_t len,char c){
	size_t i;
	for(i=0;i<len;++i){
		if( str[i] == c ) return i+1;
	}
	return 0;
}

