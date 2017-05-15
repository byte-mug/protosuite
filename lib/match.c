/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <stdio.h>
#include "match.h"
typedef const unsigned char* cuc;

size_t memeqlower_l(const void* checked,size_t clen,const void* pattern,size_t plen){
	cuc c = checked, p = pattern;
	char cr;
	size_t len = clen<plen?clen:plen;
	size_t i;
	for(i=0;i<len;++i,++c,++p){
		cr = *c;
		switch(cr){
		case 'A' ... 'Z':
			cr+='a';
			cr-='A';
		}
		if((cr)!=*p)return i;
	}
	return len;
}
size_t memeqlower_n(const void* checked,size_t clen,const void* pattern,size_t plen){
	if(plen>clen)return 0;
	return memeqlower_l(checked,clen,pattern,plen);
}
size_t memeqlower_p(const void* checked,size_t clen,const void* pattern,size_t plen){
	size_t m = memeqlower_l(checked,clen,pattern,plen);
	if(m!=plen)return 0;
	return m;
}

