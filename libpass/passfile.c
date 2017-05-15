/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include "passfile.h"
#include "../lib/safe_strings.h"
#include <stdio.h>

static struct password entry;
static char data[1<<12];

struct password* find_password(const char* fn,const char* name){
	char* line;
	size_t n;
	FILE* f = fopen(fn,"r");
	if(!f)return NULL;
	while(line=fgets(data, sizeof data,f)){
		if(*line==' ')continue;
		n = strfind_n(line,strlen(line),' ');
		if(!n)continue;
		line[n-1] = 0 ;
		entry.user = line;
		if(strcmp(line,name)) continue;
		line += n;
		n = strfind_n(line,strlen(line),':');
		if(!n)continue;
		line[n-1] = 0;
		entry.passhash = line;
		fclose(f);
		return &entry;
	}
	fclose(f);
	return 0;
}

int append_password(const char* fn,const char* user,const char* passhash){
	FILE* f;
	/* BLANC is not allowed in user names (it's a delimiter) */
	if(strfind_n(user,strlen(user),' ')) return 0;
	f = fopen(fn,"a");
	if(!f)return 0;
	fprintf(f,"%s %s:\n",user,passhash);
	fclose(f);
	return 1;
}

