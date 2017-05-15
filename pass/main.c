/*
 * Copyright (C) 2017 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libpass/passfile.h"
#include "../libyescrypt/yescrypt.h"

int main(int argc,char**argv){
	int c,fd;
	char buf16[16] = "test123test12345";
	char* file = 0;
	char* user = 0;
	char* pass = 0;
	const char* raw_pass = 0;
	const char* urand = 0;
	yescrypt_flags_t yescflags = 0;
	while ( (c = getopt(argc, argv, "f:u:r:p:xd")) != -1) {
		switch (c) {
		case 'f': file = optarg; break;
		case 'u': user = optarg; break;
		case 'r': raw_pass = optarg; break;
		case 'p': pass = optarg; break;
		case 'x': yescflags |= YESCRYPT_RW; break;
		case 'd': urand = "/dev/random"; break;
		}
	}
	if(urand){
		if((fd = open(urand,O_RDONLY))<0){
			printf("urand not fond: '%s'\n",urand);
			return 1;
		}
		read(fd,buf16,sizeof buf16);
		close(fd);
	}
	const char* prefix = yescrypt_gensalt(13,5,5,yescflags,buf16,sizeof buf16);
	if(!file){
		printf("missing -f /path/to/file\n");
		return 1;
	}
	if(!user){
		printf("missing -u username\n");
		return 1;
	}
	struct password* p = find_password(file,user);
	if(p){
		printf(
			"Oh, user '%s' already exists in the file.\n"
			"I recommend you to Grab an editor (like vi) and remove the line.\n",
			user
			);
		return 1;
	}
	
	if(pass && !raw_pass){
		raw_pass = yescrypt(pass,prefix);
		//printf("raw_pass %s\n",raw_pass ?: "<nil>");
	}
	if(!raw_pass){
		printf("missing -r raw_pass or -p pass\n");
		return 1;
	}
	if(!append_password(file,user,raw_pass)){
		printf("appending failed for various reasons.\n");
		return 1;
	}
	return 0;
}

