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
#include "../libpass/passdb.h"
#include "../libyescrypt/yescrypt.h"

static void help(void) {
	printf(
		"tool_passdb -d <password-db> -u <username> -p <password> [otherflags]\n"
		"tool_passdb -d <password-db> -u <username> -r <yescrypt-hashed-password> [otherflags]\n"
		"tool_passdb -d <password-db> -u <username> -D [otherflags]\n"
		"\nFlags:\n"
		"\t-d <password-db>\n"
		"\t\tPassword-database. The format used is the public domain sdbm format.\n"
		"\t-u <username>\n"
		"\t\tUsername of the account to be modified or added.\n"
		"\t-r <pwd-hash>\n"
		"\t\tYescrypt encrypted password.\n"
		"\t\tSee http://password-hashing.net/wiki/doku.php/yescrypt for\n"
		"\t\tfurther information about yescrypt!\n"
		"\t-p <password>\n"
		"\t\tUnencrypted password.\n"
		"\t-x\n"
		"\t\tEnables Optional time-memory trade-off (TMTO) resistance (YESCRYPT_RW).\n"
		"\t\tIgnored when -r <hash> is specified.\n"
		"\t-f\n"
		"\t\tUses /dec/random as random device.\n"
		"\t-F <devrandom>\n"
		"\t\tUses <devrandom> as random device.\n"
		"\t-D\n"
		"\t\tDeletes a user and its password.\n"
		"\t-L\n"
		"\t\tLooks up a user's password hash.\n"
		"\nRecommendations:\n"
		"\t* Specify -f or -F <devrandom>, otherwise the nonce/salt will be predictable!\n"
		"\t* Specify -x to enable time-memory trade-off (TMTO) resistance!\n"
	);
}

int main(int argc,char**argv){
	int c,fd;
	char buf16[16] = "test123test12345";
	struct password* p;
	char* file = 0;
	char* user = 0;
	char* pass = 0;
	const char* raw_pass = 0;
	const char* urand = 0;
	int delete = 0,lkup = 0;
	yescrypt_flags_t yescflags = 0;
	while ( (c = getopt(argc, argv, "hd:u:r:p:xfF:DL")) != -1) {
		switch (c) {
		case 'h': help(); return 0;
		case 'd': file = optarg; break;
		case 'u': user = optarg; break;
		case 'r': raw_pass = optarg; break;
		case 'p': pass = optarg; break;
		case 'x': yescflags |= YESCRYPT_RW; break;
		case 'f': urand = "/dev/random"; break;
		case 'F': urand = optarg; break;
		case 'D': delete = 1; break;
		case 'L': lkup = 1; break;
		}
	}
	
	if(!file){
		printf("missing -d /path/to/db_file\n");
		return 1;
	}
	if(!user){
		printf("missing -u username\n");
		return 1;
	}
	if(delete) {
		if(!passdb_delete_account(file,user)) {
			printf("DELETE failed for various reasons.\n");
			return 1;
		}
		return 0;
	}
	if(lkup) {
		p = passdb_find_account(file,user);
		if(p) printf("found account: {'%s','%s'}\n",p->user,p->passhash);
		else printf("no such account: '%s'\n",user);
		return 0;
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
	
	if(pass && !raw_pass){
		raw_pass = yescrypt(pass,prefix);
		//printf("raw_pass %s\n",raw_pass ?: "<nil>");
	}
	if(!raw_pass){
		printf("missing -r raw_pass or -p pass\n");
		return 1;
	}
	if(!passdb_upsert_account(file,user,raw_pass)){
		printf("INSERT/UPDATE failed for various reasons.\n");
		return 1;
	}
	
	p = passdb_find_account(file,user);
	if(!p){
		printf("Insert failed for user '%s'.\n",user);
		return 1;
	}
	
	return 0;
}

