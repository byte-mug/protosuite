/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "passdb.h"
#include "sdbm.h"
#include "../lib/sds_audited.h"

#define Dy (char*)

static struct password entry;
static sds username = 0;
static sds passhash = 0;

static sds sdsreplace(sds old,const char* name) {
	if(!old) return sdsnew(name);
	sdssetlen(old,0);
	return sdscat(old,name);
}
static sds sdsreplace_len(sds old,const char* name,size_t len) {
	if(!old) return sdsnewlen(name,len);
	sdssetlen(old,0);
	return sdscatlen(old,name,len);
}

static sds sdsd(datum d) { return sdsnewlen(d.dptr,d.dsize); }

struct password* passdb_find_account(const char* db,const char* name) {
	datum value;
	struct password* result = 0;
	DBM* dbm = dbm_open(db,O_RDONLY,0644);
	if(!dbm) return 0;
	username = sdsreplace(username,name);
	if(!username) goto failed;
	
	value = dbm_fetch(dbm,(datum){username,sdslen(username)});
	if(!value.dptr) goto failed;
	
	passhash = sdsreplace_len(passhash,value.dptr,value.dsize);
	if(!passhash) goto failed;
	
	entry.user = username;
	entry.passhash = passhash;
	
	result = &entry;
failed:
	dbm_close(dbm);
	return result;
}
int passdb_upsert_account(const char* db,const char* user,const char* passhash) {
	int result;
	DBM* dbm = dbm_open(db,O_RDWR|O_CREAT,0644);
	if(!dbm) return 0;
	
	result = !dbm_store(dbm,(datum){Dy user,strlen(user)},(datum){Dy passhash,strlen(passhash)},DBM_REPLACE);
	
	dbm_close(dbm);
	return result;
}

int passdb_delete_account(const char* db,const char* user) {
	int result;
	DBM* dbm = dbm_open(db,O_RDWR|O_CREAT,0644);
	if(!dbm) return 0;
	
	result = !dbm_delete(dbm,(datum){Dy user,strlen(user)});
	
	dbm_close(dbm);
	return result;
}

