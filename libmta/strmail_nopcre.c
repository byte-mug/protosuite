/*
 * Copyright (C) 2019 Simon Schmidt
 * Usage of the works is permitted provided that this instrument is retained
 * with the works, so that any entity that uses the works is notified of this
 * instrument.
 *
 * DISCLAIMER: THE WORKS ARE WITHOUT WARRANTY.
 */
//
#include "../lib/sds_audited.h"
#include "../lib/safe_strings.h"
#include "strmail.h"

void mta_unwrap_mail(mta_sds mail) {
	sds m = mail;
	size_t len,pos;
	len = sdslen(m);
	if(len<2)return;
	len = strfindrev_n(m,len,'>');
	if(len<2)return;
	len--; /* Remove '>' */
	pos = strfindrev_n(m,len,'<');
	if(!pos) return;
	len = moveback_n(m,len,pos);
	sdssetlen(m,len);
	m[len]=0;
}

/*
 * Match local-part@domain
 */
static int verify_mail_raw(const char* mail,size_t len) {
	int ads = 0;
	for(;len;--len,++mail) {
		switch(*mail) {
		case '@': ads++;
			/* fallthrough */
		case '0'...'9':
		case 'a'...'z':
		case 'A'...'Z':
		case '_':
		case '-':
		case '.': continue;
		}
		return 0;
	}
	return ads==1;
}

/*
 * Try to match
 *    User Name <local-part@domain>
 * Into
 *    local-part@domain
 *
 * Then call verify_mail_raw()
 */
static int verify_mail(const char* mail,size_t rawlen) {
	size_t pos,len;
	len = rawlen;
	if(len<2) goto shcut;
	len = strfindrev_n(mail,len,'>');
	if(len<2) goto shcut;
	len--; /* Remove '>' */
	pos = strfindrev_n(mail,len,'<');
	if(!pos) goto shcut;
	mail += pos;
	rawlen = len-pos;
	//return 0;
shcut:
	return verify_mail_raw(mail,rawlen);
}

int mta_verify_mail(mta_sds mail){
	return verify_mail(mail,sdslen(mail));
}

