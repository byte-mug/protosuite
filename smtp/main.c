/*
 * Copyright (C) 2017-2019 Simon Schmidt
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
#include "../libpass/passfile.h"
#include "../libyescrypt/yescrypt.h"
#include "../lib/base64.h"
#include "../tls_lib/tls_lib.h"
#include "../libmta/decision.h"
#include "../libmta/strmail.h"
#define LN "\r\n"

static const char* passwords;
static const char* server_name;
static const char* client_ip;

#define POLICY_SECURITY_TLS  0x001
#define POLICY_SECURITY_AUTH 0x002
#define POLICY_SECURITY_CERT 0x004

#define POLICY_STATUS_HELO   0x001
#define POLICY_STATUS_EHLO   0x002
#define POLICY_STATUS_TLS    0x004
#define POLICY_STATUS_Tsup   0x008

static int
	policy_sec_level = 0,
	policy_status = 0
;

static sds line;

static sds raw_mailfrom, raw_rctpto;

static int file_head_flags;

static sds
	helo_host,
	file_head,
	queuefn,
	queuefn2
;

static size_t
	queuefnsize
;


static int targ;

static DECISION_CTX decision_ctx;
static DECISION_CFG decision_cfg;

static void cleanup(void){
	slam_close();
	decctx_free(decision_ctx);
	deccfg_free(decision_cfg);
}

static inline int isNewLine(char c){
	switch(c){
	case '\r':
	case '\n':return 1;
	}
	return 0;
}

static void die_bye(void)      { out("221 Bye" LN); slam_flush(); cleanup(); _exit(0); }
static void die_internal(void) { out("500 5.3.0  Internal Server Error\r\n"); slam_flush(); cleanup(); _exit(1); }
static void die_nomem(void)    { out("421 4.3.0  out of memory \r\n"); slam_flush(); cleanup(); _exit(1); }
static void die_eof(void)      { out("421 4.3.0  unexpected EOF \r\n"); slam_flush(); cleanup(); _exit(1); }

static void err_unrecognized(void) { out("500 5.5.1  Command unrecognized" LN); slam_flush(); };

static void err_badsequence(void)  { out("503 5.5.1  Bad sequence of commands\r\n"); slam_flush(); }

static void err_wantmail(void)  { out("503 5.5.1  MAIL first \r\n"); slam_flush(); }
static void err_wantrcpt(void)  { out("503 5.5.1  RCPT first \r\n"); slam_flush(); }
static void err_need_auth(void) { out("530 5.7.0  Authentication required\r\n"); slam_flush(); }
static void err_need_tls(void)  { out("538 5.7.11  Encryption required for requested authentication mechanism" LN); slam_flush(); }
static void err_auth_invalid(void) { out("535 5.7.8  Authentication credentials invalid" LN); slam_flush(); }

/* 454 4.7.0  Temporary authentication failure */
static void err_auth_error(void)  { out("454 4.7.0  Temporary authentication failure" LN); slam_flush(); }
static void err_auth_base64(void) { out("454 4.7.0  Invalid Base-64 Data" LN); slam_flush(); }

static void ok_smtp(void)  { out("250 Ok" LN); slam_flush(); }
static void ok_auth(void)  { out("235 2.7.0  Authentication Succeeded" LN); slam_flush(); }

/* 550 5.7.1 Error messages and 450 4.7.1 Error messages */
static void err_badbounce(void) { out("550 5.7.1  sorry, I don't accept bounce messages with more than one recipient. Go read RFC2821." LN); slam_flush(); }
static void err_spf_fail(void) { out("550 5.7.1  Bad SPF policy Fail(-)." LN); slam_flush(); }
static void err_550_rejected(void) { out("550 5.7.1  Mail Rejected." LN); slam_flush(); }
static void err_450_rejected(void) { out("450 4.7.1  Mail Temporarily Rejected." LN); slam_flush(); }


/* 550 Error messages */
static void err_mail_syntax(void) { out("550 5.1.3  Invalid E-Mail address: Syntax error." LN); slam_flush(); }

/* Data error messages */
static void data_eof(void) { out("451 4.5.2  unexpected EOF" LN); slam_flush(); }
static void data_451(void) { out("451 4.3.0  Requested action aborted: error in processing" LN); slam_flush(); }
static void data_452(void) { out("452 4.3.1  Requested action not taken: insufficient system storage" LN); slam_flush(); } /* X.3.1 Mail system full */
static void data_552(void) { out("552 5.3.4  Requested mail action aborted: exceeded storage allocation" LN); slam_flush(); } /* X.3.4 Message too big for system */
static void data_554(void) { out("554 5.3.0  Transaction failed" LN); slam_flush(); } /* (unknown error) */

static void data_ok(void) { out("354 End data with <CR><LF>.<CR><LF>" LN); slam_flush(); }

static int md_new_message(void){
	char data[40];
	struct stat statbuf;
	if(snprintf(data,sizeof data,"tmp/%d",(int)getpid())<0)return 1;
	if(!queuefn) return 1;
	if(!queuefn2)return 1;
	sdssetlen(queuefn,queuefnsize);
	sdscat(queuefn,data);
	targ = open(queuefn,O_CREAT|O_TRUNC|O_RDWR,0600);
	if(targ<0) return 1;
	
	if(fstat(targ,&statbuf)) goto onError;
	sdssetlen(queuefn2,queuefnsize);
	if(snprintf(data,sizeof data,"new/%d",(int)statbuf.st_ino)<0) goto onError;
	sdscat(queuefn2,data);
	return 0;
onError:
	close(targ);
	return 1;
}

static int writeAll(int fd,const char* data,size_t len){
	int n;
	while(len){
		n = write(fd,data,len);
		if(n<1)return -1;
		data+=n;
		len-=n;
	}
	return 0;
}

static int evalErr(int code,int *resp){
	if(!code) return 0;
	switch(errno){
	case EFBIG:
	case ENOSPC:
	case EDQUOT:
		*resp = 452;break; /* Requested action not taken: insufficient system storage */
	case EIO:
	case EAGAIN:
		*resp = 451;break; /* Requested action aborted: error in processing */
	}
	return -1;
}

static void md_copymessage(void){
	const char* ptr;
	size_t size;
	int not_broken,err_type;
	
	/*
	 * 4XX: If this code accompanies a delivery failure report, sending in
	 * the future may be successful.
	 *
	 * 5XX: A permanent failure is one which is not likely to be resolved
	 * by resending the message in the current form.
	 */
	err_type = 451;
	
	if(writeAll(targ,file_head,sdslen(file_head)))
	{
		data_451();
		goto onError;
	}
	
	data_ok();
	not_broken = 1;
	for(;;){
		if(!slam_readline_ptr(&ptr,&size)){
			not_broken = 0;
			err_type = 1000; /* Unexpected EOF. */
			break;
		}
		if(not_broken) not_broken = !evalErr(writeAll(targ,ptr,size),&err_type);
		if(*ptr=='.'&&isNewLine(ptr[1])){
			slam_skip(size);
			break;
		}
		slam_skip(size);
	}
	
	close(targ);
	
	/*
	 * At this point, the Mail file in 'tmp/$pid' had been completed, and gets
	 * renamed into 'new/$ino'. This atomically assigns a unique name to the file.
	 *
	 * If it fails, the mail is lost...
	 */
	if(not_broken) not_broken = !rename(queuefn,queuefn2);
	
	if(not_broken){
		ok_smtp();
	}else{
		/*
		 * We are allowed to respond with one of the following status codes:
		 * 552, 554, 451 or 452.
		 */
		switch(err_type){
		case 1000: data_eof(); break;
		case 451: data_451(); break;
		case 452: data_452(); break;
		case 552: data_552(); break;
		case 554:
		default: data_554();
		}
		
	}
	
	/*
	 * If rename() succeeded, the following unlink() shall fail.
	 * This is done, in order to cleanup the resources on error.
	 */
	unlink(queuefn);
	
	return;
onError:
	close(targ);
	unlink(queuefn);
}

static int check_auth(const char* user,const char* pass) {
	struct password* p;
	if(!passwords) return -1;
	p = find_password(passwords,user);
	if(!p) return -1;
	const char* chk = yescrypt(pass,p->passhash);
	if(!chk) return -1;
	return strcmp(p->passhash,chk);
}

/* [authorize-id]\0authenticate-id\0password */
static int check_auth_plain(sds decoded){
	const char* auth_user;
	const char* auth_passwd;
	char* ptr;
	size_t pos,len;
	ptr = decoded;
	len = sdslen(decoded);
	
	/* authorize-id */
	pos = strfind_n(ptr,len,0);
	if(!pos) return -1;
	if(pos>0) auth_user = ptr;
	ptr+=pos; len-=pos;
	
	/* authenticate-id */
	pos = strfind_n(ptr,len,0);
	if(!pos) return -1;
	if(pos>0) auth_user = ptr;
	ptr+=pos; len-=pos;
	
	/* password */
	auth_passwd = ptr;
	
	if(!auth_user) return -1;
	
	return check_auth(auth_user,auth_passwd);
}

static inline void sdsmayfree(sds old) {
	if(old) sdsfree(old);
}

static void commands(void){
	helo_host = NULL;
	file_head = sdsempty();
	file_head_flags = 0;
	sds temp,temp2;
	raw_mailfrom = raw_rctpto = 0;
	
	for(;;) {
		if(!slam_readline(line)) die_eof();
		
		if(sdseqlower_p(line,"quit")){ /* QUIT */
			/* 221 Bye. */
			die_bye();
			/* Unreachable. */ break;
		}
		
		if(policy_status&POLICY_STATUS_HELO) {
			/*
			 * This Branch is deliberately kept empty.
			 */
		}else if(sdseqlower_p(line,"helo ")||sdseqlower_p(line,"ehlo ")){
			/* This is going to Happen once. */
			policy_status |= POLICY_STATUS_HELO;
			helo_host = sdsdup(line); if(!helo_host) die_nomem();
			sdssetlen(helo_host,moveback_n(helo_host,sdslen(helo_host),5));
			sdstrim(helo_host," \r\n\t");
			helo_host[sdslen(helo_host)] = 0;
		}else{ err_badsequence(); continue; }
		
		/* ---------------- HANDLING LOGIN COMMANDS ---------------- */
		if(sdseqlower_p(line,"helo ")){
			out("250 ");
			out(server_name);
			out(" Hello ");
			outsds(helo_host);
			out(LN);
			slam_flush();
			continue;
		}else if(sdseqlower_p(line,"ehlo ")){
			policy_status |= POLICY_STATUS_EHLO;
			out("250-");
			out(server_name);
			out(" Hello ");
			outsds(helo_host);
			out(LN);
			out("250-ENHANCEDSTATUSCODES" LN);
			if(policy_sec_level&POLICY_SECURITY_TLS)  out("250-AUTH PLAIN LOGIN" LN);
			if(	(policy_status&POLICY_STATUS_Tsup)&&
				!(policy_status&POLICY_STATUS_TLS)   ) out("250-STARTTLS" LN);
			out("250 8BITMIME" LN);
			slam_flush();
			continue;
			
		/* ---------------- HANDLING MAIL COMMANDS ----------------- */
		}else if(sdseqlower_p(line,"mail from:")){ /* MAIL FROM:<huhu@example.com> */
			sdssetlen(line,moveback_n(line,sdslen(line),10));
			sdstrim(line," \r\n\t");
			
			/*
			 * Verify E-Mail-Address.
			 */
			if(!mta_verify_mail(line)) { err_mail_syntax(); continue; }
			
			/*
			 * Copy and Unwrap E-Mail-Address.
			 */
			sdsmayfree(raw_mailfrom);
			raw_mailfrom = sdsdup(line); if(!raw_mailfrom) die_nomem();
			mta_unwrap_mail(raw_mailfrom);
			
			/*
			 * Invoke Policy-Decision-Framework.
			 */
			switch(decctx_mailfrom(decision_ctx,decision_cfg,client_ip,helo_host,raw_mailfrom)) {
			case 550: err_550_rejected(); continue;
			case 450: err_450_rejected(); continue;
			case 530: err_need_auth(); continue;
			}
			
			file_head = sdscat(file_head,"FROM:"); if(!file_head) die_nomem();
			file_head = sdscatsds(file_head,line); if(!file_head) die_nomem();
			file_head = sdscat(file_head,"\r\n");  if(!file_head) die_nomem();
			file_head_flags |= 1;
			
			ok_smtp();
		}else if(sdseqlower_p(line,"rcpt to:")){ /* RCPT TO:<huhu@example.com> */
			/*
			 * We will not allow "RCPT TO" before "MAIL FROM".
			 */
			if(!(file_head_flags&1)){ err_wantmail(); continue; }
			
			sdssetlen(line,moveback_n(line,sdslen(line),8));
			sdstrim(line," \r\n\t");
			
			/*
			 * Verify E-Mail-Address.
			 */
			if(!mta_verify_mail(line)) { err_mail_syntax(); continue; }
			
			/*
			 * Copy and Unwrap E-Mail-Address.
			 */
			sdsmayfree(raw_rctpto);
			raw_rctpto = sdsdup(line); if(!raw_rctpto) die_nomem();
			mta_unwrap_mail(raw_rctpto);
			
			/*
			 * Invoke Policy-Decision-Framework.
			 */
			switch(decctx_rcptto(decision_ctx,decision_cfg,client_ip,helo_host,raw_mailfrom,raw_rctpto)) {
			case 550: err_550_rejected(); continue;
			case 450: err_450_rejected(); continue;
			case 530: err_need_auth(); continue;
			}
			
			file_head = sdscat(file_head,"TO:");   if(!file_head) die_nomem();
			file_head = sdscatsds(file_head,line); if(!file_head) die_nomem();
			file_head = sdscat(file_head,"\r\n");  if(!file_head) die_nomem();
			file_head_flags |= 2;
			
			ok_smtp();
		}else if(sdseqlower_p(line,"data")){
			
			if(!(file_head_flags&1)){ err_wantmail(); continue; }
			if(!(file_head_flags&2)){ err_wantrcpt(); continue; }
			
			/* Append a DATA <CRLF> to the file_head variable. */
			file_head = sdscat(file_head,"DATA\r\n");   if(!file_head) die_nomem();
			
			if(md_new_message()){
				/* Reset buffer. */
				sdssetlen(file_head,0);
				
				data_451();
				continue;
			}
			md_copymessage();
			/* Reset buffer. */
			sdssetlen(file_head,0);
			file_head_flags = 0;
		
		/* ------------ HANDLING INTERMEDIATE COMMANDS ------------- */
		}else if(sdseqlower_p(line,"rset")){ /* RSET */
			sdssetlen(file_head,0);
			file_head_flags = 0;
			
			ok_smtp();
		}else if(sdseqlower_p(line,"noop")){
			
			ok_smtp();
		
		/* -------------- HANDLING SECURITY COMMANDS --------------- */
		}else if(sdseqlower_p(line,"starttls")){
			/* Is TLS supported? */
			if(!(policy_status&POLICY_STATUS_Tsup)){ err_unrecognized(); continue; }
			
			/* Is TLS already enabled? */
			if(policy_status&POLICY_STATUS_TLS){ err_unrecognized(); continue; }
			
			out("220 Go ahead" LN);
			slam_flush();
			
			if(!slamtls_starttls()) { _exit(1); return; }
			
			policy_status |= POLICY_STATUS_TLS;      /* Set TLS flag in status. */
			policy_sec_level |= POLICY_SECURITY_TLS; /* Set TLS flag in security level. */
		}else if(sdseqlower_p(line,"auth plain")){
			if(!(policy_sec_level&POLICY_SECURITY_TLS)){ err_need_tls(); continue; }
			/*
			 * This match clause will match
			 *   'AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=' || <CRLF>
			 * as well as
			 *   'AUTH PLAINdGVzdAB0ZXN0ADEyMzQ=' || <CRLF>
			 * , where latter is errernous input!
			 */
			sdssetlen(line,moveback_n(line,sdslen(line),10));
			sdstrim(line," \r\n\t");
			if(!sdslen(line)){
				out("334 " LN);
				slam_flush();
				if(!slam_readline(line)) die_eof();
				sdstrim(line," \r\n\t");
			}
			temp = base64_decode(line,sdslen(line));
			if(!temp){ err_auth_base64(); continue; }
			
			if(check_auth_plain(temp)){ sdsfree(temp); err_auth_invalid(); continue; }
			
			sdsfree(temp);
			
			policy_sec_level |= POLICY_SECURITY_AUTH;
			
			/* Invoke Policy-Decision-Framework */
			decctx_on_login(decision_ctx,decision_cfg);
			ok_auth();
		}else if(sdseqlower_p(line,"auth login")){
			if(!(policy_sec_level&POLICY_SECURITY_TLS)){ err_need_tls(); continue; }
			
			out("334 VXNlcm5hbWU6" LN);
			slam_flush();
			if(!slam_readline(line)) die_eof();
			sdstrim(line," \r\n\t");
			temp = base64_decode(line,sdslen(line));
			if(!temp){ err_auth_base64(); continue; }
			
			
			out("334 UGFzc3dvcmQ6" LN);
			slam_flush();
			if(!slam_readline(line)) die_eof();
			sdstrim(line," \r\n\t");
			temp2 = base64_decode(line,sdslen(line));
			if(!temp2){ sdsfree(temp); err_auth_base64(); continue; }
			
			if(check_auth(temp,temp2)){ sdsfree(temp); sdsfree(temp2); err_auth_invalid(); continue; }
			
			sdsfree(temp); sdsfree(temp2);
			
			policy_sec_level |= POLICY_SECURITY_AUTH;
			
			/* Invoke Policy-Decision-Framework */
			decctx_on_login(decision_ctx,decision_cfg);
			ok_auth();
			
		/* ------------- HANDLING UNRECOGNIZED COMMANDS ------------ */
		}else err_unrecognized();
		continue;
	}
}

#define caseof(a,b) case a: b; break
static void parseflags(void) {
	const char* env = getenv("SMTP_FLAGS");
	if(!env)return;
	if(!*env)return;
	do{switch(*env){
		caseof('T',policy_sec_level |= POLICY_SECURITY_TLS  );
		caseof('C',policy_sec_level |= POLICY_SECURITY_CERT );
		caseof('A',policy_sec_level |= POLICY_SECURITY_AUTH );
	}}while(*++env);
}

static const char* get_clientip(void) {
	const char* ip;
	/* tcploop sets $REMOTE_IP */
	ip = getenv("REMOTE_IP");
	if(ip) return ip;
	/*
	 * ucspi-tcp sets $TCPREMOTEIP
	 *    https://cr.yp.to/ucspi-tcp/environment.html
	 */
	ip = getenv("TCPREMOTEIP");
	if(ip) return ip;
	return 0;
}

int main(void) {
	parseflags();
	passwords = getenv("PASSFILE");
	const char* env = getenv("MAILDIR");
	server_name = get_servername();
	client_ip = get_clientip();
	
	decision_cfg = deccfg_new();
	if(!decision_cfg) abort();
	decision_ctx = decctx_new();
	if(!decision_ctx) abort();
	
	if(env){
		queuefn = sdsnew(env);
		if(!queuefn)abort();
		if(!sdslen(queuefn)) abort();
		if(queuefn[sdslen(queuefn)-1]!='/') queuefn = sdscat(queuefn,"/");
		if(!queuefn)abort();
		queuefnsize = sdslen(queuefn);
		queuefn = sdsgrowzero(queuefn,queuefnsize+50);
		if(!queuefn)abort();
		queuefn2 = sdsdup(queuefn);
		if(!queuefn2)abort();
	}
	
	/*
	 * Load Policy-Decision-Config File if any.
	 */
	{
		const char* decision_file = getenv("DECISION_CFG");
		if(decision_file)
			if(deccfg_parse(decision_cfg,decision_file)) abort();
	}
	
	line = sdsempty();
	if(!line) abort();
	line = sdsMakeRoomFor(line,256);
	if(!line) abort();
	slam_init();
	if(slamtls_init())
		policy_status |= POLICY_STATUS_Tsup;
	
	out("220 ");
	out(server_name);
	out(" ESMTP server_smtp" LN);
	slam_flush();
	commands();
	return 1;
}

