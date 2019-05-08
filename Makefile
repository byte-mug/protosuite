CC := gcc

#CF += -fPIC

.PHONY: all

lib/%.o: lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

tls_lib/%.o: tls_lib/%.c
	$(CC) $(CFLAGS) $(tlsflags) -c $< -o $@

libpass/%.o: libpass/%.c
	$(CC) $(CFLAGS) -c $< -o $@

libpassdb/%.o: libpassdb/%.c
	$(CC) $(CFLAGS) -c $< -o $@

libmta/%.o: libmta/%.c
	$(CC) $(CFLAGS) -c $< -o $@

libyescrypt/%.o: libyescrypt/%.c
	$(CC) $(CFLAGS) -c $< -o $@

smtp/%.o: smtp/%.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

lib += lib/safe_strings.o lib/sds.o lib/slam.o lib/match.o lib/base64.o lib/servername.o

libpass_legacy += libpass/passfile.o
libpass += libpass/passdb.o
libpass += libpass/sdbm.o
libpass += libpass/pair.o
libpass += libpass/hash.o

######################################################
#################### libMTA Module ###################

libmta += libmta/ini.o
libmta += libmta/decision.o
ifeq ($(SPF),)
libmta += libmta/no_spf.o
else
libmta += libmta/std_spf.o
libspf := $(SPF)
endif

ifeq ($(PCRE),)
libmta += libmta/strmail_nopcre.o
else
libmta += libmta/strmail_nopcre.o
endif

######################################################

ifeq ($(TLS),tlse)
has_tls += yes
tlsimpl += tls_lib/tls_tlse.o
endif

ifeq ($(TLS),openssl)
has_tls += yes
tlsimpl += tls_lib/tls_openssl.o
tlslibs += -lssl -lcrypto
endif

ifeq ($(TLS),bearssl)
ifeq ($(BRS),)
else
has_tls += yes
tlsflags += -I$(BRS)/inc
tlsimpl += tls_lib/tls_brssl.o
tlslibs += $(BRS)/build/libbearssl.a
endif
endif

ifeq ($(TLS),s2n)
ifeq ($(S2N),)
else
has_tls += yes
tlsflags += -I$(S2N)/api
tlsimpl += tls_lib/tls_s2n.o
tlslibs += $(S2N)/lib/libs2n.a -lcrypto -lpthread
endif
endif

ifeq ($(has_tls),)
has_tls += yes
tlsimpl += tls_lib/tls_none.o
endif

ifeq ($(LYC),best)
lyc_ver = libyescrypt/yescrypt-best.o
endif
ifeq ($(LYC),simd)
lyc_ver = libyescrypt/yescrypt-simd.o
endif
ifeq ($(LYC),ref)
lyc_ver = libyescrypt/yescrypt-ref.o
endif
ifeq ($(LYC),opt)
lyc_ver = libyescrypt/yescrypt-opt.o
endif
ifeq ($(lyc_ver),)
lyc_ver = libyescrypt/yescrypt-opt.o
endif

libyescrypt += $(lyc_ver) libyescrypt/yescrypt-common.o libyescrypt/sha256.o

all_programs += server_smtp server_httpd tool_passdb

all: $(all_programs)
	true

clean:
	rm $(lib) $(libpass) $(libyescrypt) tls_lib/*.o || true
	rm $(all_programs) || true
	rm */*.o || true

#-------------------programs------------------------

smtpd += smtp/main.o
smtpd += $(lib) $(libmta) $(libpass) $(libyescrypt) $(tlsimpl)

server_smtp: $(smtpd)
	$(CC) $(smtpd) $(libspf) $(tlslibs) -o server_smtp

httpd += http/main.o
httpd += $(lib) $(tlsimpl)

server_httpd: $(httpd)
	$(CC) $(httpd) $(tlslibs) -o server_httpd

pass += pass/main.o
pass += $(lib) $(libpass) $(libpass_legacy) $(libyescrypt)

tool_pass: $(pass)
	$(CC) $(pass) -o tool_pass

passdb += passdb/main.o
passdb += $(lib) $(libpass) $(libyescrypt)

tool_passdb: $(passdb)
	$(CC) $(passdb) -o tool_passdb
