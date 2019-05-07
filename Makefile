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

libpass += libpass/passfile.o
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

#lyc_ver = libyescrypt/yescrypt-best.o
#lyc_ver = libyescrypt/yescrypt-simd.o
lyc_ver = libyescrypt/yescrypt-opt.o
#lyc_ver = libyescrypt/yescrypt-ref.o

libyescrypt += $(lyc_ver) libyescrypt/yescrypt-common.o libyescrypt/sha256.o

all_programs += server_smtp tool_pass tool_passdb

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

pass += pass/main.o
pass += $(lib) $(libpass) $(libyescrypt)

tool_pass: $(pass)
	$(CC) $(pass) -o tool_pass

passdb += passdb/main.o
passdb += $(lib) $(libpass) $(libyescrypt)

tool_passdb: $(passdb)
	$(CC) $(passdb) -o tool_passdb
