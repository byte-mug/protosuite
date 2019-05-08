# TLS support

- Compile without TLS support `make`
- Compile with the venerable (and, unfortunately, bug-ridden) OpenSSL library `make TLS=openssl`
- Compile with the excelent [tlse](https://github.com/eduardsui/tlse) library `make TLS=tlse`
- Compile with the secure [s2n](https://github.com/awslabs/s2n) library from AWS labs `make TLS=s2n S2N=/path/to/s2n`
- Compile with the small, correct and secure [BearSSL](https://bearssl.org/) library `make TLS=bearssl BRS=/path/to/BearSSL`

### AWS labs s2n specific notes.

I did compile s2n simply by doing `git clone https://github.com/awslabs/s2n.git` followed by `cd s2n; make`.
If the some test cases failed, I ignored it.

Here is the section from the Makefile, that controls the s2n-support:

```makefile
# The compiler flags for the TLS abstraction layer code.
tlsflags += -I$(S2N)/api

# The TLS abstraction layer code, we want
tlsimpl += tls_lib/tls_s2n.o

# The linker args.
tlslibs += $(S2N)/lib/libs2n.a -lcrypto -lpthread
```

### BearSSL specific notes.

To use BearSSL, download it, unpack it and hit `make` in the BearSSL directory.

My version mostly works, but `curl` seems to fail with:
	`error:0D07207B:asn1 encoding routines:ASN1_get_object:header too long`
Maybe i will manage to fix this....

### Mozilla NSS

The effort of implementing TLS support based on NSS failed before it even started. Sorry!

<!-- https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil -->
