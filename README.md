# protosuite
Savely coded Internet daemons (currently, only smtp is implemented)



## Running smtp

Example start script:
```sh
TLS_CERT=/path/to/your/cert.csr

# AFAIK The tlse Library doesn't support passphrases,
# so you must decrypt your private key first, if you don't use OpenSSL!
TLS_KEY=/path/to/your/private_key.pem

# Your password DB
PASSFILE=/path/to/your/passwords

# Your Incoming mail repository
#  This must contain the following folders:
#    ./tmp
#    ./new
MAILDIR=/path/to/your/mailqueue/

# The environment variables must be exported, so the 'server_smtp' can see them.

DECISION_CFG=/path/to/your/mta_decision.ini

export TLS_CERT
export TLS_KEY
export PASSFILE
export MAILDIR
export DECISION_CFG

# You need a program (or program suite) to open a listening socket and accept
# connections like "ucspi-tcp". We use the tcphelper suite in this example.
#
#    https://github.com/byte-mug/tcphelper

# Note: $protosuite is the path, where the protosuite binaries are placed.

tcpsrv 4 0.0.0.0 25 tcploop $protosuite/server_smtp


```

The decision.ini:

```ini
; All our e-mail-addresses should end with "@my-domain.net" !
[local]
suffix = @my-domain.net

; Turn SPF = on
[mta2me]
spf=on
```

Also see: (mta_decision.ini)[./example/mta_decision.ini]
