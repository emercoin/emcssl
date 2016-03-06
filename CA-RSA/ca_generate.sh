#!/bin/sh
rm -f emcssl_ca.key emcssl_ca.crt

openssl req -new -newkey rsa:512 -nodes -keyout emcssl_ca.key -x509 -days 36500 \
  -subj '/O=EmerCoin/OU=EMCSSL/CN=EmerCoin World Wide Web Public Key Infrastructure/emailAddress=team@emercoin.com/UID=EMC' \
  -out emcssl_ca.crt

