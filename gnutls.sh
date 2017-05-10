gnutls-serv -g -u -d 9999 --priority "NONE:+DHE-RSA:+AES-256-CBC:+SHA256:+SIGN-RSA-SHA1:+COMP-NULL:+CTYPE-OPENPGP:+VERS-DTLS1.2" --pgpcertfile openpgp-server.txt --pgpkeyfile openpgp-server-key.txt
