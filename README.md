### letsencryptshell - client for LetsEncrypt ###
LetsEncryptShell is Python2/3 compatible shell-style client for [LetsEncrypt](https://letsencrypt.org/).
It's simple tool for anyone who would like to request a SSL certificate.

* [letsencryptshell.py](//mojzis.com/software/letsencryptshell/letsencryptshell.py)
* also on [github](https://github.com/janmojzis/letsencryptshell/)

### goals ###
* user friendly (simple shell-style user interface)
* script friendly (simple integration into automated scripts)
* portable code (compatible with python2 and python3)
* easy auditable (currently less than 1500 rows of code)

### usage ###

#### Run it ####
~~~
letsnecryptshell
~~~

By default it creates:
home directory: {home}/.letsencryptshell
directory for certificates: {home}/.letsencryptshell/certs
3072bit master secret-key: {home}/.letsencryptshell/sk.pem
3072bit master public-key: {home}/.letsencryptshell/pk.pem

#### Confirm the agreement and Register Your RSA public-key and email ####
~~~
LetsEncryptShell> register https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf {email@address}
~~~

#### Get challenge from LetsEncrypt server ####
~~~
LetsEncryptShell> domainchallenge {domain}
~~~

... Now It's time to create page http://{domain}/.well-known/acme-challenge/{token_from_challenge}

#### Confirm authentication ####
~~~
LetsEncryptShell> domainconfirm {domain}
~~~

#### Get certificate ####
~~~
LetsEncryptShell> certificateget {domain} {domain1} {domain2} ... {domainN}
~~~
It creates:
2048bit RSA or 256bit ECDSA key: {home}/.letsencryptshell/certs/{domain}.key
signed x509 certificate: {home}/.letsencryptshell/certs/{domain}.crt
intermediate certificate: {home}/.letsencryptshell/certs/{domain}.im

#### That's it! ####

### notes ###
* letsencryptshell currently depends on openssl binary
* home directory {home}/.letsencryptshell should be on encrypted filesystem
* letsencryptshell currently supports only http-01 ACME challege (tls-sni-01 will be added soon)
* letsencryptshell currently supports RSA(2048bit) and ECDSA(256bit) keys

See https://mojzis.com/software/letsencryptshell/
