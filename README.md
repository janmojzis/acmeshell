### acmeshell - client for LetsEncrypt ###
ACMEShell is Python2/3 compatible shell-style client for [LetsEncrypt](https://letsencrypt.org/).
It's simple tool for anyone who would like to request a SSL certificate.

* [acmeshell.py](//mojzis.com/software/acmeshell/acmeshell.py)
* also on [github](https://github.com/janmojzis/acmeshell/)

### warning ###
* project renamed from letsencryptshell due to trademark violation

### goals ###
* user friendly (simple shell-style user interface) [... see examples](examples.html)
* script friendly (simple integration into automated scripts) [... see examples](examples.html)
* portable code (compatible with python2 and python3)
* easily auditable (currently less than 1500 rows of code)

### registration ###

#### Run it ####
~~~
acmeshell
~~~

By default it creates:
home directory: {home}/.acmeshell
directory for certificates: {home}/.acmeshell/certs
3072bit master secret-key: {home}/.acmeshell/sk.pem
3072bit master public-key: {home}/.acmeshell/pk.pem

#### Confirm the agreement and Register Your RSA public-key and email ####
~~~
ACMEShell> register https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf {email@address}
~~~

### usage ###

#### Get challenge from ACME server ####
~~~
ACMEShell> domainchallenge {domain}
~~~

... Now It's time to create page http://{domain}/.well-known/acme-challenge/{httptoken_from_challenge}
... or DNS record: _acme-challenge.{domain} 300 IN TXT "{dnstoken_from_challenge}"

#### Confirm authentication ####
~~~
ACMEShell> domainconfirm {domain} http
or
ACMEShell> domainconfirm {domain} dns
~~~

#### Get certificate ####
~~~
ACMEShell> certificateget {domain}
~~~
It creates:
2048bit RSA or 256bit ECDSA key: {home}/.acmeshell/certs/{domain}.key
signed x509 certificate: {home}/.acmeshell/certs/{domain}.crt
intermediate certificate: {home}/.acmeshell/certs/{domain}.im

#### That's it! ####
#### Same steps for certificate creation and update ####


### notes ###
* acmeshell currently depends on openssl binary
* home directory {home}/.acmeshell should be on encrypted filesystem
* acmeshell currently supports only http-01 ACME challege (tls-sni-01 will be added soon)
* acmeshell currently supports RSA(2048bit) and ECDSA(256bit) keys
