all: letsencryptshell

tests:
	sh -e make-tests.sh
test:
	sh -e make-tests.sh

letsencryptshell:
	sh -e make.sh
