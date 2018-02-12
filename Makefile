all: acmeshell

tests:
	sh -e make-tests.sh
test:
	sh -e make-tests.sh

acmeshell:
	sh -e make.sh
