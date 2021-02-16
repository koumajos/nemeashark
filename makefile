#
# Makefile for Python documentation
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
# You can set these variables from the command line.
PYTHON		 = ${VENV_NAME}/bin/python3

.PHONY: help autobuild-dev 

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  prepare-dev    to prepare development environment"
	@echo "  update			to update code to ~/bin"

prepare-dev: 
	chmod 777 nemeashark.py
	mkdir -p ~/bin
	cp nemeashark.py ~/bin/nemeashark
	export PATH=$PATH":$HOME/bin"
	@echo "for help with usage: nemeashark -h"

update:
	cp nemeashark.py ~/bin/nemeashark
	@echo "nemeashark updated to ~/bin"

