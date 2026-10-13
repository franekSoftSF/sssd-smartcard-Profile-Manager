# Convenience targets. Everything here also works by calling the scripts directly.

PYTHON ?= python3
SHELL_SCRIPTS := install.sh packaging/build-tarball.sh scripts/sssd-smartcard-setup.sh \
                 lab/provision/dc.sh lab/provision/client.sh lab/run-tests.sh

.PHONY: help test lint shellcheck package deb deb-native clean lab-up lab-test lab-down install

help:
	@echo "test        run the python test suite"
	@echo "lint        bash -n every shell script"
	@echo "shellcheck  run shellcheck if it is installed"
	@echo "package     build dist/sssd-smartcard-<version>.tar.gz"
	@echo "deb         build dist/sssd-smartcard_<version>_all.deb (needs dpkg-deb)"
	@echo "deb-native  build with dpkg-buildpackage (needs debhelper)"
	@echo "lab-up      bring up the Vagrant test lab"
	@echo "lab-test    run the acceptance suite on the lab client"
	@echo "lab-down    destroy the lab"
	@echo "install     run install.sh (needs root)"
	@echo "clean       remove build and cache artefacts"

test:
	PYTHONPATH=src $(PYTHON) -m pytest -q

lint:
	@for f in $(SHELL_SCRIPTS); do printf '%-42s' "$$f"; bash -n "$$f" && echo ok || exit 1; done

shellcheck:
	@command -v shellcheck >/dev/null 2>&1 || { echo "shellcheck not installed"; exit 0; }
	shellcheck -S warning $(SHELL_SCRIPTS)

package:
	bash packaging/build-tarball.sh

deb:
	bash packaging/build-deb.sh

deb-native:
	dpkg-buildpackage -b -us -uc

lab-up:
	cd lab && vagrant up

lab-test:
	cd lab && vagrant ssh client -c 'sudo /vagrant/run-tests.sh'

lab-down:
	cd lab && vagrant destroy -f

install:
	./install.sh

clean:
	rm -rf dist build .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.py[co]' -delete 2>/dev/null || true
