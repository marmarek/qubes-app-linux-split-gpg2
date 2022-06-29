SHELL=/bin/bash

PYTHON ?= python3

.PHONY: build
build:
	$(PYTHON) setup.py build

clean:

install: install-python install-other

install-python:
	$(PYTHON) setup.py install -O1 $(PYTHON_PREFIX_ARG) --root $(DESTDIR)

install-python-dom0:
	$(PYTHON) setup-tests.py install -O1 $(PYTHON_PREFIX_ARG) --root $(DESTDIR)

install-other:
	install -d $(DESTDIR)/usr/share/split-gpg2
	install -d $(DESTDIR)/usr/share/split-gpg2-tests
	install -d $(DESTDIR)/etc/qubes-rpc
	install -d $(DESTDIR)/etc/gnupg
	install -d $(DESTDIR)/usr/lib/systemd/user/
	install -d $(DESTDIR)/usr/lib/systemd/user-preset/
	install -d $(DESTDIR)/usr/share/doc/split-gpg2
	install -d $(DESTDIR)/usr/share/doc/split-gpg2/examples
	install -m 775 split-gpg2-client $(DESTDIR)/usr/share/split-gpg2/
	install -m 755 gpg-agent-placeholder $(DESTDIR)/usr/share/split-gpg2/
	install -m 644 gpg.conf $(DESTDIR)/etc/gnupg/gpg.conf
	install -m 755 qubes.Gpg2.service $(DESTDIR)/etc/qubes-rpc/qubes.Gpg2
	install -m 644 split-gpg2-client.service $(DESTDIR)/usr/lib/systemd/user/
	install -m 644 split-gpg2-client.preset $(DESTDIR)/usr/lib/systemd/user-preset/70-split-gpg2-client.preset
	install -m 644 qubes-split-gpg2.conf.example $(DESTDIR)/usr/share/doc/split-gpg2/examples/
	install -m 644 README.md $(DESTDIR)/usr/share/doc/split-gpg2/
	install -m 644 tests/* $(DESTDIR)/usr/share/split-gpg2-tests/
