SHELL=/bin/bash

build:

clean:

install:
	install -d $(DESTDIR)/usr/share/split-gpg2 $(DESTDIR)/etc/qubes-rpc $(DESTDIR)/lib/systemd/system
	install -d $(DESTDIR)/usr/share/doc/split-gpg2
	install -d $(DESTDIR)/usr/share/doc/split-gpg2/examples
	install split-gpg2-{server,client{,-wrapper}} $(DESTDIR)/usr/share/split-gpg2/
	install -m 644 split-gpg2.rb $(DESTDIR)/usr/share/split-gpg2/
	install -m 644 qubes.Gpg2.service $(DESTDIR)/etc/qubes-rpc/qubes.Gpg2
	install -m 644 split-gpg2-client.service $(DESTDIR)/lib/systemd/system/
	install -m 644 split-gpg2-rc.example $(DESTDIR)/usr/share/doc/split-gpg2/examples/
	install -m 644 README $(DESTDIR)/usr/share/doc/split-gpg2/
