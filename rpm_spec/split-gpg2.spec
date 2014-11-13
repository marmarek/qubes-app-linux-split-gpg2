Name:           split-gpg2
Version:        0.1
Release:        1%{dist}
Summary:        split-gpg2 for Qubes

Group:          Qubes
License:        GPLv2+

Source:         .

Requires:       socat
Requires:       ruby >= 1.9
Requires:       bash
#Requires:       gnupg >= 2.1.0
Requires:       systemd
Requires:       zenity
Requires:       libnotify

%define _builddir %(pwd)

%description
split-gpg2 allows you to run the gpg2 client in a different Qubes-Domain than
the gpg-agent.

%prep

%build

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR="$RPM_BUILD_ROOT"

%post
systemctl enable split-gpg2-client

%preun
systemctl disable split-gpg2-client

%clean
rm -rf $RPM_BUILD_ROOT

%files
/etc/qubes-rpc/qubes.Gpg2
/lib/systemd/system/split-gpg2-client.service
/usr/share/split-gpg2/
/usr/share/doc/split-gpg2/
