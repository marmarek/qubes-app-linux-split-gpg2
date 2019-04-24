Name:           split-gpg2
Version:        0.1
Release:        1%{dist}
Summary:        split-gpg2 for Qubes

Group:          Qubes
License:        GPLv2+

Source:         .

BuildRequires:  python3-rpm-macros
BuildRequires:  python%{python3_pkgversion}-setuptools
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
make PYTHON=%{__python3}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR="$RPM_BUILD_ROOT" PYTHON=%{__python3}

%post
systemctl enable split-gpg2-client

%preun
systemctl disable split-gpg2-client

%clean
rm -rf $RPM_BUILD_ROOT

%files
/etc/qubes-rpc/qubes.Gpg2
/lib/systemd/system/split-gpg2-client.service
%{python3_sitelib}/splitgpg2
%{python3_sitelib}/splitgpg2-*.egg-info
/usr/share/split-gpg2/
/usr/share/doc/split-gpg2/
