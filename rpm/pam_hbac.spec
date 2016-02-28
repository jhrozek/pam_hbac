%if 0%{?fedora} > 16 || 0%{?rhel} > 6
%global security_parent_dir /%{_libdir}
%else
%global security_parent_dir /%{_lib}
%endif

Name:           pam_hbac
Version:	0.1
Release:	1%{?dist}
Summary:	A PAM module that evaluates HBAC rules stored on an IPA server

%if 0%{?rhel} < 6
Group:          System Environment/Base
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root
%endif

License:	GPLv3+
URL:		https://github.com/jhrozek/pam_hbac
Source0:	pam_hbac-0.1.tar.gz

BuildRequires:	pam-devel
BuildRequires:	openldap-devel
BuildRequires:	glib2-devel

# asciidoc is only in EPEL-5 but since pam_hbac is not in RHEL-5 either,
# it's probably OK
BuildRequires:	asciidoc

# EPEL-5's asciidoc has broken dependencies and would error out unless
# xsltproc and docbook-styles are installed
%if 0%{?rhel} == 5
BuildRequires:  libxslt
BuildRequires:  docbook-style-xsl
%endif


%description
pam_hbac is a PAM module that can be used by PAM-aware applications to check
access control decisions on an IPA client machine. It is meant as a fall-back
for environments that can't use SSSD for some reason.


%prep
%setup -q


%build
%configure --libdir=/%{security_parent_dir} \
           --with-pammoddir=/%{security_parent_dir}/security \
           ${null}

make %{?_smp_mflags}


%install
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT/%{security_parent_dir}/security/*.la


%files
%defattr(-,root,root,-)
%doc README* COPYING* ChangeLog NEWS
%{security_parent_dir}/security/pam_hbac.so
%{_mandir}/man5/pam_hbac.conf.5*
%{_mandir}/man8/pam_hbac.8*


%changelog
* Sat Feb 27 2016 Jakub Hrozek <jakub.hrozek@posteo.se> - 0.1-1
- Initial upstream packaging
