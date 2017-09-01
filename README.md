pam_hbac
========

A PAM account module that evaluates HBAC rules stored on an IPA server.

Before using pam_hbac, please make sure you really need it. If possible,
please use SSSD! pam_hbac is meant as a fall-back solution for platforms where
SSSD can't be installed.

Supported platforms
===================
pam_hbac was tested on the following operating systems and releases:
  * Linux (RHEL-5 and newer)
    * The pam_hbac developers tested RHEL-5 and newer Red Hat based
      distributions. Ubuntu is used as a CI platform, but no functional
      testing was done there except integration tests.
  * FreeBSD - tested with FreeBSD 10.2
  * Solaris - tested with Solaris 11 and Omnios. Some users run pam_hbac on Solaris 10 as well.
  * HPUX - tested with HPUX 11.31 - no SSL/TLS yet
  * AIX - tested with AIX 7.1 TL4

Building from source
====================
To build pam_hbac, make sure the dependencies are installed. Except the
usual build dependencies such as `autotools`, `pkg-config` `gettext`, or
a compiler, the only required packages are the LDAP and PAM development
libraries and a UTF-8 library. Currently `libunistring` and `glib` are
supported as UTF-8 libraries, with glib being the default.

In order to build man pages, the tool `a2x` is an optional build dependency.

The unit tests require the [cmocka](https://cmocka.org/) unit test
framework as well as `nss_wrapper` and `pam_wrapper` tools from the
[cwrap.org](https://cwrap.org/) project.

If you're building from a git checkout, generate configure first:
    $ autoreconf -if
Then run the usual "configure, make, make install" commands. For platforms
that we tested and support, there is a platform-dependent README.$platform
in the doc/ subdirectory that includes suggested configure flags.

Documentation
=============
Please see the
[pam_hbac(8)](https://github.com/jhrozek/pam_hbac/blob/master/doc/pam_hbac.8.txt)
man page distributed along with pam_hbac for documentation on setting up
the module itself. The module is configured with a configuration file as
well, its options are described in a separate man page
[pam_hbac.conf(5)](https://github.com/jhrozek/pam_hbac/blob/master/doc/pam_hbac.conf.5.txt)

Setting up the HBAC rules for LDAP clients
--------------------------------------------
This section describes how the PAM rules interact for clients that
authenticate against the compat LDAP tree.

Obviously, you'll want to set up HBAC rules for the client machine pam_hbac
runs on. But in addition to that, the slapi-nis Directory Server plugin
that runs on the IPA server itself also runs a PAM account check against
the `system-auth` PAM service. In order to satisfy this second check, you
also need to create a special `system-auth` HBAC service and allow access
using this service for any users or groups that you want allow access to
clients running pam_hbac as well.

Please see
[doc/ipa/sch-ipa.txt](https://git.fedorahosted.org/cgit/slapi-nis.git/tree/doc/ipa/sch-ipa.txt)
from the slapi-nis' tree for more information on how the compat tree works.

Contribute
==========
Please open a ticket if you encounter a bug or send a pull request with
a contribution. For questions, you can use the [freeipa-users mailing
list](http://www.redhat.com/mailman/listinfo/freeipa-users).

Build Status
------------
Generated after every commit.

[![Build Status](https://semaphoreci.com/api/v1/projects/ac5523b9-90ee-4dd1-9c0b-5bb718677e63/648576/badge.svg)](https://semaphoreci.com/jhrozek/pam_hbac)

Code Coverage
-------------
Generated after every commit.

[![Coverage Status](https://coveralls.io/repos/jhrozek/pam_hbac/badge.svg?branch=master&service=github)](https://coveralls.io/github/jhrozek/pam_hbac?branch=master)

Coverity
--------
Coverity scans are ran before releases only.

[![Coverity Scan Build Status](https://scan.coverity.com/projects/8032/badge.svg)](https://scan.coverity.com/projects/8032)
