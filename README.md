pam_hbac
========

A PAM account module that evaluates HBAC rules stored on an IPA server.

Before using pam_hbac, please make sure you really need it. If possible,
please use SSSD! pam_hbac is meant is a fall-back solution for platforms where
SSSD can't be installed.

Supported platforms
===================
pam_hbac was tested on the following operating systems and releases:
    * Linux (RHEL-5 and newer)
        * I tested RHEL-5 and newer Red Hat based distributions. Ubuntu is
          used as a CI platform, but no functional testing was done there.

Building from source
====================
To build it, make sure the dependencies are installed. Except the usual
build dependencies such as autotools, pkg-config or a compiler, the only
required packages are the LDAP and PAM development libraries and a UTF-8
library. Currently libunistring and glib are supported as UTF-8 libraries,
with glib being the default.

In order to build man pages, the tool a2x is an optional build dependency.

Unit tests require the cmocka unit test framework as well as nss_wrapper and
pam_wrapper tools from the cwrap.org project.

Documentation
=============
Please see the pam_hbac(5) man page distributed along with pam_hbac for
documentation on setting up the module itself. The module is configured
with a configuration file as well, its options are described in a separate
man page pam_hbac.conf(5).

Build Status
============
[![Build Status](https://semaphoreci.com/api/v1/projects/ac5523b9-90ee-4dd1-9c0b-5bb718677e63/648576/badge.svg)](https://semaphoreci.com/jhrozek/pam_hbac)

Code Coverage
=============
[![Coverage Status](https://coveralls.io/repos/jhrozek/pam_hbac/badge.svg?branch=master&service=github)](https://coveralls.io/github/jhrozek/pam_hbac?branch=master)
