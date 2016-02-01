#!/bin/bash

# This file is specific to Semaphore-CI:
#   https://semaphoreci.com/jhrozek/pam_hbac

# Don't query during package install
export DEBIAN_FRONTEND=noninteractive
# Update repos
sudo apt-get update
# Required for code coverage
sudo pip install cpp-coveralls

# BuildRequires
sudo apt-get -y -q install gcc make automake autopoint autoconf gettext
sudo apt-get -y -q install libpam0g-dev libldap2-dev

# Build a newer cmocka than Ubuntu 14.04 has
git clone https://git.cryptomilk.org/projects/cmocka.git/
mkdir cmocka/obj
pushd cmocka/obj
cmake -DLIB_INSTALL_DIR:PATH=/usr/lib ..
make
sudo make install
popd

# Build nss_wrapper..not in Ubuntu 14.04 at all
git clone git://git.samba.org/nss_wrapper.git
mkdir nss_wrapper/obj
pushd nss_wrapper/obj
cmake -DLIB_INSTALL_DIR:PATH=/usr/lib ..
make
sudo make install
popd

# Build pam_hbac
autoreconf -if
mkdir _build_coverage
cd _build_coverage
../configure CFLAGS="-g -O0 -Wall -W -fprofile-arcs -ftest-coverage" \
             LDFLAGS="-fprofile-arcs -ftest-coverage"
make

# Test!
make check
