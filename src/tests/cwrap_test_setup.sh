#!/bin/sh

pkg-config --exists nss_wrapper || exit 1

nss_wrapper=$(pkg-config --libs nss_wrapper)
if [ -z $nss_wrapper ]; then
    echo "Cannot locate nss wrapper"
    exit 2
fi

export LD_PRELOAD="$nss_wrapper"
export NSS_WRAPPER_PASSWD=$CWRAP_TEST_SRCDIR/passwd
export NSS_WRAPPER_GROUP=$CWRAP_TEST_SRCDIR/group
