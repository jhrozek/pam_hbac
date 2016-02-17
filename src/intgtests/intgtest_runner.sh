#!/bin/sh

pkg-config --exists pam_wrapper || exit 1
pkg-config --exists nss_wrapper || exit 2

pam_wrapper=$(pkg-config --libs pam_wrapper)
nss_wrapper=$(pkg-config --libs nss_wrapper)
if [ -z $pam_wrapper -o -z $nss_wrapper]; then
    echo "Cannot locate cwrap libraries"
    exit 3
fi

export LD_PRELOAD="$pam_wrapper $nss_wrapper"
export PAM_WRAPPER=1
export PAM_WRAPPER_SERVICE_DIR=$INTGTEST_DATADIR/test_pam_services
export NSS_WRAPPER_PASSWD=$NSS_WRAPPER_DATADIR/passwd
export NSS_WRAPPER_GROUP=$NSS_WRAPPER_DATADIR/group

export PAM_HBAC_CONFIG_PATH=$INTGTEST_DATADIR/pam_hbac.conf
export PAM_HBAC_ABS_PATH=$PAM_HBAC_ABS_PATH

exec $@
