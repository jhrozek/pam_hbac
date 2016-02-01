#!/bin/sh

pkg-config --exists pam_wrapper || exit 1

echo "WRAPPER"

pam_wrapper=$(pkg-config --libs pam_wrapper)
if [ -z $pam_wrapper ]; then
    echo "Cannot locate cwrap libraries"
    exit 2
fi

export LD_PRELOAD="$pam_wrapper"
export PAM_WRAPPER=1
export PAM_WRAPPER_SERVICE_DIR=$INTGTEST_DATADIR
export PAM_HBAC_ABS_PATH=$PAM_HBAC_ABS_PATH
