#!/bin/bash

export SRC_DIR=$PWD
BUILD_DIR=_cov_test
TARBALL=pam_hbac.tar.gz

function finish {
  cd $SRC_DIR
  rm -rf $BUILD_DIR
}
trap finish EXIT

which cov-build
if [ $? -ne 0 ]; then
        echo "The cov-build tool was not found, aborting"
        exit 1
fi

if [ -z $COVERITY_TOKEN ]; then
        echo "Please define a valid Coverity access token"
        echo "COVERITY_TOKEN=xxxx bash ci/coverity.sh"
        exit 1
fi

autoreconf -if
cd $SRC_DIR
mkdir $BUILD_DIR
pushd $BUILD_DIR
../configure
cov-build --dir cov-int make
tar czvf $TARBALL cov-int
popd

curl --form token=$COVERITY_TOKEN \
     --form email=jakub.hrozek@posteo.se \
     --form file=@$BUILD_DIR/$TARBALL \
     --form version="CI Coverity build" \
     --form description="CI Coverity build" \
     https://scan.coverity.com/builds?project=pam_hbac
