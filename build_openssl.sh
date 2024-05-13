#!/bin/bash
check_ret() {
    if [ $1 -ne 0 ]; then
        echo ""
        echo "!!! FAIL: $2"
        echo "********************************************************************************"
        echo ""
        exit $1
    else
        echo ""
        echo "*** SUCCESS: $2"
        echo "********************************************************************************"
        echo ""
    fi
}


cd openssl-3.0.12
check_ret $? "cd openssl-3.0.12"
git clean -fxd .
check_ret $? "Cleanup old files in openssl-3.0.12"
./config \
    --prefix=`pwd`/../openssl/build \
    --openssldir=`pwd`/../openssl/ssl
check_ret $? "Configure openssl-3.0.12"
perl configdata.pm --dump
make
check_ret $? "make openssl-3.0.12"
make install
check_ret $? "make install openssl-3.0.12"