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

# export LD_LIBRARY_PATH=$(pwd)/openssl/build/lib64

# export PATH = $(pwd)/openssl/build/bin:$PATH
# export OPENSSL_ROOT_DIR=$(pwd)/openssl/build
# export OPENSSL_INCLUDE_DIR=$(pwd)/openssl/build/include
# export OPENSSL_LIBRARIES=$(pwd)/openssl/build/lib64

rm -rf tmp

cmake -Btmp -S. \
    -DOPENSSL_ROOT_DIR=$(pwd)/openssl/build \
    -DOPENSSL_LIBRARIES=$(pwd)/openssl/build/lib64 \
    -DOPENSSL_CRYPTO_LIBRARY=$(pwd)/openssl/build/lib64/libcrypto.a
check_ret $? "Configure"
cmake --build tmp
check_ret $? "Build"