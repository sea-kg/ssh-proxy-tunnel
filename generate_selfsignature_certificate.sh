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

if [ -f selfsigned_ssl_tunnel.crt ]; then
    rm -rf selfsigned_ssl_tunnel.crt
    check_ret $? "Removing previously selfsigned_ssl_tunnel.crt"
fi
if [ -f selfsigned_ssl_tunnel.key ]; then
    rm -rf selfsigned_ssl_tunnel.key
    check_ret $? "Removing previously selfsigned_ssl_tunnel.crt"
fi

# cd openssl/build/bin
# export LD_LIBRARY_PATH=../lib/lib64
echo ""
echo "********************************************************************************"
echo "WARNING:"
echo "in field 'Common Name (e.g. server FQDN or YOUR name) []:'"
echo "Please set '127.0.0.1' or your domain name"
echo "********************************************************************************"
echo ""

export LD_PRELOAD=$(pwd)/openssl/build/lib64/libssl.so.3:$(pwd)/openssl/build/lib64/libcrypto.so.3
./openssl/build/bin/openssl req -x509 -new -nodes -sha512 -days 3650 -newkey rsa:2048 -keyout $(pwd)/selfsigned_ssl_tunnel.key -out $(pwd)/selfsigned_ssl_tunnel.crt
check_ret $? "Generating self-signature certificates successfully"