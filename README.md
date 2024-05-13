# ssl-tunnel-main-in-the-middle (example for reserching)

ssl tunnel example (man-in-the-middle)

## Build openssl

### Linux

`./build_openssl.sh`

## Generate self-signature sertificates

### Linux:

Command `./generate_selfsignature_certificate.sh`

**WARNING:**
**in field 'Common Name (e.g. server FQDN or YOUR name) []:'**
**Please set '127.0.0.1' or your domain name**

- `sudo mkdir /usr/share/ca-certificates/ssl_tunnel`
- Use command: `sudo cp -f selfsigned_ssl_tunnel.crt /usr/share/ca-certificates/ssl_tunnel/selfsigned_ssl_tunnel.crt`
- Update the CA store: `sudo dpkg-reconfigure ca-certificates` and marked `ssl_tunnel/...` true
- And `sudo update-ca-certificates`

Remove

- `sudo rm /usr/share/ca-certificates/ssl_tunnel/selfsigned_ssl_tunnel.crt`
- Update the CA store: `sudo update-ca-certificates --fresh`

## Test SSL self-signature sertificate via builded openssl server:

Required build openssl first and generate self-signature sertificates

```
$ LD_PRELOAD=$(pwd)/openssl/build/lib64/libssl.so.3:$(pwd)/openssl/build/lib64/libcrypto.so.3 ./openssl/build/bin/openssl s_server -key selfsigned_ssl_tunnel.key -cert selfsigned_ssl_tunnel.crt -accept 23832 -www
```

See in web-browser:

https://127.0.0.1:23832


## Test curl request via proxy

```
$ curl -I "https://127.0.0.1:23832"
```
