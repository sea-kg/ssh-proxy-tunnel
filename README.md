# ssl-proxy-tunnel


ssl proxy tunnel example (man-in-the-middle)

## Build openssl

Linux: `./build_openssl.sh`

## Generate self-signature sertificates

### Linux:

Command `./generate_selfsignature_certificate.sh`


**WARNING:**
**in field 'Common Name (e.g. server FQDN or YOUR name) []:'**
**Please set '127.0.0.1' or your domain name**

- `sudo mkdir /usr/share/ca-certificates/ssl_proxy`
- Use command: `sudo cp -f selfsigned_ssl_proxy_tunnel.crt /usr/share/ca-certificates/ssl_proxy/selfsigned_ssl_proxy_tunnel.crt`
- Update the CA store: `sudo dpkg-reconfigure ca-certificates` and marked `ssl_proxy/...` true
- And `sudo update-ca-certificates`

Remove

- `sudo rm /usr/local/share/ca-certificates/selfsigned_ssl_proxy_tunnel.crt`
- Update the CA store: `sudo update-ca-certificates --fresh`

## Test SSL self-signature sertificate via builded openssl server:

Required build openssl first and generate self-signature sertificates

```
$ LD_PRELOAD=$(pwd)/openssl/build/lib64/libssl.so.3:$(pwd)/openssl/build/lib64/libcrypto.so.3 ./openssl/build/bin/openssl s_server -key selfsigned_ssl_proxy_tunnel.key -cert selfsigned_ssl_proxy_tunnel.crt -accept 23832 -www
```
See in web-browser:

https://localhost:23832


## Test curl request via proxy

```
$ curl --proxy "https://127.0.0.1:23832" -I "https://sea5kg.ru"
```
