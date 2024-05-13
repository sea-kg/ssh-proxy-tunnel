#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "ssl_tunnel_thread.h"

#define PORT 23832

#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    // method = SSLv23_client_method();
    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    OPENSSL_assert(ctx != NULL);

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "selfsigned_ssl_tunnel.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "selfsigned_ssl_tunnel.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void init_openssl_library(void)
{
    (void)SSL_library_init();
    // OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();    /* Bring in and register error messages */

    /* ERR_load_crypto_strings(); */
    static CONF *conf = NULL;
    conf = NCONF_new(NULL);
    static char app_name[] = "ssl_tunnel";
    CONF_modules_load(conf, app_name, 0);

    // OPENSSL_config(NULL);

    /* Include <openssl/opensslconf.h> to get this define */
    #if defined (OPENSSL_THREADS)
        fprintf(stdout, "Warning: thread locking is not implemented\n");
    #endif
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    init_openssl_library();

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(PORT);
    char *buffer = new char[1024];

    std::cout << "Proxy: https://localhost:" << PORT << std::endl;

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        std::cout << "Connected (" << client << ")" << std::endl;
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            std::cerr << "Error connection" << std::endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }

        // create new thread
        auto pThread = new SslTunnelThread(ssl, client, "sea5kg.ru", 443);
        pThread->start();
    }

    close(sock);
    SSL_CTX_free(ctx);
}
