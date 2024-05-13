#include "ssl_tunnel_thread.h"
#include <iostream>
#include <cstring>

void* processJobsThreadWorker(void *arg) {
    auto *pThread = (SslTunnelThread *)arg;
    pThread->run();
    return 0;
}

SslTunnelThread::SslTunnelThread(SSL *pSsl, int nClient, const std::string &sHostName, int nHostPort) {
    m_pSsl = pSsl;
    m_sHostName = sHostName;
    m_nHostPort = nHostPort;
    m_nClient = nClient;
    m_bStop = false;
    m_pThread = nullptr;
    m_nBufferSize = 1024;
    m_pBuffer = new char[m_nBufferSize];
}

void SslTunnelThread::start() {
    m_bStop = false;
    m_pThread = new std::thread(&processJobsThreadWorker, (void *)this);
}

void SslTunnelThread::stop() {
    m_bStop = true;
}

void SslTunnelThread::run() {
    std::cout << "Starting..." << std::endl;
    bool bConnected = false;
    BIO *web = this->connectToServerB(bConnected);
    if (!bConnected) {
        this->stop();
        CONF_modules_unload(0);
        SSL_shutdown(m_pSsl);
        SSL_free(m_pSsl);
        close(m_nClient);
        return;
    }

    while (!m_bStop) {
        // clean buffer
        std::cout << "\n<<<<< Reading data from (cli-" << m_nClient << ") " << std::endl;
        memset(m_pBuffer, 0x0, m_nBufferSize);
        int len = SSL_read(m_pSsl, m_pBuffer, m_nBufferSize);
        if (len > 0) {
            std::cout << "-----" << std::endl << m_pBuffer << std::endl << "----" << std::endl;
            std::cout << "\n<<<<< Sending data to (cli-" << m_nClient << "): " << std::endl;
            BIO_puts(web, m_pBuffer);
            std::cout << "\n>>>>> Read data from  (cli-" << m_nClient << "): " << std::endl;
            // cleanup buffer
            memset(m_pBuffer, 0x0, m_nBufferSize);
            len = BIO_read(web, m_pBuffer, 1024);
            while (len > 0) {
                std::cout << "-----" << std::endl << m_pBuffer << std::endl << "----" << std::endl;
                std::cout << ">>>>> Sending data to  (cli-" << m_nClient << "): " << std::endl;
                SSL_write(m_pSsl, m_pBuffer, len);

                // std::this_thread::sleep_for(std::chrono::milliseconds(17));
                std::cout << "\n>>>>> Read data from  (cli-" << m_nClient << "): " << std::endl;
                memset(m_pBuffer, 0x0, m_nBufferSize);
                len = BIO_read(web, m_pBuffer, 1024);
            }
            // char answer[] = "\n ";
            // answer[29] = 0;
            // SSL_write(ssl, answer, 30);
        }



        // std::lock_guard<std::mutex> guard(m_vMutexObjects);
        // // int nSize = m_vObjects.size();
        // // for (int i = 0; i < nSize; i++) {
        // //     m_vObjects[i]->makeStep();
        // // }
        // std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    SSL_shutdown(m_pSsl);
    SSL_free(m_pSsl);
    close(m_nClient);
    std::cout << "Stopped..." << std::endl;
}

BIO *SslTunnelThread::connectToServerB(bool &bConnected) {
    bConnected = true;
    std::string sConnectionString = m_sHostName + ":" + std::to_string(m_nHostPort);

    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    const SSL_METHOD* method =  TLS_method();
    if(!(NULL != method)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    ctx = SSL_CTX_new(method);
    if(!(ctx != NULL)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    /* Cannot fail ??? */
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Cannot fail ??? */
    // SSL_CTX_set_verify_depth(ctx, 4);

    /* Cannot fail ??? */
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    // res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
    // if(!(1 == res)) {
    //     ERR_print_errors_fp(stderr);
    //     return -3; // handleFailure();
    // }

    web = BIO_new_ssl_connect(ctx);
    if(!(web != NULL)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    res = BIO_set_conn_hostname(web, sConnectionString.c_str());
    if(!(1 == res)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }


    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    const char PREFERRED_CIPHERS[] = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if(!(1 == res)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    res = SSL_set_tlsext_host_name(ssl, m_sHostName.c_str());
    if(!(1 == res)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if(!(NULL != out)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    res = BIO_do_connect(web);
    if(!(1 == res)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    res = BIO_do_handshake(web);
    if(!(1 == res)) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    /* Step 1: verify a server certificate was presented during the negotiation */
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { X509_free(cert); } /* Free immediately */
    if(NULL == cert) {
        bConnected = false;
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    /* Step 2: verify the result of chain verification */
    /* Verification performed according to RFC 4158    */
    // res = SSL_get_verify_result(ssl);
    // if(!(X509_V_OK == res)) return -12; // handleFailure();

    /* Step 3: hostname verification */
    /* An exercise left to the reader */
    bConnected = true;
    return web;
}