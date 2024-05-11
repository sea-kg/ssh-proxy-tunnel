// File: ssl_tunnel_thread.h
// Copyright: 2023 (c) mrseakg@gmail.com

#pragma once

#include <string>
#include <mutex>
#include <deque>
#include <thread>
#include <vector>
#include <mutex>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

class SslTunnelThread {
    public:
        SslTunnelThread(SSL *pSSL, int nClient, const std::string &sHostName, int nHostPort);
        void start();
        void stop();
        void run();

    private:
        BIO *connectToServerB(bool &bConnected);
        std::string m_sHostName;
        int m_nHostPort;
        bool m_bStop;
        std::thread *m_pThread;
        std::mutex m_vMutexObjects;

        SSL *m_pSsl;
        int m_nBufferSize;
        char *m_pBuffer;
        int m_nClient;
};