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
        SslTunnelThread(SSL *pSSL, int nClient, int nListenPort, const std::string &sTunnelToHost, int nTunnelToPort);
        void start();
        void stop();
        void run();

    private:
        BIO *connectToServerB(bool &bConnected);
        bool replaceHeaderHost(std::string &sStr);

        std::string m_sTunnelToHost;
        int m_nTunnelToPort;
        int m_nListenPort;
        bool m_bStop;
        std::thread *m_pThread;
        std::mutex m_vMutexObjects;

        SSL *m_pSsl;
        int m_nBufferSize;
        char *m_pBuffer;
        int m_nClient;
};