#include "WiFiServerSecure.h"

#include <esp_tls.h>

#include <esp32-hal-log.h>

// pulling in esp-tls is approx ~7kB flash and 16B RAM

EspTlsCfgServerWrapper::EspTlsCfgServerWrapper() { cfg = new esp_tls_cfg_server{0}; }
EspTlsCfgServerWrapper::~EspTlsCfgServerWrapper()
{
    delete cfg;
    log_v("");
}

EspTlsServerSessionWrapper::EspTlsServerSessionWrapper() { tls = new esp_tls{0}; }
EspTlsServerSessionWrapper::~EspTlsServerSessionWrapper()
{
    // this will call free on tls
    esp_tls_server_session_delete(tls);
    log_v("");
}
mbedtls_ssl_context *EspTlsServerSessionWrapper::get_ssl_context() { return &tls->ssl; }
int EspTlsServerSessionWrapper::get_socket() { return tls->sockfd; }

// we should take inspiration from
// https://github.com/espressif/esp-idf/blob/master/components/esp_https_server/src/https_server.c

WiFiServerSecure::~WiFiServerSecure()
{
    // RAII is enough
    log_v("");
}

WiFiServerSecure::WiFiServerSecure(uint16_t port, uint8_t max_clients)
    : WiFiServerSecure(IPAddress{}, port, max_clients)
{
}

WiFiServerSecure::WiFiServerSecure(const IPAddress &addr, uint16_t port, uint8_t max_clients)
    : WiFiServer(addr, port, max_clients)
{
}

WiFiClientSecure WiFiServerSecure::available()
{
    if (!WiFiServer::hasClient())
    {
        return WiFiClientSecure();
    }

    // WifiServer::hasClient()==true will populate _accepted_sockfd
    auto socket = _accepted_sockfd;
    _accepted_sockfd = -1;

    auto serverSession = std::make_unique<EspTlsServerSessionWrapper>();
    int ret;
    log_d("create session, socketfd=%i", socket);
    ret = esp_tls_server_session_create(cfgWrapped->cfg, socket, serverSession->tls);
    if (ret < 0)
    {
        log_e("session_create failed, ret=%i", ret);
        return WiFiClientSecure();
    }
    return WiFiClientSecure(std::move(serverSession));
}

void WiFiServerSecure::setServerKeyAndCert(const uint8_t *key, int keyLen, const uint8_t *cert,
                                           int certLen, const uint8_t *keyPasswd, int keyPasswdLen)
{
    if (cfgWrapped == nullptr)
    {
        cfgWrapped = std::make_unique<EspTlsCfgServerWrapper>();
    }
    auto &cfg = *cfgWrapped->cfg;

    // HTTP/2 ALPN support not levereged

    cfg.serverkey_buf = key;
    cfg.serverkey_bytes = keyLen;
    cfg.serverkey_password = keyPasswd;
    cfg.serverkey_password_len = keyPasswdLen;

    cfg.servercert_buf = cert;
    cfg.servercert_bytes = certLen;
}