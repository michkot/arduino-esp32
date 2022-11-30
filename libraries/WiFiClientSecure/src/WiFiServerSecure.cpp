#include "WiFiServerSecure.h"

// pulling in esp-tls is approx ~7kB flash and 16B RAM

// class WiFiClientSecureForServer : public WiFiClientSecure {	
//     WiFiClientSecureForServer(std::unique_ptr<EspTlsServerSessionWrapper> server_session) : WiFiClientSecure(server_session) {};
// }

EspTlsCfgServerWrapper::EspTlsCfgServerWrapper() : cfg{0} {}
EspTlsCfgServerWrapper::~EspTlsCfgServerWrapper() {}

EspTlsServerSessionWrapper::EspTlsServerSessionWrapper() : tls{0} {}
EspTlsServerSessionWrapper::~EspTlsServerSessionWrapper() {
    // WARN! this will call free on tls, and tls is aligned with this!?!
    esp_tls_server_session_delete(&tls);
}
mbedtls_ssl_context* EspTlsServerSessionWrapper::get_ssl_context()
{
    return &tls.ssl;
}
int EspTlsServerSessionWrapper::get_socket()
{
    return tls.sockfd;
}



// we should take inspiration from
// https://github.com/espressif/esp-idf/blob/master/components/esp_https_server/src/https_server.c

WiFiServerSecure::WiFiServerSecure(uint16_t port) {}

WiFiServerSecure::~WiFiServerSecure()
{
    // todo: free any memory structures that this wrapper keeps ownership of
    // we can use unique_ptr in the fields to do the same
}

WiFiClientSecure WiFiServerSecure::available()
{
    // TODO
	if (!available()) {
	
    return WiFiClientSecure();
	}
	// available()==true of WifiServer will populate _accepted_sockfd
	auto serverSession = std::make_unique<EspTlsServerSessionWrapper>();
	int ret;
	ret = esp_tls_server_session_create(&cfgWrapped.get()->cfg,  _accepted_sockfd, &serverSession.get()->tls);
	if (ret < 0)
	{
		//TODO: report error
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
    auto &cfg = cfgWrapped.get()->cfg;

    // HTTP/2 ALPN support not levereged

    cfg.serverkey_buf = key;
    cfg.serverkey_bytes = keyLen;
    cfg.serverkey_password = keyPasswd;
    cfg.serverkey_password_len = keyPasswdLen;

    cfg.servercert_buf = cert;
    cfg.servercert_bytes = certLen;
}
