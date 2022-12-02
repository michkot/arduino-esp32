#ifndef __WIFISERVERSECURE_H__
#define __WIFISERVERSECURE_H__

#include "EspTlsWrappers.h"
#include <WiFiClientSecure.h>

#include <WiFi.h>

class WiFiServerSecure : public WiFiServer
{
private:
    std::unique_ptr<EspTlsCfgServerWrapper> cfgWrapped;

public:
    WiFiServerSecure(uint16_t port=443, uint8_t max_clients=1);
    WiFiServerSecure(const IPAddress& addr, uint16_t port=443, uint8_t max_clients=1);
    virtual ~WiFiServerSecure() override;

    // void begin(uint16_t port = 0);
    // void begin(uint16_t port, int reuse_enable);

    WiFiClientSecure available();

    // void end();
    // void close();
    // void stop();

    // int setTimeout(uint32_t seconds);
    // void stopAll();

    // Set the server's RSA key and x509 certificate (required, pick one).
    // Caller needs to preserve the chain and key throughout the life of the server.
    // NOT TRUE: keyLen/certLen to -1 for PEM certificates (textual - base64 encoded data, null
    // terminated); NOT TRUE: keyLen/certLen to size of the key/cert with DER binary data TRUE:
    // always specify size, but you can you both null-terminated textual (size = sizeof(constant) =
    // strlen) PEM or binary DER
    // Note: this is matching ESP8266 v <3, in v3 this bearssl-acTLS compatbile call was removed
    // Note: we need "raw" PEM/DER format, as that's what mbedlts wants
    void setServerKeyAndCert(const uint8_t *key, int keyLen, const uint8_t *cert, int certLen,
                             const uint8_t *keyPasswd = nullptr, int keyPasswdLen = -1);
};

#endif // __WIFISERVERSECURE_H__
