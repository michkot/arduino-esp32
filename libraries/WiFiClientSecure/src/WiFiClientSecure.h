/*
  WiFiClientSecure.h - Base class that provides Client SSL to ESP32
  Copyright (c) 2011 Adrian McEwen.  All right reserved.
  Additions Copyright (C) 2017 Evandro Luis Copercini.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef WiFiClientSecure_h
#define WiFiClientSecure_h
#include "Arduino.h"
#include "IPAddress.h"
#include <WiFi.h>
#include "ssl_client.h"

#include "EspTlsWrappers.h"

class TlsSessionWrapper;

class WiFiClientSecure : public WiFiClient
{
friend class WiFiServerSecure;
protected:
    std::shared_ptr<TlsSessionWrapper> _client_session;
    std::shared_ptr<EspTlsServerSessionWrapper> _server_session;

    int _lastError = 0;
    int _peek = -1;
    // in ms
    unsigned long _handshake_timeout = 120000;
    sslclient_config _cfg = {0};

    WiFiClientSecure(const std::shared_ptr<EspTlsServerSessionWrapper>& server_session);

public:
    WiFiClientSecure *next;
    WiFiClientSecure();
    WiFiClientSecure(int socket);
    ~WiFiClientSecure();
    int connect(IPAddress ip, uint16_t port);
    int connect(IPAddress ip, uint16_t port, int32_t timeout);
    int connect(const char *host, uint16_t port);
    int connect(const char *host, uint16_t port, int32_t timeout);
    int connect(IPAddress ip, uint16_t port, const char *ca_cert, const char *cli_cert, const char *cli_key);
    int connect(const char *host, uint16_t port, const char *ca_cert, const char *cli_cert, const char *cli_key);
    int connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey);
    int connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey);
    int peek();
    //moved from private:
    using Print::write;
    size_t write(uint8_t data);
    // changed to virtual
    virtual size_t write(const uint8_t *buf, size_t size) override;
    int available();
    int read();
    int read(uint8_t *buf, size_t size);
    void flush() {}
    void stop();
    uint8_t connected();
    int lastError(char *buf, const size_t size);
    void setInsecure(); // Don't validate the chain, just accept whatever is given.  VERY INSECURE!
    void setPreSharedKey(const char *pskIdent, const char *psKey); // psKey in Hex
    void setCACert(const char *rootCA);
    void setCertificate(const char *client_ca);
    void setPrivateKey (const char *private_key);
    bool loadCACert(Stream& stream, size_t size);
    // WARN: changes global setting!!!
    void setCACertBundle(const uint8_t * bundle);
    bool loadCertificate(Stream& stream, size_t size);
    bool loadPrivateKey(Stream& stream, size_t size);
    bool verify(const char* fingerprint, const char* domain_name);
    void setHandshakeTimeout(unsigned long seconds);
    void setAlpnProtocols(const char **alpn_protos);
    const mbedtls_x509_crt* getPeerCertificate();
    bool getFingerprintSHA256(uint8_t sha256_result[32]);
    int setTimeout(uint32_t seconds);

    operator bool()
    {
        return connected();
    }
    WiFiClientSecure &operator=(const WiFiClientSecure &other);
    bool operator==(const bool value)
    {
        return bool() == value;
    }
    bool operator!=(const bool value)
    {
        return bool() != value;
    }
    bool operator==(const WiFiClientSecure &);
    bool operator!=(const WiFiClientSecure &rhs)
    {
        return !this->operator==(rhs);
    };

private:
    char *_streamLoad(Stream& stream, size_t size);

    //friend class WiFiServer;
    //using Print::write;

    // takes ownership of the socket
    void setSocket(int socket);

    int _connect(const char *host, uint16_t port, const sslclient_config& cfg);
};

#endif /* _WIFICLIENT_H_ */
