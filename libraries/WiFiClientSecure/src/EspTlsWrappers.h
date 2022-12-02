#ifndef __ESPTLSWRAPPERS_H__
#define __ESPTLSWRAPPERS_H__

// TODO: maybe move to WiFiClientSecure

// workaround https://github.com/espressif/arduino-esp32/issues/6760
#undef INADDR_NONE

// forward declaration, using a pointer to not leak types
struct esp_tls_cfg_server;

class EspTlsCfgServerWrapper final
{
public:
    esp_tls_cfg_server* cfg;
    EspTlsCfgServerWrapper();
    ~EspTlsCfgServerWrapper();
};

// forward declaration, using a pointer to not leak types
// ... and because relevant ESP-IDF functionality attempts to free this!
struct esp_tls;
// forward declaration, using a pointer to not leak types
struct mbedtls_ssl_context;

class EspTlsServerSessionWrapper final
{
public:
    esp_tls* tls;
	mbedtls_ssl_context* get_ssl_context();
	int get_socket();
    EspTlsServerSessionWrapper();
    ~EspTlsServerSessionWrapper();
};

#endif // __ESPTLSWRAPPERS_H__
