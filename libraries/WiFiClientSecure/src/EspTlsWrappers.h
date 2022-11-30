#ifndef __ESPTLSWRAPPERS_H__
#define __ESPTLSWRAPPERS_H__

// TODO: maybe move to WiFiClientSecure

#include <esp_tls.h>
// workaround https://github.com/espressif/arduino-esp32/issues/6760
#undef INADDR_NONE

class EspTlsCfgServerWrapper final
{
public:
    esp_tls_cfg_server cfg;
    EspTlsCfgServerWrapper();
    ~EspTlsCfgServerWrapper();
};

class EspTlsServerSessionWrapper final
{
public:
    esp_tls tls;
	mbedtls_ssl_context* get_ssl_context();
	int get_socket();
    EspTlsServerSessionWrapper();
    ~EspTlsServerSessionWrapper();
};

#endif // __ESPTLSWRAPPERS_H__
