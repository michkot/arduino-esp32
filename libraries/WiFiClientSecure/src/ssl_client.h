/* Provide SSL/TLS functions to ESP32 with Arduino IDE
 * by Evandro Copercini - 2017 - Apache 2.0 License
 */

#ifndef ARD_SSL_H
#define ARD_SSL_H
#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

typedef struct sslclient_context {
    // we need to grab a refernce to this for mbedtls_ssl_set_bio(), which provides it to mbedtls_net_* callbacks
    mbedtls_net_context net_ctx;
    
    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;

    mbedtls_ctr_drbg_context drbg_ctx;
    mbedtls_entropy_context entropy_ctx;

    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;
} sslclient_context;

typedef struct sslclient_config {
    const char *ca_cert;
    bool useRootCABundle; 
    const char *cli_cert;
    const char *cli_key;
    const char *pskIdent; // identity for PSK cipher suites
    const char *psKey; // key in hex for PSK cipher suites
    bool insecure; 
    const char **alpn_protos;
} sslclient_config;


void ssl_init(sslclient_context *ssl_client);
// return 0 = ok
int start_ssl(sslclient_context *ssl_client, int socket, const char *host, ulong handshake_timeout, const sslclient_config& cfg);
void stop_ssl(sslclient_context *ssl_client);
int data_to_read(sslclient_context *ssl_client);
int data_to_read(mbedtls_ssl_context *ssl_ctx);
int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len);
int send_ssl_data(mbedtls_ssl_context *ssl_ctx,  const uint8_t *data, size_t len);
int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length);
int get_ssl_receive(mbedtls_ssl_context *ssl_ctx, uint8_t *data, int length);
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name);
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name);
bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32]);
#endif
