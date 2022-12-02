/* Provide SSL/TLS functions to ESP32 with Arduino IDE
*
* Adapted from the ssl_client1 example of mbedtls.
*
* Original Copyright (C) 2006-2015, ARM Limited, All Rights Reserved, Apache 2.0 License.
* Additions Copyright (C) 2017 Evandro Luis Copercini, Apache 2.0 License.
*/

#include "Arduino.h"
#include <esp32-hal-log.h>
#include <lwip/err.h>
#include <lwip/sockets.h>
#include <lwip/sys.h>
#include <lwip/netdb.h>
#include <mbedtls/sha256.h>
#include <mbedtls/oid.h>
#include <algorithm>
#include <string>
#include "ssl_client.h"
#include "esp_crt_bundle.h"
#include "WiFi.h"

#if !defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED) && !defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
#  warning "Please call `idf.py menuconfig` then go to Component config -> mbedTLS -> TLS Key Exchange Methods -> Enable pre-shared-key ciphersuites and then check `Enable PSK based cyphersuite modes`. Save and Quit."
#else

const char *pers = "esp32-tls";

static int _handle_error(int err, const char * function, int line)
{
    if(err == -30848){
        return err;
    }
#ifdef MBEDTLS_ERROR_C
    char error_buf[100];
    mbedtls_strerror(err, error_buf, 100);
    log_e("[%s():%d]: (%d) %s", function, line, err, error_buf);
#else
    log_e("[%s():%d]: code %d", function, line, err);
#endif
    return err;
}

#define handle_error(e) _handle_error(e, __FUNCTION__, __LINE__)


void ssl_init(sslclient_context *ssl_client)
{
    // reset embedded pointers to zero
    memset(ssl_client, 0, sizeof(sslclient_context));
    mbedtls_ssl_init(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_init(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_init(&ssl_client->drbg_ctx);
}

// return 0 = ok
int start_ssl(sslclient_context *ssl_client, int socket, const char *host, unsigned long handshake_timeout, const sslclient_config& cfg)
{
    char buf[512];
    int ret, flags;
    int enable = 1;
    log_v("Free internal heap before TLS %u", ESP.getFreeHeap());

    {
        int ctr = 0;
        ctr += cfg.insecure == true;
        ctr += cfg.useRootCABundle == true;
        ctr += cfg.ca_cert != NULL;
        ctr += cfg.pskIdent != NULL || cfg.psKey;
        if (ctr != 1)
        {   
            log_e("exactly one server-verification method is allowed");
            return -1;
        }
    }

    if ((cfg.cli_cert != NULL) != (cfg.cli_key != NULL)) {
        log_e("client authentication is set-up only half-way");
        return -1;
    }
    
    log_v("Seeding the random number generator");
    mbedtls_entropy_init(&ssl_client->entropy_ctx);

    ret = mbedtls_ctr_drbg_seed(&ssl_client->drbg_ctx, mbedtls_entropy_func,
                                &ssl_client->entropy_ctx, (const unsigned char *) pers, strlen(pers));
    if (ret < 0) {
        return handle_error(ret);
    }

    log_v("Setting up the SSL/TLS structure...");

    if ((ret = mbedtls_ssl_config_defaults(&ssl_client->ssl_conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return handle_error(ret);
    }

    if (cfg.alpn_protos != NULL) {
        log_v("Setting ALPN protocols");
        if ((ret = mbedtls_ssl_conf_alpn_protocols(&ssl_client->ssl_conf, cfg.alpn_protos) ) != 0) {
            return handle_error(ret);
        }
    }

    // MBEDTLS_SSL_VERIFY_REQUIRED if a CA certificate is defined on Arduino IDE and
    // MBEDTLS_SSL_VERIFY_NONE if not.

    if (cfg.insecure) {
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
        log_d("WARNING: Skipping SSL Verification. INSECURE!");
    } else if (cfg.ca_cert != NULL) {
        auto& rootCABuff = cfg.ca_cert;
        log_v("Loading CA cert");
        mbedtls_x509_crt_init(&ssl_client->ca_cert);
        mbedtls_ssl_conf_authmode(&ssl_client->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        ret = mbedtls_x509_crt_parse(&ssl_client->ca_cert, (const unsigned char *)rootCABuff, strlen(rootCABuff) + 1);
        mbedtls_ssl_conf_ca_chain(&ssl_client->ssl_conf, &ssl_client->ca_cert, NULL);
        //mbedtls_ssl_conf_verify(&ssl_client->ssl_ctx, my_verify, NULL );
        if (ret < 0) {
            // free the ca_cert in the case parse failed, otherwise, the old ca_cert still in the heap memory, that lead to "out of memory" crash.
            mbedtls_x509_crt_free(&ssl_client->ca_cert);
            return handle_error(ret);
        }
    } else if (cfg.useRootCABundle) {
        log_v("Attaching root CA cert bundle");
        ret = esp_crt_bundle_attach(&ssl_client->ssl_conf);

        if (ret < 0) {
            return handle_error(ret);
        }
    } else if (cfg.pskIdent != NULL && cfg.psKey != NULL) {
        auto& pskIdent = cfg.pskIdent;
        auto& psKey = cfg.psKey;
        log_v("Setting up PSK");
        // convert PSK from hex to binary
        if ((strlen(psKey) & 1) != 0 || strlen(psKey) > 2*MBEDTLS_PSK_MAX_LEN) {
            log_e("pre-shared key not valid hex or too long");
            return -1;
        }
        unsigned char psk[MBEDTLS_PSK_MAX_LEN];
        size_t psk_len = strlen(psKey)/2;
        for (int j=0; j<strlen(psKey); j+= 2) {
            char c = psKey[j];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] = c<<4;
            c = psKey[j+1];
            if (c >= '0' && c <= '9') c -= '0';
            else if (c >= 'A' && c <= 'F') c -= 'A' - 10;
            else if (c >= 'a' && c <= 'f') c -= 'a' - 10;
            else return -1;
            psk[j/2] |= c;
        }
        // set mbedtls config
        ret = mbedtls_ssl_conf_psk(&ssl_client->ssl_conf, psk, psk_len,
                 (const unsigned char *)pskIdent, strlen(pskIdent));
        if (ret != 0) {
            log_e("mbedtls_ssl_conf_psk returned %d", ret);
            return handle_error(ret);
        }
    } else {
        return -1;
    }

    if (!cfg.insecure && cfg.cli_cert != NULL && cfg.cli_key != NULL) {
        auto& cli_cert = cfg.cli_cert;
        auto& cli_key = cfg.cli_key;
        mbedtls_x509_crt_init(&ssl_client->client_cert);
        mbedtls_pk_init(&ssl_client->client_key);

        log_v("Loading CRT cert");

        ret = mbedtls_x509_crt_parse(&ssl_client->client_cert, (const unsigned char *)cli_cert, strlen(cli_cert) + 1);
        if (ret < 0) {
        // free the client_cert in the case parse failed, otherwise, the old client_cert still in the heap memory, that lead to "out of memory" crash.
        mbedtls_x509_crt_free(&ssl_client->client_cert);
            return handle_error(ret);
        }

        log_v("Loading private key");
        ret = mbedtls_pk_parse_key(&ssl_client->client_key, (const unsigned char *)cli_key, strlen(cli_key) + 1, NULL, 0);

        if (ret != 0) {
            mbedtls_x509_crt_free(&ssl_client->client_cert); // cert+key are free'd in pair
            return handle_error(ret);
        }

        mbedtls_ssl_conf_own_cert(&ssl_client->ssl_conf, &ssl_client->client_cert, &ssl_client->client_key);
    }

    log_v("Setting hostname for TLS session...");

    // Hostname set here should match CN in server certificate
    if((ret = mbedtls_ssl_set_hostname(&ssl_client->ssl_ctx, host)) != 0){
        return handle_error(ret);
    }

    mbedtls_ssl_conf_rng(&ssl_client->ssl_conf, mbedtls_ctr_drbg_random, &ssl_client->drbg_ctx);

    if ((ret = mbedtls_ssl_setup(&ssl_client->ssl_ctx, &ssl_client->ssl_conf)) != 0) {
        return handle_error(ret);
    }

    ssl_client->socket = socket;
    mbedtls_ssl_set_bio(&ssl_client->ssl_ctx, &ssl_client->socket, mbedtls_net_send, mbedtls_net_recv, NULL );

    log_v("Performing the SSL/TLS handshake...");
    unsigned long handshake_start_time=millis();
    while ((ret = mbedtls_ssl_handshake(&ssl_client->ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            return handle_error(ret);
        }
        if((millis()-handshake_start_time)>handshake_timeout)
            return -1;
        vTaskDelay(2);//2 ticks
    }


    if (cfg.cli_cert != NULL && cfg.cli_key != NULL) {
        log_d("Protocol is %s Ciphersuite is %s", mbedtls_ssl_get_version(&ssl_client->ssl_ctx), mbedtls_ssl_get_ciphersuite(&ssl_client->ssl_ctx));
        if ((ret = mbedtls_ssl_get_record_expansion(&ssl_client->ssl_ctx)) >= 0) {
            log_d("Record expansion is %d", ret);
        } else {
            log_w("Record expansion is unknown (compression)");
        }
    }

    log_v("Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl_client->ssl_ctx)) != 0) {
        memset(buf, 0, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        log_e("Failed to verify peer certificate! verification info: %s", buf);
        return handle_error(ret);
    } else {
        log_v("Certificate verified.");
    }
    
    if (cfg.ca_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }

    if (cfg.cli_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
    }

    if (cfg.cli_key != NULL) {
        mbedtls_pk_free(&ssl_client->client_key);
    }

    log_v("Free internal heap after TLS %u", ESP.getFreeHeap());

    return 0;
}

void stop_ssl(sslclient_context *ssl_client)
{
    log_v("Cleaning SSL connection.");

    // avoid memory leak if ssl connection attempt failed
    if (ssl_client->ssl_conf.ca_chain != NULL) {
        mbedtls_x509_crt_free(&ssl_client->ca_cert);
    }
    if (ssl_client->ssl_conf.key_cert != NULL) {
        mbedtls_x509_crt_free(&ssl_client->client_cert);
        mbedtls_pk_free(&ssl_client->client_key);
    }
    mbedtls_ssl_free(&ssl_client->ssl_ctx);
    mbedtls_ssl_config_free(&ssl_client->ssl_conf);
    mbedtls_ctr_drbg_free(&ssl_client->drbg_ctx);
    mbedtls_entropy_free(&ssl_client->entropy_ctx);
    
    // TODO: discuss -  I think is is not needed after all the frees
    //// // reset embedded pointers to zero
    //// memset(ssl_client, 0, sizeof(sslclient_context));

    ssl_client->socket = -1;
}


int data_to_read(sslclient_context *ssl_client)
{
    return data_to_read(&ssl_client->ssl_ctx);
}

int data_to_read(mbedtls_ssl_context *ssl_ctx)
{
    int ret, res;
    ret = mbedtls_ssl_read(ssl_ctx, NULL, 0);
    //log_e("RET: %i",ret);   //for low level debug
    res = mbedtls_ssl_get_bytes_avail(ssl_ctx);
    //log_e("RES: %i",res);    //for low level debug
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
        return handle_error(ret);
    }

    return res;
}

int send_ssl_data(sslclient_context *ssl_client, const uint8_t *data, size_t len)
{
    return send_ssl_data(&ssl_client->ssl_ctx, data, len);
}

int send_ssl_data(mbedtls_ssl_context *ssl_ctx, const uint8_t *data, size_t len)
{
    log_v("Writing HTTP request with %d bytes...", len); //for low level debug
    int ret = -1;

    while ((ret = mbedtls_ssl_write(ssl_ctx, data, len)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret < 0) {
            log_v("Handling error %d", ret); //for low level debug
            return handle_error(ret);
        }
        //wait for space to become available
        vTaskDelay(2);
    }

    return ret;
}

int get_ssl_receive(sslclient_context *ssl_client, uint8_t *data, int length)
{
    return get_ssl_receive(&ssl_client->ssl_ctx, data, length);
}

int get_ssl_receive(mbedtls_ssl_context *ssl_ctx, uint8_t *data, int length)
{
    //log_d( "Reading HTTP response...");   //for low level debug
    int ret = -1;

    ret = mbedtls_ssl_read(ssl_ctx, data, length);

    //log_v( "%d bytes read", ret);   //for low level debug
    return ret;
}

static bool parseHexNibble(char pb, uint8_t* res)
{
    if (pb >= '0' && pb <= '9') {
        *res = (uint8_t) (pb - '0'); return true;
    } else if (pb >= 'a' && pb <= 'f') {
        *res = (uint8_t) (pb - 'a' + 10); return true;
    } else if (pb >= 'A' && pb <= 'F') {
        *res = (uint8_t) (pb - 'A' + 10); return true;
    }
    return false;
}

// Compare a name from certificate and domain name, return true if they match
static bool matchName(const std::string& name, const std::string& domainName)
{
    size_t wildcardPos = name.find('*');
    if (wildcardPos == std::string::npos) {
        // Not a wildcard, expect an exact match
        return name == domainName;
    }

    size_t firstDotPos = name.find('.');
    if (wildcardPos > firstDotPos) {
        // Wildcard is not part of leftmost component of domain name
        // Do not attempt to match (rfc6125 6.4.3.1)
        return false;
    }
    if (wildcardPos != 0 || firstDotPos != 1) {
        // Matching of wildcards such as baz*.example.com and b*z.example.com
        // is optional. Maybe implement this in the future?
        return false;
    }
    size_t domainNameFirstDotPos = domainName.find('.');
    if (domainNameFirstDotPos == std::string::npos) {
        return false;
    }
    return domainName.substr(domainNameFirstDotPos) == name.substr(firstDotPos);
}

// Verifies certificate provided by the peer to match specified SHA256 fingerprint
bool verify_ssl_fingerprint(sslclient_context *ssl_client, const char* fp, const char* domain_name)
{
    // Convert hex string to byte array
    uint8_t fingerprint_local[32];
    int len = strlen(fp);
    int pos = 0;
    for (size_t i = 0; i < sizeof(fingerprint_local); ++i) {
        while (pos < len && ((fp[pos] == ' ') || (fp[pos] == ':'))) {
            ++pos;
        }
        if (pos > len - 2) {
            log_d("pos:%d len:%d fingerprint too short", pos, len);
            return false;
        }
        uint8_t high, low;
        if (!parseHexNibble(fp[pos], &high) || !parseHexNibble(fp[pos+1], &low)) {
            log_d("pos:%d len:%d invalid hex sequence: %c%c", pos, len, fp[pos], fp[pos+1]);
            return false;
        }
        pos += 2;
        fingerprint_local[i] = low | (high << 4);
    }

    // Calculate certificate's SHA256 fingerprint
    uint8_t fingerprint_remote[32];
    if(!get_peer_fingerprint(ssl_client, fingerprint_remote)) 
        return false;

    // Check if fingerprints match
    if (memcmp(fingerprint_local, fingerprint_remote, 32))
    {
        log_d("fingerprint doesn't match");
        return false;
    }

    // Additionally check if certificate has domain name if provided
    if (domain_name)
        return verify_ssl_dn(ssl_client, domain_name);
    else
        return true;
}

bool get_peer_fingerprint(sslclient_context *ssl_client, uint8_t sha256[32]) 
{
    if (!ssl_client) {
        log_d("Invalid ssl_client pointer");
        return false;
    };

    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);
    if (!crt) {
        log_d("Failed to get peer cert.");
        return false;
    };

    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, false);
    mbedtls_sha256_update(&sha256_ctx, crt->raw.p, crt->raw.len);
    mbedtls_sha256_finish(&sha256_ctx, sha256);

    return true;
}

// Checks if peer certificate has specified domain in CN or SANs
bool verify_ssl_dn(sslclient_context *ssl_client, const char* domain_name)
{
    log_d("domain name: '%s'", (domain_name)?domain_name:"(null)");
    std::string domain_name_str(domain_name);
    std::transform(domain_name_str.begin(), domain_name_str.end(), domain_name_str.begin(), ::tolower);

    // Get certificate provided by the peer
    const mbedtls_x509_crt* crt = mbedtls_ssl_get_peer_cert(&ssl_client->ssl_ctx);

    // Check for domain name in SANs
    const mbedtls_x509_sequence* san = &crt->subject_alt_names;
    while (san != nullptr)
    {
        std::string san_str((const char*)san->buf.p, san->buf.len);
        std::transform(san_str.begin(), san_str.end(), san_str.begin(), ::tolower);

        if (matchName(san_str, domain_name_str))
            return true;

        log_d("SAN '%s': no match", san_str.c_str());

        // Fetch next SAN
        san = san->next;
    }

    // Check for domain name in CN
    const mbedtls_asn1_named_data* common_name = &crt->subject;
    while (common_name != nullptr)
    {
        // While iterating through DN objects, check for CN object
        if (!MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &common_name->oid))
        {
            std::string common_name_str((const char*)common_name->val.p, common_name->val.len);

            if (matchName(common_name_str, domain_name_str))
                return true;

            log_d("CN '%s': not match", common_name_str.c_str());
        }

        // Fetch next DN object
        common_name = common_name->next;
    }

    return false;
}
#endif

