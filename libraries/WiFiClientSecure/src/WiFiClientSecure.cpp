/*
  WiFiClientSecure.cpp - Client Secure class for ESP32
  Copyright (c) 2016 Hristo Gochkov  All right reserved.
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

#include "WiFiClientSecure.h"
#include "esp_crt_bundle.h"
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <errno.h>

#include <WiFiSocketWrapper.h>

#include <mbedtls/net_sockets.h>

#include <esp_debug_helpers.h>

#undef connect
#undef write
#undef read

class TlsSessionWrapper final {
public:
    sslclient_context ctx = {0};
    TlsSessionWrapper();
    ~TlsSessionWrapper();
};

TlsSessionWrapper::TlsSessionWrapper() {
    ssl_init(&ctx);
}

TlsSessionWrapper::~TlsSessionWrapper() {
    stop_ssl(&ctx);
    log_v("");
}


void WiFiClientSecure::setSocket(int socket)
{
    // TODO: use shared_ptr for sslclient_context
    // TODO: put cleanup logic in sslclient_context wrapper

    // TODO: unref sslicnet context shared ptr
    
    clientSocketHandle = std::make_shared<WiFiSocketWrapper>(socket);
}

WiFiClientSecure::WiFiClientSecure()
  : WiFiClient{}
{
}


WiFiClientSecure::WiFiClientSecure(int sock)
  : WiFiClient{sock}
{
    // TODO: discuss - this was setting _connected to true, but withotu context, which was a nonsense
    //  I propose to just "throw error here"

    // TLS context is not set-up, so we are not "connected" actually :/
    _connected = false;
}

WiFiClientSecure::WiFiClientSecure(const std::shared_ptr<EspTlsServerSessionWrapper>& server_session)
  : WiFiClient{}
{
    _server_session = server_session;
    if (_server_session) {
        // we initalized WiFiClient with clientSocketHandle == nullptr, and _connected == false
        clientSocketHandle = std::make_shared<WiFiSocketWrapper>(_server_session->get_socket());
        mbedtls_net_set_nonblock(static_cast<mbedtls_net_context*>((void*)&clientSocketHandle->sockfd));
        _connected = true;
    }
}

WiFiClientSecure::~WiFiClientSecure()
{
    stop();
    log_v("");
}

WiFiClientSecure &WiFiClientSecure::operator=(const WiFiClientSecure &other)
{
    log_d("");
    esp_backtrace_print(50);
    // comment about original code:
    // TODO: this copy assignemnt operator seems super weird! :
    // - our sslclient is STOPPED (deallocating all TLS context resources)
    // - just socket is copied to our sslclient
    // - !?! coping connected status?!
    //   - we can not continue communication on this (left-hand) side of the copy, since we do not have the active TLS context!


    stop();
    WiFiClient::operator=(other);
    _client_session = other._client_session;
    _server_session = other._server_session;

    // TODO: should we also copy configuration? this is extra dangerous because of the _streamLoad function (see bellow)

    return *this;
}

void WiFiClientSecure::stop() {
    _client_session.reset();
    _server_session.reset();
    _peek = -1;
    WiFiClient::stop();
}

int WiFiClientSecure::connect(IPAddress ip, uint16_t port)
{
    if (_cfg.pskIdent && _cfg.psKey)
        return WiFiClientSecure::connect(ip, port, _cfg.pskIdent, _cfg.psKey);
    return WiFiClientSecure::connect(ip, port, _cfg.ca_cert, _cfg.cli_cert, _cfg.cli_cert);
}

int WiFiClientSecure::connect(IPAddress ip, uint16_t port, int32_t timeout) {
    _timeout = timeout;
    return WiFiClientSecure::connect(ip, port);
}

int WiFiClientSecure::connect(const char *host, uint16_t port) {
    if (_cfg.pskIdent && _cfg.psKey)
        return WiFiClientSecure::connect(host, port, _cfg.pskIdent, _cfg.psKey);
    return WiFiClientSecure::connect(host, port, _cfg.ca_cert, _cfg.cli_cert, _cfg.cli_cert);
}

int WiFiClientSecure::connect(const char *host, uint16_t port, int32_t timeout) {
    _timeout = timeout;
    return WiFiClientSecure::connect(host, port);
}

int WiFiClientSecure::connect(IPAddress ip, uint16_t port, const char *CA_cert, const char *cert, const char *private_key) {
    return WiFiClientSecure::connect(ip.toString().c_str(), port, CA_cert, cert, private_key);
}

int WiFiClientSecure::connect(const char *host, uint16_t port, const char *CA_cert, const char *cert, const char *private_key) {
    // TODO: dicuss - should we instead create a new cfg object and let the "default" values be alone?
    setCACert(CA_cert);
    setCertificate(cert);
    setPrivateKey(private_key);

    log_v("start_ssl with certs");
    
    return _connect(host, port, std::ref(_cfg));
}

int WiFiClientSecure::connect(IPAddress ip, uint16_t port, const char *pskIdent, const char *psKey) {
    return WiFiClientSecure::connect(ip.toString().c_str(), port, pskIdent, psKey);
}

int WiFiClientSecure::connect(const char *host, uint16_t port, const char *pskIdent, const char *psKey) {
    // TODO: dicuss - should we instead create a new cfg object and let the "default" values be alone?
    setPreSharedKey(pskIdent, psKey);

    log_v("start_ssl with PSK");

    return _connect(host, port, std::ref(_cfg));
}


int WiFiClientSecure::_connect(const char *host, uint16_t port, const sslclient_config& cfg) {
    if (WiFiClient::connect(host, port, _timeout) == 0){
        return 0;
    }

    int ret = start_ssl(&_client_session->ctx, clientSocketHandle->fd(), host, _handshake_timeout, cfg);
    _lastError = ret;
    if (ret < 0) {
        log_e("start_ssl: %d", ret);
        stop();
        return 0;
    }
    _connected = true;
    return 1;
}

int WiFiClientSecure::peek(){
    if(_peek >= 0){
        return _peek;
    }
    _peek = timedRead();
    return _peek;
}

size_t WiFiClientSecure::write(uint8_t data)
{
    return write(&data, 1);
}

int WiFiClientSecure::read()
{
    uint8_t data = -1;
    int res = read(&data, 1);
    if (res < 0) {
        return res;
    }
    return data;
}

size_t WiFiClientSecure::write(const uint8_t *buf, size_t size)
{
    log_v("");
    if (!_connected) {
        return 0;
    }
    int res;
    if (_client_session)
        res = send_ssl_data(&_client_session->ctx, buf, size);
    else
        res = send_ssl_data(_server_session->get_ssl_context(), buf, size);
    log_v("");
    if (res < 0) {
        log_v("");
        stop();
        res = 0;
    }
    return res;
}

int WiFiClientSecure::read(uint8_t *buf, size_t size)
{
    int peeked = 0;
    int avail = available();
    if ((!buf && size) || avail <= 0) {
        return -1;
    }
    if(!size){
        return 0;
    }
    if(_peek >= 0){
        buf[0] = _peek;
        _peek = -1;
        size--;
        avail--;
        if(!size || !avail){
            return 1;
        }
        buf++;
        peeked = 1;
    }
    
    int res;
    if (_client_session)
        res = get_ssl_receive(&_client_session->ctx, buf, size);
    else
        res = get_ssl_receive(_server_session->get_ssl_context(), buf, size);
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res + peeked;
}

int WiFiClientSecure::available()
{
    log_v("");
    int peeked = (_peek >= 0);
    if (!_connected) {
        return peeked;
    }
    int res;
    if (_client_session)
        res = data_to_read(&_client_session->ctx);
    else
        res = data_to_read(_server_session->get_ssl_context());
    if (res < 0) {
        stop();
        return peeked?peeked:res;
    }
    return res+peeked;
}

uint8_t WiFiClientSecure::connected()
{
    // TODO: discuss why do we attempt a read, do NOT do anything with the result, and then return the boolean flag?? 
    //  do we assume that failed read will set _connected = false?
    //  ... I guess yes ;)
    log_v("");
    uint8_t dummy = 0;
    read(&dummy, 0);

    return _connected;
}

void WiFiClientSecure::setInsecure()
{
    _cfg.insecure = true;

    _cfg.ca_cert = nullptr;
    _cfg.cli_cert = nullptr;
    _cfg.cli_key = nullptr;
    _cfg.pskIdent = nullptr;
    _cfg.psKey = nullptr;
}

void WiFiClientSecure::setCACert (const char *rootCA)
{
    _cfg.ca_cert = rootCA;
}

 void WiFiClientSecure::setCACertBundle(const uint8_t * bundle)
 {
    if (bundle != NULL)
    {
        esp_crt_bundle_set(bundle);
        _cfg.useRootCABundle = true;

        _cfg.insecure = false;
        _cfg.pskIdent = nullptr;
        _cfg.psKey = nullptr;
    } else {
        esp_crt_bundle_detach(NULL);
        _cfg.useRootCABundle = false;
    }
 }

void WiFiClientSecure::setCertificate (const char *client_ca)
{
    _cfg.ca_cert = client_ca;

    _cfg.insecure = false;
    _cfg.pskIdent = nullptr;
    _cfg.psKey = nullptr;
}

void WiFiClientSecure::setPrivateKey (const char *private_key)
{
    _cfg.cli_key = private_key;

    _cfg.insecure = false;
    _cfg.pskIdent = nullptr;
    _cfg.psKey = nullptr;
}

void WiFiClientSecure::setPreSharedKey(const char *pskIdent, const char *psKey) {
    _cfg.pskIdent = pskIdent;
    _cfg.psKey = psKey;

    _cfg.insecure = false;
    _cfg.ca_cert = nullptr;
    _cfg.cli_cert = nullptr;
    _cfg.cli_key = nullptr;
}

bool WiFiClientSecure::verify(const char* fp, const char* domain_name)
{
    if (!_connected)
        return false;

    return verify_ssl_fingerprint(&_client_session->ctx, fp, domain_name);
}

// TODO: discuss - this is BAD! this means we are mixing not-owned char* ptrs passed by e.g. setCertificate or connect,
//  and self-allocated char* ptr from stream!
char *WiFiClientSecure::_streamLoad(Stream& stream, size_t size) {
  char *dest = (char*)malloc(size+1);
  if (!dest) {
    return nullptr;
  }
  if (size != stream.readBytes(dest, size)) {
    free(dest);
    dest = nullptr;
    return nullptr;
  }
  dest[size] = '\0';
  return dest;
}

// TODO: discuss - this is BAD! see above
bool WiFiClientSecure::loadCACert(Stream& stream, size_t size) {
  if (_cfg.ca_cert != NULL) free(const_cast<char*>(_cfg.ca_cert));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCACert(dest);
    ret = true;
  }
  return ret;
}

// TODO: discuss - this is BAD! see above
bool WiFiClientSecure::loadCertificate(Stream& stream, size_t size) {
  if (_cfg.cli_cert != NULL) free(const_cast<char*>(_cfg.cli_cert));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setCertificate(dest);
    ret = true;
  }
  return ret;
}

// TODO: discuss - this is BAD! see above
bool WiFiClientSecure::loadPrivateKey(Stream& stream, size_t size) {
  if (_cfg.cli_key != NULL) free(const_cast<char*>(_cfg.cli_key));
  char *dest = _streamLoad(stream, size);
  bool ret = false;
  if (dest) {
    setPrivateKey(dest);
    ret = true;
  }
  return ret;
}

int WiFiClientSecure::lastError(char *buf, const size_t size)
{
    if (!_lastError) {
        return 0;
    }
    mbedtls_strerror(_lastError, buf, size);
    return _lastError;
}

void WiFiClientSecure::setHandshakeTimeout(unsigned long handshake_timeout)
{
    _handshake_timeout = handshake_timeout * 1000;
}

void WiFiClientSecure::setAlpnProtocols(const char **alpn_protos)
{
    _cfg.alpn_protos = alpn_protos;
}
int WiFiClientSecure::setTimeout(uint32_t seconds)
{
    _timeout = seconds * 1000;
    if (fd() != -1) {
        struct timeval tv;
        tv.tv_sec = seconds;
        tv.tv_usec = 0;
        if(setSocketOption(SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval)) < 0) {
            return -1;
        }
        return setSocketOption(SO_SNDTIMEO, (char *)&tv, sizeof(struct timeval));
    }
    else {
        return 0;
    }
}

const mbedtls_x509_crt* WiFiClientSecure::getPeerCertificate() {
    return mbedtls_ssl_get_peer_cert(&_client_session->ctx.ssl_ctx); 
};

bool WiFiClientSecure::getFingerprintSHA256(uint8_t sha256_result[32]) {
    return get_peer_fingerprint(&_client_session->ctx, sha256_result);
};
