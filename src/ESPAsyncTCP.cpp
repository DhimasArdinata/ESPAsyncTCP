/*
  Asynchronous TCP library for Espressif MCUs

  Copyright (c) 2016 Hristo Gochkov. All rights reserved.
  This file is part of the esp8266 core for Arduino environment.

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
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1313  USA
*/

#include "ESPAsyncTCP.h"

// Add missing lwIP and config headers
#include "async_config.h"
extern "C" {
#include "lwip/dns.h"
#include "lwip/inet.h"
#include "lwip/init.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
}

#if ASYNC_TCP_SSL_ENABLED
#if ASYNC_TCP_USE_BEARSSL
#include "tcp_bearssl.h"
#else
// axTLS is not supported on this core version
#endif
#endif

// ACErrorTracker implementation
ACErrorTracker::ACErrorTracker(AsyncClient* c)
    : _client(c), _close_error(ERR_OK), _errored(EE_OK) {}

void ACErrorTracker::setCloseError(err_t e) {
  if (_errored == EE_OK) _close_error = e;
}

void ACErrorTracker::setErrored(size_t errorEvent) {
  if (_errored == EE_OK) _errored = static_cast<int>(errorEvent);
}

err_t ACErrorTracker::getCallbackCloseError() {
  if (_errored != EE_OK) return ERR_OK;
  if (_close_error == ERR_ABRT) setErrored(EE_ABORTED);
  return _close_error;
}

#ifdef DEBUG_MORE
void ACErrorTracker::onErrorEvent(AsNotifyHandler cb, void* arg) {
  _error_event_cb = cb;
  _error_event_cb_arg = arg;
}
#endif

// AsyncClient implementation
#if ASYNC_TCP_SSL_ENABLED
AsyncClient::AsyncClient(tcp_pcb* pcb, SSL_CTX* ssl_ctx)
#else
AsyncClient::AsyncClient(tcp_pcb* pcb)
#endif
    : _pcb(pcb),
      _connect_cb(nullptr),
      _connect_cb_arg(nullptr),
      _discard_cb(nullptr),
      _discard_cb_arg(nullptr),
      _sent_cb(nullptr),
      _sent_cb_arg(nullptr),
      _error_cb(nullptr),
      _error_cb_arg(nullptr),
      _recv_cb(nullptr),
      _recv_cb_arg(nullptr),
      _pb_cb(nullptr),
      _pb_cb_arg(nullptr),
      _timeout_cb(nullptr),
      _timeout_cb_arg(nullptr),
      _poll_cb(nullptr),
      _poll_cb_arg(nullptr),
      _pcb_busy(false),
#if ASYNC_TCP_SSL_ENABLED
      _pcb_secure(false),
      _handshake_done(true),
#endif
      _pcb_sent_at(0),
      _close_pcb(false),
      _ack_pcb(true),
      _tx_unacked_len(0),
      _tx_acked_len(0),
      _rx_ack_len(0),
      _rx_last_packet(0),
      _rx_since_timeout(0),
      _ack_timeout(ASYNC_MAX_ACK_TIME),
      _connect_port(0),
      _recv_pbuf_flags(0),
      prev(nullptr),
      next(nullptr) {
  _errorTracker = std::make_shared<ACErrorTracker>(this);
#if DEBUG_ESP_ASYNC_TCP
  static size_t _connectionCount = 0;
  _errorTracker->setConnectionId(++_connectionCount);
#endif

  if (_pcb) {
    tcp_arg(_pcb, this);
    tcp_recv(_pcb, &_s_recv);
    tcp_sent(_pcb, &_s_sent);
    tcp_err(_pcb, &_s_error);
    tcp_poll(_pcb, &_s_poll, 1);
#if ASYNC_TCP_SSL_ENABLED
    if (ssl_ctx) {
      if (tcp_ssl_new_server(_pcb, ssl_ctx) < 0) {
        _close();
        return;
      }
      tcp_ssl_arg(_pcb, this);
      tcp_ssl_data(_pcb, &_s_data);
      tcp_ssl_handshake(_pcb, &_s_handshake);
      tcp_ssl_err(_pcb, &_s_ssl_error);
      _pcb_secure = true;
      _handshake_done = false;
    }
#endif
  }
}

AsyncClient::~AsyncClient() {
  if (_pcb) _close();
  if (_errorTracker) _errorTracker->clearClient();
}

void AsyncClient::_close() {
  if (_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_pcb_secure) tcp_ssl_free(_pcb);
#endif
    tcp_arg(_pcb, nullptr);
    tcp_sent(_pcb, nullptr);
    tcp_recv(_pcb, nullptr);
    tcp_err(_pcb, nullptr);
    tcp_poll(_pcb, nullptr, 0);
    if (tcp_close(_pcb) != ERR_OK) {
      tcp_abort(_pcb);
    }
    _pcb = nullptr;
    if (_discard_cb) _discard_cb(_discard_cb_arg, this);
  }
}

// --- THIS IS THE MISSING FUNCTION ---
void AsyncClient::close(bool now) {
  if (_pcb) {
    tcp_recved(_pcb, _rx_ack_len);
  }
  if (now) {
    _close();
  } else {
    _close_pcb = true;
  }
}
// ------------------------------------

void AsyncClient::abort() {
  if (_pcb) {
    tcp_abort(_pcb);
    _pcb = nullptr;
    _errorTracker->setCloseError(ERR_ABRT);
    if (_discard_cb) _discard_cb(_discard_cb_arg, this);
  }
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(IPAddress ip, uint16_t port, bool secure) {
#else
bool AsyncClient::connect(IPAddress ip, uint16_t port) {
#endif
  if (_pcb) return false;
  _pcb = tcp_new();
  if (!_pcb) return false;

#if ASYNC_TCP_SSL_ENABLED
  _pcb_secure = secure;
  _handshake_done = !secure;
#endif

  tcp_arg(_pcb, this);
  tcp_err(_pcb, &_s_error);
  return tcp_connect(_pcb, (const ip_addr_t*)&ip, port,
                     (tcp_connected_fn)&_s_connected) == ERR_OK;
}

#if ASYNC_TCP_SSL_ENABLED
bool AsyncClient::connect(const char* host, uint16_t port, bool secure) {
#else
bool AsyncClient::connect(const char* host, uint16_t port) {
#endif
  IPAddress addr;
  err_t err = dns_gethostbyname(host, (ip_addr_t*)&addr,
                                (dns_found_callback)&_s_dns_found, this);
  if (err == ERR_OK)
    return connect(addr, port
#if ASYNC_TCP_SSL_ENABLED
                   ,
                   secure
#endif
    );
  if (err == ERR_INPROGRESS) {
#if ASYNC_TCP_SSL_ENABLED
    _pcb_secure = secure;
    _handshake_done = !secure;
#endif
    _connect_port = port;
    return true;
  }
  return false;
}

void AsyncClient::_connected(std::shared_ptr<ACErrorTracker>& errorTracker,
                             void* pcb, err_t err) {
  if (!pcb || err != ERR_OK) {
    errorTracker->setErrored(EE_CONNECTED_CB);
    _pcb = (tcp_pcb*)pcb;
    if (_pcb) {
      tcp_arg(_pcb, nullptr);
      tcp_err(_pcb, nullptr);
    }
    _pcb = nullptr;
    _error(err);
    return;
  }

  _pcb = (tcp_pcb*)pcb;
  tcp_recv(_pcb, &_s_recv);
  tcp_sent(_pcb, &_s_sent);
  tcp_poll(_pcb, &_s_poll, 1);

#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    if (tcp_ssl_new_client(_pcb) < 0) {
      _close();
      return;
    }
    tcp_ssl_arg(_pcb, this);
    tcp_ssl_data(_pcb, &_s_data);
    tcp_ssl_handshake(_pcb, &_s_handshake);
    tcp_ssl_err(_pcb, &_s_ssl_error);
  } else if (_connect_cb) {
    _connect_cb(_connect_cb_arg, this);
  }
#else
  if (_connect_cb) _connect_cb(_connect_cb_arg, this);
#endif
}

void AsyncClient::_error(err_t err) {
  if (_pcb) {
#if ASYNC_TCP_SSL_ENABLED
    if (_pcb_secure) tcp_ssl_free(_pcb);
#endif
    _pcb = nullptr;
  }
  if (_error_cb) _error_cb(_error_cb_arg, this, err);
  if (_discard_cb) _discard_cb(_discard_cb_arg, this);
}

void AsyncClient::_sent(std::shared_ptr<ACErrorTracker>& errorTracker,
                        tcp_pcb* pcb, uint16_t len) {
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure && !_handshake_done) return;
#endif
  _tx_unacked_len -= len;
  _tx_acked_len += len;
  if (_tx_unacked_len == 0) {
    errorTracker->setCloseError(ERR_OK);
    if (_sent_cb)
      _sent_cb(_sent_cb_arg, this, _tx_acked_len, (millis() - _pcb_sent_at));
    _tx_acked_len = 0;
  }
}

void AsyncClient::_recv(std::shared_ptr<ACErrorTracker>& errorTracker,
                        tcp_pcb* pcb, pbuf* pb, err_t err) {
  if (!pcb || err != ERR_OK) {
    errorTracker->setErrored(EE_RECV_CB);
    if (pb) pbuf_free(pb);
    _pcb = pcb;
    if (_pcb) tcp_arg(_pcb, nullptr);
    _pcb = nullptr;
    _error(err);
    return;
  }
  if (!pb) {
    _close();
    return;
  }
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    if (tcp_ssl_read(pcb, pb) < 0) {
      _close();
    }
    // tcp_ssl_read frees the pbuf
    return;
  }
#endif
  // Fallthrough for non-SSL
  if (_pb_cb) {
    _pb_cb(_pb_cb_arg, this, pb);
  } else if (_recv_cb) {
    _recv_cb(_recv_cb_arg, this, pb->payload, pb->tot_len);
    pbuf_free(pb);
  } else {
    pbuf_free(pb);
  }
}

void AsyncClient::_poll(std::shared_ptr<ACErrorTracker>& errorTracker,
                        tcp_pcb* pcb) {
  errorTracker->setCloseError(ERR_OK);
  if (_poll_cb) _poll_cb(_poll_cb_arg, this);
}

#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_dns_found(struct ip_addr* ipaddr) {
#else
void AsyncClient::_dns_found(const ip_addr* ipaddr) {
#endif
  if (ipaddr) {
    connect(*(IPAddress*)ipaddr, _connect_port
#if ASYNC_TCP_SSL_ENABLED
            ,
            _pcb_secure
#endif
    );
  } else {
    _error(ERR_ARG);
  }
}

err_t AsyncClient::_s_connected(void* arg, void* tpcb, err_t err) {
  AsyncClient* c = (AsyncClient*)arg;
  auto et = c->getACErrorTracker();
  c->_connected(et, tpcb, err);
  return et->getCallbackCloseError();
}

void AsyncClient::_s_error(void* arg, err_t err) {
  AsyncClient* c = (AsyncClient*)arg;
  c->getACErrorTracker()->setErrored(EE_ERROR_CB);
  c->_error(err);
}

err_t AsyncClient::_s_sent(void* arg, tcp_pcb* tpcb, uint16_t len) {
  AsyncClient* c = (AsyncClient*)arg;
  auto et = c->getACErrorTracker();
  c->_sent(et, tpcb, len);
  return et->getCallbackCloseError();
}

err_t AsyncClient::_s_recv(void* arg, tcp_pcb* tpcb, pbuf* pb, err_t err) {
  AsyncClient* c = (AsyncClient*)arg;
  auto et = c->getACErrorTracker();
  c->_recv(et, tpcb, pb, err);
  return et->getCallbackCloseError();
}

err_t AsyncClient::_s_poll(void* arg, tcp_pcb* tpcb) {
  AsyncClient* c = (AsyncClient*)arg;
  auto et = c->getACErrorTracker();
  c->_poll(et, tpcb);
  return et->getCallbackCloseError();
}

#if LWIP_VERSION_MAJOR == 1
void AsyncClient::_s_dns_found(const char* name, struct ip_addr* ipaddr,
                               void* arg) {
#else
void AsyncClient::_s_dns_found(const char* name, const ip_addr* ipaddr,
                               void* arg) {
#endif
  (void)name;
  ((AsyncClient*)arg)->_dns_found(ipaddr);
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncClient::_s_data(void* arg, struct tcp_pcb* tcp, uint8_t* data,
                          size_t len) {
  AsyncClient* c = (AsyncClient*)arg;
  if (c->_recv_cb) c->_recv_cb(c->_recv_cb_arg, c, data, len);
}
void AsyncClient::_s_handshake(void* arg, struct tcp_pcb* tcp, SSL* ssl) {
  AsyncClient* c = (AsyncClient*)arg;
  c->_handshake_done = true;
  if (c->_connect_cb) c->_connect_cb(c->_connect_cb_arg, c);
}
void AsyncClient::_s_ssl_error(void* arg, struct tcp_pcb* tcp, int8_t err) {
  ((AsyncClient*)arg)->_ssl_error(err);
}
void AsyncClient::_ssl_error(int8_t err) {
  if (_error_cb) _error_cb(_error_cb_arg, this, err);
}
#endif

void AsyncClient::stop() { close(false); }

bool AsyncClient::free() { return disconnected() || disconnecting(); }

bool AsyncClient::canSend() {
  return connected() && !_pcb_busy && (space() > 0);
}

size_t AsyncClient::space() {
  if (!connected()) return 0;
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    uint16_t s = tcp_sndbuf(_pcb);
    return (s > 256) ? s - 256 : 0;
  }
#endif
  return tcp_sndbuf(_pcb);
}

size_t AsyncClient::add(const char* data, size_t size, uint8_t apiflags) {
  if (!connected() || size == 0 || data == nullptr) return 0;
  size_t space_now = space();
  if (space_now == 0) return 0;
  size_t to_send = (space_now < size) ? space_now : size;

#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) {
    int sent = tcp_ssl_write(_pcb, (const uint8_t*)data, to_send);
    if (sent > 0) {
      _tx_unacked_len += sent;
      return sent;
    }
    return 0;
  }
#endif
  err_t err = tcp_write(_pcb, data, to_send, apiflags);
  if (err == ERR_OK) {
    _tx_unacked_len += to_send;
    return to_send;
  }
  return 0;
}

bool AsyncClient::send() {
#if ASYNC_TCP_SSL_ENABLED
  if (_pcb_secure) return true;
#endif
  if (!connected()) return false;
  err_t err = tcp_output(_pcb);
  if (err == ERR_OK) {
    _pcb_busy = true;
    _pcb_sent_at = millis();
    return true;
  }
  return false;
}

size_t AsyncClient::write(const char* data, size_t size, uint8_t apiflags) {
  size_t will_send = add(data, size, apiflags);
  if (!will_send || !send()) return 0;
  return will_send;
}

size_t AsyncClient::write(const char* data) {
  return write(data, strlen(data), 0);
}

size_t AsyncClient::ack(size_t len) {
  if (_rx_ack_len == 0) return 0;
  size_t to_ack = (len > _rx_ack_len) ? _rx_ack_len : len;
  if (to_ack > 0) tcp_recved(_pcb, to_ack);
  _rx_ack_len -= to_ack;
  return to_ack;
}

uint8_t AsyncClient::state() { return _pcb ? _pcb->state : 0; }
bool AsyncClient::connecting() {
  return _pcb && (_pcb->state > 0 && _pcb->state < ESTABLISHED);
}
bool AsyncClient::connected() { return _pcb && _pcb->state == ESTABLISHED; }
bool AsyncClient::disconnecting() { return _pcb && _pcb->state > ESTABLISHED; }
bool AsyncClient::disconnected() { return !_pcb; }
bool AsyncClient::freeable() { return disconnected() || disconnecting(); }

uint16_t AsyncClient::getMss() { return _pcb ? tcp_mss(_pcb) : 0; }
uint32_t AsyncClient::getRxTimeout() { return _rx_since_timeout; }
void AsyncClient::setRxTimeout(uint32_t timeout) {
  _rx_since_timeout = timeout;
}
uint32_t AsyncClient::getAckTimeout() { return _ack_timeout; }
void AsyncClient::setAckTimeout(uint32_t timeout) { _ack_timeout = timeout; }

void AsyncClient::setNoDelay(bool nodelay) {
  if (_pcb) {
    if (nodelay) {
      tcp_nagle_disable(_pcb);
    } else {
      tcp_nagle_enable(_pcb);
    }
  }
}

bool AsyncClient::getNoDelay() {
  return _pcb ? tcp_nagle_disabled(_pcb) : false;
}

// Implement missing remotePort/localPort for API compatibility
uint16_t AsyncClient::remotePort() { return _pcb ? _pcb->remote_port : 0; }
uint16_t AsyncClient::localPort() { return _pcb ? _pcb->local_port : 0; }

// Legacy getters
uint16_t AsyncClient::getRemotePort() { return _pcb ? _pcb->remote_port : 0; }
uint16_t AsyncClient::getLocalPort() { return _pcb ? _pcb->local_port : 0; }
IPAddress AsyncClient::remoteIP() {
  return _pcb ? IPAddress(_pcb->remote_ip) : IPAddress();
}
IPAddress AsyncClient::localIP() {
  return _pcb ? IPAddress(_pcb->local_ip) : IPAddress();
}

void AsyncClient::onConnect(AcConnectHandler cb, void* arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}
void AsyncClient::onDisconnect(AcConnectHandler cb, void* arg) {
  _discard_cb = cb;
  _discard_cb_arg = arg;
}
void AsyncClient::onAck(AcAckHandler cb, void* arg) {
  _sent_cb = cb;
  _sent_cb_arg = arg;
}
void AsyncClient::onError(AcErrorHandler cb, void* arg) {
  _error_cb = cb;
  _error_cb_arg = arg;
}
void AsyncClient::onData(AcDataHandler cb, void* arg) {
  _recv_cb = cb;
  _recv_cb_arg = arg;
}
void AsyncClient::onPacket(AcPacketHandler cb, void* arg) {
  _pb_cb = cb;
  _pb_cb_arg = arg;
}
void AsyncClient::onTimeout(AcTimeoutHandler cb, void* arg) {
  _timeout_cb = cb;
  _timeout_cb_arg = arg;
}
void AsyncClient::onPoll(AcConnectHandler cb, void* arg) {
  _poll_cb = cb;
  _poll_cb_arg = arg;
}
void AsyncClient::ackPacket(struct pbuf* pb) {
  if (pb) {
    tcp_recved(_pcb, pb->len);
    pbuf_free(pb);
  }
}

const char* AsyncClient::errorToString(err_t err) { return lwip_strerr(err); }
#if ASYNC_TCP_SSL_ENABLED
SSL* AsyncClient::getSSL() {
  return _pcb && _pcb_secure ? tcp_ssl_get_ssl(_pcb) : nullptr;
}
#endif

// AsyncServer implementation
AsyncServer::AsyncServer(uint16_t port)
    : _port(port),
      _addr(IPAddress(0, 0, 0, 0)),
      _noDelay(false),
      _pcb(nullptr),
      _connect_cb(nullptr),
      _connect_cb_arg(nullptr) {
#if ASYNC_TCP_SSL_ENABLED
  _ssl_ctx = nullptr;
#endif
}
AsyncServer::AsyncServer(IPAddress addr, uint16_t port)
    : _port(port),
      _addr(addr),
      _noDelay(false),
      _pcb(nullptr),
      _connect_cb(nullptr),
      _connect_cb_arg(nullptr) {
#if ASYNC_TCP_SSL_ENABLED
  _ssl_ctx = nullptr;
#endif
}

AsyncServer::~AsyncServer() { end(); }

void AsyncServer::onClient(AcConnectHandler cb, void* arg) {
  _connect_cb = cb;
  _connect_cb_arg = arg;
}

void AsyncServer::begin() {
  if (_pcb) return;
  _pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
  if (!_pcb) return;

  if (tcp_bind(_pcb, (const ip_addr_t*)&_addr, _port) != ERR_OK) {
    tcp_close(_pcb);
    _pcb = nullptr;
    return;
  }
  _pcb = tcp_listen(_pcb);
  if (!_pcb) return;

  tcp_arg(_pcb, this);
  tcp_accept(_pcb, &_s_accept);
}

void AsyncServer::end() {
  if (_pcb) {
    tcp_close(_pcb);
    _pcb = nullptr;
  }
#if ASYNC_TCP_SSL_ENABLED && ASYNC_TCP_USE_BEARSSL
  if (_ssl_ctx) {
    delete (BearSSL_SSL_CTX*)_ssl_ctx;
    _ssl_ctx = nullptr;
  }
#endif
}

err_t AsyncServer::_accept(tcp_pcb* newpcb, err_t err) {
  if (err != ERR_OK || !newpcb) return ERR_OK;
  if (_connect_cb) {
#if ASYNC_TCP_SSL_ENABLED
    AsyncClient* c = new (std::nothrow) AsyncClient(newpcb, _ssl_ctx);
#else
    AsyncClient* c = new (std::nothrow) AsyncClient(newpcb);
#endif
    if (c) {
      _connect_cb(_connect_cb_arg, c);
    } else {
      tcp_abort(newpcb);
    }
  } else {
    tcp_abort(newpcb);
  }
  return ERR_OK;
}

err_t AsyncServer::_s_accept(void* arg, tcp_pcb* newpcb, err_t err) {
  return ((AsyncServer*)arg)->_accept(newpcb, err);
}

#if ASYNC_TCP_SSL_ENABLED
void AsyncServer::beginSecure(const char* cert, const char* key,
                              const char* password) {
  if (_ssl_ctx) return;
  _ssl_ctx = tcp_ssl_new_server_ctx(cert, key, password);
  if (_ssl_ctx) begin();
}
void AsyncServer::onSslFileRequest(AcSSlFileHandler cb, void* arg) {
  _file_cb = cb;
  _file_cb_arg = arg;
}
#endif

void AsyncServer::setNoDelay(bool nodelay) { _noDelay = nodelay; }
bool AsyncServer::getNoDelay() { return _noDelay; }
uint8_t AsyncServer::status() { return _pcb ? _pcb->state : 0; }