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
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "SyncClient.h"

#include <interrupts.h>

#include <memory>

#include "Arduino.h"
#include "ESPAsyncTCP.h"
#include "cbuf.h"

#define DEBUG_ESP_SYNC_CLIENT
#if defined(DEBUG_ESP_SYNC_CLIENT) && !defined(SYNC_CLIENT_DEBUG)
#define SYNC_CLIENT_DEBUG(format, ...) \
  DEBUG_GENERIC_F("[SYNC_CLIENT]", format, ##__VA_ARGS__)
#endif
#ifndef SYNC_CLIENT_DEBUG
#define SYNC_CLIENT_DEBUG(...) \
  do {                         \
    (void)0;                   \
  } while (false)
#endif

/*
  Without LWIP_NETIF_TX_SINGLE_PBUF, all tcp_writes default to "no copy".
  Referenced data must be preserved and free-ed from the specified tcp_sent()
  callback. Alternative, tcp_writes need to use the TCP_WRITE_FLAG_COPY
  attribute.
*/
static_assert(LWIP_NETIF_TX_SINGLE_PBUF,
              "Required, tcp_write() must always copy.");

SyncClient::SyncClient(size_t txBufLen)
    : _client(nullptr),
      _tx_buffer(nullptr),
      _tx_buffer_size(txBufLen),
      _rx_buffer(nullptr),
      _ref(nullptr),
      _owns_client(true) {
  ref();
}

SyncClient::SyncClient(AsyncClient* client, size_t txBufLen)
    : _client(client),
      _tx_buffer(new (std::nothrow) cbuf(txBufLen)),
      _tx_buffer_size(txBufLen),
      _rx_buffer(nullptr),
      _ref(nullptr),
      _owns_client(false) {
  if (ref() > 0 && _client != nullptr) _attachCallbacks();
  // FIX: Abort if allocation fails
  if (_tx_buffer == nullptr && _client) {
    _client->abort();
  }
}

SyncClient::~SyncClient() {
  if (0 == unref()) _release();
}

void SyncClient::_release() {
  if (_client != nullptr) {
    _detachCallbacks();
    _client->abort();
    _client = nullptr;
  }
  if (_tx_buffer != nullptr) {
    cbuf* b = _tx_buffer;
    _tx_buffer = nullptr;
    delete b;
  }
  while (_rx_buffer != nullptr) {
    cbuf* b = _rx_buffer;
    _rx_buffer = _rx_buffer->next;
    delete b;
  }
}

int SyncClient::ref() {
  if (_ref == nullptr) {
    _ref = new (std::nothrow) int;
    if (_ref != nullptr)
      *_ref = 0;
    else
      return -1;
  }
  return (++*_ref);
}

int SyncClient::unref() {
  int count = -1;
  if (_ref != nullptr) {
    count = --*_ref;
    if (0 == count) {
      delete _ref;
      _ref = nullptr;
    }
  }
  return count;
}

#if ASYNC_TCP_SSL_ENABLED
int SyncClient::_connect(const IPAddress& ip, uint16_t port, bool secure) {
#else
int SyncClient::_connect(const IPAddress& ip, uint16_t port) {
#endif
  if (connected()) return 0;

  if (_client != nullptr) {
    _detachCallbacks();
    if (_owns_client) {
      delete _client;
    }
    _client = nullptr;
  }

  _owns_client = true;
  _client = new (std::nothrow) AsyncClient();
  if (_client == nullptr) return 0;

  _client->onConnect(
      [](void* obj, AsyncClient* c) { ((SyncClient*)(obj))->_onConnect(c); },
      this);
  _attachCallbacks_Disconnect();
#if ASYNC_TCP_SSL_ENABLED
  if (_client->connect(ip, port, secure)) {
#else
  if (_client->connect(ip, port)) {
#endif
    uint32_t start = millis();
    while (_client != nullptr && !_client->connected() &&
           !_client->disconnecting() &&
           (millis() - start < SYNC_CLIENT_CONNECT_TIMEOUT))
      delay(1);
    return connected();
  }
  return 0;
}

#if ASYNC_TCP_SSL_ENABLED
int SyncClient::connect(const char* host, uint16_t port, bool secure) {
#else
int SyncClient::connect(const char* host, uint16_t port) {
#endif
  if (connected()) return 0;

  if (_client != nullptr) {
    _detachCallbacks();
    if (_owns_client) {
      delete _client;
    }
    _client = nullptr;
  }

  _owns_client = true;
  _client = new (std::nothrow) AsyncClient();
  if (_client == nullptr) return 0;

  _client->onConnect(
      [](void* obj, AsyncClient* c) { ((SyncClient*)(obj))->_onConnect(c); },
      this);
  _attachCallbacks_Disconnect();
#if ASYNC_TCP_SSL_ENABLED
  if (_client->connect(host, port, secure)) {
#else
  if (_client->connect(host, port)) {
#endif
    uint32_t start = millis();
    while (_client != nullptr && !_client->connected() &&
           !_client->disconnecting() &&
           (millis() - start < SYNC_CLIENT_CONNECT_TIMEOUT))
      delay(1);
    return connected();
  }
  return 0;
}

SyncClient& SyncClient::operator=(const SyncClient& other) {
  int* rhsref = other._ref;
  if (rhsref) ++*rhsref;

  if (0 == unref()) _release();
  _ref = other._ref;
  if (_ref) ref();

  if (rhsref) --*rhsref;

  _owns_client = other._owns_client;
  _tx_buffer_size = other._tx_buffer_size;
  _tx_buffer = other._tx_buffer;
  _client = other._client;
  if (_client != nullptr && _tx_buffer == nullptr)
    _tx_buffer = new (std::nothrow) cbuf(_tx_buffer_size);

  _rx_buffer = other._rx_buffer;
  if (_client) _attachCallbacks();
  return *this;
}

void SyncClient::setTimeout(uint32_t seconds) {
  if (_client != nullptr) _client->setRxTimeout(seconds);
}

uint8_t SyncClient::status() {
  if (_client == nullptr) return 0;
  return _client->state();
}

uint8_t SyncClient::connected() {
  return (_client != nullptr && _client->connected());
}

bool SyncClient::stop(unsigned int maxWaitMs) {
  (void)maxWaitMs;
  if (_client != nullptr) {
    _detachCallbacks();
    _client->close(true);
  }
  return true;
}

size_t SyncClient::_sendBuffer() {
  if (_client == nullptr || _tx_buffer == nullptr) return 0;
  size_t available = _tx_buffer->available();
  if (!connected() || !_client->canSend() || available == 0) return 0;
  size_t sendable = _client->space();
  if (sendable < available) available = sendable;

  if (available == 0) return 0;

  std::unique_ptr<char[]> out(new (std::nothrow) char[available]);
  if (out == nullptr) return 0;

  _tx_buffer->peek(out.get(), available);
  size_t sent = _client->write(out.get(), available);
  if (sent > 0) {
    _tx_buffer->remove(sent);
  }
  return sent;
}

void SyncClient::_onData(void* data, size_t len) {
  _client->ackLater();

  if (available() + len > ASYNC_TCP_MAX_RX_BUFFER) {
    SYNC_CLIENT_DEBUG("RX buffer overflow. Aborting connection.\n");
    _client->abort();
    return;
  }

  cbuf* b = new (std::nothrow) cbuf(len + 1);
  if (b != nullptr) {
    b->write((const char*)data, len);
    if (_rx_buffer == nullptr)
      _rx_buffer = b;
    else {
      cbuf* p = _rx_buffer;
      while (p->next != nullptr) p = p->next;
      p->next = b;
    }
  } else {
    _client->abort();
  }
}

void SyncClient::_onDisconnect() {
  if (_client != nullptr) {
    _client = nullptr;
  }
  if (_tx_buffer != nullptr) {
    cbuf* b = _tx_buffer;
    _tx_buffer = nullptr;
    delete b;
  }
}

void SyncClient::_onConnect(AsyncClient* c) {
  _client = c;
  if (_tx_buffer != nullptr) {
    cbuf* b = _tx_buffer;
    _tx_buffer = nullptr;
    delete b;
  }
  _tx_buffer = new (std::nothrow) cbuf(_tx_buffer_size);
  // FIX: Safely handle allocation failure.
  if (_tx_buffer == nullptr) {
    if (_client) _client->abort();
    return;
  }
  _attachCallbacks_AfterConnected();
}

void SyncClient::_detachCallbacks() {
  if (!_client) return;
  _client->onAck(nullptr, nullptr);
  _client->onData(nullptr, nullptr);
  _client->onDisconnect(nullptr, nullptr);
  _client->onPoll(nullptr, nullptr);
  _client->onTimeout(nullptr, nullptr);
}

void SyncClient::_attachCallbacks() {
  _attachCallbacks_Disconnect();
  _attachCallbacks_AfterConnected();
}

void SyncClient::_attachCallbacks_AfterConnected() {
  _client->onAck(
      [](void* obj, AsyncClient* c, size_t len, uint32_t time) {
        (void)c;
        (void)len;
        (void)time;
        ((SyncClient*)(obj))->_sendBuffer();
      },
      this);
  _client->onData(
      [](void* obj, AsyncClient* c, void* data, size_t len) {
        (void)c;
        ((SyncClient*)(obj))->_onData(data, len);
      },
      this);
  _client->onTimeout(
      [](void* obj, AsyncClient* c, uint32_t time) {
        (void)obj;
        (void)time;
        c->close();
      },
      this);
}

void SyncClient::_attachCallbacks_Disconnect() {
  _client->onDisconnect(
      [](void* obj, AsyncClient* c) {
        SyncClient* self = (SyncClient*)obj;
        self->_onDisconnect();
        if (self->_owns_client) {
          delete c;
        }
      },
      this);
}

size_t SyncClient::write(uint8_t data) { return write(&data, 1); }

size_t SyncClient::write(const uint8_t* data, size_t len) {
  if (_tx_buffer == nullptr || !connected()) {
    return 0;
  }
  size_t toWrite = 0;
  size_t toSend = len;

  uint32_t start = millis();

  while (toSend > 0) {
    toWrite = _tx_buffer->room();
    if (toWrite > toSend) toWrite = toSend;
    if (toWrite > 0) {
      _tx_buffer->write((const char*)data, toWrite);
      data += toWrite;
      toSend -= toWrite;
    }

    if (toSend == 0) break;

    uint32_t wait_start = millis();
    while (connected() && !_client->canSend() &&
           (millis() - wait_start < SYNC_CLIENT_WRITE_TIMEOUT)) {
      delay(1);
    }

    if (!connected() || millis() - start > SYNC_CLIENT_WRITE_TIMEOUT) {
      _sendBuffer();
      return (len - toSend);
    }
    _sendBuffer();
  }

  if (connected() && _client->canSend()) _sendBuffer();
  return len;
}

int SyncClient::available() {
  if (_rx_buffer == nullptr) return 0;
  size_t a = 0;
  cbuf* b = _rx_buffer;
  while (b != NULL) {
    a += b->available();
    b = b->next;
  }
  return a;
}

int SyncClient::peek() {
  if (_rx_buffer == nullptr) return -1;
  return _rx_buffer->peek();
}

int SyncClient::read(uint8_t* data, size_t len) {
  if (_rx_buffer == nullptr) return -1;
  if (data == nullptr) return -1;

  size_t readSoFar = 0;
  while (_rx_buffer != nullptr && (len - readSoFar) > 0) {
    cbuf* b = _rx_buffer;
    size_t toRead = std::min((size_t)b->available(), len - readSoFar);

    readSoFar += b->read((char*)(data + readSoFar), toRead);

    if (b->empty()) {
      _rx_buffer = _rx_buffer->next;
      if (connected()) {
        // FIX: Acknowledge the size of the original data packet, which is
        // `b->size() - 1` because the cbuf was allocated with `len + 1`.
        _client->ack(b->size() - 1);
      }
      delete b;
    }
  }
  return readSoFar;
}

int SyncClient::read() {
  uint8_t res = 0;
  if (read(&res, 1) != 1) return -1;
  return res;
}

bool SyncClient::flush(unsigned int maxWaitMs) {
  (void)maxWaitMs;
  if (_tx_buffer == nullptr || !connected()) return false;

  uint32_t start = millis();
  while (_tx_buffer->available() > 0 && connected() &&
         (maxWaitMs == 0 || (millis() - start < maxWaitMs))) {
    _sendBuffer();
    delay(1);
  }
  return (_tx_buffer->available() == 0);
}