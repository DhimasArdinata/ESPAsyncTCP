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

#include "AsyncPrinter.h"

#include <memory>

AsyncPrinter::AsyncPrinter()
    : _client(nullptr),
      _data_cb(nullptr),
      _data_arg(nullptr),
      _close_cb(nullptr),
      _close_arg(nullptr),
      _tx_buffer(nullptr),
      _tx_buffer_size(TCP_MSS),
      _owns_client(true),
      next(nullptr) {}

AsyncPrinter::AsyncPrinter(AsyncClient* client, size_t txBufLen)
    : _client(client),
      _data_cb(nullptr),
      _data_arg(nullptr),
      _close_cb(nullptr),
      _close_arg(nullptr),
      _tx_buffer(nullptr),
      _tx_buffer_size(txBufLen),
      _owns_client(false),
      next(nullptr) {
  if (_client) {
    _attachCallbacks();
  }
  _tx_buffer = new (std::nothrow) cbuf(_tx_buffer_size);
}

AsyncPrinter::~AsyncPrinter() {
  // FIX: Detach callbacks before closing to prevent use-after-free race
  // condition.
  _detachCallbacks();
  _on_close();
}

void AsyncPrinter::onData(ApDataHandler cb, void* arg) {
  _data_cb = cb;
  _data_arg = arg;
}

void AsyncPrinter::onClose(ApCloseHandler cb, void* arg) {
  _close_cb = cb;
  _close_arg = arg;
}

#if ASYNC_TCP_SSL_ENABLED
int AsyncPrinter::connect(IPAddress ip, uint16_t port) {
  return connect(ip, port, false);
}
int AsyncPrinter::connect(const char* host, uint16_t port) {
  return connect(host, port, false);
}
int AsyncPrinter::connect(IPAddress ip, uint16_t port, bool secure) {
#else
int AsyncPrinter::connect(IPAddress ip, uint16_t port) {
#endif
  // FIX: Safely handle existing client
  if (!_owns_client) return 0;
  if (_client != nullptr) {
    if (connected()) return 1;
    _detachCallbacks();
    delete _client;
    _client = nullptr;
  }

  _client = new (std::nothrow) AsyncClient();
  if (_client == nullptr) {
    return 0;
  }

  _client->onConnect(
      [](void* obj, AsyncClient* c) { ((AsyncPrinter*)(obj))->_onConnect(c); },
      this);

  if (_client->connect(ip, port
#if ASYNC_TCP_SSL_ENABLED
                       ,
                       secure
#endif
                       )) {
    while (_client && _client->connecting()) delay(1);
    return connected();
  }
  // Connection failed immediately, clean up.
  delete _client;
  _client = nullptr;
  return 0;
}

#if ASYNC_TCP_SSL_ENABLED
int AsyncPrinter::connect(const char* host, uint16_t port, bool secure) {
#else
int AsyncPrinter::connect(const char* host, uint16_t port) {
#endif
  if (!_owns_client) return 0;
  if (_client != nullptr) {
    if (connected()) return 1;
    _detachCallbacks();
    delete _client;
    _client = nullptr;
  }

  _client = new (std::nothrow) AsyncClient();
  if (_client == nullptr) {
    return 0;
  }

  _client->onConnect(
      [](void* obj, AsyncClient* c) { ((AsyncPrinter*)(obj))->_onConnect(c); },
      this);

  if (_client->connect(host, port
#if ASYNC_TCP_SSL_ENABLED
                       ,
                       secure
#endif
                       )) {
    while (_client && _client->connecting()) delay(1);
    return connected();
  }
  // Connection failed immediately, clean up.
  delete _client;
  _client = nullptr;
  return 0;
}

void AsyncPrinter::_onConnect(AsyncClient* c) {
  (void)c;
  if (_tx_buffer != nullptr) {
    delete _tx_buffer;
  }
  _tx_buffer = new (std::nothrow) cbuf(_tx_buffer_size);
  if (!_tx_buffer && _client) {
    _client->close(true);  // Abort if we can't allocate buffer
    return;
  }
  _attachCallbacks();
}

AsyncPrinter::operator bool() { return connected(); }

size_t AsyncPrinter::write(uint8_t data) { return write(&data, 1); }

size_t AsyncPrinter::write(const uint8_t* data, size_t len) {
  if (_tx_buffer == nullptr || !connected()) return 0;

  size_t toWrite = 0;
  size_t toSend = len;
  const uint8_t* p = data;

  while (toSend > 0) {
    _sendBuffer();
    toWrite = _tx_buffer->room();
    if (toWrite == 0) {
      // FIX: Add a small delay and check connection to avoid busy-looping on a
      // full buffer
      if (!connected()) break;
      delay(1);
      continue;
    }
    if (toWrite > toSend) toWrite = toSend;
    _tx_buffer->write((const char*)p, toWrite);
    p += toWrite;
    toSend -= toWrite;
  }
  _sendBuffer();
  return len - toSend;
}

bool AsyncPrinter::connected() {
  return (_client != nullptr && _client->connected());
}

void AsyncPrinter::close() {
  // FIX: Detach callbacks before closing to prevent race condition.
  _detachCallbacks();
  if (_client != nullptr) _client->close(true);
}

size_t AsyncPrinter::_sendBuffer() {
  if (_tx_buffer == nullptr || _client == nullptr) return 0;

  size_t available = _tx_buffer->available();
  if (!connected() || !_client->canSend() || available == 0) return 0;

  size_t sendable = _client->space();
  if (sendable < available) available = sendable;

  if (available == 0) return 0;

  std::unique_ptr<char[]> out(new (std::nothrow) char[available]);
  if (out == nullptr) {
    return 0;
  }

  // FIX: Prevent data loss with peek()->write()->remove() pattern
  _tx_buffer->peek(out.get(), available);
  size_t sent = _client->write(out.get(), available);
  if (sent > 0) {
    _tx_buffer->remove(sent);
  }
  return sent;
}

void AsyncPrinter::_onData(void* data, size_t len) {
  if (_data_cb) _data_cb(_data_arg, this, (uint8_t*)data, len);
}

void AsyncPrinter::_on_close() {
  // Only delete the client if we own it.
  if (_owns_client && _client != nullptr) {
    delete _client;
  }
  // Detach from the client pointer in any case to avoid stale usage.
  _client = nullptr;

  if (_tx_buffer != nullptr) {
    delete _tx_buffer;
    _tx_buffer = nullptr;
  }
  if (_close_cb) _close_cb(_close_arg, this);
}

void AsyncPrinter::_detachCallbacks() {
  if (!_client) return;
  _client->onPoll(nullptr, nullptr);
  _client->onAck(nullptr, nullptr);
  _client->onDisconnect(nullptr, nullptr);
  _client->onData(nullptr, nullptr);
  _client->onTimeout(nullptr, nullptr);
}

void AsyncPrinter::_attachCallbacks() {
  if (!_client) return;
  _client->onPoll(
      [](void* obj, AsyncClient* c) {
        (void)c;
        ((AsyncPrinter*)(obj))->_sendBuffer();
      },
      this);
  _client->onAck(
      [](void* obj, AsyncClient* c, size_t len, uint32_t time) {
        (void)c;
        (void)len;
        (void)time;
        ((AsyncPrinter*)(obj))->_sendBuffer();
      },
      this);
  _client->onDisconnect(
      [](void* obj, AsyncClient* c) {
        (void)c;
        ((AsyncPrinter*)(obj))->_on_close();
      },
      this);
  _client->onData(
      [](void* obj, AsyncClient* c, void* data, size_t len) {
        (void)c;
        ((AsyncPrinter*)(obj))->_onData(data, len);
      },
      this);
}