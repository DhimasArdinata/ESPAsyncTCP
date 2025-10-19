/**
 * @file  ESPAsyncTCPbuffer.cpp
 * @date  22.01.2016
 * @author Markus Sattler
 *
 * Copyright (c) 2015 Markus Sattler. All rights reserved.
 * This file is part of the Asynv TCP for ESP.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "ESPAsyncTCPbuffer.h"

#include <Arduino.h>
#include <debug.h>

#include <memory>

AsyncTCPbuffer::AsyncTCPbuffer(AsyncClient* client) {
  if (client == NULL) {
    DEBUG_ASYNC_TCP("[A-TCP] client is null!!!\n");
    panic();
  }

  _client = client;
  _TXbufferWrite = new (std::nothrow) cbuf(TCP_MSS);
  _TXbufferLinkCount = 1;  // We start with one buffer
  _TXbufferRead = _TXbufferWrite;
  _RXbuffer = new (std::nothrow) cbuf(100);
  _RXmode = ATB_RX_MODE_FREE;
  _rxSize = 0;
  _rxTerminator = 0x00;
  _rxReadBytesPtr = NULL;
  _rxReadStringPtr = NULL;
  _cbDisconnect = NULL;

  _cbRX = NULL;
  _cbDone = NULL;
  _attachCallbacks();
}

AsyncTCPbuffer::~AsyncTCPbuffer() {
  if (_client) {
    _client->close();
  }

  if (_RXbuffer) {
    delete _RXbuffer;
    _RXbuffer = NULL;
  }

  if (_TXbufferWrite) {
    // will be deleted in _TXbufferRead chain
    _TXbufferWrite = NULL;
  }

  if (_TXbufferRead) {
    cbuf* next = _TXbufferRead->next;
    delete _TXbufferRead;
    while (next != NULL) {
      _TXbufferRead = next;
      next = _TXbufferRead->next;
      delete _TXbufferRead;
    }
    _TXbufferRead = NULL;
  }
}

size_t AsyncTCPbuffer::write(String& data) {
  return write(data.c_str(), data.length());
}

size_t AsyncTCPbuffer::write(uint8_t data) { return write(&data, 1); }

size_t AsyncTCPbuffer::write(const char* data) {
  return write((const uint8_t*)data, strlen(data));
}

size_t AsyncTCPbuffer::write(const char* data, size_t len) {
  return write((const uint8_t*)data, len);
}

/**
 * write data in to buffer and try to send the data
 * @param data
 * @param len
 * @return
 */
size_t AsyncTCPbuffer::write(const uint8_t* data, size_t len) {
  if (_TXbufferWrite == NULL || _client == NULL || !_client->connected() ||
      data == NULL || len == 0) {
    return 0;
  }

  size_t bytesLeft = len;
  while (bytesLeft) {
    size_t w = _TXbufferWrite->write((const char*)data, bytesLeft);
    bytesLeft -= w;
    data += w;
    _sendBuffer();

    // add new buffer since we have more data
    if (_TXbufferWrite->full() && bytesLeft > 0) {
      // Check against the maximum number of buffer links to prevent memory
      // exhaustion
      if (_TXbufferLinkCount >= ASYNC_TCP_BUFFER_MAX_LINKS) {
        DEBUG_ASYNC_TCP(
            "[A-TCP] TX buffer link limit reached. Cannot send all data.\n");
        return (len - bytesLeft);
      }

      // Check for low memory
      if (ESP.getFreeHeap() < 2 * TCP_MSS) {  // Increased safety margin
        DEBUG_ASYNC_TCP("[A-TCP] run out of Heap can not send all Data!\n");
        return (len - bytesLeft);
      }

      cbuf* next = new (std::nothrow) cbuf(TCP_MSS);
      if (next == NULL) {
        DEBUG_ASYNC_TCP(
            "[A-TCP] run out of Heap! Can't create new TX buffer.\n");
        return (len - bytesLeft);
      } else {
        DEBUG_ASYNC_TCP("[A-TCP] new cbuf\n");
      }

      // add new buffer to chain (current cbuf)
      _TXbufferWrite->next = next;

      // move ptr for next data
      _TXbufferWrite = next;
      _TXbufferLinkCount++;
    }
  }

  return len;
}

void AsyncTCPbuffer::flush() {
  while (!_TXbufferWrite->empty()) {
    while (connected() && !_client->canSend()) {
      delay(0);
    }
    if (!connected()) return;
    _sendBuffer();
  }
}

void AsyncTCPbuffer::noCallback() { _RXmode = ATB_RX_MODE_NONE; }

void AsyncTCPbuffer::readStringUntil(char terminator, String* str,
                                     AsyncTCPbufferDoneCb done) {
  if (_client == NULL || str == nullptr) {
    return;
  }
  DEBUG_ASYNC_TCP("[A-TCP] readStringUntil terminator: %02X\n", terminator);
  _RXmode = ATB_RX_MODE_NONE;
  _cbDone = done;
  _rxReadStringPtr = str;
  _rxTerminator = terminator;
  _rxSize = 0;
  _RXmode = ATB_RX_MODE_TERMINATOR_STRING;
}

void AsyncTCPbuffer::readBytes(char* buffer, size_t length,
                               AsyncTCPbufferDoneCb done) {
  if (_client == NULL || buffer == nullptr) {
    return;
  }
  DEBUG_ASYNC_TCP("[A-TCP] readBytes length: %d\n", length);
  _RXmode = ATB_RX_MODE_NONE;
  _cbDone = done;
  _rxReadBytesPtr = (uint8_t*)buffer;
  _rxSize = length;
  _RXmode = ATB_RX_MODE_READ_BYTES;
}

void AsyncTCPbuffer::readBytes(uint8_t* buffer, size_t length,
                               AsyncTCPbufferDoneCb done) {
  readBytes((char*)buffer, length, done);
}

void AsyncTCPbuffer::onData(AsyncTCPbufferDataCb cb) {
  if (_client == NULL) {
    return;
  }
  DEBUG_ASYNC_TCP("[A-TCP] onData\n");
  _RXmode = ATB_RX_MODE_NONE;
  _cbDone = NULL;
  _cbRX = cb;
  _RXmode = ATB_RX_MODE_FREE;
}

void AsyncTCPbuffer::onDisconnect(AsyncTCPbufferDisconnectCb cb) {
  _cbDisconnect = cb;
}

IPAddress AsyncTCPbuffer::remoteIP() {
  if (!_client) {
    return IPAddress(0U);
  }
  return _client->remoteIP();
}

uint16_t AsyncTCPbuffer::remotePort() {
  if (!_client) {
    return 0;
  }
  return _client->remotePort();
}

IPAddress AsyncTCPbuffer::localIP() {
  if (!_client) {
    return IPAddress(0U);
  }
  return _client->localIP();
}

uint16_t AsyncTCPbuffer::localPort() {
  if (!_client) {
    return 0;
  }
  return _client->localPort();
}

bool AsyncTCPbuffer::connected() {
  if (!_client) {
    return false;
  }
  return _client->connected();
}

void AsyncTCPbuffer::stop() {
  if (!_client) {
    return;
  }
  _client->stop();
  _client = NULL;

  if (_cbDone) {
    switch (_RXmode) {
      case ATB_RX_MODE_READ_BYTES:
      case ATB_RX_MODE_TERMINATOR:
      case ATB_RX_MODE_TERMINATOR_STRING:
        _RXmode = ATB_RX_MODE_NONE;
        _cbDone(false, NULL);
        break;
      default:
        break;
    }
  }
  _RXmode = ATB_RX_MODE_NONE;
}

void AsyncTCPbuffer::close() { stop(); }

///--------------------------------

void AsyncTCPbuffer::_attachCallbacks() {
  if (!_client) {
    return;
  }
  DEBUG_ASYNC_TCP("[A-TCP] attachCallbacks\n");

  _client->onPoll(
      [](void* obj, AsyncClient* c) {
        (void)c;
        AsyncTCPbuffer* b = ((AsyncTCPbuffer*)(obj));
        if ((b->_TXbufferRead != NULL) && !b->_TXbufferRead->empty()) {
          b->_sendBuffer();
        }
      },
      this);

  _client->onAck(
      [](void* obj, AsyncClient* c, size_t len, uint32_t time) {
        (void)c;
        (void)len;
        (void)time;
        ((AsyncTCPbuffer*)(obj))->_sendBuffer();
      },
      this);

  _client->onDisconnect(
      [](void* obj, AsyncClient* c) {
        DEBUG_ASYNC_TCP("[A-TCP] onDisconnect\n");
        AsyncTCPbuffer* b = ((AsyncTCPbuffer*)(obj));
        b->_client = NULL;
        bool del = true;
        if (b->_cbDisconnect) {
          del = b->_cbDisconnect(b);
        }
        delete c;
        if (del) {
          delete b;
        }
      },
      this);

  _client->onData(
      [](void* obj, AsyncClient* c, void* buf, size_t len) {
        (void)c;
        AsyncTCPbuffer* b = ((AsyncTCPbuffer*)(obj));
        b->_rxData((uint8_t*)buf, len);
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

void AsyncTCPbuffer::_sendBuffer() {
  if (_TXbufferRead == nullptr) return;

  size_t available = _TXbufferRead->available();
  if (available == 0 || _client == NULL || !_client->connected() ||
      !_client->canSend()) {
    return;
  }

  while (connected() && (_client->space() > 0) &&
         (_TXbufferRead->available() > 0) && _client->canSend()) {
    available = _TXbufferRead->available();

    if (available > _client->space()) {
      available = _client->space();
    }

    std::unique_ptr<char[]> out(new (std::nothrow) char[available]);
    if (out == nullptr) {
      DEBUG_ASYNC_TCP("[A-TCP] to less heap, try later.\n");
      return;
    }

    _TXbufferRead->peek(out.get(), available);

    size_t send = _client->write(out.get(), available);
    if (send > 0) {
      _TXbufferRead->remove(send);
    }

    if (send != available) {
      DEBUG_ASYNC_TCP("[A-TCP] write failed send: %d available: %d \n", send,
                      available);
      if (!connected()) {
        DEBUG_ASYNC_TCP("[A-TCP] incomplete transfer, connection lost.\n");
      }
    }

    if (_TXbufferRead->available() == 0 && _TXbufferRead->next != NULL) {
      cbuf* old = _TXbufferRead;
      _TXbufferRead = _TXbufferRead->next;
      delete old;
      _TXbufferLinkCount--;
      DEBUG_ASYNC_TCP("[A-TCP] delete cbuf\n");
    }
  }
}

void AsyncTCPbuffer::_rxData(uint8_t* buf, size_t len) {
  if (!_client || !_client->connected()) {
    return;
  }
  if (!_RXbuffer) {
    return;
  }

  size_t handled = 0;

  if (_RXmode != ATB_RX_MODE_NONE) {
    handled = _handleRxBuffer((uint8_t*)buf, len);
    buf += handled;
    len -= handled;

    if (_RXbuffer->empty()) {
      while (_RXmode != ATB_RX_MODE_NONE && handled != 0 && len > 0) {
        handled = _handleRxBuffer(buf, len);
        buf += handled;
        len -= handled;
      }
    }
  }

  if (len > 0) {
    if (_RXbuffer->available() + len > ASYNC_TCP_MAX_RX_BUFFER) {
      DEBUG_ASYNC_TCP("[A-TCP] RX buffer overflow. Aborting connection.\n");
      if (_client) _client->abort();
      return;
    }

    if (_RXbuffer->room() < len) {
      _RXbuffer->resizeAdd(len - _RXbuffer->room());
    }

    _RXbuffer->write((const char*)(buf), len);
  }

  if (!_RXbuffer->empty() && _RXmode != ATB_RX_MODE_NONE) {
    handled = 1;  // Prime the loop
    while (_RXmode != ATB_RX_MODE_NONE && handled != 0 && !_RXbuffer->empty()) {
      handled = _handleRxBuffer(NULL, 0);
    }
  }

  if (_RXbuffer->empty() && _RXbuffer->size() != 100) {
    _RXbuffer->resize(100);
  }
}

size_t AsyncTCPbuffer::_handleRxBuffer(uint8_t* buf, size_t len) {
  if (!_client || !_client->connected() || _RXbuffer == NULL) {
    return 0;
  }

  size_t BufferAvailable = _RXbuffer->available();
  size_t r = 0;

  if (_RXmode == ATB_RX_MODE_NONE) {
    return 0;
  } else if (_RXmode == ATB_RX_MODE_FREE) {
    if (_cbRX == NULL) {
      return 0;
    }

    if (BufferAvailable > 0) {
      std::unique_ptr<uint8_t[]> b(new (std::nothrow) uint8_t[BufferAvailable]);
      if (b == nullptr) {
        return 0;
      }
      _RXbuffer->peek((char*)b.get(), BufferAvailable);
      r = _cbRX(b.get(), BufferAvailable);
      _RXbuffer->remove(r);
    }

    if (r == BufferAvailable && buf && (len > 0)) {
      return _cbRX(buf, len);
    } else {
      return 0;
    }

  } else if (_RXmode == ATB_RX_MODE_READ_BYTES) {
    if (_rxReadBytesPtr == NULL || _cbDone == NULL) {
      return 0;
    }

    size_t newReadCount = 0;
    size_t to_read = 0;

    if (BufferAvailable) {
      to_read = (_rxSize < BufferAvailable) ? _rxSize : BufferAvailable;
      r = _RXbuffer->read((char*)_rxReadBytesPtr, to_read);
      _rxSize -= r;
      _rxReadBytesPtr += r;
    }

    if (_rxSize > 0 && (len > 0) && buf) {
      to_read = (_rxSize < len) ? _rxSize : len;
      memcpy(_rxReadBytesPtr, buf, to_read);
      _rxReadBytesPtr += to_read;
      _rxSize -= to_read;
      newReadCount += to_read;
    }

    if (_rxSize == 0) {
      _RXmode = ATB_RX_MODE_NONE;
      _cbDone(true, NULL);
    }

    return newReadCount;

  } else if (_RXmode == ATB_RX_MODE_TERMINATOR_STRING) {
    if (_rxReadStringPtr == NULL || _cbDone == NULL) {
      return 0;
    }

    if (BufferAvailable > 0) {
      while (!_RXbuffer->empty()) {
        char c = _RXbuffer->read();
        if (c == _rxTerminator || c == 0x00) {
          _RXmode = ATB_RX_MODE_NONE;
          _cbDone(true, _rxReadStringPtr);
          return 0;
        } else {
          (*_rxReadStringPtr) += c;
        }
      }
    }

    if ((len > 0) && buf) {
      size_t newReadCount = 0;
      while (newReadCount < len) {
        char c = (char)*buf;
        buf++;
        newReadCount++;
        if (c == _rxTerminator || c == 0x00) {
          _RXmode = ATB_RX_MODE_NONE;
          _cbDone(true, _rxReadStringPtr);
          return newReadCount;
        } else {
          (*_rxReadStringPtr) += c;
        }
      }
      return newReadCount;
    }
  }

  return 0;
}