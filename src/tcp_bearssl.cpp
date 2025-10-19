/*
  BearSSL glue layer for ESPAsyncTCP

  This file provides the bridge between the lwIP raw TCP API and the BearSSL
  TLS engine, allowing for non-blocking, asynchronous TLS communication.

  FULLY PATCHED & COMPATIBLE VERSION:
  - Uses the correct BearSSL API (`br_ssl_engine_set_buffers_bidi` with
    separate buffers) for full compatibility with ESP8266 Arduino Core versions.
  - Adds PROGMEM awareness to automatically handle certificates from flash,
    fixing LoadStoreError crashes.
  - Replaces large, fixed-size I/O buffers with smaller, configurable split
    buffers to drastically reduce RAM usage per client and increase scalability.
  - Resolves incompatibility with older BearSSL PEM decoder APIs.
  - Includes robust NULL checks to prevent crashes from invalid arguments.
*/

#include "tcp_bearssl.h"

#include <bearssl/bearssl_pem.h>
#include <pgmspace.h>  // For PROGMEM functions (PROGMEM patch)

#include <memory>  // For std::unique_ptr (PROGMEM patch)
#include <vector>

// FIX: Required include for PrivateKey
#include <WiFiClientSecureBearSSL.h>
using BearSSL::PrivateKey;

// Dummy SSL struct for API compatibility with ESPAsyncTCP
struct SSL {};

// Per-connection state for a BearSSL session
struct tcp_ssl_pcb {
  struct tcp_pcb* tcp;
  br_ssl_client_context sc_client;
  br_ssl_server_context sc_server;
  br_x509_minimal_context xc;
  // --- MEMORY OPTIMIZATION ---
  // Use two smaller, configurable split buffers.
  unsigned char inbuf[ASYNC_TCP_SSL_BUFFER_SIZE];
  unsigned char outbuf[ASYNC_TCP_SSL_BUFFER_SIZE];
  // -------------------------
  bool is_server;
  bool handshake_done;

  // Callbacks and arguments
  void* arg;
  tcp_ssl_data_cb_t on_data;
  tcp_ssl_handshake_cb_t on_handshake;
  tcp_ssl_error_cb_t on_error;

  SSL dummy_ssl;  // API compatibility
  struct tcp_ssl_pcb* next;
};

// Linked list of all active BearSSL connections
static tcp_ssl_pcb* tcp_ssl_pcbs = nullptr;

// Forward declaration
static void process_ssl_engine(tcp_ssl_pcb* ssl_pcb);

// Helper to find a connection's state from its lwIP pcb
static tcp_ssl_pcb* find_ssl_pcb(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  while (iter) {
    if (iter->tcp == pcb) {
      return iter;
    }
    iter = iter->next;
  }
  return nullptr;
}

// FIX: Implement the destructor declared in the header
BearSSL_SSL_CTX::~BearSSL_SSL_CTX() {
  for (auto& cert : chain_vector) {
    free(cert.data);
  }
  delete pk;
}

// --- Internal Helper Functions for Parsing ---

struct CertParseCtx {
  std::vector<br_x509_certificate>* certs;
  unsigned char* buf;
  size_t len;
  bool error;
};

static void append_to_cert_vector(void* ctx, const void* data, size_t len) {
  CertParseCtx* pctx = (CertParseCtx*)ctx;
  if (pctx->error) return;

  unsigned char* new_buf = (unsigned char*)realloc(pctx->buf, pctx->len + len);
  if (!new_buf) {
    pctx->error = true;
    free(pctx->buf);
    pctx->buf = nullptr;
    return;
  }
  pctx->buf = new_buf;
  memcpy(pctx->buf + pctx->len, data, len);
  pctx->len += len;
}

static size_t parse_certificates(const char* pem,
                                 std::vector<br_x509_certificate>& certs) {
  if (!pem) return 0;

  const unsigned char* data = (const unsigned char*)pem;
  size_t len = strlen(pem);

  br_pem_decoder_context pc;
  br_pem_decoder_init(&pc);

  CertParseCtx pctx;
  pctx.certs = &certs;
  pctx.buf = nullptr;
  pctx.len = 0;
  pctx.error = false;

  br_pem_decoder_setdest(&pc, append_to_cert_vector, &pctx);

  size_t pushed = 0;
  while (pushed < len) {
    size_t chunk_len = len - pushed;
    pushed += br_pem_decoder_push(&pc, data + pushed, chunk_len);

    if (pctx.error) {
      for (auto& cert : certs) free(cert.data);
      certs.clear();
      return 0;
    }

    int event = br_pem_decoder_event(&pc);
    if (event == BR_PEM_BEGIN_OBJ) {
      free(pctx.buf);
      pctx.buf = nullptr;
      pctx.len = 0;
    } else if (event == BR_PEM_END_OBJ) {
      if (pctx.buf && pctx.len > 0 &&
          strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0) {
        certs.push_back({pctx.buf, pctx.len});
      } else {
        free(pctx.buf);
      }
      pctx.buf = nullptr;
      pctx.len = 0;
    } else if (event < 0) {
      free(pctx.buf);
      for (auto& cert : certs) free(cert.data);
      certs.clear();
      return 0;
    }
  }

  return certs.size();
}

// --- Public API Implementation ---

SSL_CTX* tcp_ssl_new_server_ctx(const char* cert_pem,
                                const char* private_key_pem,
                                const char* password) {
  (void)password;
  if (!cert_pem || !private_key_pem) {
    return nullptr;
  }

  // --- START: PROGMEM AWARENESS PATCH ---
  std::unique_ptr<char[]> cert_ram_buf;
  std::unique_ptr<char[]> key_ram_buf;

  // FIX: Make this platform-specific check safer by guarding it.
  // This is a pragmatic hack for ESP8266's memory map.
#if defined(ESP8266)
  if ((uint32_t)cert_pem >= 0x40200000) {
    size_t len = strlen_P(cert_pem) + 1;
    cert_ram_buf.reset(new (std::nothrow) char[len]);
    if (!cert_ram_buf) return nullptr;
    memcpy_P(cert_ram_buf.get(), cert_pem, len);
    cert_pem = cert_ram_buf.get();
  }

  if ((uint32_t)private_key_pem >= 0x40200000) {
    size_t len = strlen_P(private_key_pem) + 1;
    key_ram_buf.reset(new (std::nothrow) char[len]);
    if (!key_ram_buf) return nullptr;
    memcpy_P(key_ram_buf.get(), private_key_pem, len);
    private_key_pem = key_ram_buf.get();
  }
#endif
  // --- END: PROGMEM AWARENESS PATCH ---

  BearSSL_SSL_CTX* ctx = new (std::nothrow) BearSSL_SSL_CTX();
  if (!ctx) {
    return nullptr;
  }

  if (parse_certificates(cert_pem, ctx->chain_vector) == 0) {
    delete ctx;
    return nullptr;
  }

  ctx->pk = new (std::nothrow) PrivateKey(private_key_pem);
  if (!ctx->pk) {
    delete ctx;
    return nullptr;
  }

  if (!ctx->pk->getRSA() && !ctx->pk->getEC()) {
    delete ctx;
    return nullptr;
  }

  return (SSL_CTX*)ctx;
}

int tcp_ssl_new_client(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* ssl_pcb = new (std::nothrow) tcp_ssl_pcb();
  if (!ssl_pcb) return -1;

  ssl_pcb->tcp = pcb;
  ssl_pcb->is_server = false;
  ssl_pcb->handshake_done = false;
  ssl_pcb->arg = nullptr;
  ssl_pcb->on_data = nullptr;
  ssl_pcb->on_handshake = nullptr;
  ssl_pcb->on_error = nullptr;

  br_ssl_client_init_full(&ssl_pcb->sc_client, &ssl_pcb->xc, NULL, 0);

  // --- COMPATIBILITY FIX ---
  // Use the correct function name with the correct (5) arguments.
  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_client.eng, ssl_pcb->inbuf,
                                 sizeof(ssl_pcb->inbuf), ssl_pcb->outbuf,
                                 sizeof(ssl_pcb->outbuf));
  // -------------------------

  ssl_pcb->next = tcp_ssl_pcbs;
  tcp_ssl_pcbs = ssl_pcb;
  process_ssl_engine(ssl_pcb);
  return 0;
}

int tcp_ssl_new_server(struct tcp_pcb* pcb, SSL_CTX* ssl_ctx) {
  if (!pcb || !ssl_ctx) {
    return -1;
  }

  tcp_ssl_pcb* ssl_pcb = new (std::nothrow) tcp_ssl_pcb();
  if (!ssl_pcb) return -1;

  ssl_pcb->tcp = pcb;
  ssl_pcb->is_server = true;
  ssl_pcb->handshake_done = false;
  ssl_pcb->arg = nullptr;
  ssl_pcb->on_data = nullptr;
  ssl_pcb->on_handshake = nullptr;
  ssl_pcb->on_error = nullptr;

  BearSSL_SSL_CTX* ctx = (BearSSL_SSL_CTX*)ssl_ctx;

  if (ctx->pk && ctx->pk->getRSA()) {
    br_ssl_server_init_full_rsa(&ssl_pcb->sc_server, ctx->chain_vector.data(),
                                ctx->chain_vector.size(), ctx->pk->getRSA());
  } else if (ctx->pk && ctx->pk->getEC()) {
    br_ssl_server_init_full_ec(
        &ssl_pcb->sc_server, ctx->chain_vector.data(), ctx->chain_vector.size(),
        BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN, ctx->pk->getEC());
  } else {
    delete ssl_pcb;
    return -1;
  }

  // --- COMPATIBILITY FIX ---
  // Use the correct function name with the correct (5) arguments.
  br_ssl_engine_set_buffers_bidi(&ssl_pcb->sc_server.eng, ssl_pcb->inbuf,
                                 sizeof(ssl_pcb->inbuf), ssl_pcb->outbuf,
                                 sizeof(ssl_pcb->outbuf));
  // -------------------------

  ssl_pcb->next = tcp_ssl_pcbs;
  tcp_ssl_pcbs = ssl_pcb;
  return 0;
}

int tcp_ssl_free(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* iter = tcp_ssl_pcbs;
  tcp_ssl_pcb* prev = nullptr;
  while (iter) {
    if (iter->tcp == pcb) {
      if (prev) {
        prev->next = iter->next;
      } else {
        tcp_ssl_pcbs = iter->next;
      }
      delete iter;
      return 0;
    }
    prev = iter;
    iter = iter->next;
  }
  return -1;
}

// --- Internal Engine Logic ---

static void process_ssl_engine(tcp_ssl_pcb* ssl_pcb) {
  if (!ssl_pcb) return;

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server) {
    eng = &ssl_pcb->sc_server.eng;
  } else {
    eng = &ssl_pcb->sc_client.eng;
  }

  for (;;) {
    uint32_t state = br_ssl_engine_current_state(eng);

    if (state & BR_SSL_CLOSED) {
      if (ssl_pcb->on_error) {
        ssl_pcb->on_error(ssl_pcb->arg, ssl_pcb->tcp,
                          br_ssl_engine_last_error(eng));
      }
      return;
    }

    if (state & BR_SSL_RECVAPP) {
      size_t len = 0;
      unsigned char* buf = br_ssl_engine_recvapp_buf(eng, &len);
      if (len > 0) {
        if (ssl_pcb->on_data) {
          ssl_pcb->on_data(ssl_pcb->arg, ssl_pcb->tcp, buf, len);
        }
        br_ssl_engine_recvapp_ack(eng, len);
        continue;
      }
    }

    size_t len;
    unsigned char* buf = br_ssl_engine_sendrec_buf(eng, &len);
    if (len > 0) {
      if (tcp_sndbuf(ssl_pcb->tcp) >= len) {
        tcp_write(ssl_pcb->tcp, buf, len, TCP_WRITE_FLAG_COPY);
        br_ssl_engine_sendrec_ack(eng, len);
        tcp_output(ssl_pcb->tcp);
        continue;
      }
    }

    break;
  }

  uint32_t state = br_ssl_engine_current_state(eng);
  if (!ssl_pcb->handshake_done && (state & BR_SSL_RECVAPP)) {
    ssl_pcb->handshake_done = true;
    if (ssl_pcb->on_handshake) {
      ssl_pcb->on_handshake(ssl_pcb->arg, ssl_pcb->tcp, &ssl_pcb->dummy_ssl);
    }
  }
}

// --- Public Read/Write API ---

int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) return -1;

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server)
    eng = &ssl_pcb->sc_server.eng;
  else
    eng = &ssl_pcb->sc_client.eng;

  if (!(br_ssl_engine_current_state(eng) & BR_SSL_SENDAPP)) return 0;

  size_t wlen;
  unsigned char* buf = br_ssl_engine_sendapp_buf(eng, &wlen);
  if (wlen == 0) {
    process_ssl_engine(ssl_pcb);
    return 0;
  }

  size_t clen = (len > wlen) ? wlen : len;
  memcpy(buf, data, clen);
  br_ssl_engine_sendapp_ack(eng, clen);
  br_ssl_engine_flush(eng, 0);
  process_ssl_engine(ssl_pcb);
  return clen;
}

int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* p) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (!ssl_pcb) {
    pbuf_free(p);
    return -1;
  }

  br_ssl_engine_context* eng;
  if (ssl_pcb->is_server)
    eng = &ssl_pcb->sc_server.eng;
  else
    eng = &ssl_pcb->sc_client.eng;

  size_t pbuf_offset = 0;
  while (true) {
    size_t len;
    unsigned char* buf = br_ssl_engine_recvrec_buf(eng, &len);
    if (len > 0) {
      size_t can_copy = pbuf_copy_partial(p, buf, len, pbuf_offset);
      if (can_copy == 0) break;
      br_ssl_engine_recvrec_ack(eng, can_copy);
      pbuf_offset += can_copy;
    } else {
      break;
    }
  }

  tcp_recved(pcb, p->tot_len);
  pbuf_free(p);

  process_ssl_engine(ssl_pcb);

  if (br_ssl_engine_current_state(eng) & BR_SSL_CLOSED) return -1;
  return 0;
}

// --- Callback and state management functions ---

SSL* tcp_ssl_get_ssl(struct tcp_pcb* pcb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  return ssl_pcb ? &ssl_pcb->dummy_ssl : nullptr;
}

bool tcp_ssl_has(struct tcp_pcb* pcb) { return find_ssl_pcb(pcb) != nullptr; }

void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->arg = arg;
}

void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_data = cb;
}

void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_handshake = cb;
}

void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb) {
  tcp_ssl_pcb* ssl_pcb = find_ssl_pcb(pcb);
  if (ssl_pcb) ssl_pcb->on_error = cb;
}