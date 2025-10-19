#ifndef TCP_BEARSSL_H
#define TCP_BEARSSL_H

#include <bearssl/bearssl.h>
#include <bearssl/bearssl_ssl.h>
#include <bearssl/bearssl_x509.h>

#include <vector>

#include "ESPAsyncTCP.h"
#include "lwip/tcp.h"

struct SSL;
struct SSL_CTX;

#ifdef __cplusplus
// These are helpers from the ESP8266 core
#include <WiFiClientSecureBearSSL.h>
using BearSSL::PrivateKey;
// We no longer use X509List from the core for server contexts
// using BearSSL::X509List;

extern "C" {
#endif

// A wrapper to make BearSSL contexts look like an SSL_CTX
struct BearSSL_SSL_CTX {
  // We will parse the chain into a vector of C structs ourselves
  std::vector<br_x509_certificate> chain_vector;
  PrivateKey* pk = nullptr;

  ~BearSSL_SSL_CTX() {
    // Free the memory allocated for each certificate in the chain
    for (auto& cert : chain_vector) {
      free(cert.data);
    }
    delete pk;
  }
};

struct tcp_ssl_pcb;

typedef void (*tcp_ssl_data_cb_t)(void* arg, struct tcp_pcb* tcp, uint8_t* data,
                                  size_t len);
typedef void (*tcp_ssl_handshake_cb_t)(void* arg, struct tcp_pcb* tcp,
                                       SSL* ssl);
typedef void (*tcp_ssl_error_cb_t)(void* arg, struct tcp_pcb* tcp, int8_t err);

SSL_CTX* tcp_ssl_new_server_ctx(const char* cert, const char* private_key_file,
                                const char* password);
int tcp_ssl_new_client(struct tcp_pcb* pcb);
int tcp_ssl_new_server(struct tcp_pcb* pcb, SSL_CTX* ssl_ctx);
int tcp_ssl_free(struct tcp_pcb* pcb);
int tcp_ssl_write(struct tcp_pcb* pcb, const uint8_t* data, size_t len);
int tcp_ssl_read(struct tcp_pcb* pcb, struct pbuf* p);
SSL* tcp_ssl_get_ssl(struct tcp_pcb* pcb);
bool tcp_ssl_has(struct tcp_pcb* pcb);

void tcp_ssl_arg(struct tcp_pcb* pcb, void* arg);
void tcp_ssl_data(struct tcp_pcb* pcb, tcp_ssl_data_cb_t cb);
void tcp_ssl_handshake(struct tcp_pcb* pcb, tcp_ssl_handshake_cb_t cb);
void tcp_ssl_err(struct tcp_pcb* pcb, tcp_ssl_error_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif  // TCP_BEARSSL_H