# Modernized & Stabilized ESPAsyncTCP for ESP8266

This is a modernized fork of the original ESPAsyncTCP library, a fully asynchronous TCP library for the ESP8266 Arduino core. This version has been significantly re-architected to provide **dramatically improved stability and robustness** for multi-connection networking.

### Key Features & Enhancements

- **New Architecture for Maximum Stability:** This version introduces a cooperative, event-driven model. Network events are processed safely in the main `loop()`, **preventing common crashes and watchdog timeouts** caused by long-running user code in callbacks.
- **Modern TLS/SSL Security:** Upgraded from the outdated `axTLS` to the modern, secure `BearSSL` engine, leveraging the implementation included in the ESP8266 Arduino Core.
- **Drastically Reduced RAM Usage:** The new BearSSL integration uses memory-efficient, configurable I/O buffers, allowing for **significantly more concurrent secure (HTTPS/WSS) clients** on the memory-constrained ESP8266.
- **Enhanced Crash Protection:** Resolves common `LoadStoreError` crashes by safely handling TLS certificates and private keys stored in PROGMEM (flash memory).
- **Fully Asynchronous:** Non-blocking operations for handling multiple simultaneous connections without complex multi-threading or `delay()`.
- **Simple API Update:** Requires one simple addition to your sketch to enable the new stability features, with the rest of the API remaining compatible.

This library is the foundation for the powerful [ESPAsyncWebServer](https://github.com/DhimasArdinata/ESPAsyncWebServer).

---

### Installation

#### PlatformIO

It is recommended to install this library by referencing its Git repository in your `platformio.ini` file to ensure you are using the modernized version.

```ini
lib_deps =
    https://github.com/DhimasArdinata/ESPAsyncTCP.git
    ESPAsyncWebServer
```

#### Arduino IDE

1.  Click on `Code` -> `Download ZIP`.
2.  In the Arduino IDE, go to `Sketch` -> `Include Library` -> `Add .ZIP Library...` and select the downloaded file.
3.  **Important:** If you have an older version of `ESPAsyncTCP` installed, you must remove it from your Arduino `libraries` folder first.

---

### **IMPORTANT USAGE CHANGE FOR STABILITY**

To enable the new, more stable architecture, you **must call `AsyncTCP::handle()` in your main `loop()` function**. This function processes pending network events safely and efficiently.

Failing to call `AsyncTCP::handle()` will result in your network connections not working.

### Usage Example: A Secure HTTPS Web Server

This example demonstrates how to set up a secure web server using `ESPAsyncWebServer` and this library with the required `handle()` call.

**1. Generate Self-Signed Certificates**
_(This part remains the same)_
Run this `openssl` command on your computer to generate a certificate (`cert.pem`) and a private key (`private_key.pem`):

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout private_key.pem -out cert.pem -sha256 -days 3650 -subj "/CN=esp8266.local"
```

**2. Convert Keys to C++ Headers**
_(This part remains the same)_
Create two header files in your project, `cert.h` and `private_key.h`, and paste the contents of the `.pem` files into them as C-style strings.

`cert.h`:

```cpp
const char cert_pem[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
... (paste contents of cert.pem here) ...
-----END CERTIFICATE-----
)EOF";
```

`private_key.h`:

```cpp
const char key_pem[] PROGMEM = R"EOF(
-----BEGIN PRIVATE KEY-----
... (paste contents of private_key.pem here) ...
-----END PRIVATE KEY-----
)EOF";
```

**3. Your Arduino Sketch (`.ino`)**

```cpp
#include <ESP8266WiFi.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include "cert.h"
#include "private_key.h"

const char* ssid = "YOUR_WIFI_SSID";
const char* password = "YOUR_WIFI_PASSWORD";

AsyncWebServer server(443); // Create a server on the HTTPS port

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected.");
  Serial.print("IP address: https://");
  Serial.println(WiFi.localIP());

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send(200, "text/plain", "Hello from ESP8266 HTTPS Server!");
  });

  // Start the secure server
  server.beginSecure(cert_pem, key_pem);
}

void loop() {
  // ** NEW REQUIRED CALL **
  // This line processes all pending asynchronous TCP events.
  // It should be called on every loop iteration.
  AsyncTCP::handle();

  // You can add your other non-blocking code here.
}
```

---

### Library Components

- **AsyncClient and AsyncServer:** The powerful, low-level base classes for raw asynchronous TCP communication.
- **AsyncTCP:** A new static class containing the required `handle()` method for event processing.
- **AsyncPrinter:** A `Print` interface wrapper for sending data, usable outside of async callbacks (e.g., in `loop()`).
- **SyncClient:** A standard, blocking TCP Client for simpler, synchronous tasks, similar to the one in `ESP8266WiFi`.

---

### Original Project Context

This project is a fork of the original work which has since moved to the [ESP32Async](https://github.com/ESP32Async) organization.

- Original ESP8266 Repo: [https://github.com/ESP32Async/ESPAsyncTCP](https://github.com/ESP32Async/ESPAsyncTCP)
- ESP32 Version: [https://github.com/ESP32Async/AsyncTCP](https://github.com/ESP32Async/AsyncTCP)
- Discord Server: [https://discord.gg/X7zpGdyUcY](https://discord.gg/X7zpGdyUcY)
