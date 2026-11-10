# mbedTLS dynamic record buffers (from ESP-IDF v4.4.7)

`components/mbedtls/port/dynamic/` of ESP-IDF v4.4.7, the release the Arduino
core 2.0.17 libraries are built from (Apache-2.0, Espressif Systems). It is
what `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y` compiles in an ESP-IDF project. The
Arduino core ships mbedTLS prebuilt without it, so every TLS session holds
two fixed 16 KB record buffers (~33 KB) for its whole life.

**How it is hooked in:** `platformio.ini` passes `-Wl,--wrap=<function>` for
the nine `mbedtls_ssl_*` functions these files wrap, exactly as ESP-IDF's
CMake does. The prebuilt library itself is unchanged; the wrappers allocate
the input buffer per received record and the output buffer per write, and
free them afterwards.

**Measured on the device:** an idle session costs ~12 KB instead of ~50 KB.

**Changes to upstream** (marked `AuthKey patch`):

- `esp_mbedtls_dynamic_impl.c`, `esp_mbedtls_add_rx_buffer()`: on a
  non-blocking socket (what `WiFiClientSecure` uses) a 5-byte record header
  split across two TCP segments was read half into a stack buffer and lost on
  `WANT_READ`. It now waits up to 2 s for the rest, else fails the connection.
- `esp_ssl_tls.c`, `__wrap_mbedtls_ssl_write()`: after the handshake the
  output buffer is sized for the write (upstream: always 16 KB).
- `esp_ssl_cli.c`: the client's handshake messages get a 4 KB output buffer
  (upstream: 16 KB each). One 17 KB block is often not available on a
  fragmented heap even with plenty of RAM free.

Not usable for DTLS (not used here). `esp_ssl_srv.c` is the server half,
unmodified; nothing in this firmware runs a TLS server.

When upgrading the Arduino core: take these files from the matching ESP-IDF
tag and re-apply the three patches, or drop the folder and the `--wrap`
flags if the core's mbedTLS is built with dynamic buffers.
