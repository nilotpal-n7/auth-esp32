# Patched WebServer (from Arduino-ESP32 2.0.17)

A copy of the core's `WebServer` library (LGPL-2.1, Ivan Grokhotkov and
contributors). PlatformIO uses it instead of the framework's copy because it
lives in the project's `lib/`. Lines changed are marked `AuthKey patch`.

**Why:** when `malloc` fails, `String::substring()` returns an invalid String
(null buffer). The parser then move-assigns it into a String that already has
a buffer, and the core's `String::move()` copies from address 0. The device
crashed this way, again and again, when a browser sent a 2 KB `Cookie` header
while the Telegram TLS session held most of the RAM (core dump:
`memmove <- String::move <- WebServer::_parseRequest`, Parsing.cpp:246).

**Changes:**

- `Parsing.cpp`: `takePart()` / `takeValid()` check a substring or
  `urlDecode()` result before assigning it: the request line, both header
  loops, the multipart boundary and query arguments. When memory runs out,
  the request is dropped (the browser retries) instead of crashing.
- `WebServer.cpp`, `handleClient()`: a connection that has sent nothing for
  500 ms is dropped when another one is waiting. Browsers open spare
  connections; upstream waits up to 5 s on each while the real request
  queues behind it, which made the page hang.

When upgrading the Arduino core, compare with the new upstream copy and
re-apply, or drop this folder if upstream fixed `String::move()`.
