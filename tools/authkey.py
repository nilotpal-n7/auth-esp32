#!/usr/bin/env python3
"""AuthKey-ESP32 USB serial client.

Library:  AuthKeySerial (console commands) and SerialCtapDevice (a python-fido2
          CtapDevice that tunnels CTAP2 over the console's `ctap` command).
CLI:      python tools/authkey.py [--port COMx] <console command ...>
          python tools/authkey.py status
          python tools/authkey.py totp uri "otpauth://totp/GitHub:me?secret=..."
          python tools/authkey.py            (interactive console)
"""
from __future__ import annotations

import argparse
import sys
import threading
import time

import serial
import serial.tools.list_ports

# USB-UART bridges commonly found on ESP32 dev boards.
KNOWN_BRIDGES = {(0x10C4, 0xEA60), (0x1A86, 0x7523), (0x1A86, 0x55D4), (0x0403, 0x6001)}


def find_port() -> str:
    for p in serial.tools.list_ports.comports():
        if (p.vid, p.pid) in KNOWN_BRIDGES:
            return p.device
    raise SystemExit("No ESP32 serial port found. Is the USB driver installed? Use --port.")


class AuthKeySerial:
    def __init__(self, port: str | None = None, baud: int = 115200, echo_logs: bool = False):
        # Configure DTR/RTS low *before* opening so the board is not reset.
        self.ser = serial.Serial(None, baud, timeout=0.1)
        self.ser.port = port or find_port()
        self.ser.dtr = False
        self.ser.rts = False
        self.ser.open()
        self.echo_logs = echo_logs
        self._buf = b""
        self.lock = threading.Lock()

    def close(self):
        self.ser.close()

    def readline(self, timeout: float) -> str | None:
        deadline = time.monotonic() + timeout
        while True:
            nl = self._buf.find(b"\n")
            if nl >= 0:
                line, self._buf = self._buf[:nl], self._buf[nl + 1:]
                text = line.decode(errors="replace").rstrip("\r")
                if self.echo_logs and text.startswith("["):
                    print("   device:", text)
                return text
            if time.monotonic() > deadline:
                return None
            self._buf += self.ser.read(self.ser.in_waiting or 1)

    def send(self, line: str):
        self.ser.write(line.encode() + b"\n")
        self.ser.flush()

    def wait_ready(self, timeout: float = 15.0):
        """Wait until the console answers (e.g. after a reset)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.send("time")
            end = time.monotonic() + 1.0
            while time.monotonic() < end:
                line = self.readline(0.2)
                if line and line.startswith("UTC "):
                    return
        raise TimeoutError("device console did not respond")

    def command(self, line: str, timeout: float = 5.0, until=("OK", "ERR", "CODE", "UTC")) -> list[str]:
        """Send a console command; return output lines up to a terminating line."""
        with self.lock:
            self._drain()
            self.send(line)
            out = []
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                l = self.readline(0.2)
                if l is None:
                    if out and until is None:
                        break
                    continue
                if l.startswith("[") and not l.startswith("[EVENT]"):
                    continue
                out.append(l)
                if until and l.startswith(until):
                    break
            return out

    def _drain(self):
        while self.readline(0.05) is not None:
            pass


class SerialCtapDevice:
    """python-fido2 CtapDevice speaking CTAP2 through the console.

    With approve="auto" the harness answers on-device prompts through the
    test-build console hooks (`approve`, `uvpin <pin>`), standing in for a
    person pressing OK.
    """

    CTAPHID_CBOR = 0x10

    def __init__(self, dev: AuthKeySerial, approve: str | None = None, pin: str | None = None):
        self.dev = dev
        self.approve = approve      # None (wait for a human), "auto", "deny", or a list of console lines
        self.pin = pin
        self.prompts = 0

    @property
    def capabilities(self) -> int:
        return 0x04  # CBOR

    def close(self):
        pass

    def call(self, cmd, data=b"", event=None, on_keepalive=None) -> bytes:
        if cmd != self.CTAPHID_CBOR:
            raise ValueError(f"unsupported CTAPHID command {cmd:#x}")
        dev = self.dev
        with dev.lock:
            dev._drain()
            dev.send("ctap " + bytes(data).hex())
            start = time.monotonic()
            answered = False
            while True:
                line = dev.readline(0.1)
                if line and line.startswith("CTAP "):
                    return bytes.fromhex(line[5:].strip())
                if line and line.startswith("ERR") and not answered:
                    raise IOError(line)
                if event is not None and event.is_set():
                    dev.send("deny")
                if not answered and time.monotonic() - start > 0.6:
                    # No immediate reply: the device is showing a prompt.
                    if on_keepalive:
                        on_keepalive(2)  # STATUS.UPNEEDED
                    if self.approve == "auto":
                        self.prompts += 1
                        dev.send(f"uvpin {self.pin}" if self.pin else "approve")
                        answered = True
                    elif self.approve == "deny":
                        self.prompts += 1
                        dev.send("deny")
                        answered = True
                    elif isinstance(self.approve, list):
                        self.prompts += 1
                        for cmd_line in self.approve:
                            dev.send(cmd_line)
                            time.sleep(0.5)
                        answered = True
                if time.monotonic() - start > 40:
                    raise TimeoutError("no CTAP response")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    dev = AuthKeySerial(args.port)
    try:
        if args.command:
            parts = [f'"{a}"' if " " in a else a for a in args.command]
            for line in dev.command(" ".join(parts), timeout=3.0, until=("OK", "ERR", "CODE", "UTC", "CTAP")):
                print(line)
            # Multi-line outputs (status, list) end without OK; show what arrived.
            return
        print("Connected. Type commands (help), Ctrl+C to quit.")
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                line = dev.readline(0.2)
                if line is not None:
                    print(line)

        threading.Thread(target=reader, daemon=True).start()
        for line in sys.stdin:
            dev.send(line.rstrip("\n"))
    except KeyboardInterrupt:
        pass
    finally:
        dev.close()


if __name__ == "__main__":
    main()
