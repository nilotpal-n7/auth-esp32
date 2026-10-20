#!/usr/bin/env python3
"""Phone-free AuthKey helper: watches your screen for QR codes and hands them
to the AuthKey-ESP32.

- Passkey QR ("Use a phone or tablet" in Windows / Chrome): sent to the device
  over USB if it is plugged in, otherwise over Bluetooth; the device then
  completes the sign-in.
- Authenticator-app QR (otpauth://, shown when you turn on 2FA on a site):
  the account is added to the device's TOTP codes (USB only). Each QR is
  added once.

    .venv/Scripts/python tools/qr_bridge.py [--port COMx] [--ble] [--log FILE]

tools/autostart.ps1 starts it hidden at login; it then logs to
%LOCALAPPDATA%\\AuthKey\\qr_bridge.log. Only one copy runs at a time.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import socket
import sys
import threading
import time
from urllib.parse import unquote

import cv2
import numpy as np
from PIL import ImageGrab

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PROV_WRITE = "a3c87501-8ed3-4bdf-8a39-a01bebede295"
PROV_STATUS = "a3c87502-8ed3-4bdf-8a39-a01bebede295"
DEVICE_NAME = "AuthKey-ESP32"
INSTANCE_PORT = 47624            # localhost port held as a single-instance lock
DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "AuthKey")
SEEN_FILE = os.path.join(DATA_DIR, "totp_added.txt")   # SHA-256 of each URI added (never the secret)


def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def find_qr(detector: cv2.QRCodeDetector) -> str | None:
    """Returns the first passkey (FIDO:/) or authenticator (otpauth://) QR on screen."""
    shot = ImageGrab.grab(all_screens=True)
    gray = cv2.cvtColor(np.array(shot), cv2.COLOR_RGB2GRAY)
    # Windows dark mode draws the QR light-on-dark; small dialogs need upscaling.
    candidates = [gray, 255 - gray]
    for img in list(candidates):
        candidates.append(cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST))

    def wanted(t: str) -> bool:
        return bool(t) and (t.upper().startswith("FIDO:/") or t.lower().startswith("otpauth://totp/"))

    for img in candidates:
        ok, texts, _, _ = detector.detectAndDecodeMulti(img)
        if ok:
            for t in texts:
                if wanted(t):
                    return t
        t, _, _ = detector.detectAndDecode(img)
        if wanted(t):
            return t
    return None


def open_device(port: str | None, attempts: int = 5):
    """Opens the USB console, retrying while the unlock service briefly holds it.
    Returns None if the device isn't plugged in."""
    from authkey import AuthKeySerial, find_port
    try:
        port = port or find_port()
    except SystemExit:
        return None
    for i in range(attempts):
        try:
            return AuthKeySerial(port)
        except Exception as e:  # noqa: BLE001  (port busy)
            if i == attempts - 1:
                log(f"  USB busy ({e})")
            time.sleep(0.4)
    return None


class SerialLink:
    """Opens the USB console only while handing over a QR (the AuthKey Unlock
    service needs the port too), streaming the device's log meanwhile."""

    SHOW = ("[HYBRID]", "[CTAP]", "[EVENT]", "[WS]", "[NET]", "[BLE]")

    def __init__(self, port: str | None):
        self.port = port

    def send(self, qr: str) -> bool:
        dev = open_device(self.port)
        if not dev:
            return False
        threading.Thread(target=self._stream, args=(dev, qr), daemon=True).start()
        return True

    def _stream(self, dev, qr: str):
        try:
            dev.send(f"hybrid {qr}")
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                line = dev.readline(0.2)
                if not line:
                    continue
                if line.startswith(self.SHOW) or line.startswith(("OK", "ERR")):
                    print("  device:", line, flush=True)
                if "session ended" in line or line.startswith("ERR"):
                    break
        finally:
            dev.close()


async def send_ble(qr: str) -> bool:
    from bleak import BleakClient, BleakScanner
    device = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=10)
    if not device:
        log(f"  {DEVICE_NAME} not found over Bluetooth")
        return False
    done = asyncio.Event()

    def on_status(_, data: bytearray):
        s = data.decode(errors="replace")
        print("  device:", s, flush=True)
        if s in ("waiting for PC", "connected") or "fail" in s or s in ("no WiFi", "bad QR"):
            done.set()

    async with BleakClient(device) as client:
        await client.start_notify(PROV_STATUS, on_status)
        await client.write_gatt_char(PROV_WRITE, qr.encode(), response=True)
        try:
            await asyncio.wait_for(done.wait(), 25)
        except asyncio.TimeoutError:
            log("  no status from device")
    # Disconnecting lets the device advertise to Windows.
    return True


def handle_passkey(qr: str, link: SerialLink | None):
    log(f"Passkey QR found, sending to {DEVICE_NAME}...")
    sent = link.send(qr) if link else False
    if not sent:
        try:
            sent = asyncio.run(send_ble(qr))
        except Exception as e:  # noqa: BLE001
            log(f"  Bluetooth error: {e}")
            sent = False
    log("  -> handed to the device" if sent else "  -> could not reach the device")


def _seen() -> set[str]:
    try:
        with open(SEEN_FILE, encoding="ascii") as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def handle_totp(uri: str, port: str | None) -> bool:
    """Adds an authenticator account to the device, once per distinct URI.
    Returns False only when the device isn't reachable (worth retrying soon)."""
    digest = hashlib.sha256(uri.encode()).hexdigest()
    label = unquote(uri.split("?", 1)[0][len("otpauth://totp/"):])
    if digest in _seen():
        return True
    if '"' in uri:
        log("Authenticator QR has an unsupported character; add it with tools/authkey.py")
        return True
    dev = open_device(port)
    if not dev:
        log(f"Authenticator QR found ({label}), but the AuthKey isn't on USB; plug it in and the QR is retried")
        return False
    try:
        out = dev.command(f'totp uri "{uri}"', timeout=5)
    finally:
        dev.close()
    result = next((l for l in out if l.startswith(("OK", "ERR"))), "no reply")
    if result.startswith("OK"):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(SEEN_FILE, "a", encoding="ascii") as f:
            f.write(digest + "\n")
        log(f"Authenticator account added to the device: {label} ({result})")
    else:
        log(f"Authenticator QR found ({label}) but the device refused it: {result}")
    return True


def single_instance() -> socket.socket | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", INSTANCE_PORT))
        s.listen(1)
        return s
    except OSError:
        s.close()
        return None


def redirect_output(path: str | None):
    """pythonw has no console: send output to a log file (kept under ~1 MB)."""
    if path is None and sys.stdout is not None:
        return
    path = path or os.path.join(DATA_DIR, "qr_bridge.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path) > 1024 * 1024:
        os.replace(path, path + ".old")
    sys.stdout = sys.stderr = open(path, "a", encoding="utf-8", buffering=1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="serial port (default: auto-detect each time)")
    ap.add_argument("--ble", action="store_true", help="always use Bluetooth for passkeys, even if USB is connected")
    ap.add_argument("--interval", type=float, default=0.5)
    ap.add_argument("--log", help="write output to this file instead of the console")
    args = ap.parse_args()
    redirect_output(args.log)

    lock = single_instance()
    if not lock:
        log("Another qr_bridge is already running; exiting.")
        return

    link = None if args.ble else SerialLink(args.port)
    detector = cv2.QRCodeDetector()
    last_qr, last_time = None, 0.0
    log("Watching the screen for passkey and authenticator QR codes. Ctrl+C to stop.")
    try:
        while True:
            try:
                qr = find_qr(detector)
            except OSError:
                # Screenshots fail while the PC is locked / on the secure desktop.
                time.sleep(2)
                continue
            if qr and (qr != last_qr or time.time() - last_time > 120):
                last_qr, last_time = qr, time.time()
                if qr.lower().startswith("otpauth://"):
                    if not handle_totp(qr, args.port):
                        last_time = time.time() - 115   # not on USB yet: retry in ~5 s
                else:
                    handle_passkey(qr, link)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        lock.close()


if __name__ == "__main__":
    main()
