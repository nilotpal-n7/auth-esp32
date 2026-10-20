#!/usr/bin/env python3
"""Phone-free passkey sign-in: watches your screen for the passkey QR code that
Windows / Chrome show ("Use a phone or tablet") and hands it to the
AuthKey-ESP32 — over USB if it is plugged in, otherwise over Bluetooth.
The device then completes the sign-in after you press OK on it.

    .venv/Scripts/python tools/qr_bridge.py [--port COMx] [--ble]

Leave it running in the background (or start it at login).
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
import time

import cv2
import numpy as np
from PIL import ImageGrab

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

PROV_WRITE = "a3c87501-8ed3-4bdf-8a39-a01bebede295"
PROV_STATUS = "a3c87502-8ed3-4bdf-8a39-a01bebede295"
DEVICE_NAME = "AuthKey-ESP32"


def find_fido_qr(detector: cv2.QRCodeDetector) -> str | None:
    shot = ImageGrab.grab(all_screens=True)
    gray = cv2.cvtColor(np.array(shot), cv2.COLOR_RGB2GRAY)
    # Windows dark mode draws the QR light-on-dark; small dialogs need upscaling.
    candidates = [gray, 255 - gray]
    for img in list(candidates):
        candidates.append(cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_NEAREST))
    for img in candidates:
        ok, texts, _, _ = detector.detectAndDecodeMulti(img)
        if ok:
            for t in texts:
                if t and t.upper().startswith("FIDO:/"):
                    return t
        t, _, _ = detector.detectAndDecode(img)
        if t and t.upper().startswith("FIDO:/"):
            return t
    return None


class SerialLink:
    """Opens the USB console only while handing over a QR (the AuthKey Unlock
    service needs the port too), streaming the device's log meanwhile."""

    SHOW = ("[HYBRID]", "[CTAP]", "[EVENT]", "[WS]", "[NET]", "[BLE]")

    def __init__(self, port: str | None):
        from authkey import find_port
        self.port = port or find_port()

    def send(self, qr: str) -> bool:
        from authkey import AuthKeySerial
        try:
            dev = AuthKeySerial(self.port)
        except Exception as e:  # noqa: BLE001  (busy: e.g. the unlock service is using it)
            print(f"  USB busy ({e}); using Bluetooth")
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
                    print("  device:", line)
                if "session ended" in line or line.startswith("ERR"):
                    break
        finally:
            dev.close()


def open_serial(port: str | None) -> "SerialLink | None":
    try:
        return SerialLink(port)
    except (SystemExit, Exception) as e:  # noqa: BLE001
        print(f"USB serial not available ({e}); will use Bluetooth.")
        return None


async def send_ble(qr: str) -> bool:
    from bleak import BleakClient, BleakScanner
    device = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=10)
    if not device:
        print(f"  {DEVICE_NAME} not found over Bluetooth")
        return False
    done = asyncio.Event()

    def on_status(_, data: bytearray):
        s = data.decode(errors="replace")
        print("  device:", s)
        if s in ("waiting for PC", "connected") or "fail" in s or s in ("no WiFi", "bad QR"):
            done.set()

    async with BleakClient(device) as client:
        await client.start_notify(PROV_STATUS, on_status)
        await client.write_gatt_char(PROV_WRITE, qr.encode(), response=True)
        try:
            await asyncio.wait_for(done.wait(), 25)
        except asyncio.TimeoutError:
            print("  no status from device")
    # Disconnecting lets the device advertise to Windows.
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", help="serial port (default: auto-detect)")
    ap.add_argument("--ble", action="store_true", help="always use Bluetooth, even if USB is connected")
    ap.add_argument("--interval", type=float, default=0.5)
    args = ap.parse_args()

    link = None if args.ble else open_serial(args.port)
    if link:
        print(f"Using USB serial ({link.port}) when a QR appears; device log follows.")
    detector = cv2.QRCodeDetector()
    last_qr, last_time = None, 0.0
    print("Watching the screen for passkey QR codes. Ctrl+C to stop.")
    try:
        while True:
            try:
                qr = find_fido_qr(detector)
            except OSError:
                # Screenshots fail while the PC is locked / on the secure desktop.
                time.sleep(2)
                continue
            if qr and (qr != last_qr or time.time() - last_time > 120):
                last_qr, last_time = qr, time.time()
                print(f"[{time.strftime('%H:%M:%S')}] Passkey QR found, sending to {DEVICE_NAME}...")
                sent = link.send(qr) if link else False
                if not sent:
                    try:
                        sent = asyncio.run(send_ble(qr))
                    except Exception as e:  # noqa: BLE001
                        print(f"  Bluetooth error: {e}")
                        sent = False
                print("  -> press OK on the device when it asks." if sent else "  -> could not reach the device")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
