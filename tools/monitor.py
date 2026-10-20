#!/usr/bin/env python3
"""Print the device's serial log, optionally resetting it first.

    python tools/monitor.py [--port COMx] [--reset] [--seconds N]
"""
import argparse
import sys
import time

import serial

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
from authkey import find_port  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port")
    ap.add_argument("--reset", action="store_true", help="reset the board before reading")
    ap.add_argument("--seconds", type=float, default=0, help="stop after N seconds (0 = forever)")
    args = ap.parse_args()
    ser = serial.Serial(args.port or find_port(), 115200, timeout=0.2)
    if args.reset:
        ser.dtr = False
        ser.rts = True     # EN low
        time.sleep(0.1)
        ser.rts = False
    else:
        ser.dtr = ser.rts = False
    end = time.monotonic() + args.seconds if args.seconds else None
    try:
        while end is None or time.monotonic() < end:
            data = ser.read(512)
            if data:
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
