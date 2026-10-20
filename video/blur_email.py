#!/usr/bin/env python3
"""Blurs the Google account email on every frame of esp-pc.mp4 and writes
esp-pc-blurred.mp4, which make_reel.py uses.

    python blur_email.py            # esp-pc.mp4 -> esp-pc-blurred.mp4
    python blur_email.py --check    # scan esp-pc-blurred.mp4 for any email left

How it works: the email appears in 5 screen layouts (LAYOUTS below: the time
and pixel box where it shows in each). Those boxes are cut out as templates;
every frame is searched for them (OpenCV template matching) and each match is
pixelated + blurred. A match is held for a few frames so fades never flash it.
--check runs the same search on the output: a score near 1.0 means an email is
still readable, below ~0.55 means none is left.

Needs: ffmpeg on PATH, and Python with opencv-python + numpy
(e.g. the AuthKey project's .venv\\Scripts\\python).
"""
import os
import subprocess
import sys

import cv2

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "esp-pc.mp4")
OUT = os.path.join(HERE, "esp-pc-blurred.mp4")

# (name, time in s, x0, y0, x1, y1): where the email text is in each layout
LAYOUTS = [
    ("menu", 1, 308, 426, 548, 452),       # account menu popup
    ("choose", 6, 92, 490, 330, 516),      # "Choose an account"
    ("chip", 11, 86, 420, 333, 447),       # "Hi Quintessa" email chip
    ("dialog", 16, 150, 380, 384, 405),    # Windows "Sign in with a passkey"
    ("account", 37, 158, 333, 396, 358),   # Google Account page header
]
SEARCH_W, SEARCH_H = 820, 1198   # the email only appears in the browser half
THRESH = 0.62                    # match score that counts as "email here"
HOLD = 6                         # frames to keep blurring after a match fades
PAD = 6                          # extra pixels around the box


def load_templates():
    cap = cv2.VideoCapture(SRC)
    tpls = []
    for name, t, x0, y0, x1, y1 in LAYOUTS:
        cap.set(cv2.CAP_PROP_POS_MSEC, t * 1000)
        ok, frame = cap.read()
        if not ok:
            sys.exit(f"could not read {SRC} at {t}s")
        tpls.append((name, cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)[y0:y1, x0:x1].copy()))
    cap.release()
    return tpls


def find(gray, tpls):
    region = gray[:SEARCH_H, :SEARCH_W]
    hits = []
    for name, tpl in tpls:
        _, score, _, (x, y) = cv2.minMaxLoc(cv2.matchTemplate(region, tpl, cv2.TM_CCOEFF_NORMED))
        hits.append((name, score, x, y, tpl.shape[1], tpl.shape[0]))
    return hits


def blur_box(frame, x, y, w, h):
    x0, y0 = max(0, x - PAD), max(0, y - PAD)
    x1, y1 = min(frame.shape[1], x + w + PAD), min(frame.shape[0], y + h + PAD)
    roi = frame[y0:y1, x0:x1]
    small = cv2.resize(roi, (max(1, roi.shape[1] // 10), max(1, roi.shape[0] // 10)), interpolation=cv2.INTER_AREA)
    roi[:] = cv2.GaussianBlur(cv2.resize(small, (roi.shape[1], roi.shape[0]), interpolation=cv2.INTER_LINEAR), (0, 0), 4)


def blur():
    tpls = load_templates()
    cap = cv2.VideoCapture(SRC)
    w, h = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)), int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    enc = subprocess.Popen(["ffmpeg", "-v", "error", "-y", "-f", "rawvideo", "-pix_fmt", "bgr24",
                            "-s", f"{w}x{h}", "-r", f"{fps}", "-i", "-", "-c:v", "libx264", "-preset", "medium",
                            "-crf", "12", "-pix_fmt", "yuv420p", OUT], stdin=subprocess.PIPE)
    held, n, blurred = {}, 0, 0
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        for name, score, x, y, tw, th in find(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), tpls):
            if score >= THRESH:
                held[name] = ((x, y, tw, th), HOLD)
            elif name in held:
                box, left = held[name]
                if left > 1:
                    held[name] = (box, left - 1)
                else:
                    del held[name]
        for box, _ in held.values():
            blur_box(frame, *box)
        blurred += bool(held)
        enc.stdin.write(frame.tobytes())
        n += 1
        if n % 150 == 0:
            print(f"  {n} frames...", flush=True)
    cap.release()
    enc.stdin.close()
    enc.wait()
    print(f"Done: {n} frames, email blurred on {blurred} of them -> {OUT}")


def check():
    tpls = load_templates()
    cap = cv2.VideoCapture(OUT)
    worst, n = (0.0, -1, ""), 0
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        for name, score, *_ in find(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), tpls):
            if score > worst[0]:
                worst = (score, n, name)
        n += 1
    print(f"{n} frames checked. Highest email match: {worst[0]:.3f} (frame {worst[1]}, {worst[2]})")
    print("OK: no readable email" if worst[0] < 0.55 else "WARNING: an email may still be readable")


if __name__ == "__main__":
    check() if "--check" in sys.argv else blur()
