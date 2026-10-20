#!/usr/bin/env python3
"""Generates circuit.svg (and circuit.png via ImageMagick) from the pin map in
src/config.h. Re-run after changing pins:  python tools/make_circuit.py
"""
import os
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ESP32 DevKit V1 (30-pin), antenna at the top, USB at the bottom.
LEFT_PINS = ["EN", "VP 36", "VN 39", "D34", "D35", "D32", "D33", "D25", "D26", "D27",
             "D14", "D12", "D13", "GND", "VIN"]
RIGHT_PINS = ["D23", "D22", "TX0", "RX0", "D21", "D19", "D18", "D5", "TX2", "RX2",
              "D4", "D2", "D15", "GND", "3V3"]

BX0, BX1, BY0 = 450, 770, 110          # board edges
PIN_Y0, PITCH = 170, 40
def ly(name): return PIN_Y0 + PITCH * LEFT_PINS.index(name)
def ry(name): return PIN_Y0 + PITCH * RIGHT_PINS.index(name)

C = {"vcc": "#d32f2f", "gnd": "#212121", "sda": "#1565c0", "scl": "#f9a825",
     "up": "#2e7d32", "down": "#ef6c00", "ok": "#00838f", "left": "#6a1b9a", "right": "#ad1457"}

out = []
def add(s): out.append(s)
def wire(points, color, width=4):
    pts = " ".join(f"{x},{y}" for x, y in points)
    add(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="{width}" '
        f'stroke-linejoin="round" stroke-linecap="round"/>')
def dot(x, y, color, r=6): add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{color}"/>')
def text(x, y, s, size=18, anchor="start", weight="normal", color="#212121"):
    add(f'<text x="{x}" y="{y}" font-size="{size}" text-anchor="{anchor}" font-weight="{weight}" '
        f'fill="{color}">{s}</text>')

W, H = 1200, 960
add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
    f'font-family="Segoe UI, Roboto, Arial, sans-serif">')
add(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
text(W / 2, 50, "AuthKey-ESP32 wiring", 30, "middle", "bold")
text(W / 2, 80, "ESP32 DevKit V1 (30-pin) · SSD1306 128×64 I²C OLED · 5 push buttons", 17, "middle",
     color="#555")

# --- ESP32 board ---
add(f'<rect x="{BX0}" y="{BY0}" width="{BX1 - BX0}" height="690" rx="14" fill="#263238"/>')
MX = (BX0 + BX1) / 2
add(f'<rect x="{MX - 60}" y="{BY0 + 14}" width="120" height="26" rx="4" fill="#90a4ae"/>')  # antenna
add(f'<rect x="{MX - 72}" y="{BY0 + 46}" width="144" height="190" rx="6" fill="#b0bec5"/>')
text(MX, BY0 + 132, "ESP32-", 20, "middle", "bold", "#263238")
text(MX, BY0 + 158, "WROOM-32", 20, "middle", "bold", "#263238")
add(f'<rect x="{(BX0 + BX1) / 2 - 35}" y="{BY0 + 668}" width="70" height="34" rx="5" fill="#9e9e9e"/>')
text((BX0 + BX1) / 2, BY0 + 722, "USB", 15, "middle", color="#555")

used_left = {"D32": C["left"], "D33": C["right"], "D25": C["up"], "D26": C["down"],
             "D27": C["ok"], "GND": C["gnd"]}
used_right = {"D22": C["scl"], "D21": C["sda"], "GND": C["gnd"], "3V3": C["vcc"]}
for name in LEFT_PINS:
    y = ly(name)
    used = name in used_left
    add(f'<circle cx="{BX0}" cy="{y}" r="7" fill="{used_left.get(name, "#fff")}" stroke="#cfd8dc" stroke-width="2"/>')
    text(BX0 + 16, y + 6, name, 16, weight="bold" if used else "normal", color="#fff" if used else "#90a4ae")
for name in RIGHT_PINS:
    y = ry(name)
    used = name in used_right
    add(f'<circle cx="{BX1}" cy="{y}" r="7" fill="{used_right.get(name, "#fff")}" stroke="#cfd8dc" stroke-width="2"/>')
    text(BX1 - 16, y + 6, name, 16, "end", weight="bold" if used else "normal",
         color="#fff" if used else "#90a4ae")

# --- Buttons (left) ---
# (label, pin, button y, vertical lane x) — lanes chosen so no wires cross.
buttons = [("LEFT", "D32", 250, 420, C["left"], "optional"),
           ("RIGHT", "D33", 340, 395, C["right"], "optional"),
           ("UP", "D25", 430, 370, C["up"], ""),
           ("DOWN", "D26", 520, 395, C["down"], ""),
           ("OK", "D27", 610, 420, C["ok"], "approve")]
GND_BUS_X = 70
for label, pin, by, lane, color, note in buttons:
    py = ly(pin)
    pts = [(BX0, py)]
    if lane is not None:
        pts += [(lane, py), (lane, by)]
    pts += [(235, by)]
    wire(pts, color)
    # Push-button symbol: two contacts and a bridging plunger.
    add(f'<line x1="{GND_BUS_X}" y1="{by}" x2="135" y2="{by}" stroke="{C["gnd"]}" stroke-width="4"/>')
    dot(135, by, "#212121", 5)
    dot(235, by, "#212121", 5)
    add(f'<line x1="140" y1="{by - 18}" x2="230" y2="{by - 18}" stroke="#212121" stroke-width="4"/>')
    add(f'<line x1="185" y1="{by - 18}" x2="185" y2="{by - 34}" stroke="#212121" stroke-width="4"/>')
    add(f'<line x1="170" y1="{by - 34}" x2="200" y2="{by - 34}" stroke="#212121" stroke-width="4"/>')
    gpio = pin.replace("D", "GPIO ")
    text(185, by + 28, f"{label} · {gpio}", 16, "middle", "bold", color)
    if note:
        text(185, by + 47, note, 14, "middle", color="#777")
# Common ground bus to the left GND pin.
wire([(GND_BUS_X, buttons[0][2]), (GND_BUS_X, ly("GND")), (BX0, ly("GND"))], C["gnd"])
for _, _, by, *_ in buttons:
    dot(GND_BUS_X, by, C["gnd"], 6)
text(GND_BUS_X + 10, ly("GND") + 24, "GND (shared by all buttons)", 15, color="#555")

# --- OLED (right) ---
OX0, OY0, OX1, OY1 = 905, 400, 1150, 600
add(f'<rect x="{OX0}" y="{OY0}" width="{OX1 - OX0}" height="{OY1 - OY0}" rx="10" fill="#0d47a1"/>')
add(f'<rect x="{OX0 + 75}" y="{OY0 + 30}" width="{OX1 - OX0 - 90}" height="{OY1 - OY0 - 60}" rx="4" fill="#000"/>')
text((OX0 + 75 + OX1 - 15) / 2, OY0 + 95, "0.96\" OLED", 20, "middle", "bold", "#4fc3f7")
text((OX0 + 75 + OX1 - 15) / 2, OY0 + 122, "SSD1306 · I²C 0x3C", 15, "middle", color="#4fc3f7")
# (label, oled pin y, esp pin, lane x, color)
oled = [("SCL", 440, "D22", 880, C["scl"]),
        ("SDA", 480, "D21", 860, C["sda"]),
        ("GND", 520, "GND", 840, C["gnd"]),
        ("VCC", 560, "3V3", 880, C["vcc"])]
for label, oy, pin, lane, color in oled:
    py = ry(pin)
    wire([(BX1, py), (lane, py), (lane, oy), (OX0, oy)], color)
    add(f'<circle cx="{OX0}" cy="{oy}" r="7" fill="{color}" stroke="#bbdefb" stroke-width="2"/>')
    text(OX0 + 14, oy + 6, label, 15, weight="bold", color="#fff")
text(OX0, OY1 + 30, "Pin order differs between modules —", 14, color="#777")
text(OX0, OY1 + 48, "match the labels printed on yours.", 14, color="#777")

# --- Footer ---
text(W / 2, 905, "Every button: one leg to its GPIO, the other to GND. No resistors needed (internal pull-ups).",
     17, "middle")
text(W / 2, 932, "LEFT / RIGHT are optional shortcuts; UP, DOWN and OK are enough to use every feature.",
     15, "middle", color="#555")
add("</svg>")

svg_path = os.path.join(ROOT, "circuit.svg")
with open(svg_path, "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("wrote", svg_path)

magick = shutil.which("magick")
if magick:
    subprocess.run([magick, "-density", "144", svg_path, "-resize", "1600x", os.path.join(ROOT, "circuit.png")],
                   check=True)
    print("wrote circuit.png")
else:
    print("ImageMagick not found; circuit.png not regenerated")
