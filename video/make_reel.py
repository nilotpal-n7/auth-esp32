#!/usr/bin/env python3
"""Builds the AuthKey-ESP32 Instagram video (1920x1080, 28.6 s).

    python make_reel.py                                  # current look: overlay 12%, music 100%, captions on
    python make_reel.py --opacity 20 --volume 80
    python make_reel.py --opacity 8 --no-captions
    python make_reel.py --opacity 15 --volume 120 --out final.mp4

--opacity   Batman x Sajan overlay visibility, 0-100 % (default 12)
--volume    music loudness, 0-200 % (default 100 = original; above 100 is limited so it doesn't clip)
--no-captions  leave out the hook / step captions and the Tom punchline
--out       output file (default: reel_op<opacity>_vol<volume>[_nocap].mp4)

Inputs (same folder): esp-pc-blurred.mp4 (PC recording, email blurred),
esp-32.mp4, overlay.mp4, tom-gif.gif. Needs ffmpeg on PATH, and Pillow for
captions that contain emoji.
"""
import argparse
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FONT_FILE = r"C:\Windows\Fonts\segoeuib.ttf"        # Segoe UI Bold
EMOJI_FILE = r"C:\Windows\Fonts\seguiemj.ttf"       # Segoe UI Emoji (colour)
FONT = "C\\:/Windows/Fonts/segoeuib.ttf"            # same font, escaped for ffmpeg
SPEED = 1.5
SRC_START, SRC_END = 1.5, 39.0                  # part of the recordings used
MAIN = (SRC_END - SRC_START) / SPEED            # 25 s of action
TOTAL = 28.6                                    # = music length; the Tom ending fills the rest
LEFT_CENTER = "((W-668)-text_w)/2"              # centered left of the ESP32 corner
FADE = 0.18

# (start, end, text, size, x, y)
# Captions with emoji are drawn as an image (colour emoji); their x/y use the
# image size w/h instead of text_w/text_h.
CAPTIONS = [
    (0.15, 2.9, "No phone. No password.", 92, "(W-text_w)/2", "(H-text_h)/2-40"),
    (2.9, 5.6, "Just an ESP32 I turned into a passkey", 76, "(W-text_w)/2", "(H-text_h)/2-40"),
    (8.3, 12.6, "Google asks for a passkey", 50, LEFT_CENTER, "H-150"),
    (13.0, 15.0, "Windows shows a QR...", 50, LEFT_CENTER, "H-150"),
    (15.2, 18.8, "My script reads it and sends it to the ESP32", 48, LEFT_CENTER, "H-150"),
    (19.0, 22.9, "ESP32 approves it over Bluetooth + WiFi", 50, LEFT_CENTER, "H-150"),
    (23.2, 24.95, "Signed in.", 64, LEFT_CENTER, "H-160"),
    (25.2, 28.5, "with great power comes great responsibility \U0001F608", 66, "(W-w)/2", "H-h-20"),
]


def has_emoji(text):
    return any(ord(c) >= 0x1F000 or 0x2600 <= ord(c) <= 0x27BF for c in text)


def render_caption(text, size, path):
    """Draws a caption like the drawtext ones (white bold text, shadow, dark
    box) but with colour emoji, as a transparent PNG."""
    from PIL import Image, ImageDraw, ImageFont

    pad, max_w = 18, 1840
    runs = []
    for c in text:                                   # split into text / emoji runs
        e = has_emoji(c)
        if runs and runs[-1][0] == e:
            runs[-1][1] += c
        else:
            runs.append([e, c])
    while True:
        tf, ef = ImageFont.truetype(FONT_FILE, size), ImageFont.truetype(EMOJI_FILE, size)
        width = sum((ef if e else tf).getlength(s) for e, s in runs)
        if width + 2 * pad <= max_w or size <= 20:
            break
        size -= 2
    ascent, descent = tf.getmetrics()
    img = Image.new("RGBA", (int(width) + 2 * pad, ascent + descent + 2 * pad), (0, 0, 0, 140))
    d = ImageDraw.Draw(img)
    x, base = pad, pad + ascent
    for e, s in runs:
        if e:
            d.text((x, base), s, font=ef, anchor="ls", embedded_color=True)
            x += ef.getlength(s)
        else:
            d.text((x + 2, base + 2), s, font=tf, anchor="ls", fill=(0, 0, 0, 153))
            d.text((x, base), s, font=tf, anchor="ls", fill=(255, 255, 255, 255))
            x += tf.getlength(s)
    img.save(path)


def text_alpha(a, b):
    return (f"if(lt(t,{a}),0,if(lt(t,{a + FADE}),(t-{a})/{FADE},"
            f"if(lt(t,{b - FADE}),1,if(lt(t,{b}),({b}-t)/{FADE},0))))")


def build_graph(opacity, volume, captions, first_image_input):
    """Returns (graph, [(png caption tuple)...]) - image captions become extra inputs."""
    trim = f"trim=start={SRC_START}:end={SRC_END},setpts=(PTS-STARTPTS)/{SPEED},fps=30"
    tail = TOTAL - MAIN + 0.1
    draws, images = [], []
    for cap in (CAPTIONS if captions else []):
        a, b, text, size, x, y = cap
        if has_emoji(text):
            images.append(cap)
        else:
            draws.append(f"drawtext=fontfile='{FONT}':text='{text}':fontsize={size}:fontcolor=white:"
                         f"box=1:boxcolor=black@0.55:boxborderw=18:shadowcolor=black@0.6:shadowx=2:shadowy=2:"
                         f"x={x}:y={y}:enable='between(t,{a},{b})':alpha='{text_alpha(a, b)}'")
    gain = volume / 100
    audio = f"atrim=duration={TOTAL},volume={gain:.3f}"
    if gain > 1:
        audio += ",alimiter=limit=0.89:level=0"
    audio += f",afade=t=out:st={TOTAL - 0.5}:d=0.5"

    graph = f"""[0:v]{trim},scale=1920:-2:flags=lanczos,crop=1920:1080:0:0,tpad=stop_mode=clone:stop_duration={tail},setsar=1[pc];
[1:v]{trim},hflip,vflip,crop=1560:1170:600:330,eq=brightness=0.06:contrast=1.15:saturation=1.1,scale=632:474:flags=lanczos,pad=640:482:4:4:color=0xF0F0F0,setsar=1[esp];
[pc][esp]overlay=W-w-28:H-h-28:enable='lt(t,{MAIN})':eof_action=pass[m1];
[m1]boxblur=luma_radius=18:luma_power=2:enable='gte(t,{MAIN})',eq=brightness=-0.08:enable='gte(t,{MAIN})'[m2];
[3:v]fps=30,scale=-2:860:flags=lanczos,setsar=1,setpts=PTS-STARTPTS+{MAIN}/TB[tom];
[m2][tom]overlay=(W-w)/2:(H-h)/2-30:enable='gte(t,{MAIN})':eof_action=pass[m3];
[2:v]fps=30,scale=1920:1080:flags=lanczos,setsar=1,format=yuva420p,colorchannelmixer=aa={opacity / 100:.3f}[ov];
[m3][ov]overlay=0:0:eof_action=pass{''.join(',' + d for d in draws)}[c0];
"""
    for i, (a, b, _text, _size, x, y) in enumerate(images):
        k = first_image_input + i
        graph += (f"[{k}:v]format=rgba,fade=t=in:st={a}:d={FADE}:alpha=1,"
                  f"fade=t=out:st={b - FADE}:d={FADE}:alpha=1[img{i}];\n"
                  f"[c{i}][img{i}]overlay={x}:{y}:enable='between(t,{a},{b})'[c{i + 1}];\n")
    graph += f"[c{len(images)}]trim=duration={TOTAL},format=yuv420p[vout];\n[2:a]{audio}[aout]\n"
    return graph, images


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--opacity", type=float, default=12, help="overlay visibility %% (0-100, default 12)")
    ap.add_argument("--volume", type=float, default=100, help="music loudness %% (0-200, default 100)")
    ap.add_argument("--no-captions", action="store_true", help="leave out all captions")
    ap.add_argument("--out", help="output file name")
    args = ap.parse_args()
    if not 0 <= args.opacity <= 100:
        sys.exit("--opacity must be 0-100")
    if not 0 <= args.volume <= 200:
        sys.exit("--volume must be 0-200")

    def fmt(v):
        return f"{v:g}"

    out = args.out or f"reel_op{fmt(args.opacity)}_vol{fmt(args.volume)}{'_nocap' if args.no_captions else ''}.mp4"
    out = os.path.join(HERE, out)
    inputs = ["esp-pc-blurred.mp4", "esp-32.mp4", "overlay.mp4", "tom-gif.gif"]
    for name in inputs:
        if not os.path.exists(os.path.join(HERE, name)):
            sys.exit(f"missing {name} in {HERE}")

    tmp = tempfile.mkdtemp(prefix="reel_")
    graph_text, images = build_graph(args.opacity, args.volume, not args.no_captions, first_image_input=4)
    graph = os.path.join(tmp, "graph.txt")
    with open(graph, "w", encoding="utf-8") as g:
        g.write(graph_text)
    image_inputs = []
    for i, (_a, _b, text, size, _x, _y) in enumerate(images):
        png = os.path.join(tmp, f"caption{i}.png")
        render_caption(text, size, png)
        image_inputs += ["-loop", "1", "-framerate", "30", "-t", f"{TOTAL}", "-i", png]

    cmd = ["ffmpeg", "-v", "error", "-stats", "-y",
           "-i", inputs[0], "-i", inputs[1], "-i", inputs[2],
           "-ignore_loop", "0", "-t", f"{TOTAL - MAIN + 0.1:.2f}", "-i", inputs[3],
           *image_inputs,
           "-filter_complex_script", graph, "-map", "[vout]", "-map", "[aout]",
           "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-profile:v", "high", "-pix_fmt", "yuv420p",
           "-r", "30", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", out]
    print(f"overlay {fmt(args.opacity)}%, music {fmt(args.volume)}%, captions {'off' if args.no_captions else 'on'}")
    try:
        code = subprocess.call(cmd, cwd=HERE)
    finally:
        for f in os.listdir(tmp):
            os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)
    if code:
        sys.exit(f"ffmpeg failed ({code})")
    print(f"\nDone: {out}")


if __name__ == "__main__":
    main()
