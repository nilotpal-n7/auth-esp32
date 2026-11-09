"""Install firmware on the AuthKey over WiFi, through its web page's update API.

    python tools/webflash.py [--host authkey-esp32.local] [.pio/build/esp32dev/firmware.bin]
    pio run -e web -t upload          (builds, then runs this)

No USB, so the PC helper keeps its Bluetooth link, and no inbound connection
to the PC (espota needs one, which Windows Firewall usually blocks).

Two presses on the AuthKey: OK to allow this PC's browser session, then OK to
install, after the device shows the version it received. The device checks the
image (ESP32 header, SHA-256, AuthKey tag) before asking, and keeps running the
old firmware unless you press OK.
"""
import argparse
import http.client
import json
import os
import sys
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def env_host():
    """OTA_HOST from .env (only that key is read)."""
    try:
        with open(os.path.join(ROOT, ".env"), encoding="utf-8") as f:
            for line in f:
                key, _, value = line.strip().partition("=")
                if key.strip() == "OTA_HOST" and value.strip():
                    return value.strip().strip("\"'")
    except OSError:
        pass
    return "authkey-esp32.local"


class Device:
    def __init__(self, host):
        self.host = host
        self.cookie = ""

    def request(self, method, path, body=None, headers=None, timeout=15):
        h = {"X-AuthKey": "1"}
        if self.cookie:
            h["Cookie"] = self.cookie
        h.update(headers or {})
        c = http.client.HTTPConnection(self.host, 80, timeout=timeout)
        try:
            c.request(method, path, body=body, headers=h)
            r = c.getresponse()
            data = r.read()
            for k, v in r.getheaders():
                if k.lower() == "set-cookie" and v.startswith("ak="):
                    self.cookie = v.split(";", 1)[0]
            try:
                j = json.loads(data or b"{}")
            except ValueError:
                j = {}
            return r.status, j
        finally:
            c.close()

    def allow(self):
        st, j = self.request("POST", "/api/session")
        if st != 200:
            sys.exit(f"Session refused: {j.get('error', st)}")
        print("Press OK on the AuthKey to allow this PC (ALLOW WEB ACCESS?) ...")
        for _ in range(45):
            time.sleep(1)
            _, p = self.request("GET", f"/api/session?id={j['id']}")
            if p.get("state") == "allowed":
                return
            if p.get("state") != "waiting":
                sys.exit(f"Not allowed: {p.get('state')}")
        sys.exit("Timed out waiting for OK.")

    def upload(self, path):
        data = open(path, "rb").read()
        if not data or data[0] != 0xE9:
            sys.exit(f"{path} is not an ESP32 firmware image.")
        boundary = uuid.uuid4().hex
        head = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"fw\"; filename=\"firmware.bin\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{boundary}--\r\n".encode()
        total = len(head) + len(data) + len(tail)
        c = http.client.HTTPConnection(self.host, 80, timeout=60)
        c.putrequest("POST", "/api/update")
        c.putheader("X-AuthKey", "1")
        c.putheader("Cookie", self.cookie)
        c.putheader("Content-Type", f"multipart/form-data; boundary={boundary}")
        c.putheader("Content-Length", str(total))
        c.endheaders()
        c.send(head)
        step = 16384
        for off in range(0, len(data), step):
            c.send(data[off:off + step])
            print(f"\rUploading {min(off + step, len(data)) * 100 // len(data):3d} %", end="", flush=True)
        c.send(tail)
        print()
        r = c.getresponse()
        try:
            j = json.loads(r.read() or b"{}")
        except ValueError:
            j = {}
        c.close()
        if r.status != 200:
            sys.exit(f"Not installed: {j.get('error', r.status)}")
        return j


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default=None, help="device address (default: OTA_HOST from .env, else authkey-esp32.local)")
    ap.add_argument("firmware", nargs="?", default=os.path.join(ROOT, ".pio", "build", "esp32dev", "firmware.bin"))
    a = ap.parse_args()
    dev = Device(a.host or env_host())
    try:
        st, s = dev.request("GET", "/api/status", timeout=8)
    except OSError as e:
        sys.exit(f"Can't reach {dev.host}: {e} (is the web page on? Try --host <device IP>)")
    print(f"{dev.host}: running v{s.get('fw')}, firmware file {os.path.getsize(a.firmware) // 1024} KB")
    if not s.get("auth"):
        dev.allow()
    r = dev.upload(a.firmware)
    print(f"v{r['version']} received ({r['size'] // 1024} KB, image checked). "
          f"Press OK on the AuthKey to install it (INSTALL FIRMWARE?) ...")
    for _ in range(60):
        time.sleep(1)
        try:
            _, p = dev.request("GET", f"/api/update?id={r['id']}")
        except OSError:
            continue
        state = p.get("state")
        if state == "installed":
            break
        if state != "waiting":
            sys.exit("Not installed: " + ("denied on the device" if state == "denied" else p.get("error") or state))
    else:
        sys.exit("Timed out waiting for OK.")
    print("Installed; the AuthKey is restarting ...")
    time.sleep(8)
    for _ in range(40):
        try:
            _, s = dev.request("GET", "/api/status", timeout=4)
            print(f"Back up, running v{s.get('fw')}.")
            return
        except OSError:
            time.sleep(2)
    print("It hasn't come back on the network yet; check the screen.")


if __name__ == "__main__":
    main()
