"""Background features of the AuthKey PC helper (started by qr_bridge.py).

Proximity lock
    Watches the AuthKey's Bluetooth adverts (the device advertises all the time,
    even while connected). When the AuthKey has been out of range for
    `away_seconds`, the PC locks (like Win+L).

    It only locks after it has seen the AuthKey nearby, and every lock disarms
    it until the AuthKey is seen nearby again. So if you sign in with your
    Windows PIN or password while the AuthKey is away, the PC stays unlocked
    instead of locking again in a loop; bring the AuthKey back and auto-lock
    re-arms.

Campus notifications
    Polls the AuthKey's web status (http://authkey-esp32.local/api/status, no
    sign-in needed) and shows a Windows notification when the campus (IITG)
    internet drops, comes back, or the login is stuck (session limit, rejected).

Settings: %LOCALAPPDATA%\\AuthKey\\helper.json (created with defaults on first run).
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import os
import subprocess
import threading
import time
import urllib.request
from xml.sax.saxutils import escape

DEVICE_NAME = "AuthKey-ESP32"
FIDO_SERVICE = "0000fffd-0000-1000-8000-00805f9b34fb"
DATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "AuthKey")
CONFIG_FILE = os.path.join(DATA_DIR, "helper.json")
AUMID = "AuthKey.Helper"

DEFAULTS = {
    "auto_lock": True,
    "away_seconds": 20,          # out of range this long -> lock
    "min_rssi": -85,             # adverts weaker than this count as "away" (dBm; closer to 0 = nearer)
    "campus_notifications": True,
    "device_host": "authkey-esp32.local",
    "device_address": None,      # Bluetooth address, learned automatically
}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    save_config(cfg)   # writes defaults for any missing key
    return cfg


def save_config(cfg: dict):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_FILE)
    except OSError:
        pass


# --- Windows notifications ----------------------------------------------------------

def _register_aumid():
    """Registers "AuthKey" as a notification sender for this user (no admin needed)."""
    import winreg
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\AppUserModelId\{AUMID}") as k:
        winreg.SetValueEx(k, "DisplayName", 0, winreg.REG_SZ, "AuthKey")


def _popup(title: str, body: str, seconds: int = 12):
    """Fallback when Windows notifications are turned off: a small message box
    that closes itself (user32 MessageBoxTimeoutW), shown from its own thread."""
    def show():
        mb = ctypes.windll.user32.MessageBoxTimeoutW
        mb(None, body, f"AuthKey: {title}", 0x40 | 0x40000, 0, seconds * 1000)   # info icon, topmost
    threading.Thread(target=show, daemon=True).start()


def notify(title: str, body: str):
    """Shows a Windows notification (toast via PowerShell's WinRT bridge). If
    notifications are turned off in Windows, falls back to a pop-up."""
    xml = (f"<toast><visual><binding template='ToastGeneric'><text>{escape(title)}</text>"
           f"<text>{escape(body)}</text></binding></visual></toast>")
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;"
        "[Windows.Data.Xml.Dom.XmlDocument,Windows.Data.Xml.Dom.XmlDocument,ContentType=WindowsRuntime]|Out-Null;"
        f"$n=[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{AUMID}');"
        "if($n.Setting -ne 'Enabled'){Write-Output $n.Setting;exit};"
        "$x=New-Object Windows.Data.Xml.Dom.XmlDocument;"
        f"$x.LoadXml('{xml.replace(chr(39), chr(39) * 2)}');"
        "$n.Show([Windows.UI.Notifications.ToastNotification]::new($x));Write-Output Shown"
    )
    try:
        _register_aumid()
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=30, capture_output=True, text=True)
        result = r.stdout.strip()
    except Exception as e:  # noqa: BLE001
        result = f"error {e}"
    if result != "Shown":
        print(f"  Windows notifications unavailable ({result or 'no answer'}); showing a pop-up", flush=True)
        _popup(title, body)


# --- Proximity lock ---------------------------------------------------------------------

class ProximityLock(threading.Thread):
    def __init__(self, cfg: dict, log, watch_only: bool = False):
        super().__init__(name="proximity-lock", daemon=True)
        self.cfg, self.log = cfg, log
        self.watch_only = watch_only   # report the signal, never lock
        self.address: str | None = cfg.get("device_address")
        self.last_near: float | None = None   # monotonic time of the last advert at or above min_rssi
        self.last_rssi: int | None = None
        self.armed = False
        self._report = 0.0

    def _on_advert(self, device, adv):
        named = adv.local_name == DEVICE_NAME or device.name == DEVICE_NAME
        if named and device.address != self.address:
            self.address = device.address
            saved = load_config()      # update just this key on disk
            saved["device_address"] = device.address
            save_config(saved)
            self.log(f"Proximity lock: found {DEVICE_NAME} at {device.address}")
        if device.address != self.address:
            return
        self.last_rssi = adv.rssi
        if adv.rssi >= self.cfg["min_rssi"]:
            self.last_near = time.monotonic()

    def _tick(self, now: float, gap: float):
        since = now - self.last_near if self.last_near is not None else float("inf")
        if self.watch_only:
            self.log(f"signal {self.last_rssi} dBm, " + ("near" if since < 5 else f"away for {since:.0f}s"))
            return
        if gap > 10 and self.armed:
            # The PC slept or the helper stalled: give the adverts time to arrive.
            self.last_near = now
            since = 0
        near = since < 5
        away = since > self.cfg["away_seconds"]
        if near and not self.armed:
            self.armed = True
            self.log(f"Proximity lock: armed (AuthKey nearby, {self.last_rssi} dBm)")
        elif self.armed and away:
            self.armed = False
            self.log(f"Proximity lock: AuthKey away for {self.cfg['away_seconds']}s, locking the PC "
                     "(re-arms when it is back)")
            ctypes.windll.user32.LockWorkStation()
        if now - self._report > 600:
            self._report = now
            state = "armed" if self.armed else "waiting for the AuthKey"
            self.log(f"Proximity lock: {state}; last signal {self.last_rssi} dBm "
                     f"(threshold {self.cfg['min_rssi']})")

    async def _main(self):
        from bleak import BleakScanner
        while True:
            try:
                async with BleakScanner(detection_callback=self._on_advert):
                    self.log("Proximity lock: scanning for the AuthKey")
                    prev = time.monotonic()
                    while True:
                        await asyncio.sleep(1)
                        now = time.monotonic()
                        self._tick(now, now - prev)
                        prev = now
            except Exception as e:  # noqa: BLE001  (Bluetooth off / adapter missing)
                if self.armed:
                    self.log("Proximity lock: disarmed (Bluetooth unavailable)")
                self.armed = False
                self.log(f"Proximity lock: Bluetooth unavailable ({e}); retrying in 30 s")
                await asyncio.sleep(30)

    def run(self):
        asyncio.run(self._main())


# --- Campus notifications -----------------------------------------------------------------

class CampusNotifier(threading.Thread):
    POLL = 15

    def __init__(self, cfg: dict, log):
        super().__init__(name="campus-notify", daemon=True)
        self.cfg, self.log = cfg, log
        self.host_ip: str | None = None
        self.prev: dict | None = None
        self.unreachable_since: float | None = None

    def _fetch(self) -> dict | None:
        for host in [h for h in (self.host_ip, self.cfg["device_host"]) if h]:
            try:
                with urllib.request.urlopen(f"http://{host}/api/status", timeout=4) as r:
                    st = json.load(r)
                ip = st.get("wifi", {}).get("ip")
                if ip and ip != "0.0.0.0":
                    self.host_ip = ip   # skip the .local lookup next time
                return st
            except Exception:  # noqa: BLE001
                continue
        return None

    def _check(self, c: dict):
        p = self.prev
        self.prev = c
        if p is None or not c.get("have"):
            return
        if p["online"] and not c["online"]:
            if c["paused"]:
                return   # logged out on purpose
            body = ("IITG session ended. The AuthKey is logging back in..." if c["auto"]
                    else "IITG session ended and auto-login is off. Log in from the AuthKey menu.")
            notify("Campus internet dropped", body)
            self.log(f"Campus: dropped ({c['state']})")
        elif not p["online"] and c["online"]:
            notify("Campus internet is back", f"Logged in again ({c.get('last') or 'online'}).")
            self.log("Campus: back online")
        elif c["state"] != p["state"] and c["state"] in ("limit reached", "login failed"):
            body = (f"IITG says the session limit is reached. Retrying every 5 minutes. ({c.get('last', '')})"
                    if c["state"] == "limit reached"
                    else f"IITG rejected the login: {c.get('last', '')}. Check IITG_PASSWORD in .env.")
            notify("Campus login stuck", body)
            self.log(f"Campus: {c['state']}")

    def run(self):
        while True:
            st = self._fetch()
            if st is None:
                if self.unreachable_since is None:
                    self.unreachable_since = time.monotonic()
                    self.log("Campus: AuthKey web status not reachable (is it on WiFi?)")
            else:
                if self.unreachable_since is not None:
                    self.log("Campus: AuthKey reachable again")
                self.unreachable_since = None
                self._check(st.get("campus", {}))
            time.sleep(self.POLL)


def start(log, lock: bool = True, campus: bool = True) -> dict:
    cfg = load_config()
    if lock and cfg["auto_lock"]:
        ProximityLock(cfg, log).start()
    else:
        log("Proximity lock: off")
    if campus and cfg["campus_notifications"]:
        CampusNotifier(cfg, log).start()
    return cfg


if __name__ == "__main__":
    # Quick checks:  python tools/presence.py notify   |   python tools/presence.py watch
    import sys
    if sys.argv[1:] == ["notify"]:
        notify("AuthKey test", "Notifications from the AuthKey helper work.")
        time.sleep(13)   # keep the pop-up fallback alive
    else:
        def _log(m):
            print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)
        ProximityLock(load_config(), _log, watch_only=True).start()
        while True:
            time.sleep(1)
