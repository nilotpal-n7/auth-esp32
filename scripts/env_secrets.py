# PlatformIO pre-build script: reads secrets from .env (repo root, git-ignored)
# and turns them into the firmware's secrets.h plus the OTA upload settings.
#
#   WIFI_<n>_SSID / WIFI_<n>_PASSWORD   networks imported on first boot (n = 1, 2, ...)
#   OTA_PASSWORD                        over-the-air updates; empty = OTA disabled
#   OTA_HOST                            where `pio run -e ota -t upload` sends firmware
#
# The header is generated inside the build directory, so no secret file lives
# in src/. See .env.example.
import os
import re

Import("env")  # noqa: F821  (provided by PlatformIO)

ROOT = env.subst("$PROJECT_DIR")  # noqa: F821
ENV_FILE = os.path.join(ROOT, ".env")


def load_env(path):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key, value = key.strip(), value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            values[key] = value
    return values


def c_string(s):
    out = []
    for ch in s:
        if ch in "\\\"":
            out.append("\\" + ch)
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.extend("\\x%02x" % b for b in ch.encode("utf-8"))
    # Split after hex escapes so a following hex digit isn't swallowed.
    return '"' + re.sub(r'(\\x[0-9a-f]{2})(?=[0-9a-fA-F])', r'\1""', "".join(out)) + '"'


secrets = load_env(ENV_FILE)
if not os.path.exists(ENV_FILE):
    print("env_secrets: no .env found - building without WiFi networks or OTA (see .env.example)")

networks = []
indices = sorted({int(m.group(1)) for k in secrets for m in [re.match(r"WIFI_(\d+)_SSID$", k)] if m})
for i in indices:
    ssid = secrets.get(f"WIFI_{i}_SSID", "")
    if ssid:
        networks.append((ssid, secrets.get(f"WIFI_{i}_PASSWORD", "")))
ota_password = secrets.get("OTA_PASSWORD", "")
iitg_user = secrets.get("IITG_USERNAME", "")
iitg_pass = secrets.get("IITG_PASSWORD", "")

header = [
    "// Generated from .env by scripts/env_secrets.py - do not edit or commit.",
    "#pragma once",
    "#define SECRET_WIFI_NETWORKS \\",
]
header += [f"    {{ {c_string(s)}, {c_string(p)} }}, \\" for s, p in networks]
header += ["", f"#define SECRET_OTA_PASSWORD {c_string(ota_password)}"]
header += [f"#define SECRET_IITG_USER {c_string(iitg_user)}",
          f"#define SECRET_IITG_PASS {c_string(iitg_pass)}", ""]
content = "\n".join(header)

gen_dir = os.path.join(env.subst("$BUILD_DIR"), "secrets")  # noqa: F821
os.makedirs(gen_dir, exist_ok=True)
gen_file = os.path.join(gen_dir, "authkey_secrets.h")
old = open(gen_file, encoding="utf-8").read() if os.path.exists(gen_file) else None
if old != content:  # rewrite only on change, so unchanged secrets don't force a rebuild
    with open(gen_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
env.Prepend(CPPPATH=[gen_dir])  # noqa: F821
print(f"env_secrets: {len(networks)} WiFi network(s), OTA {'enabled' if ota_password else 'disabled'}, "
      f"IITG portal {'set' if (iitg_user and iitg_pass) else 'off'}")

# OTA uploads: password and host come from .env too.
if env.subst("$UPLOAD_PROTOCOL") == "espota":  # noqa: F821
    if not ota_password:
        print("env_secrets: OTA_PASSWORD is empty in .env - the device has OTA disabled")
    env.Append(UPLOAD_FLAGS=[f"--auth={ota_password}"])  # noqa: F821

    def _no_debug(target, source, env):
        # espota's --debug prints every option, including the password.
        env.Replace(UPLOADERFLAGS=[f for f in env.get("UPLOADERFLAGS", []) if f != "--debug"])

    env.AddPreAction("upload", _no_debug)  # noqa: F821
    if not env.subst("$UPLOAD_PORT"):  # noqa: F821
        env.Replace(UPLOAD_PORT=secrets.get("OTA_HOST", "authkey-esp32.local"))  # noqa: F821
