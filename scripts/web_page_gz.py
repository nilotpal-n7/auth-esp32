# PlatformIO pre-build script: gzips the management page (src/net/web_page.h,
# the HTML between R"HTML( and )HTML") into web_page_gz.h in the build
# directory. The device sends the ~5 KB gzip instead of ~17 KB of HTML: with
# the Telegram TLS session holding most of the RAM, a large send stalls.
import gzip
import os

Import("env")  # noqa: F821  (provided by PlatformIO)

src = os.path.join(env.subst("$PROJECT_DIR"), "src", "net", "web_page.h")  # noqa: F821
text = open(src, encoding="utf-8").read()
start = text.index('R"HTML(') + len('R"HTML(')
end = text.index(')HTML"', start)
html = text[start:end].encode("utf-8")
gz = gzip.compress(html, compresslevel=9, mtime=0)

lines = ["// Generated from src/net/web_page.h by scripts/web_page_gz.py - do not edit.",
         "#pragma once", "#include <stdint.h>", "#include <stddef.h>",
         f"static const size_t WEB_PAGE_GZ_LEN = {len(gz)};",
         "static const uint8_t WEB_PAGE_GZ[] = {"]
for i in range(0, len(gz), 20):
    lines.append("    " + ",".join(str(b) for b in gz[i:i + 20]) + ",")
lines += ["};", ""]
content = "\n".join(lines)

gen_dir = os.path.join(env.subst("$BUILD_DIR"), "webpage")  # noqa: F821
os.makedirs(gen_dir, exist_ok=True)
gen = os.path.join(gen_dir, "web_page_gz.h")
if not os.path.exists(gen) or open(gen, encoding="utf-8").read() != content:
    with open(gen, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
env.Prepend(CPPPATH=[gen_dir])  # noqa: F821
print(f"web_page_gz: page {len(html)} bytes -> {len(gz)} gzip")
