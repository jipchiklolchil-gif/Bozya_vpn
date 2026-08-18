from pathlib import Path
from urllib.parse import unquote

import base64
import requests

OUT = Path("output")
OUT.mkdir(exist_ok=True)

SOURCES = [
    ("aska", "https://sub.aska.lol/Ux7lmK0xkIl2"),
    ("connliberty", "https://connliberty.com/connection/subs/dcf2b960-d490-40dd-a18b-1718550f939e"),
    ("akonit", "https://akonit.tech/sub/f9afd2d3-3858-403e-bbc9-9a720420c188"),
    ("vlessforu", "https://sub.vlessfo.ru/vlessforu/working_configs.txt"),
]

BAD_WORDS = [
    "россия",
    "russia",
    " ru ",
    "🇷🇺",
]

GOOD = [
    ("нидер", "🇳🇱 Нидерланды"),
    ("netherlands", "🇳🇱 Нидерланды"),
    ("фин", "🇫🇮 Финляндия"),
    ("finland", "🇫🇮 Финляндия"),
    ("швец", "🇸🇪 Швеция"),
    ("sweden", "🇸🇪 Швеция"),
    ("герман", "🇩🇪 Германия"),
    ("germany", "🇩🇪 Германия"),
    ("франц", "🇫🇷 Франция"),
    ("france", "🇫🇷 Франция"),
    ("итал", "🇮🇹 Италия"),
    ("italy", "🇮🇹 Италия"),
    ("испан", "🇪🇸 Испания"),
    ("spain", "🇪🇸 Испания"),
    ("турц", "🇹🇷 Турция"),
    ("turkey", "🇹🇷 Турция"),
    ("сша", "🇺🇸 США"),
    ("usa", "🇺🇸 США"),
    ("united states", "🇺🇸 США"),
    ("канада", "🇨🇦 Канада"),
    ("canada", "🇨🇦 Канада"),
    ("синга", "🇸🇬 Сингапур"),
    ("sing", "🇸🇬 Сингапур"),
    ("япон", "🇯🇵 Япония"),
    ("japan", "🇯🇵 Япония"),
    ("латви", "🇱🇻 Латвия"),
    ("latvia", "🇱🇻 Латвия"),
    ("грец", "🇬🇷 Греция"),
    ("greece", "🇬🇷 Греция"),
    ("поль", "🇵🇱 Польша"),
    ("poland", "🇵🇱 Польша"),
]

def decode_text(raw):
    text = raw.decode("utf-8", errors="ignore").strip()
    if "://" in text:
        return text
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text

def rename_label(label, n):
    low = label.lower()
    for key, value in GOOD:
        if key in low:
            return f"{value} #{n}"
    return f"🌐 Неизвестно #{n}"

all_lines = []

for _, url in SOURCES:
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        text = decode_text(r.content)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if not (
                line.startswith("vless://")
                or line.startswith("vmess://")
                or line.startswith("trojan://")
                or line.startswith("hysteria2://")
                or line.startswith("hy2://")
            ):
                continue
            label = ""
            if "#" in line:
                label = unquote(line.split("#", 1)[1]).strip()
            low = f" {label.lower()} "
            blocked = False
            for bad in BAD_WORDS:
                if bad in low:
                    blocked = True
                    break
            if blocked:
                continue
            all_lines.append(line)
    except Exception as e:
        print("WARN", url, e)

unique = []
seen = set()
counts = {}

for line in all_lines:
    key = line.split("#", 1)[0]
    if key in seen:
        continue
    seen.add(key)

    label = ""
    if "#" in line:
        label = unquote(line.split("#", 1)[1]).strip()

    new_name = rename_label(label, counts.get(label, 0) + 1)
    counts[label] = counts.get(label, 0) + 1
    unique.append(line.split("#", 1)[0] + "#" + requests.utils.requote_uri(new_name))

result = unique[:50]
text_out = "
".join(result)

(OUT / "top50.txt").write_text(text_out, encoding="utf-8")
(OUT / "top50.b64.txt").write_text(base64.b64encode(text_out.encode()).decode(), encoding="utf-8")
print("DONE", len(result))
