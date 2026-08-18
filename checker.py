from pathlib import Path
import base64
import requests

OUT = Path('output')
OUT.mkdir(exist_ok=True)

URLS = [
    'https://sub.aska.lol/Ux7lmK0xkIl2',
    'https://connliberty.com/connection/subs/dcf2b960-d490-40dd-a18b-1718550f939e',
    'https://akonit.tech/sub/f9afd2d3-3858-403e-bbc9-9a720420c188',
    'https://sub.vlessfo.ru/vlessforu/working_configs.txt',
]

items = []
for url in URLS:
    try:
        r = requests.get(url, timeout=30, headers={'User-Agent': 'Mozilla/5.0'})
        r.raise_for_status()
        text = r.text
        if '://' not in text:
            try:
                padded = text.strip() + '=' * (-len(text.strip()) % 4)
                decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
                if '://' in decoded:
                    text = decoded
            except Exception:
                pass
        for line in text.splitlines():
            line = line.strip()
            low = line.lower()
            if not line:
                continue
            if not low.startswith(('vless://', 'vmess://', 'trojan://', 'hysteria2://', 'hy2://')):
                continue
            if 'russia' in low or 'россия' in low or '🇷🇺' in line:
                continue
            items.append(line)
    except Exception as e:
        print('WARN', url, e)

seen = set()
result = []
for line in items:
    key = line.split('#', 1)[0]
    if key in seen:
        continue
    seen.add(key)
    result.append(line)
    if len(result) >= 50:
        break

joined = chr(10).join(result)
(OUT / 'top50.txt').write_text(joined, encoding='utf-8')
(OUT / 'top50.b64.txt').write_text(base64.b64encode(joined.encode()).decode(), encoding='utf-8')
print('DONE', len(result))
