import asyncio, base64, json, os, re, socket, statistics, time
from pathlib import Path
from urllib.parse import unquote, urlsplit

import requests
import yaml

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"
OUT.mkdir(exist_ok=True)

MAX_TOTAL = 50
PER_SOURCE_LIMITS = {
    "aska": 5,
    "akonit": 10,
}
DENY_COUNTRIES = {"RU"}
ALLOWED_SCHEMES = {"vless", "vmess", "trojan", "hysteria2", "hy2"}

SUBSCRIPTIONS = [
    {"name": "aska", "type": "url", "value": "https://sub.aska.lol/Ux7lmK0xkIl2"},
    {"name": "connliberty", "type": "url", "value": "https://connliberty.com/connection/subs/dcf2b960-d490-40dd-a18b-1718550f939e"},
    {"name": "akonit", "type": "url", "value": "https://akonit.tech/sub/f9afd2d3-3858-403e-bbc9-9a720420c188"},
    {"name": "crypt5", "type": "literal", "value": "happ://crypt5/fzvddadgPcZyMOoQyrEz0BJF17qyI26TmLWkDN3W93Dcmku+tMeQ9hCbe/ZmxVSL1PyIdiz+zmGOLBVwFSBdGPLxx7NvVE77MgmpdvPXsxZO+cMr/W9gGF1cz8qIlvQsYOU3dPYLt3ezbqMlQVI7ESf30RmJakjAOlqlqjPEPEJ4QtJ5KZPiD2GtylnhuP9pqULwV5pUQMMotiZFM8VXjtHrfMcEs/PpbL+iIHpDEH9MIW+GoJQ/xakZz+X6GLj56+s9H2VC5+H16bH3PZz45DTFOH6QIkGoGJzQ/Lei0jnKNfUNBqxxYXldZHQ1kT85nFo5MEwyBlxDEyR2lBhTy+t9fhNEGuHDToolMAK/Oo0b9sToXfGaWOSlNvf25J+BMRwwi8m7AsyBSl0OULkaUU3HOORiEWVutU5oOWuWvaHT8N/LHUtCTiM6aY+GVeIyLVWMEhJ7GuyyQ68n5PfuGqYT5QFKdEV2q3EmL+1wq6ZpPeYbxZPR0x5fSvlcvY2fzwoZhlXHCsT9k1r8PcvtiDeikv10BtE8fq45QOKoRoZf+KG/AgYpE6kjdR4XjUD9kzYAv3xXwXmoMFpcq5u4SqjAmEPpQe0b4GAglqrFMtLXFrXKfQdAyctE5zR+mqTFIeyxtHIsAuSLti2J9IDB06IAz96ezXPi6rKqWY3bgcR8TXejnpHiIwE+sCQKft5FSXbgAifaKqWR442I/8Yh8Qq7dOmZeRpbYCuQXV34UyY48VafoSgzKle2jVEvXpMBYyRGioGEUmfpcyQdq/tJW+VSN7vzK/wyg0QH5KxIXzppxO0NaN02gVKzo8OWiMz0uozGO9ese0xxxtHnI6jri+xXotImNp05unecHkdD83AS7iXKlUDViZ8wfoI=ff"},
    {"name": "vlessforu", "type": "url", "value": "https://sub.vlessfo.ru/vlessforu/working_configs.txt"},
]

COUNTRY_MAP = {
    "NL": "Нидерланды", "FI": "Финляндия", "SE": "Швеция", "DE": "Германия",
    "FR": "Франция", "IT": "Италия", "ES": "Испания", "TR": "Турция",
    "GB": "Великобритания", "US": "США", "CA": "Канада", "SG": "Сингапур",
    "JP": "Япония", "LV": "Латвия", "GR": "Греция", "PL": "Польша",
    "EE": "Эстония", "NO": "Норвегия", "CH": "Швейцария", "RO": "Румыния",
    "CZ": "Чехия", "LT": "Литва", "HU": "Венгрия", "AT": "Австрия",
    "IE": "Ирландия", "UNKNOWN": "Неизвестно"
}
FLAG_MAP = {
    "NL":"🇳🇱","FI":"🇫🇮","SE":"🇸🇪","DE":"🇩🇪","FR":"🇫🇷","IT":"🇮🇹","ES":"🇪🇸","TR":"🇹🇷",
    "GB":"🇬🇧","US":"🇺🇸","CA":"🇨🇦","SG":"🇸🇬","JP":"🇯🇵","LV":"🇱🇻","GR":"🇬🇷","PL":"🇵🇱",
    "EE":"🇪🇪","NO":"🇳🇴","CH":"🇨🇭","RO":"🇷🇴","CZ":"🇨🇿","LT":"🇱🇹","HU":"🇭🇺","AT":"🇦🇹","IE":"🇮🇪"
}

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")

def decode_text(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="ignore").strip()
    if any(s in text for s in ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://")):
        return text
    try:
        padded = text + "=" * (-len(text) % 4)
        dec = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(s in dec for s in ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://")):
            return dec
    except Exception:
        pass
    return text

def fetch_subscription(sub):
    if sub["type"] == "literal":
        return sub["value"]
    r = requests.get(sub["value"], timeout=30, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return decode_text(r.content)

def extract_lines(text: str):
    lines = []
    for part in re.split(r"[
]+", text):
        part = part.strip()
        if not part:
            continue
        candidates = re.findall(r'(?:vless|vmess|trojan|hysteria2|hy2)://[^s]+', part)
        if candidates:
            lines.extend(candidates)
        elif "://" in part:
            lines.append(part)
    return lines

def parse_node(uri: str, source: str):
    scheme = uri.split("://", 1)[0].lower()
    if scheme not in ALLOWED_SCHEMES:
        return None
    try:
        frag = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
        base = uri.split("#", 1)[0]
        parsed = urlsplit(base)
        host = parsed.hostname
        port = parsed.port
        if not host or not port:
            return None
        return {
            "source": source,
            "uri": uri,
            "scheme": scheme,
            "host": host,
            "port": int(port),
            "name_raw": frag.strip(),
        }
    except Exception:
        return None

def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def country_from_label(label: str):
    s = label.lower()
    patterns = [
        ("нидер", "NL"), ("netherlands", "NL"), ("nl ", "NL"),
        ("фин", "FI"), ("finland", "FI"),
        ("швец", "SE"), ("sweden", "SE"),
        ("герман", "DE"), ("germany", "DE"), ("gemini", "DE"),
        ("франц", "FR"), ("france", "FR"),
        ("итал", "IT"), ("italy", "IT"),
        ("испан", "ES"), ("spain", "ES"),
        ("турц", "TR"), ("turkey", "TR"),
        ("великобрит", "GB"), ("united kingdom", "GB"),
        ("сша", "US"), ("usa", "US"), ("united states", "US"),
        ("канада", "CA"), ("canada", "CA"),
        ("синга", "SG"), ("sing", "SG"),
        ("япон", "JP"), ("japan", "JP"),
        ("латви", "LV"), ("latvia", "LV"),
        ("грец", "GR"), ("greece", "GR"),
        ("поль", "PL"), ("poland", "PL"),
        ("росс", "RU"), ("russia", "RU"),
    ]
    for token, code in patterns:
        if token in s:
            return code
    return None

def ip_country(ip: str):
    if not ip or not IPINFO_TOKEN:
        return None
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10, params={"token": IPINFO_TOKEN})
        if r.ok:
            return r.json().get("country")
    except Exception:
        pass
    return None

async def tcp_probe(host, port, timeout=3.5, attempts=3):
    times = []
    ok = 0
    for _ in range(attempts):
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(round(elapsed, 1))
            ok += 1
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            pass
    if not times:
        return {"success_rate": 0.0, "median_ms": None, "jitter_ms": None, "best_ms": None}
    return {
        "success_rate": ok / attempts,
        "median_ms": round(statistics.median(times), 1),
        "jitter_ms": round(statistics.pstdev(times), 1) if len(times) > 1 else 0.0,
        "best_ms": min(times),
    }

def score(node):
    s = node["probe"]["success_rate"] * 100
    if node["probe"]["median_ms"] is not None:
        s += max(0, 250 - node["probe"]["median_ms"]) / 5
    if node["probe"]["jitter_ms"] is not None:
        s -= min(node["probe"]["jitter_ms"], 100) / 5
    return round(s, 2)

def rename_node(node, idx):
    cc = node.get("country") or "UNKNOWN"
    country = COUNTRY_MAP.get(cc, cc)
    flag = FLAG_MAP.get(cc, "🌐")
    display_name = f"{flag} {country} #{idx}"
    node["display_name"] = display_name
    base = node["uri"].split("#", 1)[0]
    node["renamed_uri"] = f"{base}#{requests.utils.requote_uri(display_name)}"

async def main():
    all_nodes = []
    for sub in SUBSCRIPTIONS:
        try:
            text = fetch_subscription(sub)
            lines = extract_lines(text)
            for line in lines:
                node = parse_node(line, sub["name"])
                if node:
                    all_nodes.append(node)
        except Exception as e:
            print(f"WARN fetch {sub['name']}: {e}")

    dedup = {}
    for n in all_nodes:
        dedup[(n["scheme"], n["host"], n["port"], n["uri"].split("#",1)[0])] = n
    nodes = list(dedup.values())

    for n in nodes:
        n["resolved_ip"] = resolve_host(n["host"])
        n["country"] = country_from_label(n["name_raw"]) or ip_country(n["resolved_ip"]) or "UNKNOWN"

    nodes = [n for n in nodes if n["country"] not in DENY_COUNTRIES]

    sem = asyncio.Semaphore(80)

    async def run_probe(n):
        async with sem:
            n["probe"] = await tcp_probe(n["host"], n["port"])
            n["score"] = score(n)

    await asyncio.gather(*(run_probe(n) for n in nodes))
    nodes = [n for n in nodes if n["probe"]["success_rate"] >= 0.67]
    nodes.sort(key=lambda x: (-x["score"], x["probe"]["median_ms"] or 99999))

    selected = []
    counts = {}
    for n in nodes:
        src = n["source"]
        lim = PER_SOURCE_LIMITS.get(src)
        if lim is not None and counts.get(src, 0) >= lim:
            continue
        selected.append(n)
        counts[src] = counts.get(src, 0) + 1
        if len(selected) >= MAX_TOTAL:
            break

    by_country = {}
    for n in selected:
        cc = n.get("country") or "UNKNOWN"
        by_country[cc] = by_country.get(cc, 0) + 1
        rename_node(n, by_country[cc])

    txt = "
".join(n["renamed_uri"] for n in selected)
    (OUT / "top50.txt").write_text(txt, encoding="utf-8")
    (OUT / "top50.b64.txt").write_text(base64.b64encode(txt.encode()).decode(), encoding="utf-8")

    report = [
        {
            "display_name": n["display_name"],
            "source": n["source"],
            "scheme": n["scheme"],
            "host": n["host"],
            "port": n["port"],
            "resolved_ip": n["resolved_ip"],
            "country": n["country"],
            "score": n["score"],
            **n["probe"],
        }
        for n in selected
    ]
    (OUT / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    summary = {
        "selected": len(selected),
        "source_counts": counts,
        "country_counts": by_country,
        "generated_files": ["output/top50.txt", "output/top50.b64.txt", "output/report.json"],
    }
    (OUT / "summary.yaml").write_text(yaml.safe_dump(summary, allow_unicode=True, sort_keys=False), encoding="utf-8")

if __name__ == "__main__":
    asyncio.run(main())
