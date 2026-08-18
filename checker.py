import asyncio
import base64
import json
import os
import socket
import statistics
import time
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
ALLOWED_SCHEMES = ("vless://", "vmess://", "trojan://", "hysteria2://", "hy2://")

SUBSCRIPTIONS = [
    {"name": "aska", "value": "https://sub.aska.lol/Ux7lmK0xkIl2"},
    {"name": "connliberty", "value": "https://connliberty.com/connection/subs/dcf2b960-d490-40dd-a18b-1718550f939e"},
    {"name": "akonit", "value": "https://akonit.tech/sub/f9afd2d3-3858-403e-bbc9-9a720420c188"},
    {"name": "vlessforu", "value": "https://sub.vlessfo.ru/vlessforu/working_configs.txt"},
]

COUNTRY_MAP = {
    "NL": "Нидерланды",
    "FI": "Финляндия",
    "SE": "Швеция",
    "DE": "Германия",
    "FR": "Франция",
    "IT": "Италия",
    "ES": "Испания",
    "TR": "Турция",
    "GB": "Великобритания",
    "US": "США",
    "CA": "Канада",
    "SG": "Сингапур",
    "JP": "Япония",
    "LV": "Латвия",
    "GR": "Греция",
    "PL": "Польша",
    "UNKNOWN": "Неизвестно",
}

FLAG_MAP = {
    "NL": "🇳🇱",
    "FI": "🇫🇮",
    "SE": "🇸🇪",
    "DE": "🇩🇪",
    "FR": "🇫🇷",
    "IT": "🇮🇹",
    "ES": "🇪🇸",
    "TR": "🇹🇷",
    "GB": "🇬🇧",
    "US": "🇺🇸",
    "CA": "🇨🇦",
    "SG": "🇸🇬",
    "JP": "🇯🇵",
    "LV": "🇱🇻",
    "GR": "🇬🇷",
    "PL": "🇵🇱",
}

IPINFO_TOKEN = os.getenv("IPINFO_TOKEN", "")


def decode_text(raw):
    text = raw.decode("utf-8", errors="ignore").strip()
    if any(prefix in text for prefix in ALLOWED_SCHEMES):
        return text
    try:
        padded = text + "=" * (-len(text) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        if any(prefix in decoded for prefix in ALLOWED_SCHEMES):
            return decoded
    except Exception:
        pass
    return text


def fetch_subscription(url):
    r = requests.get(url, timeout=30, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return decode_text(r.content)


def extract_lines(text):
    result = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(ALLOWED_SCHEMES):
            result.append(line)
            continue
        for token in line.split():
            if token.startswith(ALLOWED_SCHEMES):
                result.append(token)
    return result


def parse_node(uri, source):
    try:
        scheme = uri.split("://", 1)[0].lower()
        if scheme not in ("vless", "vmess", "trojan", "hysteria2", "hy2"):
            return None
        fragment = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
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
            "name_raw": fragment.strip(),
        }
    except Exception:
        return None


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def country_from_label(label):
    s = label.lower()
    pairs = [
        ("нидер", "NL"), ("netherlands", "NL"), ("nl ", "NL"),
        ("фин", "FI"), ("finland", "FI"),
        ("швец", "SE"), ("sweden", "SE"),
        ("герман", "DE"), ("germany", "DE"),
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
    for token, code in pairs:
        if token in s:
            return code
    return None


def ip_country(ip):
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
        started = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            elapsed = (time.perf_counter() - started) * 1000
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
        return {"success_rate": 0.0, "median_ms": None, "jitter_ms": None}
    return {
        "success_rate": ok / attempts,
        "median_ms": round(statistics.median(times), 1),
        "jitter_ms": round(statistics.pstdev(times), 1) if len(times) > 1 else 0.0,
    }


def calc_score(node):
    probe = node["probe"]
    value = probe["success_rate"] * 100
    if probe["median_ms"] is not None:
        value += max(0, 250 - probe["median_ms"]) / 5
    if probe["jitter_ms"] is not None:
        value -= min(probe["jitter_ms"], 100) / 5
    return round(value, 2)


def rename_node(node, idx):
    cc = node.get("country") or "UNKNOWN"
    country = COUNTRY_MAP.get(cc, cc)
    flag = FLAG_MAP.get(cc, "🌐")
    display_name = f"{flag} {country} #{idx}"
    base = node["uri"].split("#", 1)[0]
    node["display_name"] = display_name
    node["renamed_uri"] = f"{base}#{requests.utils.requote_uri(display_name)}"


async def main():
    all_nodes = []

    for sub in SUBSCRIPTIONS:
        try:
            text = fetch_subscription(sub["value"])
            lines = extract_lines(text)
            for line in lines:
                node = parse_node(line, sub["name"])
                if node:
                    all_nodes.append(node)
        except Exception as e:
            print(f"WARN fetch {sub['name']}: {e}")

    dedup = {}
    for node in all_nodes:
        key = (node["scheme"], node["host"], node["port"], node["uri"].split("#", 1)[0])
        dedup[key] = node
    nodes = list(dedup.values())

    for node in nodes:
        node["resolved_ip"] = resolve_host(node["host"])
        node["country"] = country_from_label(node["name_raw"]) or ip_country(node["resolved_ip"]) or "UNKNOWN"

    nodes = [node for node in nodes if node["country"] not in DENY_COUNTRIES]

    sem = asyncio.Semaphore(80)

    async def run_one(node):
        async with sem:
            node["probe"] = await tcp_probe(node["host"], node["port"])
            node["score"] = calc_score(node)

    await asyncio.gather(*(run_one(node) for node in nodes))

    nodes = [node for node in nodes if node["probe"]["success_rate"] >= 0.67]
    nodes.sort(key=lambda x: (-x["score"], x["probe"]["median_ms"] or 999999))

    selected = []
    counts = {}

    for node in nodes:
        src = node["source"]
        limit = PER_SOURCE_LIMITS.get(src)
        if limit is not None and counts.get(src, 0) >= limit:
            continue
        selected.append(node)
        counts[src] = counts.get(src, 0) + 1
        if len(selected) >= MAX_TOTAL:
            break

    by_country = {}
    for node in selected:
        cc = node.get("country") or "UNKNOWN"
        by_country[cc] = by_country.get(cc, 0) + 1
        rename_node(node, by_country[cc])

    txt = "
".join(node["renamed_uri"] for node in selected)
    (OUT / "top50.txt").write_text(txt, encoding="utf-8")
    (OUT / "top50.b64.txt").write_text(base64.b64encode(txt.encode()).decode(), encoding="utf-8")

    report = []
    for node in selected:
        report.append({
            "display_name": node["display_name"],
            "source": node["source"],
            "scheme": node["scheme"],
            "host": node["host"],
            "port": node["port"],
            "resolved_ip": node["resolved_ip"],
            "country": node["country"],
            "score": node["score"],
            "success_rate": node["probe"]["success_rate"],
            "median_ms": node["probe"]["median_ms"],
            "jitter_ms": node["probe"]["jitter_ms"],
        })

    (OUT / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "summary.yaml").write_text(
        yaml.safe_dump(
            {
                "selected": len(selected),
                "source_counts": counts,
                "country_counts": by_country,
            },
            allow_unicode=True,
            sort_keys=False,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    asyncio.run(main())
