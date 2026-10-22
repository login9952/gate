#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线
==========================================
流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt
"""

import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = Path(__file__).resolve().parent
VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = (os.environ.get("CHECK_WORKER") or "").rstrip("/")
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "0"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = Path(os.environ.get("PUBLIC_DIR", str(REPO_DIR / "public")))
TEMPLATE_HTML = REPO_DIR / "web" / "index.html"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_public_dir() -> None:
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    for name in ("data.json", "index.html", "nodes.txt"):
        target = PUBLIC_DIR / name
        if target.exists():
            target.unlink()


def read_text(url: str, timeout: int = 60) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def parse_api_rows(raw_text: str):
    text = raw_text.strip()
    if not text:
        return []

    try:
        payload = json.loads(text)
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("data", "nodes"):
                if isinstance(payload.get(key), list):
                    return payload[key]
    except Exception:
        pass

    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    records = []
    for ln in lines:
        if ln.startswith("#"):
            continue
        if re.search(r"^(Host|HostName|Country|IP|Score)", ln, re.I):
            continue
        if ln.startswith("vpn_gw"):
            continue
        if not any(ch.isdigit() for ch in ln):
            continue
        records.append(ln)

    if not records:
        return []

    reader = csv.reader(io.StringIO("\n".join(records)))
    rows = []
    for row in reader:
        if not row or len(row) < 4:
            continue
        rows.append(row)
    return rows


def normalize_node_rows(rows):
    nodes = []
    for row in rows:
        if isinstance(row, dict):
            host = str(row.get("Host") or row.get("HostName") or row.get("host") or "").strip()
            port = str(row.get("Port") or row.get("port") or "443").strip()
            country = str(row.get("CountryLong") or row.get("Country") or row.get("country") or "Unknown").strip()
            country_code = str(row.get("CountryShort") or row.get("country_code") or "?").strip().upper()
            if not host:
                continue
            nodes.append({
                "host": host,
                "port": port,
                "country": country,
                "country_code": country_code,
                "raw": row,
            })
            continue

        if isinstance(row, str):
            parts = [p.strip() for p in row.split()]
            if len(parts) < 2:
                continue
            host = parts[0]
            port = parts[1] if re.fullmatch(r"\d+", parts[1]) else "443"
            country = parts[2] if len(parts) >= 3 else "Unknown"
            country_code = parts[3] if len(parts) >= 4 else "?"
            nodes.append({
                "host": host,
                "port": port,
                "country": country,
                "country_code": country_code,
                "raw": {"host": host, "port": port, "country": country},
            })
            continue

        if isinstance(row, (list, tuple)):
            row = [str(x).strip() for x in row]
            if len(row) < 2:
                continue
            host = row[0]
            port = row[1] if re.fullmatch(r"\d+", row[1]) else "443"
            country = row[2] if len(row) > 2 else "Unknown"
            country_code = row[3] if len(row) > 3 else "?"
            if not host:
                continue
            nodes.append({
                "host": host,
                "port": port,
                "country": country,
                "country_code": country_code,
                "raw": {"host": host, "port": port, "country": country},
            })

    seen = set()
    deduped = []
    for item in nodes:
        key = (item["host"], item["port"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def fetch_nodes():
    urls = [VPNGATE_API, VPNGATE_MIRROR]
    last_error = None
    for url in urls:
        if not url:
            continue
        try:
            raw = read_text(url, timeout=HTTP_TIMEOUT)
            rows = parse_api_rows(raw)
            nodes = normalize_node_rows(rows)
            if nodes:
                return nodes
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    if last_error:
        print(f"warn: fetch nodes failed, fallback to empty dataset: {last_error}", file=sys.stderr)
    return []


def worker_url_for(host: str, port: str):
    if not WORKER_CHECK_URL:
        return None
    base = WORKER_CHECK_URL.rstrip("/")
    if "sstp=" in base:
        return base.replace("sstp=", f"sstp=vpn:vpn@{host}:{port}")
    if base.endswith("@"):
        return f"{base}{host}:{port}"
    if "?" in base:
        return f"{base}&sstp=vpn:vpn@{host}:{port}"
    if base.endswith("/check") or base.endswith("/check/"):
        return f"{base}?sstp=vpn:vpn@{host}:{port}"
    if base.endswith("/"):
        return f"{base}check?sstp=vpn:vpn@{host}:{port}"
    return f"{base}/check?sstp=vpn:vpn@{host}:{port}"


def detect_node(host: str, port: str):
    result = {
        "host": host,
        "port": port,
        "country": "Unknown",
        "country_code": "?",
        "residential": "unknown",
        "latency_ms": None,
        "success": False,
        "checked_at": utc_now_iso(),
        "exit": {},
    }
    url = worker_url_for(host, port)
    if not url:
        result["success"] = True
        result["residential"] = "unknown"
        result["checked_at"] = utc_now_iso()
        return result

    try:
        resp = requests.get(url, timeout=CHECK_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        if isinstance(payload, dict):
            result["success"] = bool(payload.get("success"))
            result["residential"] = str(payload.get("residential") or "unknown")
            result["latency_ms"] = payload.get("latency_ms")
            result["country"] = payload.get("country") or result["country"]
            result["country_code"] = str(payload.get("country_code") or result["country_code"]).upper()
            result["exit"] = payload.get("exit") or {}
            if payload.get("checked_at"):
                result["checked_at"] = payload["checked_at"]
    except Exception as exc:
        print(f"warn: check failed for {host}:{port}: {exc}", file=sys.stderr)
        result["success"] = False
        result["residential"] = "unknown"
        result["exit"] = {}
    return result


def iter_detected_nodes(nodes):
    if MAX_CHECK_NODES > 0:
        nodes = nodes[:MAX_CHECK_NODES]

    detected = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        future_map = {executor.submit(detect_node, item["host"], item["port"]): item for item in nodes}
        for future in as_completed(future_map):
            item = future_map[future]
            try:
                detected.append(future.result())
            except Exception as exc:
                print(f"warn: detection error for {item['host']}:{item['port']}: {exc}", file=sys.stderr)
    detected.sort(key=lambda n: (0 if n.get("success") else 1, n.get("host") or ""))
    return detected, len(nodes)


def build_country_map(rows):
    countries = {}
    for row in rows:
        if not row.get("success"):
            continue
        country = row.get("country") or "Unknown"
        code = (row.get("country_code") or "?").upper()
        bucket = countries.setdefault(country, {"code": code, "nodes": [], "residential": 0, "datacenter": 0})
        bucket["nodes"].append(row)
        if row.get("residential") == "residential":
            bucket["residential"] += 1
        elif row.get("residential") == "datacenter":
            bucket["datacenter"] += 1
    for info in countries.values():
        info["nodes"] = sorted(
            info["nodes"],
            key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 9999, n.get("host") or ""),
        )
    return dict(sorted(countries.items(), key=lambda kv: (-len(kv[1]["nodes"]), kv[0])))


def write_nodes_txt(rows):
    lines = []
    for row in rows:
        if not row.get("success"):
            continue
        host = row.get("host")
        port = row.get("port")
        if not host or not port:
            continue
        lines.append(f"sstp://vpn:vpn@{host}:{port}")
    target = PUBLIC_DIR / "nodes.txt"
    target.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_data_json(rows):
    countries = build_country_map(rows)
    stats = {
        "sstp_nodes": len(rows),
        "checked": len(rows),
        "success": sum(1 for row in rows if row.get("success")),
        "countries": len(countries),
        "residential_est": sum(1 for row in rows if row.get("residential") == "residential"),
        "datacenter_est": sum(1 for row in rows if row.get("residential") == "datacenter"),
    }
    data = {
        "generated_at": utc_now_iso(),
        "source": "VPN Gate + Cloudflare Worker",
        "stats": stats,
        "countries": countries,
    }
    (PUBLIC_DIR / "data.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def write_index_html():
    if TEMPLATE_HTML.exists():
        html = TEMPLATE_HTML.read_text(encoding="utf-8")
    else:
        html = """<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>VPN Gate SSTP</title></head><body><h1>VPN Gate SSTP 节点检测</h1><p>data.json 加载失败，等待下一次 Action 生成。</p></body></html>"""
    (PUBLIC_DIR / "index.html").write_text(html, encoding="utf-8")


def main():
    ensure_public_dir()
    raw_nodes = fetch_nodes()
    print(f"raw nodes: {len(raw_nodes)}")

    detected, _ = iter_detected_nodes(raw_nodes)
    print(f"detected nodes: {len(detected)}")

    write_data_json(detected)
    write_nodes_txt(detected)
    write_index_html()

    print(f"Wrote files to {PUBLIC_DIR}")
    print(f"- data.json: {len((PUBLIC_DIR / 'data.json').read_bytes())} bytes")
    print(f"- nodes.txt: {len((PUBLIC_DIR / 'nodes.txt').read_text(encoding='utf-8'))} chars")
    print(f"- index.html: {len((PUBLIC_DIR / 'index.html').read_bytes())} bytes")


if __name__ == "__main__":
    main()
