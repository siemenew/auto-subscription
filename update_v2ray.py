import base64
import json
import re
import requests
import yaml
from urllib.parse import urlparse, parse_qs

SOURCES_FILE = "sources.txt"
V2RAY_TEMPLATE = "v2ray_template.json"
OUTPUT_V2RAY = "v2ray.json"
OUTPUT_CLASH = "clash.yaml"
OUTPUT_SINGBOX = "singbox.json"
TIMEOUT = 10


def fetch_text(url: str) -> str:
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        print(f"[INFO] 拉取成功: {url} ({len(resp.text)} 字符)")
        return resp.text.strip()
    except Exception as e:
        print(f"[WARN] 拉取失败: {url} -> {e}")
        return ""


def try_b64_decode(text: str) -> str:
    raw = text.strip().replace("\n", "")
    padding = 4 - (len(raw) % 4)
    if padding and padding < 4:
        raw += "=" * padding
    try:
        return base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def load_sources():
    urls_or_uris = []
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                urls_or_uris.append(line)
    except FileNotFoundError:
        print(f"[WARN] 未找到 {SOURCES_FILE}")
    return urls_or_uris


def is_url(s: str) -> bool:
    p = urlparse(s)
    return p.scheme in ("http", "https")


def parse_uri_lines(text: str):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return [l for l in lines if "://" in l]


# ---------------- 协议解析器 ----------------

def parse_vmess_uri(uri: str) -> dict:
    try:
        raw = uri[len("vmess://"):]
        data = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode("utf-8")
        node = json.loads(data)
        return {
            "address": node.get("add", "example.com"),
            "port": int(node.get("port", 443)),
            "id": node.get("id", "00000000-0000-0000-0000-000000000000"),
            "alterId": int(node.get("aid", 0)),
            "security": node.get("scy", "auto")
        }
    except Exception as e:
        print(f"[WARN] vmess 解析失败: {e}")
        return {}


def parse_vless_uri(uri: str) -> dict:
    try:
        u = urlparse(uri)
        uuid = u.username
        host = u.hostname
        port = u.port or 443
        qs = parse_qs(u.query)
        return {
            "address": host,
            "port": port,
            "id": uuid,
            "security": qs.get("security", ["none"])[0]
        }
    except Exception as e:
        print(f"[WARN] vless 解析失败: {e}")
        return {}


def parse_trojan_uri(uri: str) -> dict:
    try:
        u = urlparse(uri)
        pwd = u.username
        host = u.hostname
        port = u.port or 443
        qs = parse_qs(u.query)
        return {
            "address": host,
            "port": port,
            "password": pwd,
            "security": qs.get("security", ["tls"])[0]
        }
    except Exception as e:
        print(f"[WARN] trojan 解析失败: {e}")
        return {}


def parse_ss_uri(uri: str) -> dict:
    try:
        raw = uri[len("ss://"):]
        if not re.match(r".+@.+:\d+", raw):
            decoded = base64.b64decode(raw + '=' * (-len(raw) % 4)).decode("utf-8")
        else:
            decoded = raw
        method_pwd, server_port = decoded.split("@")
        method, pwd = method_pwd.split(":")
        host, port = server_port.split(":")
        return {
            "address": host,
            "port": int(port),
            "method": method,
            "password": pwd
        }
    except Exception as e:
        print(f"[WARN] ss 解析失败: {e}")
        return {}


def parse_clash_yaml(text: str) -> list:
    try:
        data = yaml.safe_load(text)
        proxies = data.get("proxies", [])
        vnext_list = []
        for p in proxies:
            if p.get("type") == "vmess":
                vnext_list.append({
                    "address": p.get("server", "example.com"),
                    "port": p.get("port", 443),
                    "users": [
                        {
                            "id": p.get("uuid", "00000000-0000-0000-0000-000000000000"),
                            "alterId": p.get("alterId", 0),
                            "security": p.get("cipher", "auto")
                        }
                    ]
                })
        return vnext_list
    except Exception as e:
        print(f"[WARN] Clash YAML 解析失败: {e}")
        return []


# ---------------- 输出函数 ----------------

def output_v2ray(vnext_list):
    try:
        with open(V2RAY_TEMPLATE, "r", encoding="utf-8") as f:
            tpl = json.load(f)
    except FileNotFoundError:
        tpl = {"outbounds": [{"protocol": "vmess", "settings": {"vnext": []}}]}
    tpl["outbounds"][0]["settings"]["vnext"] = vnext_list or []
    with open(OUTPUT_V2RAY, "w", encoding="utf-8") as f:
        json.dump(tpl, f, indent=2, ensure_ascii=False)
    print("[INFO] 已生成 v2ray.json")


def output_clash(proxies):
    clash_config = {
        "proxies": proxies or [],
        "proxy-groups": [
            {
                "name": "Auto",
                "type": "select",
                "proxies": ["DIRECT"] + [p.get("name", "node") for p in (proxies or [])]
            }
        ],
        "rules": ["MATCH,Auto"]
    }
    with open(OUTPUT_CLASH, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True)
    print("[INFO] 已生成 clash.yaml")


def output_singbox(outbounds):
    singbox_config = {
        "outbounds": outbounds or []
    }
    with open(OUTPUT_SINGBOX, "w", encoding="utf-8") as f:
        json.dump(singbox_config, f, indent=2, ensure_ascii=False)
    print("[INFO] 已生成 singbox.json")


# ---------------- 主流程 ----------------

def main():
    entries = load_sources()
    print(f"[INFO] 从 {SOURCES_FILE} 读取到 {len(entries)} 条入口")

    vnext_list = []
    clash_proxies = []
    singbox_outbounds = []

    for item in entries:
        text = ""
        if is_url(item):
            text = fetch_text(item)
            if not text:
                continue
            if "proxies:" in text:
                vnext_list.extend(parse_clash_yaml(text))
                continue
            decoded = try_b64_decode(text)
            if decoded:
                uris = parse_uri_lines(decoded)
            else:
                uris = parse_uri_lines(text)
        else:
            uris = [item]

        for uri in uris:
            if uri.startswith("vmess://"):
                node = parse_vmess_uri(uri)
                if node:
                    vnext_list.append({
                        "address": node["address"],
                        "port": node["port"],
                        "users": [{"id": node["id"], "alterId": node["alterId"], "security": node["security"]}]
                    })
                    clash_proxies.append({"name": "vmess-node", "type": "vmess", "server": node["address"], "port": node["port"], "uuid": node["id"]})
                    singbox_outbounds.append({"type": "vmess", "server": node["address"], "port": node["port"], "uuid": node["id"]})

            elif uri.startswith("vless://"):
    node = parse_vless_uri(uri)
    if node:
        vnext_list.append({
            "address": node["address"],
            "port": node["port"],
            "users": [{"id": node["id"], "security": node["security"]}]
        })
        clash_proxies.append({
            "name": "vless-node",
            "type": "vless",
            "server": node["address"],
            "port": node["port"],
            "uuid": node["id"]
        })
        singbox_outbounds.append({
            "type": "vless",
            "server": node["address"],
            "port": node["port"],
            "uuid": node["id"]
        })
