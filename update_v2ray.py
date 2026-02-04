import base64
import json
import requests
import yaml
from urllib.parse import urlparse

SOURCES_FILE = "sources.txt"
V2RAY_TEMPLATE = "v2ray_template.json"
OUTPUT_FILE = "v2ray.json"
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


def parse_clash_yaml(text: str) -> list:
    """
    解析 Clash YAML，提取 vmess 节点并转换成 V2Ray vnext 格式
    """
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


def parse_vmess_uri(uri: str) -> dict:
    """
    解析 vmess://xxx
    返回 V2Ray vnext 所需字段
    """
    # TODO: 这里你可以实现完整的 vmess:// Base64 解码逻辑
    return {
        "address": "example.com",
        "port": 443,
        "id": "00000000-0000-0000-0000-000000000000",
        "alterId": 0,
        "security": "auto"
    }


def build_vnext_from_uris(uris):
    vnext_list = []
    for uri in uris:
        if uri.startswith("vmess://"):
            node = parse_vmess_uri(uri)
            vnext_list.append({
                "address": node["address"],
                "port": node["port"],
                "users": [
                    {
                        "id": node["id"],
                        "alterId": node["alterId"],
                        "security": node["security"]
                    }
                ]
            })
        else:
            print(f"[INFO] 暂不处理协议: {uri[:20]}...")
    return vnext_list


def main():
    all_vnext = []

    entries = load_sources()
    print(f"[INFO] 从 {SOURCES_FILE} 读取到 {len(entries)} 条入口")

    for item in entries:
        if is_url(item):
            text = fetch_text(item)
            if not text:
                continue

            # 先尝试 YAML
            if "proxies:" in text:
                vnext_list = parse_clash_yaml(text)
                all_vnext.extend(vnext_list)
                continue

            # 尝试 Base64
            decoded = try_b64_decode(text)
            if decoded:
                uris = parse_uri_lines(decoded)
                vnext_list = build_vnext_from_uris(uris)
                all_vnext.extend(vnext_list)
                continue

            # 直接按文本 URI
            uris = parse_uri_lines(text)
            vnext_list = build_vnext_from_uris(uris)
            all_vnext.extend(vnext_list)
        else:
            # 本地直接写的 URI
            if item.startswith("vmess://"):
                node = parse_vmess_uri(item)
                all_vnext.append({
                    "address": node["address"],
                    "port": node["port"],
                    "users": [
                        {
                            "id": node["id"],
                            "alterId": node["alterId"],
                            "security": node["security"]
                        }
                    ]
                })

    # 去重
    seen = set()
    deduped = []
    for v in all_vnext:
        key = f"{v['address']}:{v['port']}"
        if key not in seen:
            seen.add(key)
            deduped.append(v)

    print(f"[INFO] vnext 节点数: {len(deduped)}")

    # 读取模板并填充
    with open(V2RAY_TEMPLATE, "r", encoding="utf-8") as f:
        tpl = json.load(f)

    tpl["outbounds"][0]["settings"]["vnext"] = deduped

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(tpl, f, indent=2, ensure_ascii=False)

    print(f"[INFO] 已生成 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
