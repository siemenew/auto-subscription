import base64
import requests
import yaml
from urllib.parse import urlparse

# 在这里填入你自己的公开订阅链接（不含任何节点示例）
SOURCE_URLS = [
    # "https://example.com/clash.yaml",
    # "https://example.com/base64-sub",
]

TIMEOUT = 10


def fetch_text(url: str) -> str:
    try:
        resp = requests.get(url, timeout=TIMEOUT)
        resp.raise_for_status()
        return resp.text.strip()
    except Exception as e:
        print(f"[WARN] 拉取失败: {url} -> {e}")
        return ""


def is_yaml(text: str) -> bool:
    try:
        data = yaml.safe_load(text)
        return isinstance(data, dict)
    except Exception:
        return False


def try_b64_decode(text: str) -> str:
    # 处理常见的 base64 订阅（带换行、缺 padding）
    raw = text.strip()
    raw = raw.replace("\n", "")
    # 补齐 padding
    padding = 4 - (len(raw) % 4)
    if padding and padding < 4:
        raw += "=" * padding
    try:
        return base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_clash_yaml(text: str) -> list:
    """
    解析 Clash YAML，提取 proxies 数组
    """
    try:
        data = yaml.safe_load(text)
        proxies = data.get("proxies", [])
        if isinstance(proxies, list):
            return proxies
    except Exception as e:
        print(f"[WARN] 解析 Clash YAML 失败: {e}")
    return []


def parse_uri_lines(text: str) -> list:
    """
    解析通用订阅（vmess://, ss://, trojan:// 等）
    这里只做“原样收集”，不做协议级解析，
    后续可以接 Clash 转换器处理。
    """
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    uris = []
    for line in lines:
        if "://" in line:
            uris.append(line)
    return uris


def normalize_proxy_for_dedup(proxy) -> str:
    """
    用于去重的 key，尽量不暴露细节：
    - 优先用 name
    - 其次用 server + port
    """
    if isinstance(proxy, dict):
        name = proxy.get("name")
        server = proxy.get("server")
        port = proxy.get("port")
        if name:
            return f"name:{name}"
        if server and port:
            return f"{server}:{port}"
    return str(proxy)


def main():
    all_clash_proxies = []
    all_uri_lines = []

    for url in SOURCE_URLS:
        print(f"[INFO] 拉取订阅: {url}")
        text = fetch_text(url)
        if not text:
            continue

        # 1. 先尝试当作 Clash YAML
        if is_yaml(text):
            print(f"[INFO] 识别为 Clash YAML: {url}")
            proxies = parse_clash_yaml(text)
            all_clash_proxies.extend(proxies)
            continue

        # 2. 尝试当作 base64 订阅
        decoded = try_b64_decode(text)
        if decoded:
            print(f"[INFO] 识别为 Base64 订阅: {url}")
            uris = parse_uri_lines(decoded)
            all_uri_lines.extend(uris)
            continue

        # 3. 直接按文本行解析 URI
        print(f"[INFO] 识别为纯文本 URI 列表: {url}")
        uris = parse_uri_lines(text)
        all_uri_lines.extend(uris)

    # 去重 Clash proxies
    dedup_map = {}
    for p in all_clash_proxies:
        key = normalize_proxy_for_dedup(p)
        dedup_map[key] = p
    clash_proxies_deduped = list(dedup_map.values())

    print(f"[INFO] Clash proxies 数量: 原始={len(all_clash_proxies)}, 去重后={len(clash_proxies_deduped)}")
    print(f"[INFO] URI 节点行数（未转换）: {len(all_uri_lines)}")

    # 读取模板
    with open("sub_template.yaml", "r", encoding="utf-8") as f:
        tpl = yaml.safe_load(f)

    # 写入 Clash proxies
    tpl["proxies"] = clash_proxies_deduped

    # 你也可以把 all_uri_lines 写入一个单独文件，供其他工具转换
    with open("raw_uris.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_uri_lines))

    # 输出最终 Clash 订阅
    with open("sub.yaml", "w", encoding="utf-8") as f:
        yaml.dump(tpl, f, allow_unicode=True)

    print("[INFO] 已生成 sub.yaml 与 raw_uris.txt")


if __name__ == "__main__":
    main()
