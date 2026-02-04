import base64
import json
import requests
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
    except Exception as e:
        print(f"[WARN] Base64 解码失败: {e}")
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
        print(f"[WARN] 未找到 {SOURCES_FILE}，将不处理任何源")
    return urls_or_uris


def is_url(s: str) -> bool:
    p = urlparse(s)
    return p.scheme in ("http", "https")


def parse_uri_lines(text: str):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return [l for l in lines if "://" in l]


def parse_vmess_uri(uri: str) -> dict:
    """
    这里只给出结构示例，你自己实现解析逻辑。
    返回 V2Ray vnext 所需字段：
      address, port, id, alterId, security 等
    """
    # TODO: 这里写你自己的 vmess:// 解析逻辑
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
            # 其他协议（vless/trojan等）你可以后续扩展
            print(f"[INFO] 暂不处理协议: {uri[:20]}...")
    return vnext_list


def main():
    all_uris = []

    entries = load_sources()
    print(f"[INFO] 从 {SOURCES_FILE} 读取到 {len(entries)} 条入口")

    for item in entries:
        if is_url(item):
            text = fetch_text(item)
            if not text:
                continue

            # 尝试 Base64 订阅
            decoded = try_b64_decode(text)
            if decoded:
                uris = parse_uri_lines(decoded)
                print(f"[INFO] 从 Base64 订阅解析出 {len(uris)} 条 URI")
                all_uris.extend(uris)
            else:
                # 直接按文本 URI 列表处理
                uris = parse_uri_lines(text)
                print(f"[INFO] 从文本订阅解析出 {len(uris)} 条 URI")
                all_uris.extend(uris)
        else:
            # 本地直接写的 vmess:// / vless:// 等
            all_uris.append(item)

    # 去重
    all_uris = list(dict.fromkeys(all_uris))
    print(f"[INFO] URI 总数（去重后）: {len(all_uris)}")

    # 构建 vnext
    vnext_list = build_vnext_from_uris(all_uris)
    print(f"[INFO] vnext 节点数: {len(vnext_list)}")

    # 读取模板并填充
    with open(V2RAY_TEMPLATE, "r", encoding="utf-8") as f:
        tpl = json.load(f)

    if not tpl.get("outbounds"):
        print("[ERROR] 模板中缺少 outbounds 字段")
        return

    # 这里只处理第一个 outbound，协议 vmess
    tpl["outbounds"][0]["settings"]["vnext"] = vnext_list

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(tpl, f, indent=2, ensure_ascii=False)

    print(f"[INFO] 已生成 {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
