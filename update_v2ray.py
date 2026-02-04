import base64
import json
import re
from urllib.parse import urlparse, parse_qs

def parse_vmess_uri(uri: str) -> dict:
    """
    vmess://Base64(JSON)
    """
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
    """
    vless://uuid@host:port?encryption=none&security=tls
    """
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
    """
    trojan://password@host:port?security=tls
    """
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
    """
    ss://method:password@host:port
    """
    try:
        raw = uri[len("ss://"):]
        # 有些是 base64 编码
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
