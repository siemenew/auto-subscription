import yaml
import requests

# 你可以把公开源放在这里（不含任何节点）
SOURCE_URLS = [
    # "https://example.com/free1",
    # "https://example.com/free2"
]

def fetch(url):
    try:
        return requests.get(url, timeout=10).text
    except:
        return ""

def main():
    proxies = []

    # 拉取所有公开源（你自己填）
    for url in SOURCE_URLS:
        data = fetch(url)
        if data:
            proxies.append(data)

    # 去重（简单示例）
    proxies = list(set(proxies))

    # 读取模板
    with open("sub_template.yaml", "r", encoding="utf-8") as f:
        tpl = yaml.safe_load(f)

    # 填充
    tpl["proxies"] = proxies

    # 输出最终订阅
    with open("sub.yaml", "w", encoding="utf-8") as f:
        yaml.dump(tpl, f, allow_unicode=True)

if __name__ == "__main__":
    main()
