import socket
import time
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# لیست جامع پورت‌های پرکاربرد (وب، شبکه، دیتابیس، ریموت و سرور)
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2082: "cPanel HTTP",
    2083: "cPanel HTTPS",
    2086: "WHM HTTP",
    2087: "WHM HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt / Dev Server",
    8080: "HTTP-Proxy ",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "SonarQube / FastCGI",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def _extract_target(url: str) -> str:
    """استخراج دامنه یا IP از آدرس ورودی"""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL or Hostname provided.")
    return hostname


def _check_port(host: str, port: int, service_name: str, timeout: float = 1.5):
    """تست پورت و محاسبه زمان اتصال بر حسب میلی‌ثانیه"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start_time = time.perf_counter()
    try:
        result = sock.connect_ex((host, port))
        elapsed = (time.perf_counter() - start_time) * 1000  

        if result == 0:
            print(
                f"  [+] Port {port:<5} ({service_name:<18}) is OPEN   | Latency: {elapsed:6.2f} ms"
            )
            return port, service_name, elapsed
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(
    url: str = None,
    ports: dict = None,
    timeout: float = 1.5,
    max_threads: int = 30,
):
    """
    تابع اصلی برای اسکن پورت‌ها
    اگر url داده نشود، از کاربر در ترمینال دریافت می‌شود.
    """
    if not url:
        url = input("🎅 Enter target URL or IP : ").strip()

    try:
        target_host = _extract_target(url)
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[-] Error : Socket cant resolve url : '{url}'.")
        return []
    except Exception as e:
        print(f"[-] Error : {e}")
        return []

    port_list = ports if ports is not None else COMMON_PORTS

    print("\n" + "=" * 65)
    print(f"  PortMiner Scanner ")
    print(f"  Target  : {target_host} ({target_ip})")
    print(f"  Scanning : {len(port_list)} ports...")
    print("=" * 65)

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [
            executor.submit(_check_port, target_ip, p, svc, timeout)
            for p, svc in port_list.items()
        ]
        for f in futures:
            res = f.result()
            if res:
                open_ports.append(res)

    print("=" * 65)
    print(
        f"🎅 Scan complete . Found {len(open_ports)} open port(s) on {target_host}.\n"
    )
    return open_ports

if __name__ == "__main__":
    scan_ports()