# core9.py
import socket
from concurrent.futures import ThreadPoolExecutor
import time
import requests

default_common_ports = [
    21, 22, 23, 25, 53, 80, 110, 123, 143, 389, 443, 445, 
    3306, 3389, 5432, 8080
]

def grab_banner(site, port):
    try:
        if port in [80, 443]:
            proto = 'https://' if port == 443 else 'http://'
            url = proto + site
            response = requests.get(url, timeout=5)
            return dict(response.headers)
    except:
        return None

def scan_port(site, port):
    result_info = {
        "port": port,
        "status": "closed",
        "banner": None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            result = sock.connect_ex((site, port))
            if result == 0:
                result_info["status"] = "open"
                banner = grab_banner(site, port)
                if banner:
                    result_info["banner"] = banner
    except:
        result_info["status"] = "error"
    return result_info

def scan_ports_for_domain(site, ports=None, max_threads=100):
    if ports is None:
        ports = default_common_ports

    results = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, site, port): port for port in ports}
        for future in future_to_port:
            result = future.result()
            results.append(result)

    return {site: results}
