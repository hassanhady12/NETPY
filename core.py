import socket
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

# ─── ثوابت ───────────────────────────────────────────────────────────────────
TIMEOUT     = 8
MAX_WORKERS = 20
HEADERS     = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def _normalize(site: str) -> str:
    """أضف https:// إذا لم يكن موجوداً"""
    site = site.strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    return site


def resolve_ip(site: str) -> tuple[str, str]:
    original = site
    site = _normalize(site)

    # ── 1. حاول https أولاً ─────────────────────────────────────────────────
    for scheme in ("https://", "http://"):
        url = scheme + urlparse(site).netloc or site
        try:
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                                allow_redirects=True, verify=False)
            domain = urlparse(resp.url).netloc.split(":")[0]  # أزل port إن وجد
            if domain:
                ip = socket.gethostbyname(domain)
                return original, ip
        except requests.exceptions.SSLError:
            continue   # جرب http بعدها
        except requests.exceptions.ConnectionError:
            break
        except requests.exceptions.Timeout:
            return original, "Error: Request timed out"
        except requests.exceptions.TooManyRedirects:
            return original, "Error: Too many redirects"
        except requests.exceptions.RequestException as e:
            return original, f"Error: {e}"
        except socket.gaierror:
            return original, "Error: DNS resolution failed"
        except Exception as e:
            return original, f"Error: {e}"

    # ── 2. إذا فشل الطلب HTTP، جرب DNS مباشرة ──────────────────────────────
    try:
        domain = urlparse(site).netloc or site.replace("https://", "").replace("http://", "")
        domain = domain.split(":")[0].split("/")[0]
        ip = socket.gethostbyname(domain)
        return original, ip
    except socket.gaierror:
        return original, "Error: Domain not found"
    except Exception as e:
        return original, f"Error: {e}"


def resolve_ips(sites: list) -> list:
    """حل قائمة مواقع بشكل متوازٍ"""
    sites = [s for s in sites if s.strip()]
    if not sites:
        return []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        return list(executor.map(resolve_ip, sites))
