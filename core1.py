import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

TIMEOUT     = 10
MAX_WORKERS = 20
HEADERS     = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}


def _normalize(site: str) -> str:
    site = site.strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    return site


def _fetch_one(site: str) -> str:
    original = site
    site = _normalize(site)
    name = urlparse(site).netloc or site

    for scheme in ("https://", "http://"):
        url = scheme + urlparse(site).netloc
        try:
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                                allow_redirects=True, verify=False)
            final = urlparse(resp.url).netloc or name
            code  = resp.status_code
            reason = resp.reason or ""

            # تصنيف الكود
            if code < 300:
                label = "✅"
            elif code < 400:
                label = "↪️ Redirect"
            elif code < 500:
                label = "⚠️ Client Error"
            else:
                label = "❌ Server Error"

            return f"{label} {final} — {code} {reason}"

        except requests.exceptions.SSLError:
            continue   # جرب http
        except requests.exceptions.ConnectionError:
            return f"❌ {name} — Connection refused or unreachable"
        except requests.exceptions.Timeout:
            return f"⏱️ {name} — Timed out after {TIMEOUT}s"
        except requests.exceptions.TooManyRedirects:
            return f"🔁 {name} — Too many redirects"
        except requests.exceptions.MissingSchema:
            return f"❌ {original} — Invalid URL"
        except requests.exceptions.RequestException as e:
            return f"❌ {name} — {e}"

    return f"❌ {name} — Failed on both https and http"


def fetch_status_code(sites: list) -> list:
    sites = [s for s in sites if s.strip()]
    if not sites:
        return []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        return list(executor.map(_fetch_one, sites))
