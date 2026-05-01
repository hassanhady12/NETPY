"""
core15.py — Parameter & Endpoint Discovery
يكتشف:
  1. URLs + Parameters من Wayback Machine
  2. URLs + Parameters من CommonCrawl
  3. API Endpoints من ملفات JavaScript
  4. Parameters من HTML Forms
  5. Parameters من روابط الصفحة الرئيسية
"""

import re
import json
import random
import requests
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Helpers ──────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

def _h():
    return {"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"}

def _get(url, timeout=20):
    try:
        r = requests.get(url, headers=_h(), timeout=timeout, verify=False)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ""

def _normalize(domain):
    domain = domain.strip().lstrip("https://").lstrip("http://").rstrip("/")
    return domain

def _extract_params(url):
    """استخراج الـ parameters من URL"""
    try:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        path   = parsed.path
        return params, path
    except Exception:
        return [], ""


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Wayback Machine CDX API
# ═══════════════════════════════════════════════════════════════════════════════
def discover_via_wayback(domain):
    """
    يجلب كل URLs التاريخية من Wayback Machine ويستخرج منها parameters وendpoints.
    """
    results = {"urls": set(), "params": set(), "endpoints": set()}

    # CDX API — يرجع كل URLs المحفوظة
    cdx_url = (
        f"http://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        f"&limit=5000&filter=statuscode:200"
    )
    text = _get(cdx_url, timeout=30)
    if not text:
        return results

    try:
        data = json.loads(text)
        # أول عنصر هو الـ header ["original"]
        urls = [row[0] for row in data[1:] if row]
    except Exception:
        return results

    for url in urls:
        params, path = _extract_params(url)
        results["urls"].add(url)
        results["params"].update(params)
        if path and path != "/":
            results["endpoints"].add(path)

    print(f"[Wayback] {len(urls)} URLs — {len(results['params'])} params — {len(results['endpoints'])} endpoints")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 2. CommonCrawl
# ═══════════════════════════════════════════════════════════════════════════════
def discover_via_commoncrawl(domain):
    results = {"urls": set(), "params": set(), "endpoints": set()}

    # احصل على آخر index
    idx_text = _get("https://index.commoncrawl.org/collinfo.json", timeout=15)
    if not idx_text:
        return results
    try:
        indexes = json.loads(idx_text)
        latest = indexes[0]["cdx-api"]
    except Exception:
        latest = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"

    cc_url = f"{latest}?url=*.{domain}/*&output=json&limit=3000&filter=status:200"
    text = _get(cc_url, timeout=30)
    if not text:
        return results

    for line in text.splitlines():
        try:
            obj = json.loads(line)
            url = obj.get("url", "")
            if not url:
                continue
            params, path = _extract_params(url)
            results["urls"].add(url)
            results["params"].update(params)
            if path and path != "/":
                results["endpoints"].add(path)
        except Exception:
            continue

    print(f"[CommonCrawl] {len(results['params'])} params — {len(results['endpoints'])} endpoints")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# 3. JavaScript File Mining
# ═══════════════════════════════════════════════════════════════════════════════

# Patterns لاستخراج endpoints وparameters من JS
_JS_ENDPOINT_PATTERNS = [
    r'["\'](/api/[^\s"\'<>{}|\\^`\[\]]*)["\']',
    r'["\'](/v\d+/[^\s"\'<>{}|\\^`\[\]]*)["\']',
    r'["\'](/[a-z0-9_\-]+/[a-z0-9_\-/]+)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'url:\s*["\']([^"\']+)["\']',
    r'endpoint:\s*["\']([^"\']+)["\']',
    r'baseURL:\s*["\']([^"\']+)["\']',
    r'\.get\(["\']([^"\']+)["\']',
    r'\.post\(["\']([^"\']+)["\']',
    r'\.put\(["\']([^"\']+)["\']',
    r'\.delete\(["\']([^"\']+)["\']',
]

_JS_PARAM_PATTERNS = [
    r'[?&]([a-z_][a-z0-9_]{1,30})=',
    r'params\[[\'""]([a-z_][a-z0-9_]{1,30})[\'""]',
    r'data\[[\'""]([a-z_][a-z0-9_]{1,30})[\'""]',
    r'["\']([a-z_][a-z0-9_]{1,30})["\']\s*:\s*["\'][^"\']*["\']',  # JSON keys
    r'name=["\']([a-z_][a-z0-9_]{1,30})["\']',
]

# كلمات شائعة يجب تجاهلها (ليست parameters)
_IGNORE_PARAMS = {
    "function", "return", "const", "class", "style", "type", "href", "src",
    "true", "false", "null", "undefined", "default", "export", "import",
    "var", "let", "new", "this", "from", "else", "then", "catch", "async",
    "await", "data", "value", "name", "text", "html", "json", "url", "key",
    "id", "el", "fn", "cb", "ok", "on", "is", "in", "to", "of", "if", "or"
}

def _mine_js_file(js_url):
    """استخراج endpoints وparams من ملف JS واحد"""
    endpoints = set()
    params = set()
    content = _get(js_url, timeout=15)
    if not content:
        return endpoints, params

    for pattern in _JS_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            ep = match.group(1).strip()
            if 2 < len(ep) < 120 and ep.startswith("/"):
                endpoints.add(ep)

    for pattern in _JS_PARAM_PATTERNS:
        for match in re.finditer(pattern, content, re.IGNORECASE):
            p = match.group(1).strip().lower()
            if 2 < len(p) < 30 and p not in _IGNORE_PARAMS:
                params.add(p)

    return endpoints, params


def discover_via_js(domain):
    results = {"urls": set(), "params": set(), "endpoints": set()}

    # افتح الصفحة الرئيسية واجمع روابط JS
    for scheme in ["https", "http"]:
        base = f"{scheme}://{domain}"
        html = _get(base)
        if not html:
            continue

        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("http"):
                js_urls.add(src)
            elif src.startswith("/"):
                js_urls.add(f"{scheme}://{domain}{src}")
            else:
                js_urls.add(urljoin(base, src))

        # أيضاً استخرج params من HTML نفسه
        for a in soup.find_all("a", href=True):
            params, path = _extract_params(a["href"])
            results["params"].update(params)
            if path and path != "/":
                results["endpoints"].add(path)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                _, path = _extract_params(action)
                if path:
                    results["endpoints"].add(path)
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name", "")
                if name and len(name) > 1 and name not in _IGNORE_PARAMS:
                    results["params"].add(name)

        # سكان JS files بالتوازي
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(_mine_js_file, u): u for u in list(js_urls)[:60]}
            for f in as_completed(futures):
                eps, prms = f.result()
                results["endpoints"].update(eps)
                results["params"].update(prms)

        break

    # فلترة نهائية للـ params
    results["params"] = {
        p for p in results["params"]
        if p not in _IGNORE_PARAMS and 2 < len(p) < 30
    }

    print(f"[JS Mining] {len(results['params'])} params — {len(results['endpoints'])} endpoints")
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# الدالة الرئيسية
# ═══════════════════════════════════════════════════════════════════════════════
SOURCE_MAP = {
    "wayback":     ("Wayback Machine",  discover_via_wayback),
    "commoncrawl": ("CommonCrawl",      discover_via_commoncrawl),
    "js":          ("JS File Mining",   discover_via_js),
}

def discover_params(domain, sources=None):
    """
    يجمع كل النتائج من المصادر المحددة.
    يرجع dict: {params: set, endpoints: set, urls: set}
    """
    domain = _normalize(domain)
    if sources is None:
        sources = list(SOURCE_MAP.keys())

    all_params    = set()
    all_endpoints = set()
    all_urls      = set()

    for key in sources:
        if key not in SOURCE_MAP:
            continue
        _, fn = SOURCE_MAP[key]
        try:
            r = fn(domain)
            all_params    |= r.get("params", set())
            all_endpoints |= r.get("endpoints", set())
            all_urls      |= r.get("urls", set())
        except Exception as e:
            print(f"[{key}] Error: {e}")

    return {
        "domain":    domain,
        "params":    sorted(all_params),
        "endpoints": sorted(all_endpoints),
        "urls":      sorted(all_urls),
    }
