import re
import time
import random
import requests
from urllib.parse import quote_plus

# ─── User-Agents ─────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]

DORK_TEMPLATES = [
    "site:*.{domain}",
    "site:*.{domain} -www",
    "site:*.{domain} -site:www.{domain}",
    "site:*.{domain} inurl:login",
    "site:*.{domain} inurl:admin",
    "site:*.{domain} inurl:portal",
    "site:*.{domain} inurl:dashboard",
    "site:*.{domain} inurl:api",
    "site:*.{domain} inurl:vpn",
    "site:*.{domain} inurl:mail",
    "site:*.{domain} inurl:dev",
    "site:*.{domain} inurl:test",
    "site:*.{domain} inurl:staging",
    "site:*.{domain} inurl:beta",
    "site:*.{domain} inurl:jenkins",
    "site:*.{domain} inurl:jira",
    "site:*.{domain} inurl:gitlab",
    "site:*.{domain} inurl:grafana",
    "site:*.{domain} inurl:phpmyadmin",
    'site:*.{domain} "index of"',
]


def _headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
        "Connection": "keep-alive",
    }


def _extract_subs(text, domain):
    escaped = re.escape(domain)
    pattern = rf'([a-z0-9][a-z0-9\-\.]*\.{escaped})'
    matches = re.findall(pattern, text.lower())
    subs = set()
    for m in matches:
        m = m.strip(".").strip()
        if not m.endswith(f".{domain}"):
            continue
        parts = m[:-(len(domain) + 1)]
        if not parts:
            continue
        if all(re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', p) or re.match(r'^[a-z0-9]$', p)
               for p in parts.split(".")):
            subs.add(m)
    return subs


def _fetch(url, method="GET", data=None, timeout=15):
    try:
        if method == "POST":
            r = requests.post(url, data=data, headers=_headers(), timeout=timeout)
        else:
            r = requests.get(url, headers=_headers(), timeout=timeout)
        return r.text if r.status_code == 200 else ""
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════════════
# Generator versions — يبثون النتائج dork بـ dork
# ═══════════════════════════════════════════════════════════════════════════

def dork_bing(domain):
    """Returns full set (used by non-streaming calls)"""
    subs = set()
    for s in dork_bing_stream(domain):
        subs |= s
    return subs

def dork_bing_stream(domain):
    """Generator: yields set of new subs per dork"""
    dorks = [t.format(domain=domain) for t in DORK_TEMPLATES[:15]]
    for dork in dorks:
        html = ""
        for p in range(3):
            first = p * 10 + 1
            url = f"https://www.bing.com/search?q={quote_plus(dork)}&first={first}&count=50&setlang=en"
            html += _fetch(url)
            time.sleep(random.uniform(0.8, 1.5))
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(0.5, 1.2))


def dork_duckduckgo(domain):
    subs = set()
    for s in dork_duckduckgo_stream(domain):
        subs |= s
    return subs

def dork_duckduckgo_stream(domain):
    dorks = [t.format(domain=domain) for t in DORK_TEMPLATES[:12]]
    for dork in dorks:
        html = _fetch("https://html.duckduckgo.com/html/", method="POST", data={"q": dork})
        html += _fetch("https://html.duckduckgo.com/html/", method="POST",
                       data={"q": dork, "s": "30", "dc": "31"})
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(1, 2))


def dork_yahoo(domain):
    subs = set()
    for s in dork_yahoo_stream(domain):
        subs |= s
    return subs

def dork_yahoo_stream(domain):
    dorks = [t.format(domain=domain) for t in DORK_TEMPLATES[:10]]
    for dork in dorks:
        html = ""
        for p in range(3):
            b = p * 10 + 1
            url = f"https://search.yahoo.com/search?p={quote_plus(dork)}&b={b}&pz=10&ei=UTF-8"
            html += _fetch(url)
            time.sleep(random.uniform(0.8, 1.5))
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(0.5, 1))


def dork_ask(domain):
    subs = set()
    for s in dork_ask_stream(domain):
        subs |= s
    return subs

def dork_ask_stream(domain):
    dorks = [t.format(domain=domain) for t in DORK_TEMPLATES[:6]]
    for dork in dorks:
        html = _fetch(f"https://www.ask.com/web?q={quote_plus(dork)}")
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(1, 2))


def dork_baidu(domain):
    subs = set()
    for s in dork_baidu_stream(domain):
        subs |= s
    return subs

def dork_baidu_stream(domain):
    queries = [f"site:{domain}", f"site:*.{domain}"]
    for q in queries:
        html = ""
        for pn in range(5):
            url = f"https://www.baidu.com/s?wd={quote_plus(q)}&pn={pn*10}&rn=50"
            html += _fetch(url)
            time.sleep(random.uniform(0.8, 1.5))
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(0.5, 1))


def dork_yandex(domain):
    subs = set()
    for s in dork_yandex_stream(domain):
        subs |= s
    return subs

def dork_yandex_stream(domain):
    queries = [f"host:.{domain}", f"site:*.{domain}"]
    for q in queries:
        html = ""
        for p in range(3):
            url = f"https://www.yandex.com/search/?text={quote_plus(q)}&p={p}"
            html += _fetch(url)
            time.sleep(random.uniform(0.8, 1.5))
        found = _extract_subs(html, domain)
        if found:
            yield found
        time.sleep(random.uniform(0.5, 1))


def dork_google(domain):
    """Google محجوب بـ CAPTCHA — يرجع set فارغ دائماً"""
    return set()

def dork_google_stream(domain):
    """Google محجوب — لا ترسل أي نتائج"""
    return
    yield  # جعلها generator


# ─── Map للاستخدام في app.py ────────────────────────────────────────────────
STREAM_MAP = {
    "google":     ("Google",     dork_google_stream),
    "bing":       ("Bing",       dork_bing_stream),
    "duckduckgo": ("DuckDuckGo", dork_duckduckgo_stream),
    "yahoo":      ("Yahoo",      dork_yahoo_stream),
    "ask":        ("Ask",        dork_ask_stream),
    "baidu":      ("Baidu",      dork_baidu_stream),
    "yandex":     ("Yandex",     dork_yandex_stream),
}
