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
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
]

# ─── Dork queries شاملة ──────────────────────────────────────────────────────
DORK_TEMPLATES = [
    # أساسية
    "site:*.{domain}",
    "site:*.{domain} -www",
    "site:*.{domain} -site:www.{domain}",
    # خدمات داخلية
    "site:*.{domain} inurl:login",
    "site:*.{domain} inurl:admin",
    "site:*.{domain} inurl:portal",
    "site:*.{domain} inurl:dashboard",
    "site:*.{domain} inurl:api",
    "site:*.{domain} inurl:vpn",
    "site:*.{domain} inurl:mail",
    "site:*.{domain} inurl:webmail",
    "site:*.{domain} inurl:owa",
    # بيئات تطوير
    "site:*.{domain} inurl:dev",
    "site:*.{domain} inurl:test",
    "site:*.{domain} inurl:staging",
    "site:*.{domain} inurl:beta",
    "site:*.{domain} inurl:uat",
    "site:*.{domain} inurl:preprod",
    # أدوات DevOps
    "site:*.{domain} inurl:jenkins",
    "site:*.{domain} inurl:jira",
    "site:*.{domain} inurl:gitlab",
    "site:*.{domain} inurl:git",
    "site:*.{domain} inurl:ci",
    "site:*.{domain} inurl:monitor",
    "site:*.{domain} inurl:grafana",
    "site:*.{domain} inurl:kibana",
    # Databases & services
    "site:*.{domain} inurl:db",
    "site:*.{domain} inurl:ftp",
    "site:*.{domain} inurl:mysql",
    "site:*.{domain} inurl:phpmyadmin",
    # محتوى
    "site:*.{domain} filetype:pdf",
    "site:*.{domain} filetype:xml",
    "site:*.{domain} filetype:txt",
    "site:*.{domain} inurl:wp-admin",
    "site:*.{domain} inurl:wp-content",
    "site:*.{domain} inurl:upload",
    "site:*.{domain} inurl:backup",
    "site:*.{domain} inurl:config",
    # IP & Internal
    "site:*.{domain} intext:{domain}",
    'site:*.{domain} "index of"',
    'site:*.{domain} intitle:"index of"',
]


def _headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
    }


def _extract_subs(text, domain):
    """استخراج النطاقات الفرعية من النص الكامل"""
    escaped = re.escape(domain)
    pattern = rf'([a-z0-9][a-z0-9\-\.]*\.{escaped})'
    matches = re.findall(pattern, text.lower())
    subs = set()
    for m in matches:
        m = m.strip(".").strip()
        if not m.endswith(f".{domain}"):
            continue
        parts = m[: -(len(domain) + 1)]  # الجزء قبل .domain
        if not parts:
            continue
        # تأكد من أن كل segment صحيح
        if all(re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$', p) or re.match(r'^[a-z0-9]$', p)
               for p in parts.split(".")):
            subs.add(m)
    return subs


def _fetch(url, method="GET", data=None, timeout=20):
    try:
        if method == "POST":
            r = requests.post(url, data=data, headers=_headers(), timeout=timeout)
        else:
            r = requests.get(url, headers=_headers(), timeout=timeout)
        return r.text if r.status_code == 200 else ""
    except Exception:
        return ""


# ─── Bing: أكثر مرونة مع السكرابينج ─────────────────────────────────────────
def _bing_pages(query, max_pages=5):
    html = ""
    for p in range(max_pages):
        first = p * 10 + 1
        url = f"https://www.bing.com/search?q={quote_plus(query)}&first={first}&count=50&setlang=en"
        html += _fetch(url)
        time.sleep(random.uniform(1.5, 2.5))
    return html

def dork_bing(domain):
    subs = set()
    # نأخذ أهم 15 dork
    for dork in [t.format(domain=domain) for t in DORK_TEMPLATES[:15]]:
        subs |= _extract_subs(_bing_pages(dork, max_pages=3), domain)
        time.sleep(random.uniform(1.5, 3))
    print(f"[Bing] Found {len(subs)} subdomains")
    return subs


# ─── DuckDuckGo: مع دعم pagination ──────────────────────────────────────────
def _ddg_pages(query, max_pages=3):
    html = ""
    # الصفحة الأولى
    html += _fetch("https://html.duckduckgo.com/html/", method="POST", data={"q": query})
    time.sleep(random.uniform(1.5, 2.5))
    # صفحات إضافية عبر parameter s
    for p in range(1, max_pages):
        html += _fetch("https://html.duckduckgo.com/html/", method="POST",
                       data={"q": query, "s": str(p * 30), "dc": str(p * 30 + 1)})
        time.sleep(random.uniform(1.5, 2.5))
    return html

def dork_duckduckgo(domain):
    subs = set()
    for dork in [t.format(domain=domain) for t in DORK_TEMPLATES[:12]]:
        subs |= _extract_subs(_ddg_pages(dork, max_pages=2), domain)
        time.sleep(random.uniform(2, 3.5))
    print(f"[DuckDuckGo] Found {len(subs)} subdomains")
    return subs


# ─── Yahoo Search ─────────────────────────────────────────────────────────────
def _yahoo_pages(query, max_pages=5):
    html = ""
    for p in range(max_pages):
        b = p * 10 + 1
        url = f"https://search.yahoo.com/search?p={quote_plus(query)}&b={b}&pz=10&ei=UTF-8"
        html += _fetch(url)
        time.sleep(random.uniform(1.5, 2.5))
    return html

def dork_yahoo(domain):
    subs = set()
    for dork in [t.format(domain=domain) for t in DORK_TEMPLATES[:10]]:
        subs |= _extract_subs(_yahoo_pages(dork, max_pages=3), domain)
        time.sleep(random.uniform(2, 3.5))
    print(f"[Yahoo] Found {len(subs)} subdomains")
    return subs


# ─── Ask.com ─────────────────────────────────────────────────────────────────
def dork_ask(domain):
    subs = set()
    for dork in [t.format(domain=domain) for t in DORK_TEMPLATES[:6]]:
        html = _fetch(f"https://www.ask.com/web?q={quote_plus(dork)}")
        subs |= _extract_subs(html, domain)
        time.sleep(random.uniform(2, 3.5))
    print(f"[Ask] Found {len(subs)} subdomains")
    return subs


# ─── Baidu: قوي لكثير من المواقع الدولية ────────────────────────────────────
def dork_baidu(domain):
    subs = set()
    queries = [
        f"site:{domain}",
        f"site:*.{domain}",
    ]
    for q in queries:
        for pn in range(5):
            url = f"https://www.baidu.com/s?wd={quote_plus(q)}&pn={pn*10}&rn=50"
            html = _fetch(url)
            subs |= _extract_subs(html, domain)
            time.sleep(random.uniform(1.5, 2.5))
    print(f"[Baidu] Found {len(subs)} subdomains")
    return subs


# ─── Yandex ───────────────────────────────────────────────────────────────────
def dork_yandex(domain):
    subs = set()
    queries = [f"host:.{domain}", f"site:*.{domain}"]
    for q in queries:
        for p in range(3):
            url = f"https://www.yandex.com/search/?text={quote_plus(q)}&p={p}"
            html = _fetch(url)
            subs |= _extract_subs(html, domain)
            time.sleep(random.uniform(2, 3.5))
    print(f"[Yandex] Found {len(subs)} subdomains")
    return subs


# ─── Google: مع تدوير User-Agent وDelay لتجنب CAPTCHA ───────────────────────
_GOOGLE_HEADERS = [
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-CH-UA": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
    },
    {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://www.google.com/",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
    },
]

def _google_fetch(query, start=0):
    url = (
        f"https://www.google.com/search"
        f"?q={quote_plus(query)}&num=100&start={start}"
        f"&hl=en&gl=us&filter=0"
    )
    session = requests.Session()
    session.headers.update(random.choice(_GOOGLE_HEADERS))
    try:
        r = session.get(url, timeout=20, allow_redirects=True)
        if r.status_code == 429 or "captcha" in r.text.lower() or "unusual traffic" in r.text.lower():
            print(f"[Google] CAPTCHA/Rate limit detected — skipping page")
            return ""
        return r.text if r.status_code == 200 else ""
    except Exception:
        return ""

def dork_google(domain):
    subs = set()
    # نأخذ الأقوى 8 dorks فقط لتجنب الحظر
    priority_dorks = [
        f"site:*.{domain}",
        f"site:*.{domain} -www",
        f"site:*.{domain} inurl:admin",
        f"site:*.{domain} inurl:api",
        f"site:*.{domain} inurl:login",
        f"site:*.{domain} inurl:dev",
        f"site:*.{domain} inurl:portal",
        f"site:*.{domain} inurl:mail",
    ]
    for dork in priority_dorks:
        for start in range(0, 200, 100):  # صفحتين: 0-99, 100-199
            html = _google_fetch(dork, start=start)
            if not html:
                break
            subs |= _extract_subs(html, domain)
            time.sleep(random.uniform(3, 6))  # delay أطول لتجنب الحظر
        time.sleep(random.uniform(4, 7))
    print(f"[Google] Found {len(subs)} subdomains")
    return subs


# ─── الدالة الرئيسية ────────────────────────────────────────────────────────
def dork_all_engines(domain):
    all_subs = set()
    for fn in [dork_google, dork_bing, dork_duckduckgo, dork_yahoo, dork_ask, dork_baidu, dork_yandex]:
        all_subs |= fn(domain)
    return sorted(all_subs)
