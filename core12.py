"""
core12.py — Advanced Subdomain Discovery
أساليب متقدمة لا تعتمد على APIs خارجية:
  1. SPF / TXT Record Chain Mining
  2. Reverse IP + ASN Range Scanning
  3. JavaScript File Mining
  4. GitHub Code Scraping
"""

import re
import socket
import random
import time
import requests
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, quote_plus

# ─── Helpers ─────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
]

def _h():
    return {"User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"}

def _get(url, timeout=20, json=False):
    try:
        r = requests.get(url, headers=_h(), timeout=timeout)
        if r.status_code == 200:
            return r.json() if json else r.text
    except Exception:
        pass
    return None

def _valid_sub(s, domain):
    s = s.strip().lower().strip(".")
    if not s.endswith(f".{domain}") or s == domain:
        return None
    parts = s[: -(len(domain) + 1)].split(".")
    if all(re.match(r'^[a-z0-9][a-z0-9\-]*[a-z0-9]$|^[a-z0-9]$', p) for p in parts):
        return s
    return None

def _extract_subs_from_text(text, domain):
    escaped = re.escape(domain)
    matches = re.findall(rf'([a-z0-9][a-z0-9\-\.]*\.{escaped})', text.lower())
    return {s for m in matches if (s := _valid_sub(m, domain))}


# ═══════════════════════════════════════════════════════════════════════════════
# الطريقة 1: SPF / TXT Record Chain Mining
# ─────────────────────────────────────────
# SPF records تحتوي على:
#   include:mail.domain.com  → subdomain مباشر
#   a:smtp.domain.com        → subdomain مباشر
#   redirect=domain.com      → domain كامل للتتبع
# ═══════════════════════════════════════════════════════════════════════════════

def _get_txt(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [r.to_text().strip('"') for r in answers]
    except Exception:
        return []

def _parse_spf(txt_record, root_domain):
    """استخراج كل المضيفين من سجل SPF"""
    subs = set()
    # include: و a: و mx: و ptr:
    for match in re.finditer(r'(?:include|a|mx|ptr|exists):([^\s]+)', txt_record):
        host = match.group(1).strip(".")
        # subdomain مباشر
        v = _valid_sub(host, root_domain)
        if v:
            subs.add(v)
        # إذا كان domain مختلفاً، اتبعه recursively
        elif "." in host and host != root_domain:
            subs.update(mine_spf_chain(host, root_domain, depth=0))
    # redirect=
    for match in re.finditer(r'redirect=([^\s]+)', txt_record):
        host = match.group(1).strip(".")
        subs.update(mine_spf_chain(host, root_domain, depth=0))
    return subs

def mine_spf_chain(domain_to_query, root_domain, depth=0, visited=None):
    """تتبع سلسلة SPF بشكل recursive"""
    if visited is None:
        visited = set()
    if depth > 5 or domain_to_query in visited:
        return set()
    visited.add(domain_to_query)

    subs = set()
    txt_records = _get_txt(domain_to_query)
    for txt in txt_records:
        subs |= _extract_subs_from_text(txt, root_domain)
        if "v=spf" in txt.lower():
            subs |= _parse_spf(txt, root_domain)
    return subs

def discover_via_spf(domain):
    """Mine SPF + كل سجلات TXT للعثور على subdomains"""
    subs = set()
    # TXT للـ root domain
    for txt in _get_txt(domain):
        subs |= _extract_subs_from_text(txt, domain)
        if "v=spf" in txt.lower():
            subs |= _parse_spf(txt, domain)
    # TXT لـ _dmarc و _domainkey
    for prefix in ["_dmarc", "_domainkey", "mail", "smtp", "email"]:
        for txt in _get_txt(f"{prefix}.{domain}"):
            subs |= _extract_subs_from_text(txt, domain)
    # MX records
    try:
        for r in dns.resolver.resolve(domain, "MX", lifetime=5):
            host = str(r.exchange).rstrip(".")
            v = _valid_sub(host, domain)
            if v:
                subs.add(v)
    except Exception:
        pass
    print(f"[SPF Mining] Found {len(subs)} subdomains")
    return subs


# ═══════════════════════════════════════════════════════════════════════════════
# الطريقة 2: Reverse IP + ASN Range Scanning
# ───────────────────────────────────────────
# - نحصل على IP للدومين
# - نحصل على الـ ASN ونطاق IPs
# - نعمل reverse DNS على كل IP في النطاق
# ═══════════════════════════════════════════════════════════════════════════════

def _get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def _reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def _reverse_ip_hackertarget(ip):
    """كل الدومينات على نفس الـ IP"""
    result = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}", timeout=15)
    if result and "error" not in result.lower():
        return [line.strip() for line in result.splitlines() if line.strip()]
    return []

def _get_asn_ranges(ip):
    """نطاقات IP الخاصة بالـ ASN عبر bgpview.io"""
    # أولاً: نحصل على الـ ASN
    data = _get(f"https://api.bgpview.io/ip/{ip}", json=True, timeout=15)
    if not data:
        return []
    asn_list = []
    try:
        for prefix in data.get("data", {}).get("prefixes", []):
            cidr = prefix.get("prefix", "")
            if cidr:
                asn_list.append(cidr)
    except Exception:
        pass
    return asn_list[:3]  # أول 3 نطاقات فقط لتجنب الطول الزائد

def _expand_cidr_ips(cidr, max_ips=256):
    """توليد IPs من CIDR مع حد أقصى"""
    import ipaddress
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(network.hosts())
        return [str(ip) for ip in hosts[:max_ips]]
    except Exception:
        return []

def discover_via_reverse_ip(domain):
    subs = set()
    ip = _get_ip(domain)
    if not ip:
        print(f"[Reverse IP] Could not resolve {domain}")
        return subs

    # Reverse IP للـ IP المباشر
    for host in _reverse_ip_hackertarget(ip):
        v = _valid_sub(host, domain)
        if v:
            subs.add(v)

    # ASN range scan (reverse DNS)
    cidrs = _get_asn_ranges(ip)
    for cidr in cidrs:
        ips = _expand_cidr_ips(cidr, max_ips=512)
        with ThreadPoolExecutor(max_workers=100) as ex:
            futures = {ex.submit(_reverse_dns, i): i for i in ips}
            for f in as_completed(futures):
                host = f.result()
                if host:
                    v = _valid_sub(host, domain)
                    if v:
                        subs.add(v)
        time.sleep(0.5)

    print(f"[Reverse IP + ASN] Found {len(subs)} subdomains")
    return subs


# ═══════════════════════════════════════════════════════════════════════════════
# الطريقة 3: JavaScript File Mining
# ──────────────────────────────────
# نفتح الصفحة الرئيسية → نجمع كل ملفات JS → نستخرج الـ subdomains منها
# ═══════════════════════════════════════════════════════════════════════════════

def _get_js_urls(base_url, html):
    """استخراج روابط ملفات JS من HTML"""
    js_urls = set()
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        src = match.group(1)
        if src.startswith("http"):
            js_urls.add(src)
        elif src.startswith("/"):
            parsed = urlparse(base_url)
            js_urls.add(f"{parsed.scheme}://{parsed.netloc}{src}")
        else:
            js_urls.add(urljoin(base_url, src))
    return js_urls

def discover_via_js(domain):
    subs = set()
    for scheme in ["https", "http"]:
        base = f"{scheme}://{domain}"
        html = _get(base, timeout=15)
        if not html:
            continue
        subs |= _extract_subs_from_text(html, domain)

        js_urls = _get_js_urls(base, html)
        def fetch_js(url):
            content = _get(url, timeout=10)
            return _extract_subs_from_text(content, domain) if content else set()

        with ThreadPoolExecutor(max_workers=20) as ex:
            for result in ex.map(fetch_js, list(js_urls)[:50]):
                subs |= result
        break  # نكتفي بأول scheme يعمل

    print(f"[JS Mining] Found {len(subs)} subdomains")
    return subs


# ═══════════════════════════════════════════════════════════════════════════════
# الطريقة 4: GitHub Code Scraping (بدون API key)
# ───────────────────────────────────────────────
# نبحث في GitHub عن الدومين في الكود → نستخرج subdomains من النتائج
# ═══════════════════════════════════════════════════════════════════════════════

def discover_via_github(domain):
    subs = set()
    queries = [
        f'"{domain}"',
        f'"api.{domain}"',
        f'"staging.{domain}"',
        f'"{domain}" filename:config',
        f'"{domain}" filename:.env',
    ]
    session = requests.Session()
    session.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    for q in queries:
        try:
            url = f"https://github.com/search?q={quote_plus(q)}&type=code"
            r = session.get(url, timeout=20)
            if r.status_code == 200:
                subs |= _extract_subs_from_text(r.text, domain)
            time.sleep(random.uniform(3, 5))
        except Exception:
            pass
    print(f"[GitHub Scraping] Found {len(subs)} subdomains")
    return subs


# ═══════════════════════════════════════════════════════════════════════════════
# الدالة الرئيسية
# ═══════════════════════════════════════════════════════════════════════════════

SOURCE_MAP = {
    "spf":        ("SPF / DNS Mining",    discover_via_spf),
    "reverse_ip": ("Reverse IP + ASN",    discover_via_reverse_ip),
    "js":         ("JS File Mining",      discover_via_js),
    "github":     ("GitHub Code Scraping", discover_via_github),
}

def discover_advanced(domain, sources=None):
    if sources is None:
        sources = list(SOURCE_MAP.keys())
    all_subs = set()
    for key in sources:
        if key in SOURCE_MAP:
            _, fn = SOURCE_MAP[key]
            all_subs |= fn(domain)
    return sorted(all_subs)
