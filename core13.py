import requests
import re
import random
import time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

# WAF fingerprint signatures: (waf_name, header_key, header_value_pattern)
WAF_HEADER_SIGNATURES = [
    ("Cloudflare",       "cf-ray",                  r".+"),
    ("Cloudflare",       "server",                  r"cloudflare"),
    ("Cloudflare",       "cf-cache-status",         r".+"),
    ("Akamai",           "x-check-cacheable",       r".+"),
    ("Akamai",           "x-akamai-transformed",    r".+"),
    ("Akamai",           "akamai-origin-hop",       r".+"),
    ("Imperva / Incapsula", "x-iinfo",              r".+"),
    ("Imperva / Incapsula", "x-cdn",                r"incapsula"),
    ("Imperva / Incapsula", "visid_incap",          r".+"),   # cookie
    ("AWS WAF",          "x-amzn-requestid",        r".+"),
    ("AWS WAF",          "x-amz-cf-id",             r".+"),
    ("Sucuri",           "x-sucuri-id",             r".+"),
    ("Sucuri",           "x-sucuri-cache",          r".+"),
    ("Sucuri",           "server",                  r"sucuri"),
    ("Barracuda",        "set-cookie",              r"barra_counter_session"),
    ("F5 BIG-IP ASM",   "x-wa-info",               r".+"),
    ("F5 BIG-IP ASM",   "set-cookie",              r"ts[0-9a-f]+"),
    ("ModSecurity",      "server",                  r"mod_security"),
    ("ModSecurity",      "x-mod-security-message",  r".+"),
    ("Wordfence",        "x-fw-hash",               r".+"),
    ("DDoS-Guard",       "server",                  r"ddos-guard"),
    ("DDoS-Guard",       "set-cookie",              r"__ddg"),
    ("Fastly",           "x-fastly-request-id",     r".+"),
    ("Fastly",           "via",                     r"varnish"),
    ("Fastly",           "x-served-by",             r"cache-"),
    ("Netlify",          "x-nf-request-id",         r".+"),
    ("Vercel",           "x-vercel-id",             r".+"),
    ("Alibaba Cloud WAF","ali-cdn",                 r".+"),
    ("Alibaba Cloud WAF","eagleid",                 r".+"),
    ("Tencent WAF",      "x-from-tencent",          r".+"),
    ("Nginx WAF",        "server",                  r"nginx"),
    ("Apache",           "server",                  r"apache"),
    ("Microsoft Azure",  "x-msedge-ref",            r".+"),
    ("Microsoft Azure",  "x-azure-ref",             r".+"),
    ("Reblaze",          "x-reblaze-protection",    r".+"),
    ("SiteLock",         "x-sitelock-request-id",   r".+"),
    ("StackPath",        "x-sp-url",                r".+"),
    ("Limelight",        "x-llnw",                  r".+"),
    ("Radware AppWall",  "x-sl-compstate",          r".+"),
    ("Palo Alto",        "x-pa-",                   r".+"),
]

# Payloads that WAFs commonly block (SQLI/XSS probes)
WAF_PROBE_PAYLOADS = [
    "/?q=<script>alert(1)</script>",
    "/?id=1' OR '1'='1",
    "/?q=../../../../etc/passwd",
    "/?search=<img src=x onerror=alert(1)>",
    "/?id=1 UNION SELECT NULL--",
]

WAF_BLOCK_CODES = {403, 406, 412, 416, 429, 503}


def _req(url, timeout=10):
    try:
        return requests.get(
            url,
            headers={"User-Agent": random.choice(USER_AGENTS), "Accept": "*/*"},
            timeout=timeout,
            allow_redirects=True,
            verify=False,
        )
    except Exception:
        return None


def _normalize_url(domain):
    if not domain.startswith(("http://", "https://")):
        return f"https://{domain}"
    return domain


def _check_headers(resp):
    """Match response headers against known WAF signatures."""
    detected = set()
    headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    # also check Set-Cookie
    cookies_raw = resp.headers.get("set-cookie", "").lower()

    for waf_name, header_key, pattern in WAF_HEADER_SIGNATURES:
        value = headers_lower.get(header_key.lower(), "")
        if not value and header_key.lower() == "set-cookie":
            value = cookies_raw
        if value and re.search(pattern, value, re.IGNORECASE):
            detected.add(waf_name)
    return detected


def _probe_waf(base_url):
    """Send probe payloads and check if any are blocked."""
    blocked_by_waf = False
    block_codes_seen = set()
    for payload in WAF_PROBE_PAYLOADS:
        url = base_url.rstrip("/") + payload
        resp = _req(url, timeout=8)
        if resp and resp.status_code in WAF_BLOCK_CODES:
            blocked_by_waf = True
            block_codes_seen.add(resp.status_code)
        time.sleep(0.3)
    return blocked_by_waf, block_codes_seen


def detect_waf(domain):
    """
    Detect WAF for a domain.
    Returns a dict with keys: domain, waf_detected (bool), wafs (list),
    status_code, server, headers_summary, probe_blocked, block_codes.
    """
    base_url = _normalize_url(domain)
    result = {
        "domain": domain,
        "waf_detected": False,
        "wafs": [],
        "status_code": None,
        "server": "unknown",
        "cdn": "unknown",
        "headers_summary": {},
        "probe_blocked": False,
        "block_codes": [],
        "error": None,
    }

    # Step 1: Normal request
    resp = _req(base_url)
    if resp is None:
        # Try HTTP fallback
        resp = _req(base_url.replace("https://", "http://"))
    if resp is None:
        result["error"] = "Connection failed"
        return result

    result["status_code"] = resp.status_code
    result["server"] = resp.headers.get("Server", "unknown")

    # Collect interesting headers
    interesting = [
        "server", "x-powered-by", "cf-ray", "x-iinfo", "x-sucuri-id",
        "x-amzn-requestid", "x-amz-cf-id", "x-fastly-request-id",
        "x-vercel-id", "x-nf-request-id", "x-msedge-ref", "via",
        "x-cache", "x-cdn", "x-fw-hash", "x-wa-info",
    ]
    result["headers_summary"] = {
        k: resp.headers[k]
        for k in interesting
        if k in {h.lower() for h in resp.headers}
        for rk in resp.headers
        if rk.lower() == k
    }
    # simpler approach
    result["headers_summary"] = {
        rk: rv for rk, rv in resp.headers.items()
        if rk.lower() in interesting
    }

    # Step 2: Header-based detection
    detected = _check_headers(resp)

    # Step 3: Probe payloads
    probe_blocked, block_codes = _probe_waf(base_url)
    result["probe_blocked"] = probe_blocked
    result["block_codes"] = sorted(block_codes)

    if probe_blocked and not detected:
        detected.add("Unknown WAF")

    result["wafs"] = sorted(detected)
    result["waf_detected"] = len(detected) > 0

    return result
