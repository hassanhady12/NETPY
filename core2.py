import json
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

TIMEOUT     = 10
MAX_WORKERS = 20
HEADERS     = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

# ─── Headers المهمة من ناحية الأمان مع تحليلها ────────────────────────────
SECURITY_CHECKS = {
    # ❌ مفقودة = ثغرة محتملة
    "Strict-Transport-Security": {
        "missing": "⚠️ HSTS missing — site may be vulnerable to SSL stripping",
    },
    "Content-Security-Policy": {
        "missing": "⚠️ CSP missing — XSS attacks may be possible",
    },
    "X-Frame-Options": {
        "missing": "⚠️ X-Frame-Options missing — Clickjacking possible",
    },
    "X-Content-Type-Options": {
        "missing": "⚠️ X-Content-Type-Options missing — MIME sniffing possible",
    },
    "Permissions-Policy": {
        "missing": "⚠️ Permissions-Policy missing — browser features unrestricted",
    },
    "Referrer-Policy": {
        "missing": "⚠️ Referrer-Policy missing — URL leakage to third parties",
    },

    # 🔍 موجودة = معلومات مفيدة
    "Server": {
        "found": "🔍 Server disclosed — reveals tech stack",
    },
    "X-Powered-By": {
        "found": "🔍 X-Powered-By disclosed — reveals backend (PHP/ASP/Express...)",
    },
    "X-Generator": {
        "found": "🔍 X-Generator disclosed — reveals CMS version",
    },
    "X-AspNet-Version": {
        "found": "🔍 ASP.NET version disclosed",
    },
    "X-AspNetMvc-Version": {
        "found": "🔍 ASP.NET MVC version disclosed",
    },
    "X-Backend-Server": {
        "found": "🔍 Internal backend server name exposed",
    },
    "X-Forwarded-For": {
        "found": "🔍 X-Forwarded-For present — may reveal internal IPs",
    },
    "X-Real-IP": {
        "found": "🔍 X-Real-IP present — may reveal origin server IP",
    },
    "Via": {
        "found": "🔍 Via header present — proxy/CDN info disclosed",
    },
    "Access-Control-Allow-Origin": {
        "found": "🔍 CORS enabled — check for wildcard (*) misconfiguration",
        "wildcard": "🚨 CORS wildcard (*) — any origin can read responses!",
    },
    "Set-Cookie": {
        "found":    "🔍 Cookie set — checking flags...",
        "no_secure":   "🚨 Cookie missing Secure flag — sent over HTTP too",
        "no_httponly": "🚨 Cookie missing HttpOnly flag — accessible via JS (XSS risk)",
        "no_samesite": "⚠️ Cookie missing SameSite flag — CSRF possible",
    },
    "WWW-Authenticate": {
        "found": "🔍 WWW-Authenticate — Basic/Digest/NTLM auth detected",
    },
    "X-Debug-Token": {
        "found": "🚨 Symfony debug token exposed — debug mode ON",
    },
    "X-Debug-Token-Link": {
        "found": "🚨 Symfony profiler link exposed — internal info leaked",
    },
    "X-Application-Context": {
        "found": "🚨 Spring Boot app context exposed",
    },
}


def _analyze_security(headers: dict) -> list:
    """تحليل الـ headers وإرجاع قائمة ملاحظات أمنية"""
    findings = []
    headers_lower = {k.lower(): (k, v) for k, v in headers.items()}

    for header, rules in SECURITY_CHECKS.items():
        key_lower = header.lower()
        if key_lower in headers_lower:
            _, val = headers_lower[key_lower]

            if "found" in rules:
                findings.append(rules["found"] + f"  →  `{val}`")

            # فحوصات خاصة
            if header == "Access-Control-Allow-Origin" and val.strip() == "*":
                findings.append(rules.get("wildcard", ""))

            if header == "Set-Cookie":
                val_lower = val.lower()
                if "secure" not in val_lower:
                    findings.append(rules["no_secure"])
                if "httponly" not in val_lower:
                    findings.append(rules["no_httponly"])
                if "samesite" not in val_lower:
                    findings.append(rules["no_samesite"])
        else:
            if "missing" in rules:
                findings.append(rules["missing"])

    return [f for f in findings if f]


def _normalize(site: str) -> str:
    site = site.strip()
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    return site


def _fetch_one(site: str) -> str:
    site = _normalize(site)
    name = urlparse(site).netloc or site
    output_parts = [f"{'═'*55}", f"  🌐 {name}", f"{'═'*55}"]

    for scheme in ("https://", "http://"):
        url = scheme + urlparse(site).netloc
        try:
            resp = requests.get(url, timeout=TIMEOUT, headers=HEADERS,
                                allow_redirects=True, verify=False)

            # ── كل الـ headers ────────────────────────────────────────────
            output_parts.append("\n📋 ALL HEADERS:")
            output_parts.append(json.dumps(dict(resp.headers), indent=2))

            # ── التحليل الأمني ────────────────────────────────────────────
            findings = _analyze_security(dict(resp.headers))
            if findings:
                output_parts.append("\n🔐 SECURITY ANALYSIS:")
                for f in findings:
                    output_parts.append(f"   {f}")

            return "\n".join(output_parts)

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            return f"❌ {name} — Connection refused or unreachable"
        except requests.exceptions.Timeout:
            return f"⏱️ {name} — Timed out after {TIMEOUT}s"
        except requests.exceptions.TooManyRedirects:
            return f"🔁 {name} — Too many redirects"
        except requests.exceptions.RequestException as e:
            return f"❌ {name} — {e}"

    return f"❌ {name} — Failed on both https and http"


def fetch_headers(sites: list) -> list:
    sites = [s for s in sites if s.strip()]
    if not sites:
        return []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        return list(executor.map(_fetch_one, sites))
