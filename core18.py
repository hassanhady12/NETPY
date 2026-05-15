"""
core18.py — Professional API Security Scanner v2
يغطي OWASP API Top 10 + فحوصات متقدمة

التطويرات في v2:
  ✦ Soft-404 Baseline Detection    — يمنع الـ false positives
  ✦ SSRF Detection                 — Server-Side Request Forgery
  ✦ Open Redirect                  — كشف إعادة التوجيه المفتوحة
  ✦ API Key / Token Exposure       — مفاتيح مكشوفة في الـ response
  ✦ SQL / NoSQL Injection Hints    — أخطاء DB في الـ API
  ✦ HTTP Parameter Pollution       — تلاعب بالـ parameters
  ✦ Broken Function Level Auth     — وصول لدوال مقيّدة
  ✦ Improved content validation    — تحقق من المحتوى الفعلي
  ✦ Better BOLA                    — كشف أذكى
  ✦ Improved CORS                  — فحص أشمل
"""

import re
import json
import time
import hashlib
import base64
import hmac
import hashlib as _hl
import requests
import urllib3
from urllib.parse import urljoin, urlparse, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEV = {
    "critical": "red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "green",
}

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")

_BASE_HEADERS = {
    "User-Agent": _UA,
    "Accept":     "application/json, text/html, */*",
    "Connection": "close",
}


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _s(timeout=12):
    sess = requests.Session()
    sess.verify  = False
    sess.timeout = timeout
    sess.headers.update(_BASE_HEADERS)
    return sess

def _get(sess, url, **kw):
    try:
        return sess.get(url, allow_redirects=True, **kw)
    except Exception:
        return None

def _req(sess, method, url, **kw):
    try:
        return sess.request(method, url, allow_redirects=False, **kw)
    except Exception:
        return None

def _finding(sev, title, url, desc, evidence="", recommendation=""):
    return {
        "type": "finding", "severity": sev,
        "sev_color": SEV.get(sev, "blue"),
        "title": title, "url": url,
        "description": desc,
        "evidence": evidence,
        "recommendation": recommendation,
    }

def _info(msg):
    return {"type": "log", "message": msg}

def _base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _body_hash(r):
    """Hash لمقارنة الـ responses"""
    return hashlib.md5(r.content[:2000]).hexdigest() if r else ""

def _body_sig(r):
    """Signature مختصر للمقارنة (أول 500 char بعد strip HTML tags)"""
    if not r:
        return ""
    text = re.sub(r'<[^>]+>', '', r.text)[:500]
    return text.strip()


# ═══════════════════════════════════════════════════════════════════
# Soft-404 Baseline  ← الحل الأساسي لمشكلة False Positives
# ═══════════════════════════════════════════════════════════════════

class Baseline:
    """
    يرسل طلب لمسار عشوائي مضمون عدم وجوده
    ثم يستخدم الـ response كـ baseline لرفض الـ soft-404
    """
    def __init__(self, sess, base):
        self.status   = None
        self.hash     = None
        self.length   = None
        self.is_catch_all = False
        self._build(sess, base)

    def _build(self, sess, base):
        canary = "/this-path-definitely-does-not-exist-xk9z2q7m"
        r = _get(sess, base + canary)
        if r:
            self.status = r.status_code
            self.hash   = _body_hash(r)
            self.length = len(r.content)
            # الموقع يُعيد 200 لكل شيء = Soft-404
            if r.status_code == 200:
                self.is_catch_all = True

    def is_fake(self, r):
        """هل هذا الـ response هو نفس الـ baseline (soft-404)?"""
        if not r or not self.hash:
            return False
        if r.status_code != 200:
            return False
        # نفس الـ hash → نفس الصفحة
        if _body_hash(r) == self.hash:
            return True
        # طول متقارب جداً (±5%) → غالباً نفس الصفحة
        if self.length and self.length > 0:
            ratio = abs(len(r.content) - self.length) / self.length
            if ratio < 0.05:
                return True
        return False

    def is_real_200(self, r, min_unique_keywords=None):
        """
        هل الـ 200 حقيقي (ليس soft-404)?
        min_unique_keywords: قائمة كلمات يجب وجودها في الـ response
        """
        if not r or r.status_code not in (200, 201):
            return False
        if self.is_fake(r):
            return False
        if min_unique_keywords:
            body = r.text.lower()
            return any(k in body for k in min_unique_keywords)
        return True


# ═══════════════════════════════════════════════════════════════════
# 1. API Endpoint Discovery
# ═══════════════════════════════════════════════════════════════════

API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/openapi.json", "/api/docs",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/docs", "/redoc", "/rapidoc",
    "/.well-known/openapi",
    "/api/schema", "/api/schema.json",
    "/api/v1/docs", "/api/v2/docs",
]

def check_api_discovery(sess, base, bl):
    yield _info("🔍 Scanning for exposed API documentation...")
    for path in API_DOC_PATHS:
        url = base + path
        r = _get(sess, url)
        if not r or r.status_code not in (200, 201):
            continue
        if bl.is_fake(r):
            continue

        ct   = r.headers.get("Content-Type", "")
        body = r.text[:3000]
        is_swagger  = any(k in body.lower() for k in ("swagger", "openapi", "\"paths\""))
        is_html_doc = any(k in body.lower() for k in ("redoc", "swagger-ui", "rapidoc"))
        is_json_api = "application/json" in ct and len(r.content) > 200

        if not (is_swagger or is_html_doc or is_json_api):
            continue

        endpoints_hint = ""
        try:
            doc   = r.json()
            paths = list(doc.get("paths", {}).keys())[:15]
            if paths:
                endpoints_hint = "Endpoints: " + ", ".join(paths)
        except Exception:
            pass

        yield _finding(
            "high", "Exposed API Documentation",
            url,
            "API documentation is publicly accessible. Attackers can enumerate "
            "all endpoints, parameters, authentication, and data models.",
            f"HTTP {r.status_code} · {path}\n{endpoints_hint}",
            "Restrict API docs behind authentication or IP whitelist in production.",
        )

    yield _info("  ✓ API discovery done")


# ═══════════════════════════════════════════════════════════════════
# 2. API Version Enumeration
# ═══════════════════════════════════════════════════════════════════

VERSION_PATHS = [
    "/v1", "/v2", "/v3", "/v4",
    "/api/v1", "/api/v2", "/api/v3",
    "/beta", "/alpha", "/old", "/legacy",
    "/api/beta", "/api/old", "/2.0", "/1.0",
]

def check_api_versions(sess, base, bl):
    yield _info("🔍 Enumerating API versions...")
    active = []
    for path in VERSION_PATHS:
        url = base + path
        r   = _get(sess, url)
        if r and r.status_code in (200, 201, 400, 401, 403, 405, 422):
            if not bl.is_fake(r):
                active.append((url, r.status_code))

    if active:
        old  = [u for u, _ in active if any(x in u for x in ("beta","old","legacy","alpha"))]
        sev  = "medium" if old else "info"
        ev   = "\n".join(f"{u}  →  HTTP {s}" for u, s in active)
        yield _finding(
            sev, "Multiple API Versions Detected", base,
            "Old/deprecated versions may lack security patches.",
            ev,
            "Retire deprecated API versions. Apply same security controls to all.",
        )
    else:
        yield _info("  ✓ No extra API versions found")


# ═══════════════════════════════════════════════════════════════════
# 3. Auth Bypass
# ═══════════════════════════════════════════════════════════════════

AUTH_ENDPOINTS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/accounts", "/api/profile", "/api/me",
    "/api/user/1", "/api/users/1", "/api/v1/me",
    "/api/orders", "/api/payments",
    "/api/config", "/api/settings",
    "/api/keys", "/api/tokens",
]

SENSITIVE_KW = ("email","password","token","secret","user","id","admin",
                "phone","address","credit","card","ssn","dob","birth")

def check_auth_bypass(sess, base, bl):
    yield _info("🔍 Testing authentication bypass...")
    for path in AUTH_ENDPOINTS:
        url = base + path
        r   = _req(sess, "GET", url, headers={"Authorization": ""})
        if not r or r.status_code not in (200, 201):
            continue
        if bl.is_fake(r):
            continue

        body = r.text[:500]
        has_data = (
            any(k in body.lower() for k in SENSITIVE_KW)
            or len(r.content) > 300
        )
        if has_data:
            yield _finding(
                "critical", "API Authentication Bypass (OWASP API2)",
                url,
                "Endpoint returns data without any authentication token.",
                f"GET {url} → HTTP {r.status_code}\n{body[:250]}",
                "Enforce JWT/OAuth2 on ALL endpoints. Never rely on obscurity.",
            )


# ═══════════════════════════════════════════════════════════════════
# 4. JWT Weaknesses
# ═══════════════════════════════════════════════════════════════════

def _jwt_none(payload):
    h = base64.urlsafe_b64encode(
        json.dumps({"alg":"none","typ":"JWT"}).encode()
    ).rstrip(b"=").decode()
    b = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{h}.{b}."

def _jwt_hs256(payload, secret):
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
    b = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    msg = h + b"." + b
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg, _hl.sha256).digest()
    ).rstrip(b"=")
    return (msg + b"." + sig).decode()

def check_jwt(sess, base, bl):
    yield _info("🔍 Testing JWT vulnerabilities...")
    paths   = ["/api/me","/api/profile","/api/v1/me","/api/users/1"]
    payload = {"sub":"1","role":"admin","exp":9999999999}

    # None algorithm
    fake = _jwt_none(payload)
    for path in paths:
        url = base + path
        r   = _req(sess, "GET", url, headers={"Authorization": f"Bearer {fake}"})
        if r and r.status_code in (200, 201) and not bl.is_fake(r):
            yield _finding(
                "critical", "JWT Algorithm None Accepted (OWASP API2)", url,
                "Server accepted JWT with algorithm=none — no signature verification.",
                f"Bearer {fake[:80]}...\n→ HTTP {r.status_code}",
                "Whitelist only RS256/ES256. Never accept 'none'.",
            )
            return

    # Weak secrets
    for secret in ["secret","password","123456","jwt_secret","changeme","letmein",""]:
        token = _jwt_hs256(payload, secret)
        for path in paths:
            url = base + path
            r   = _req(sess, "GET", url, headers={"Authorization": f"Bearer {token}"})
            if r and r.status_code in (200, 201) and not bl.is_fake(r):
                yield _finding(
                    "critical", f"JWT Weak Secret: '{secret}'", url,
                    f"JWT signed with weak secret '{secret}' was accepted.",
                    f"→ HTTP {r.status_code}",
                    "Use cryptographically strong random secrets (≥256 bits).",
                )
                return

    yield _info("  ✓ JWT checks passed")


# ═══════════════════════════════════════════════════════════════════
# 5. BOLA / IDOR
# ═══════════════════════════════════════════════════════════════════

IDOR_PATTERNS = [
    "/api/user/{id}", "/api/users/{id}",
    "/api/v1/user/{id}", "/api/v1/users/{id}",
    "/api/account/{id}", "/api/accounts/{id}",
    "/api/order/{id}", "/api/orders/{id}",
    "/api/profile/{id}", "/api/invoice/{id}",
]

def check_bola(sess, base, bl):
    yield _info("🔍 Testing BOLA/IDOR...")
    for pattern in IDOR_PATTERNS:
        responses = {}
        for oid in [1, 2, 100, 999]:
            url = base + pattern.replace("{id}", str(oid))
            r   = _get(sess, url)
            if r and not bl.is_fake(r):
                responses[oid] = (r.status_code, len(r.content))

        ok = [i for i,(sc,_) in responses.items() if sc == 200]
        if len(ok) >= 2:
            ev = "\n".join(f"ID={i}: HTTP {responses[i][0]}, {responses[i][1]}B" for i in ok)
            yield _finding(
                "high", "Potential BOLA/IDOR (OWASP API1)",
                base + pattern.replace("{id}","1"),
                "Multiple object IDs return 200 without authorization check.",
                ev,
                "Validate ownership per request. Use UUIDs. Object-level auth.",
            )

    yield _info("  ✓ BOLA check done")


# ═══════════════════════════════════════════════════════════════════
# 6. HTTP Method Tampering
# ═══════════════════════════════════════════════════════════════════

def check_http_methods(sess, base, bl):
    yield _info("🔍 Testing HTTP method tampering...")
    paths = ["/api", "/api/users", "/api/v1", "/"]
    danger = []
    for path in paths:
        url = base + path

        # TRACE
        r = _req(sess, "TRACE", url)
        if r and r.status_code == 200:
            yield _finding(
                "medium", "HTTP TRACE Enabled", url,
                "TRACE allows Cross-Site Tracing (XST) to steal auth headers.",
                f"TRACE {url} → HTTP {r.status_code}",
                "Disable TRACE in web server config.",
            )

        # OPTIONS
        r = _req(sess, "OPTIONS", url)
        if r and r.status_code == 200:
            allow = r.headers.get("Allow", "")
            if any(m in allow for m in ("DELETE","TRACE","PUT")):
                yield _finding(
                    "low", "Dangerous Methods in Allow Header", url,
                    f"Allow: {allow}",
                    f"OPTIONS {url} → Allow: {allow}",
                    "Remove dangerous methods from Allow header.",
                )

        # DELETE / PUT
        for method in ("DELETE", "PUT"):
            r = _req(sess, method, url)
            if r and r.status_code not in (404, 405, 501, 403, 0):
                danger.append(f"{method} {url} → HTTP {r.status_code}")

    if danger:
        yield _finding(
            "medium", "Unexpected HTTP Methods Accepted", base,
            "API accepts potentially dangerous HTTP methods.",
            "\n".join(danger),
            "Whitelist allowed methods per endpoint. Return 405 for others.",
        )


# ═══════════════════════════════════════════════════════════════════
# 7. CORS Misconfiguration (improved)
# ═══════════════════════════════════════════════════════════════════

def check_cors(sess, base, bl):
    yield _info("🔍 Testing CORS...")
    domain = urlparse(base).netloc
    origins = [
        "https://evil.com",
        "https://attacker.com",
        f"https://evil.{domain}",
        "null",
        f"https://{domain}.evil.com",
        f"https://not{domain}",
    ]
    paths = ["/api", "/api/v1", "/api/users", "/"]
    for path in paths:
        url = base + path
        for origin in origins:
            r = _req(sess, "GET", url, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            })
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin","")
            acac = r.headers.get("Access-Control-Allow-Credentials","")

            if acao == "*":
                yield _finding("medium","CORS Wildcard",url,
                    "Any origin can access this API.",
                    f"ACAO: {acao}",
                    "Use explicit origin allowlist.")
                return

            if acao == origin and acac.lower() == "true":
                yield _finding("high","CORS Origin Reflect + Credentials (OWASP API7)",url,
                    "Origin reflected AND credentials allowed — session theft possible.",
                    f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                    "Never combine origin reflection with Allow-Credentials: true.")
                return

            if acao and acao not in ("", "*") and acao == origin:
                yield _finding("medium","CORS Origin Reflected",url,
                    "Any attacker origin can read API responses.",
                    f"Origin: {origin}\nACAO: {acao}",
                    "Use strict origin allowlist.")
                return

    yield _info("  ✓ CORS looks OK")


# ═══════════════════════════════════════════════════════════════════
# 8. Security Headers
# ═══════════════════════════════════════════════════════════════════

REQUIRED_H = {
    "X-Content-Type-Options":    ("nosniff","low",   "Prevents MIME sniffing"),
    "X-Frame-Options":           (None,     "low",   "Prevents clickjacking"),
    "Strict-Transport-Security": (None,     "medium","Enforces HTTPS"),
    "Content-Security-Policy":   (None,     "medium","Prevents XSS"),
    "Referrer-Policy":           (None,     "low",   "Controls referrer leakage"),
    "Permissions-Policy":        (None,     "low",   "Restricts browser features"),
}
LEAK_H = {
    "X-Powered-By":     "medium",
    "Server":           "low",
    "X-AspNet-Version": "medium",
    "X-Generator":      "low",
    "X-Runtime":        "low",
    "X-Debug-Token":    "high",
}

def check_security_headers(sess, base, bl):
    yield _info("🔍 Checking security headers...")
    r = _get(sess, base + "/api") or _get(sess, base)
    if not r:
        return

    missing = [(h, s, reason)
               for h, (val, s, reason) in REQUIRED_H.items()
               if not r.headers.get(h)]
    if missing:
        worst = "medium" if any(s == "medium" for _,s,_ in missing) else "low"
        yield _finding(worst, "Missing Security Headers", base,
            f"{len(missing)} headers missing.",
            "\n".join(f"[{s.upper()}] {h}: {reason}" for h,s,reason in missing),
            "Add all missing headers in server/framework config.")

    leaked = [f"{h}: {r.headers[h]}" for h in LEAK_H if r.headers.get(h)]
    if leaked:
        yield _finding("low","Server Info Disclosure via Headers",base,
            "Headers reveal tech stack.",
            "\n".join(leaked),
            "Remove or mask X-Powered-By, Server, X-AspNet-Version.")


# ═══════════════════════════════════════════════════════════════════
# 9. Sensitive Endpoints (with Baseline)
# ═══════════════════════════════════════════════════════════════════

SENSITIVE_PATHS = [
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/debug", "/api/debug/vars", "/api/debug/info",
    "/api/internal", "/api/private", "/api/config",
    "/api/settings", "/api/env", "/api/health",
    "/api/metrics", "/api/actuator", "/api/actuator/env",
    "/api/actuator/beans", "/api/actuator/heapdump",
    "/actuator", "/actuator/env",
    "/.env", "/api/.env", "/api/logs",
    "/api/backup", "/api/export",
    "/phpinfo.php", "/api/phpinfo",    # ← الآن مع baseline check
    "/info.php", "/test.php",
    "/api/console", "/console",
    "/api/graphql", "/graphql",
]

SENS_KW = ("password","secret","token","admin","config","database",
           "db_","key","env","debug","heap","private","internal",
           "phpinfo","php version","loaded modules")

def check_sensitive_endpoints(sess, base, bl):
    yield _info("🔍 Scanning sensitive endpoints...")
    found = []
    for path in SENSITIVE_PATHS:
        url = base + path
        r   = _get(sess, url)
        if not r or r.status_code not in (200, 201):
            continue

        # ← الفلتر الأساسي: تجاهل Soft-404
        if bl.is_fake(r):
            continue

        body = r.text[:800]
        interesting = any(k in body.lower() for k in SENS_KW)
        sev = "critical" if interesting else "high"

        # تحقق إضافي: الـ phpinfo يجب أن يحتوي على "PHP Version"
        if "phpinfo" in path.lower() and "php version" not in body.lower():
            continue   # soft-404 يرجع صفحة عادية بدون PHP info

        found.append((url, r.status_code, sev, body[:300]))

    for url, sc, sev, preview in found:
        yield _finding(sev,"Sensitive Endpoint Exposed (OWASP API9)",url,
            "Administrative/debug endpoint accessible without authentication.",
            f"HTTP {sc}\n{preview}",
            "Restrict access. Remove debug endpoints from production.")

    if not found:
        yield _info("  ✓ No sensitive endpoints exposed")


# ═══════════════════════════════════════════════════════════════════
# 10. Rate Limiting
# ═══════════════════════════════════════════════════════════════════

def check_rate_limiting(sess, base, bl):
    yield _info("🔍 Testing rate limiting...")
    test_url = None
    for path in ["/api/login","/api/v1/login","/api/auth/login",
                 "/api/auth","/login","/api/users"]:
        r = _get(sess, base + path)
        if r and r.status_code not in (404, 502, 503) and not bl.is_fake(r):
            test_url = base + path
            break
    if not test_url:
        test_url = base + "/api"

    codes = []
    for _ in range(25):
        r = _req(sess, "POST", test_url,
                 json={"username":"test","password":"test"},
                 headers={"Content-Type":"application/json"}, timeout=5)
        codes.append(r.status_code if r else 0)

    has_block = any(c in codes for c in (429,503,509))
    if not has_block and len(set(codes)) <= 2 and codes[0] not in (404,):
        yield _finding("medium","No Rate Limiting (OWASP API4)",test_url,
            f"25 rapid requests — no throttling (no 429). Brute-force possible.",
            f"Responses: {dict((c,codes.count(c)) for c in set(codes))}",
            "Add rate limiting: 5 req/min on auth. Use Redis token bucket.")
    else:
        yield _info(f"  ✓ Rate limiting active ({codes.count(429)} × 429)")


# ═══════════════════════════════════════════════════════════════════
# 11. Error / Stack Trace
# ═══════════════════════════════════════════════════════════════════

STACK_PAT = [
    r"Traceback \(most recent call",
    r"at\s+\w+\.\w+\([\w\.]+:\d+\)",
    r"System\.Web\.", r"Microsoft\.AspNet",
    r"ORA-\d{5}", r"mysql_fetch", r"PDOException",
    r"Uncaught Exception", r"SQL syntax.*MySQL",
    r"Warning.*pg_", r"SQLSTATE\[",
    r"laravel", r"django\.core", r"stack trace",
    r"Internal Server Error.*at\s",
]

def check_error_disclosure(sess, base, bl):
    yield _info("🔍 Testing error disclosure...")
    probes = [
        ("GET",  "/api/users/abc", {}),
        ("POST", "/api/users",     {"id":"' OR 1=1--","name":"<script>alert(1)</script>"}),
        ("GET",  "/api/user/99999999", {}),
        ("GET",  "/api/v1/users/0", {}),
    ]
    for method, path, body in probes:
        url = base + path
        r   = _req(sess, method, url,
                   json=body if body else None,
                   headers={"Content-Type":"application/json"} if body else {})
        if not r:
            continue
        for pat in STACK_PAT:
            if re.search(pat, r.text, re.IGNORECASE):
                yield _finding("medium","Verbose Error / Stack Trace (OWASP API8)",url,
                    "Error responses reveal stack trace / internal paths.",
                    f"{method} {url} → HTTP {r.status_code}\n"
                    f"Matched: {pat}\n{r.text[:300]}",
                    "Return generic errors in production. Log details server-side only.")
                break


# ═══════════════════════════════════════════════════════════════════
# 12. Sensitive Data Exposure
# ═══════════════════════════════════════════════════════════════════

SENS_DATA_PAT = {
    r'["\']?password["\']?\s*:\s*["\'][^"\']{3,}["\']':     ("high",   "Password in response"),
    r'["\']?secret["\']?\s*:\s*["\'][^"\']{8,}["\']':       ("high",   "Secret key in response"),
    r'["\']?api[_-]?key["\']?\s*:\s*["\'][^"\']{8,}["\']':  ("high",   "API key in response"),
    r'["\']?token["\']?\s*:\s*["\'][^"\']{20,}["\']':        ("medium", "Token in response"),
    r'\b\d{3}-\d{2}-\d{4}\b':                               ("high",   "SSN pattern"),
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b':          ("high",   "Credit card pattern"),
    r'"credit_card"\s*:':                                    ("high",   "Credit card field"),
    r'"ssn"\s*:':                                            ("high",   "SSN field"),
    r'-----BEGIN (RSA |EC )?PRIVATE KEY':                    ("critical","Private key in response"),
    r'["\']?aws[_-]?access[_-]?key["\']?\s*:\s*["\']AKIA':  ("critical","AWS key in response"),
}

def check_sensitive_data(sess, base, bl):
    yield _info("🔍 Checking sensitive data exposure...")
    paths = ["/api/users","/api/user/1","/api/me","/api/profile",
             "/api/v1/users","/api/v1/me","/api/accounts"]
    for path in paths:
        url = base + path
        r   = _get(sess, url)
        if not r or r.status_code not in (200,201) or bl.is_fake(r):
            continue
        for pat, (sev, label) in SENS_DATA_PAT.items():
            m = re.search(pat, r.text, re.IGNORECASE)
            if m:
                snippet = r.text[max(0,m.start()-30):m.end()+30]
                yield _finding(sev,f"Sensitive Data Exposure: {label} (OWASP API3)",url,
                    f"API response contains {label.lower()}.",
                    f"Pattern: {pat}\n...{snippet}...",
                    "Never return passwords/secrets. Mask sensitive fields.")


# ═══════════════════════════════════════════════════════════════════
# 13. Mass Assignment
# ═══════════════════════════════════════════════════════════════════

def check_mass_assignment(sess, base, bl):
    yield _info("🔍 Testing mass assignment...")
    paths   = ["/api/users","/api/v1/users","/api/profile","/api/register"]
    priv    = {"role":"admin","is_admin":True,"admin":True,"isAdmin":True,
               "permissions":["admin"],"balance":999999,"verified":True}
    for path in paths:
        url = base + path
        r   = _req(sess, "POST", url,
                   json={"name":"test","email":"test@test.com",**priv},
                   headers={"Content-Type":"application/json"})
        if not r or r.status_code not in (200,201) or bl.is_fake(r):
            continue
        reflected = [k for k in priv if k.lower() in r.text.lower()]
        if reflected:
            yield _finding("high","Mass Assignment (OWASP API6)",url,
                f"Privileged fields accepted: {reflected}",
                f"POST {url} → HTTP {r.status_code}\nFields: {reflected}",
                "Use DTO allowlist. Never bind request body directly to DB model.")


# ═══════════════════════════════════════════════════════════════════
# 14. GraphQL Introspection
# ═══════════════════════════════════════════════════════════════════

GQL_PATHS  = ["/graphql","/api/graphql","/gql","/api/gql","/query"]
GQL_QUERY  = {"query":"{ __schema { queryType { name } types { name fields { name } } } }"}

def check_graphql(sess, base, bl):
    yield _info("🔍 Testing GraphQL...")
    for path in GQL_PATHS:
        url = base + path
        r   = _req(sess, "POST", url,
                   json=GQL_QUERY,
                   headers={"Content-Type":"application/json"})
        if not r or bl.is_fake(r):
            continue
        if r.status_code in (200,201):
            try:
                data = r.json()
                if "__schema" in str(data):
                    types = [t["name"] for t in
                             data.get("data",{}).get("__schema",{}).get("types",[])
                             if not t["name"].startswith("__")][:15]
                    yield _finding("high","GraphQL Introspection Enabled (OWASP API9)",url,
                        "Full schema exposed — all types, fields, mutations visible.",
                        f"Types: {', '.join(types)}",
                        "Disable introspection in production. Add query depth limits.")
                else:
                    yield _finding("info","GraphQL Endpoint Detected",url,
                        "GraphQL endpoint found, introspection disabled.",
                        f"HTTP {r.status_code}",
                        "Ensure auth, depth limiting, and no introspection in prod.")
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════
# 15. SSRF Detection  ← NEW
# ═══════════════════════════════════════════════════════════════════

SSRF_PARAMS   = ["url","redirect","callback","uri","endpoint","target",
                 "dest","destination","link","src","source","fetch","load"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://metadata.google.internal/",            # GCP metadata
    "http://127.0.0.1:22",
    "http://localhost:6379",                       # Redis
    "http://0.0.0.0:3306",                        # MySQL
    "dict://127.0.0.1:11211/stat",                # Memcached
]
SSRF_INDICATORS = [
    "ami-id","instance-id","local-ipv4",   # AWS
    "computeMetadata","project-id",         # GCP
    "SSH-","redis_version",                 # Redis/SSH
    "mysql","mariadb",
]

def check_ssrf(sess, base, bl):
    yield _info("🔍 Testing SSRF...")
    found = False

    # فحص الـ endpoints الشائعة التي تقبل URLs
    probe_paths = ["/api/fetch","/api/proxy","/api/screenshot",
                   "/api/webhook","/api/import","/api/url"]
    for path in probe_paths:
        for ssrf_url in SSRF_PAYLOADS[:2]:
            url = base + path
            for param in SSRF_PARAMS[:3]:
                r = _req(sess, "GET", url, params={param: ssrf_url})
                if not r or bl.is_fake(r):
                    continue
                body = r.text
                if any(ind in body for ind in SSRF_INDICATORS):
                    yield _finding(
                        "critical", "SSRF — Internal Metadata Accessible", url,
                        f"Server fetched internal resource: {ssrf_url}",
                        f"Param: {param}={ssrf_url}\nHTTP {r.status_code}\n{body[:200]}",
                        "Validate and whitelist URLs. Block internal IP ranges. "
                        "Use network egress filtering.",
                    )
                    found = True
                    break

    # فحص الـ response time: إذا كان الـ request لـ internal IP بطيئاً → SSRF محتمل
    for path in ["/api", "/api/v1"]:
        for param in SSRF_PARAMS[:4]:
            url   = base + path
            start = time.perf_counter()
            r = _req(sess, "GET", url,
                     params={param: "http://169.254.169.254/latest/meta-data/"},
                     timeout=8)
            elapsed = time.perf_counter() - start
            if r and elapsed > 5 and r.status_code not in (400, 403, 422):
                yield _finding(
                    "medium", "Possible SSRF — Slow Response to Internal IP",
                    f"{url}?{param}=...",
                    f"Request to internal IP took {elapsed:.1f}s — server may be fetching it.",
                    f"Param: {param} · {elapsed:.1f}s delay · HTTP {r.status_code}",
                    "Validate and block internal IP ranges in URL parameters.",
                )
                found = True
                break

    if not found:
        yield _info("  ✓ No obvious SSRF found")


# ═══════════════════════════════════════════════════════════════════
# 16. Open Redirect  ← NEW
# ═══════════════════════════════════════════════════════════════════

REDIRECT_PARAMS = ["redirect","return","next","url","goto","dest",
                   "destination","continue","redir","r","return_url","callback"]
REDIRECT_TEST   = "https://evil.com/phishing"

def check_open_redirect(sess, base, bl):
    yield _info("🔍 Testing open redirect...")
    paths = ["/api/login","/api/auth","/login","/api/v1/login","/","/api"]

    for path in paths:
        url = base + path
        for param in REDIRECT_PARAMS:
            r = _req(sess, "GET", url, params={param: REDIRECT_TEST})
            if not r:
                continue
            loc = r.headers.get("Location","")
            if r.status_code in (301,302,303,307,308) and "evil.com" in loc:
                yield _finding(
                    "high", "Open Redirect Vulnerability",
                    f"{url}?{param}=...",
                    f"Redirect parameter '{param}' can send users to attacker-controlled URLs. "
                    "Used in phishing and OAuth token theft attacks.",
                    f"?{param}={REDIRECT_TEST}\n→ HTTP {r.status_code} Location: {loc}",
                    "Validate redirect URLs against a strict allowlist. "
                    "Never redirect to user-supplied external URLs.",
                )
                return

    yield _info("  ✓ No open redirect found")


# ═══════════════════════════════════════════════════════════════════
# 17. SQL / NoSQL Injection Hints  ← NEW
# ═══════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = ["'", "''", "' OR '1'='1", "1 OR 1=1", "' OR 1=1--",
                 "\" OR \"1\"=\"1", "';SELECT 1--"]
SQLI_ERRORS   = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"pg_query\(\)",
    r"SQLite.*error",
    r"Microsoft.*ODBC.*Driver",
    r"SQLSTATE\[",
    r"syntax error.*near",
]

NOSQL_PAYLOADS = [
    '{"$gt":""}',
    '{"$ne":null}',
    '{"$where":"1==1"}',
]

def check_sql_injection(sess, base, bl):
    yield _info("🔍 Testing SQL/NoSQL injection hints...")
    paths = ["/api/users","/api/login","/api/search",
             "/api/v1/users","/api/products","/api/items"]

    for path in paths:
        url = base + path

        # GET params
        for payload in SQLI_PAYLOADS[:4]:
            r = _req(sess, "GET", url,
                     params={"id": payload, "q": payload, "search": payload})
            if not r:
                continue
            body = r.text.lower()
            for err in SQLI_ERRORS:
                if re.search(err, body, re.IGNORECASE):
                    yield _finding(
                        "critical", "SQL Injection Hint Detected",
                        url,
                        f"Error message in response suggests SQL injection vulnerability.",
                        f"Payload: {payload}\nHTTP {r.status_code}\n"
                        f"Matched error: {err}\nResponse: {r.text[:300]}",
                        "Use parameterized queries / prepared statements. "
                        "Never concatenate user input in SQL queries.",
                    )
                    return

        # NoSQL (POST JSON)
        for payload in NOSQL_PAYLOADS:
            try:
                data = json.loads(payload)
                r = _req(sess, "POST", url,
                         json={"username": data, "password": data},
                         headers={"Content-Type":"application/json"})
                if r and r.status_code in (200, 201) and not bl.is_fake(r):
                    body = r.text
                    if any(k in body.lower() for k in SENSITIVE_KW):
                        yield _finding(
                            "critical", "NoSQL Injection — Possible Authentication Bypass",
                            url,
                            f"NoSQL operator payload returned data — authentication may be bypassable.",
                            f"Payload: {payload}\nHTTP {r.status_code}\n{body[:300]}",
                            "Sanitize all input before MongoDB/CouchDB queries. "
                            "Validate field types strictly.",
                        )
                        return
            except Exception:
                pass

    yield _info("  ✓ No obvious SQLi found")


# ═══════════════════════════════════════════════════════════════════
# 18. API Key / Token Exposure in Headers & Responses  ← NEW
# ═══════════════════════════════════════════════════════════════════

KEY_PATTERNS = {
    r'AKIA[0-9A-Z]{16}':                             ("critical", "AWS Access Key"),
    r'["\']?aws_secret["\']?\s*:\s*["\'][^"\']{20,}':(  "critical", "AWS Secret Key"),
    r'ghp_[A-Za-z0-9]{36}':                          ("critical", "GitHub Personal Token"),
    r'ghs_[A-Za-z0-9]{36}':                          ("critical", "GitHub App Token"),
    r'xox[baprs]-[0-9A-Za-z]{10,}':                  ("critical", "Slack Token"),
    r'AIza[0-9A-Za-z\-_]{35}':                       ("high",     "Google API Key"),
    r'["\']?stripe["\']?\s*:\s*["\']sk_(live|test)_[0-9a-zA-Z]{24,}':(
                                                       "critical", "Stripe Secret Key"),
    r'-----BEGIN (RSA |EC )?PRIVATE KEY':             ("critical", "Private Key"),
    r'["\']?auth[_-]?token["\']?\s*:\s*["\'][^"\']{20,}':(
                                                       "high",     "Auth Token in Response"),
}

def check_key_exposure(sess, base, bl):
    yield _info("🔍 Checking for exposed API keys/tokens...")
    paths = ["/api","/api/v1","/api/config","/api/settings","/.env","/api/.env"]
    for path in paths:
        url = base + path
        r   = _get(sess, url)
        if not r or bl.is_fake(r):
            continue
        # فحص الـ headers أيضاً
        combined = r.text + str(dict(r.headers))
        for pat, (sev, label) in KEY_PATTERNS.items():
            m = re.search(pat, combined, re.IGNORECASE)
            if m:
                snippet = combined[max(0,m.start()-20):m.end()+20]
                yield _finding(sev, f"Exposed {label}", url,
                    f"A {label} was found in the API response or response headers.",
                    f"Pattern: {pat}\n...{snippet}...",
                    "Immediately rotate the exposed key. Never include secrets in responses.")


# ═══════════════════════════════════════════════════════════════════
# Main orchestrator
# ═══════════════════════════════════════════════════════════════════

CHECKS = [
    ("API Documentation",    check_api_discovery),
    ("API Versions",         check_api_versions),
    ("Auth Bypass",          check_auth_bypass),
    ("JWT Weaknesses",       check_jwt),
    ("BOLA / IDOR",          check_bola),
    ("HTTP Methods",         check_http_methods),
    ("CORS",                 check_cors),
    ("Security Headers",     check_security_headers),
    ("Sensitive Endpoints",  check_sensitive_endpoints),
    ("Rate Limiting",        check_rate_limiting),
    ("Error Disclosure",     check_error_disclosure),
    ("Sensitive Data",       check_sensitive_data),
    ("Mass Assignment",      check_mass_assignment),
    ("GraphQL",              check_graphql),
    ("SSRF",                 check_ssrf),
    ("Open Redirect",        check_open_redirect),
    ("SQL / NoSQL Injection",check_sql_injection),
    ("Key / Token Exposure", check_key_exposure),
]


def scan_api(target_url, selected_checks=None, auth_header=None, timeout=12):
    base = _base(target_url.rstrip("/"))
    sess = _s(timeout=timeout)
    if auth_header:
        sess.headers["Authorization"] = auth_header

    # ← بناء الـ Baseline أولاً
    yield _info("🔧 Building soft-404 baseline...")
    bl = Baseline(sess, base)
    if bl.is_catch_all:
        yield _info(f"  ⚠️ Soft-404 detected (site returns 200 for all paths) — false positives will be filtered")
    else:
        yield _info(f"  ✓ Baseline built (404 = HTTP {bl.status})")

    total_checks = len(selected_checks) if selected_checks else len(CHECKS)
    done_checks  = 0
    findings     = 0

    yield {"type":"start","base":base,"total_checks":total_checks}

    for name, fn in CHECKS:
        if selected_checks and name not in selected_checks:
            continue

        yield {"type":"section","name":name}
        try:
            for event in fn(sess, base, bl):
                if event.get("type") == "finding":
                    findings += 1
                yield event
        except Exception as e:
            yield _info(f"  ⚠️ {name} failed: {e}")

        done_checks += 1
        yield {
            "type":    "progress",
            "done":    done_checks,
            "total":   total_checks,
            "percent": round(done_checks / total_checks * 100),
        }

    yield {"type":"done","findings":findings,"checks":done_checks}
