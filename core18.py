"""
core18.py — Professional API Security Scanner
يغطي OWASP API Top 10 + اكتشاف متقدم

الفحوصات:
  1.  API Endpoint Discovery     — swagger, openapi, graphql, api-docs
  2.  API Version Enumeration    — v1/v2/v3/beta/old/legacy
  3.  Auth Bypass                — الوصول بدون token
  4.  JWT Weaknesses             — none alg, weak secret, expired accepted
  5.  BOLA / IDOR                — تغيير الـ IDs في الـ endpoints
  6.  HTTP Method Tampering      — PUT/DELETE/PATCH/TRACE على endpoints
  7.  CORS Misconfiguration      — wildcard, credential + origin reflect
  8.  Security Headers           — فحص الهيدرات المفقودة
  9.  Sensitive Endpoints        — admin/debug/internal/config
  10. Rate Limiting              — هل يوجد حماية من الـ flooding
  11. Error & Stack Trace        — verbose errors تكشف stack/DB/path
  12. Sensitive Data Exposure    — PII / secrets في الـ responses
  13. Mass Assignment            — إضافة حقول غير مصرّح بها
  14. GraphQL Introspection      — schema مكشوف
"""

import re
import json
import time
import base64
import requests
import urllib3
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Colours / Severity ───────────────────────────────────────────────────────
SEV = {
    "critical": "red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "blue",
    "info":     "green",
}

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/122.0.0.0 Safari/537.36")

_BASE_HEADERS = {
    "User-Agent": _UA,
    "Accept":     "application/json, */*",
    "Connection": "close",
}


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _s(timeout=12):
    """New requests session"""
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
        "type":           "finding",
        "severity":       sev,
        "sev_color":      SEV.get(sev, "blue"),
        "title":          title,
        "url":            url,
        "description":    desc,
        "evidence":       evidence,
        "recommendation": recommendation,
    }


def _info(msg):
    return {"type": "log", "message": msg}


def _base(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


# ─── 1. API Endpoint Discovery ───────────────────────────────────────────────
API_DOC_PATHS = [
    "/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api-docs", "/api-docs.json",
    "/api/swagger.json", "/api/openapi.json", "/api/docs",
    "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
    "/api/v1/swagger.json", "/api/v2/swagger.json",
    "/docs", "/docs/", "/redoc", "/rapidoc",
    "/.well-known/openapi", "/api",
    "/api/schema", "/api/schema.json",
]

def check_api_discovery(sess, base):
    yield _info("🔍 Scanning for exposed API documentation...")
    found_endpoints = []

    for path in API_DOC_PATHS:
        url = base + path
        r = _get(sess, url)
        if not r or r.status_code not in (200, 201):
            continue

        ct = r.headers.get("Content-Type", "")
        body = r.text[:2000]

        is_swagger  = "swagger" in body.lower() or "openapi" in body.lower()
        is_json_api = ct.startswith("application/json") and len(r.content) > 100
        is_html_doc = "redoc" in body.lower() or "swagger-ui" in body.lower()

        if is_swagger or is_json_api or is_html_doc:
            found_endpoints.append(url)
            # Extract endpoints from swagger if possible
            endpoints_hint = ""
            try:
                doc = r.json()
                paths = list(doc.get("paths", {}).keys())[:10]
                if paths:
                    endpoints_hint = "Paths found: " + ", ".join(paths)
            except Exception:
                pass

            yield _finding(
                "high", "Exposed API Documentation",
                url,
                "API documentation is publicly accessible. Attackers can enumerate "
                "all endpoints, parameters, authentication methods, and data models.",
                f"HTTP {r.status_code} — {path}\n{endpoints_hint}",
                "Restrict access to API docs (require auth or IP whitelist). "
                "Never expose docs in production.",
            )

    if not found_endpoints:
        yield _info("  ✓ No exposed API docs found")


# ─── 2. API Version Enumeration ──────────────────────────────────────────────
VERSION_PATHS = [
    "/v1", "/v2", "/v3", "/v4",
    "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/", "/api/v2/",
    "/beta", "/alpha", "/old", "/legacy",
    "/api/beta", "/api/old",
    "/2.0", "/1.0", "/1.1",
]

def check_api_versions(sess, base):
    yield _info("🔍 Enumerating API versions...")
    active = []

    for path in VERSION_PATHS:
        url = base + path
        r = _get(sess, url)
        if r and r.status_code in (200, 201, 400, 401, 403, 405, 422):
            active.append((url, r.status_code))

    if active:
        found_str = "\n".join(f"{u}  →  HTTP {s}" for u, s in active)
        # Flag old/deprecated versions
        old = [u for u, _ in active if any(x in u for x in ("beta", "old", "legacy", "alpha"))]
        sev = "medium" if old else "info"
        yield _finding(
            sev, "Multiple API Versions Detected",
            base,
            "Multiple API versions are active. Old/deprecated versions may lack "
            "security patches and expose legacy vulnerabilities.",
            found_str,
            "Retire deprecated API versions. Redirect old versions to latest. "
            "Apply the same security controls across all versions.",
        )
    else:
        yield _info("  ✓ No extra API versions found")


# ─── 3. Auth Bypass ──────────────────────────────────────────────────────────
AUTH_ENDPOINTS = [
    "/api/users", "/api/v1/users", "/api/v2/users",
    "/api/admin", "/api/v1/admin",
    "/api/accounts", "/api/profile", "/api/me",
    "/api/user/1", "/api/users/1",
    "/api/v1/user/1", "/api/v1/me",
    "/api/orders", "/api/payments",
    "/api/config", "/api/settings",
    "/api/keys", "/api/tokens",
]

def check_auth_bypass(sess, base):
    yield _info("🔍 Testing authentication bypass...")

    for path in AUTH_ENDPOINTS:
        url = base + path
        # بدون أي auth header
        r = _req(sess, "GET", url, headers={"Authorization": ""})
        if not r:
            continue

        if r.status_code in (200, 201):
            body_preview = r.text[:300]
            # تحقق إذا الـ response يحتوي على بيانات حساسة
            has_data = any(k in body_preview.lower() for k in
                           ("email", "password", "token", "secret", "user", "id", "admin"))
            if has_data or len(r.content) > 200:
                yield _finding(
                    "critical", "API Authentication Bypass (OWASP API2)",
                    url,
                    "This endpoint returns data without any authentication token. "
                    "Broken Authentication allows attackers to access protected resources freely.",
                    f"GET {url} → HTTP {r.status_code}\nResponse preview: {body_preview[:200]}",
                    "Enforce authentication on ALL API endpoints. Use JWT/OAuth2 with "
                    "proper validation. Never rely on security-through-obscurity.",
                )


# ─── 4. JWT Weaknesses ───────────────────────────────────────────────────────
def _make_jwt_none(payload: dict) -> str:
    """صنع JWT مع algorithm=none"""
    header  = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body    = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."   # بدون signature


def check_jwt(sess, base):
    yield _info("🔍 Testing JWT vulnerabilities...")

    # JWT none algorithm
    test_endpoints = ["/api/me", "/api/profile", "/api/v1/me", "/api/users/1"]
    payload = {"sub": "1", "role": "admin", "exp": 9999999999}
    fake_jwt = _make_jwt_none(payload)

    for path in test_endpoints:
        url = base + path
        r = _req(sess, "GET", url, headers={"Authorization": f"Bearer {fake_jwt}"})
        if r and r.status_code in (200, 201):
            yield _finding(
                "critical", "JWT Algorithm None Accepted (OWASP API2)",
                url,
                "The server accepted a JWT token with algorithm=none, meaning "
                "it does not verify the token signature. Attackers can forge any token.",
                f"Bearer {fake_jwt[:80]}...\n→ HTTP {r.status_code}",
                "Explicitly whitelist allowed algorithms (only RS256/ES256). "
                "Never accept 'none' or 'HS256' with untrusted keys.",
            )
            return

    # JWT with expired token test — try common weak secrets
    weak_secrets = ["secret", "password", "123456", "jwt_secret", ""]
    import hmac, hashlib
    for secret in weak_secrets:
        header_b  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=")
        payload_b = base64.urlsafe_b64encode(
            json.dumps({"sub": "1", "role": "admin", "exp": 9999999999}).encode()
        ).rstrip(b"=")
        msg = header_b + b"." + payload_b
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), msg, hashlib.sha256).digest()
        ).rstrip(b"=")
        token = (msg + b"." + sig).decode()

        for path in test_endpoints:
            url = base + path
            r = _req(sess, "GET", url, headers={"Authorization": f"Bearer {token}"})
            if r and r.status_code in (200, 201):
                yield _finding(
                    "critical", f"JWT Weak Secret Accepted: '{secret}'",
                    url,
                    f"The JWT was signed with the weak secret '{secret}' and was accepted. "
                    "Attackers can forge admin tokens and bypass all authorization.",
                    f"Secret: '{secret}' → HTTP {r.status_code}",
                    "Use cryptographically strong random secrets (≥256 bits). "
                    "Consider asymmetric signing (RS256).",
                )
                return

    yield _info("  ✓ JWT basic checks passed")


# ─── 5. BOLA / IDOR ──────────────────────────────────────────────────────────
IDOR_PATTERNS = [
    "/api/user/{id}", "/api/users/{id}",
    "/api/v1/user/{id}", "/api/v1/users/{id}",
    "/api/account/{id}", "/api/accounts/{id}",
    "/api/order/{id}", "/api/orders/{id}",
    "/api/profile/{id}",
    "/api/invoice/{id}",
]

def check_bola(sess, base):
    yield _info("🔍 Testing BOLA/IDOR vulnerabilities...")

    found_any = False
    test_ids  = [1, 2, 100, 999]

    for pattern in IDOR_PATTERNS:
        responses = {}
        for oid in test_ids:
            url = base + pattern.replace("{id}", str(oid))
            r = _get(sess, url)
            if r:
                responses[oid] = (r.status_code, len(r.content))

        # إذا أكثر من ID يرجع 200 بمحتوى مختلف → BOLA محتمل
        ok_ids = [i for i, (sc, _) in responses.items() if sc == 200]
        if len(ok_ids) >= 2:
            evidence = "\n".join(
                f"ID={i}: HTTP {responses[i][0]}, {responses[i][1]} bytes"
                for i in ok_ids
            )
            yield _finding(
                "high", "Potential BOLA/IDOR Vulnerability (OWASP API1)",
                base + pattern.replace("{id}", "1"),
                "Multiple object IDs return 200 without authorization check. "
                "This suggests Broken Object Level Authorization — attackers can "
                "access any user's data by changing the ID in the URL.",
                evidence,
                "Validate that the authenticated user owns the requested resource. "
                "Use UUIDs instead of sequential integers. Implement object-level checks.",
            )
            found_any = True

    if not found_any:
        yield _info("  ✓ No obvious BOLA patterns found")


# ─── 6. HTTP Method Tampering ─────────────────────────────────────────────────
DANGEROUS_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"]

def check_http_methods(sess, base):
    yield _info("🔍 Testing HTTP method tampering...")

    test_paths = ["/api", "/api/users", "/api/v1", "/"]
    dangerous_found = []

    for path in test_paths:
        url = base + path
        for method in DANGEROUS_METHODS:
            r = _req(sess, method, url)
            if not r:
                continue

            if method == "TRACE" and r.status_code == 200:
                dangerous_found.append((method, url, r.status_code))
                yield _finding(
                    "medium", "HTTP TRACE Method Enabled",
                    url,
                    "TRACE method is enabled. Can be used in Cross-Site Tracing (XST) "
                    "attacks to steal cookies and auth headers.",
                    f"TRACE {url} → HTTP {r.status_code}",
                    "Disable TRACE method in server configuration.",
                )

            elif method == "OPTIONS" and r.status_code == 200:
                allow = r.headers.get("Allow", "")
                if any(m in allow for m in ("DELETE", "TRACE", "PUT")):
                    yield _finding(
                        "low", "Dangerous HTTP Methods Advertised",
                        url,
                        f"OPTIONS response advertises potentially dangerous methods: {allow}",
                        f"OPTIONS {url} → Allow: {allow}",
                        "Remove dangerous methods from Allow header if not required.",
                    )

            elif method in ("DELETE", "PUT") and r.status_code not in (404, 405, 501, 403):
                dangerous_found.append((method, url, r.status_code))

    if dangerous_found:
        ev = "\n".join(f"{m} {u} → HTTP {s}" for m, u, s in dangerous_found)
        yield _finding(
            "medium", "Unexpected HTTP Methods Accepted",
            base,
            "The API accepts potentially dangerous HTTP methods that may allow "
            "unauthorized data modification or deletion.",
            ev,
            "Explicitly whitelist allowed HTTP methods per endpoint. "
            "Return 405 for all others.",
        )


# ─── 7. CORS Misconfiguration ────────────────────────────────────────────────
def check_cors(sess, base):
    yield _info("🔍 Testing CORS misconfiguration...")

    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        f"https://evil.{urlparse(base).netloc}",  # subdomain takeover style
        "null",
    ]

    api_paths = ["/api", "/api/v1", "/api/users", "/"]

    for path in api_paths:
        url = base + path
        for origin in test_origins:
            r = _req(sess, "GET", url, headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
            })
            if not r:
                continue

            acao  = r.headers.get("Access-Control-Allow-Origin", "")
            acac  = r.headers.get("Access-Control-Allow-Credentials", "")

            if acao == "*":
                yield _finding(
                    "medium", "CORS Wildcard Origin",
                    url,
                    "The server allows all origins (*). Any website can make "
                    "cross-origin requests to this API.",
                    f"Origin: {origin}\nAccess-Control-Allow-Origin: {acao}",
                    "Define explicit allowed origins. Never use * with credentials.",
                )
                return

            if acao == origin and acac.lower() == "true":
                yield _finding(
                    "high", "CORS Origin Reflection + Credentials (OWASP API7)",
                    url,
                    "The server reflects the attacker's origin AND allows credentials. "
                    "This is a critical CORS misconfiguration — allows CSRF/session theft "
                    "from any malicious website.",
                    f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                    "Maintain a strict allowlist of trusted origins. "
                    "Never combine origin reflection with Allow-Credentials: true.",
                )
                return

            if acao == "null" or (acao and acao != "*" and acao == origin):
                yield _finding(
                    "medium", "CORS Origin Reflected",
                    url,
                    "The server reflects any Origin header. Attackers can craft "
                    "malicious pages to read API responses.",
                    f"Origin: {origin}\nACAO: {acao}",
                    "Use a strict allowlist of trusted origins.",
                )
                return

    yield _info("  ✓ CORS appears properly configured")


# ─── 8. Security Headers ─────────────────────────────────────────────────────
REQUIRED_HEADERS = {
    "X-Content-Type-Options":    ("nosniff", "low",    "Prevents MIME-type sniffing attacks"),
    "X-Frame-Options":           (None,      "low",    "Prevents clickjacking attacks"),
    "Strict-Transport-Security": (None,      "medium", "Enforces HTTPS connections"),
    "Content-Security-Policy":   (None,      "medium", "Prevents XSS and injection attacks"),
    "X-XSS-Protection":          (None,      "low",    "Legacy XSS filter (still useful)"),
    "Referrer-Policy":           (None,      "low",    "Controls referrer information leakage"),
    "Permissions-Policy":        (None,      "low",    "Restricts browser feature access"),
}

DANGEROUS_HEADERS = {
    "X-Powered-By":    "high",
    "Server":          "low",
    "X-AspNet-Version":"medium",
    "X-Generator":     "low",
}

def check_security_headers(sess, base):
    yield _info("🔍 Checking security headers...")

    r = _get(sess, base + "/api")
    if not r:
        r = _get(sess, base)
    if not r:
        return

    missing = []
    for hdr, (val, sev, reason) in REQUIRED_HEADERS.items():
        present = r.headers.get(hdr, "")
        if not present:
            missing.append((hdr, sev, reason))
        elif val and val.lower() not in present.lower():
            missing.append((hdr, sev, f"Wrong value: '{present}' (expected '{val}')"))

    if missing:
        by_sev = {}
        for h, s, r_txt in missing:
            by_sev.setdefault(s, []).append(f"{h}: {r_txt}")
        worst = "medium" if "medium" in by_sev else "low"
        evidence = "\n".join(
            f"[{s.upper()}] {h}" for h, s, _ in missing
        )
        yield _finding(
            worst, "Missing Security Headers",
            base,
            f"{len(missing)} security headers are missing from API responses.",
            evidence,
            "Add all missing security headers in your web server / API framework configuration.",
        )

    # Dangerous headers (info disclosure)
    leaked = []
    for hdr, sev in DANGEROUS_HEADERS.items():
        val = r.headers.get(hdr, "")
        if val:
            leaked.append(f"{hdr}: {val}")

    if leaked:
        yield _finding(
            "low", "Server Information Disclosure via Headers",
            base,
            "Response headers reveal technology stack details that help attackers fingerprint the server.",
            "\n".join(leaked),
            "Remove or mask X-Powered-By, Server, X-AspNet-Version headers.",
        )


# ─── 9. Sensitive Endpoints ───────────────────────────────────────────────────
SENSITIVE_PATHS = [
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/debug", "/api/debug/vars", "/api/debug/info",
    "/api/internal", "/api/private",
    "/api/config", "/api/settings", "/api/env",
    "/api/health", "/api/metrics", "/api/actuator",
    "/api/actuator/env", "/api/actuator/beans",
    "/api/actuator/heapdump", "/api/actuator/trace",
    "/actuator", "/actuator/env", "/actuator/beans",
    "/.env", "/api/.env",
    "/api/logs", "/api/log",
    "/api/backup", "/api/export",
    "/api/graphql", "/graphql",
    "/api/console", "/console",
    "/api/phpinfo", "/phpinfo.php",
]

def check_sensitive_endpoints(sess, base):
    yield _info("🔍 Scanning for sensitive/admin endpoints...")
    found = []

    for path in SENSITIVE_PATHS:
        url = base + path
        r = _get(sess, url)
        if not r:
            continue

        if r.status_code in (200, 201):
            body = r.text[:500]
            # تحقق إذا فيه محتوى مفيد
            interesting = any(k in body.lower() for k in (
                "password", "secret", "token", "admin", "config",
                "database", "db_", "key", "env", "debug", "heap"
            ))
            sev = "critical" if interesting else "high"
            found.append((url, r.status_code, sev, body[:200]))

        elif r.status_code == 403:
            # 403 يعني موجود لكن محمي — لا نبلّغ لكن نُسجّل
            pass

    for url, sc, sev, preview in found:
        yield _finding(
            sev, "Sensitive Endpoint Exposed (OWASP API9)",
            url,
            "A sensitive or administrative endpoint is publicly accessible without authentication. "
            "This can expose configuration, user data, debug info, or server internals.",
            f"HTTP {sc}\nPreview: {preview}",
            "Restrict access to sensitive endpoints. Require strong authentication. "
            "Remove debug/actuator endpoints from production.",
        )

    if not found:
        yield _info("  ✓ No sensitive endpoints exposed")


# ─── 10. Rate Limiting ────────────────────────────────────────────────────────
def check_rate_limiting(sess, base):
    yield _info("🔍 Testing rate limiting...")

    test_url = None
    for path in ["/api/login", "/api/v1/login", "/api/auth/login",
                 "/api/auth", "/login", "/api/users"]:
        r = _get(sess, base + path)
        if r and r.status_code not in (404, 502, 503):
            test_url = base + path
            break

    if not test_url:
        test_url = base + "/api"

    codes = []
    for _ in range(20):
        r = _req(sess, "POST", test_url,
                 json={"username": "test", "password": "test"},
                 headers={"Content-Type": "application/json"},
                 timeout=5)
        if r:
            codes.append(r.status_code)
        else:
            codes.append(0)

    has_429    = 429 in codes
    has_block  = any(c in codes for c in (429, 503, 509))
    all_same   = len(set(codes)) == 1

    if not has_block and all_same and codes[0] not in (404,):
        yield _finding(
            "medium", "No Rate Limiting Detected (OWASP API4)",
            test_url,
            "20 rapid requests were sent with no throttling response (429/503). "
            "This allows brute-force attacks on login, OTP, and other sensitive endpoints.",
            f"20 requests → all returned HTTP {codes[0]}. No 429 detected.",
            "Implement rate limiting (e.g. 5 req/min per IP on auth endpoints). "
            "Use tools like nginx limit_req, Redis token bucket, or API gateway throttling.",
        )
    else:
        yield _info(f"  ✓ Rate limiting appears active (got {codes.count(429)} × 429)")


# ─── 11. Error & Stack Trace ─────────────────────────────────────────────────
ERROR_PAYLOADS = [
    ("GET",  "/{}'\"<>",     {}),
    ("POST", "/api/users",   {"id": "' OR 1=1--", "name": "<script>"}),
    ("GET",  "/api/users/abc", {}),   # invalid type
    ("GET",  "/api/user/99999999", {}),
]

STACK_PATTERNS = [
    r"Traceback \(most recent call",   # Python
    r"at\s+\w+\.\w+\([\w\.]+:\d+\)",  # Java/Kotlin
    r"System\.Web\.",                  # ASP.NET
    r"Microsoft\.AspNet",
    r"ORA-\d{5}",                      # Oracle DB
    r"mysql_fetch",                    # MySQL
    r"PDOException",                   # PHP PDO
    r"Uncaught Exception",
    r"SQL syntax.*MySQL",
    r"Warning.*pg_",                   # PostgreSQL PHP
    r"SQLSTATE\[",
    r"laravel",
    r"django\.core",
    r"stack trace",
]

def check_error_disclosure(sess, base):
    yield _info("🔍 Testing error & stack trace disclosure...")

    for method, path, body in ERROR_PAYLOADS:
        url = urljoin(base + "/", path.lstrip("/"))
        r = _req(sess, method, url,
                 json=body if body else None,
                 headers={"Content-Type": "application/json"} if body else {})
        if not r:
            continue

        text = r.text
        for pattern in STACK_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                yield _finding(
                    "medium", "Verbose Error / Stack Trace Disclosed (OWASP API8)",
                    url,
                    "Error responses contain stack traces, internal paths, or DB details. "
                    "Attackers use this to understand the tech stack and craft targeted attacks.",
                    f"{method} {url} → HTTP {r.status_code}\nMatched: {pattern}\n"
                    f"Response excerpt: {text[:300]}",
                    "Use generic error messages in production. Log details server-side only. "
                    "Never expose framework/DB internals to clients.",
                )
                break


# ─── 12. Sensitive Data Exposure ─────────────────────────────────────────────
SENSITIVE_PATTERNS = {
    r'["\']?password["\']?\s*:\s*["\'][^"\']{3,}["\']':      ("high",     "Password in response"),
    r'["\']?secret["\']?\s*:\s*["\'][^"\']{8,}["\']':        ("high",     "Secret key in response"),
    r'["\']?api[_-]?key["\']?\s*:\s*["\'][^"\']{8,}["\']':   ("high",     "API key in response"),
    r'["\']?token["\']?\s*:\s*["\'][^"\']{20,}["\']':         ("medium",   "Token in response"),
    r'\b[A-Z0-9]{20,}\b':                                     ("low",      "Possible secret/key"),
    r'\b\d{3}-\d{2}-\d{4}\b':                                 ("high",     "SSN pattern"),
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b':           ("high",     "Credit card pattern"),
    r'"credit_card"\s*:':                                     ("high",     "Credit card field"),
    r'"ssn"\s*:':                                             ("high",     "SSN field"),
}

def check_sensitive_data(sess, base):
    yield _info("🔍 Checking for sensitive data exposure...")

    probe_paths = [
        "/api/users", "/api/user/1", "/api/me",
        "/api/profile", "/api/v1/users", "/api/v1/me",
        "/api/accounts", "/api/orders",
    ]

    for path in probe_paths:
        url = base + path
        r = _get(sess, url)
        if not r or r.status_code not in (200, 201):
            continue

        body = r.text
        for pattern, (sev, label) in SENSITIVE_PATTERNS.items():
            if re.search(pattern, body, re.IGNORECASE):
                match = re.search(pattern, body, re.IGNORECASE)
                snippet = body[max(0, match.start()-30):match.end()+30]
                yield _finding(
                    sev, f"Sensitive Data Exposure: {label} (OWASP API3)",
                    url,
                    f"The API response contains {label.lower()}. "
                    "Exposing sensitive data violates privacy regulations (GDPR, PCI-DSS) "
                    "and enables account takeover or financial fraud.",
                    f"Pattern: {pattern}\nSnippet: ...{snippet}...",
                    "Never return passwords/secrets in API responses. "
                    "Mask or remove sensitive fields. Use response filtering.",
                )


# ─── 13. Mass Assignment ──────────────────────────────────────────────────────
def check_mass_assignment(sess, base):
    yield _info("🔍 Testing mass assignment vulnerability...")

    test_paths = [
        "/api/users", "/api/v1/users",
        "/api/profile", "/api/account",
        "/api/register",
    ]

    priv_fields = {
        "role":        "admin",
        "is_admin":    True,
        "admin":       True,
        "isAdmin":     True,
        "permissions": ["admin", "superuser"],
        "balance":     999999,
        "credits":     999999,
        "verified":    True,
        "activated":   True,
    }

    for path in test_paths:
        url = base + path
        payload = {"name": "test", "email": "test@test.com", **priv_fields}
        r = _req(sess, "POST", url,
                 json=payload,
                 headers={"Content-Type": "application/json"})
        if not r:
            continue

        if r.status_code in (200, 201):
            body = r.text.lower()
            # تحقق إذا أي حقل مميز انعكس في الـ response
            reflected = [k for k in priv_fields if k.lower() in body]
            if reflected:
                yield _finding(
                    "high", "Mass Assignment Vulnerability (OWASP API6)",
                    url,
                    "The API accepted and possibly processed privileged fields "
                    f"({', '.join(reflected)}) submitted by the client. "
                    "Mass assignment allows attackers to modify fields they shouldn't control "
                    "(roles, permissions, balance).",
                    f"POST {url}\nPayload fields accepted: {reflected}\n"
                    f"HTTP {r.status_code}",
                    "Use an allowlist of accepted fields (DTO pattern). "
                    "Never bind request body directly to database models.",
                )


# ─── 14. GraphQL Introspection ────────────────────────────────────────────────
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/gql", "/api/gql", "/query"]

INTROSPECTION_QUERY = {
    "query": "{ __schema { queryType { name } types { name fields { name } } } }"
}

def check_graphql(sess, base):
    yield _info("🔍 Testing GraphQL introspection...")

    for path in GRAPHQL_PATHS:
        url = base + path

        # تحقق من وجود GraphQL endpoint
        r = _req(sess, "POST", url,
                 json=INTROSPECTION_QUERY,
                 headers={"Content-Type": "application/json"})
        if not r:
            continue

        if r.status_code in (200, 201):
            try:
                data = r.json()
                if "data" in data and "__schema" in str(data):
                    types = []
                    try:
                        types = [t["name"] for t in
                                 data["data"]["__schema"]["types"]
                                 if not t["name"].startswith("__")][:15]
                    except Exception:
                        pass

                    yield _finding(
                        "high", "GraphQL Introspection Enabled (OWASP API9)",
                        url,
                        "GraphQL introspection is enabled in production. Attackers can "
                        "query the full schema — all types, fields, mutations, and queries — "
                        "to map the entire API surface.",
                        f"Endpoint: {url}\nTypes found: {', '.join(types)}",
                        "Disable introspection in production. "
                        "Use query depth limiting and complexity analysis.",
                    )
                elif r.status_code == 200:
                    yield _finding(
                        "info", "GraphQL Endpoint Detected",
                        url,
                        "A GraphQL endpoint was found. Introspection is disabled but "
                        "the endpoint exists.",
                        f"POST {url} → HTTP {r.status_code}",
                        "Ensure proper authentication, query depth limiting, and "
                        "disable introspection in production.",
                    )
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Main scan orchestrator
# ═══════════════════════════════════════════════════════════════════════════════

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
]


def scan_api(target_url, selected_checks=None, auth_header=None, timeout=12):
    """
    Generator — يبث النتائج واحدة واحدة.

    target_url     : مثل https://api.example.com
    selected_checks: list من أسماء الفحوصات (None = الكل)
    auth_header    : مثل "Bearer eyJhbGci..." أو "Token xxx"
    """
    base = _base(target_url.rstrip("/"))

    sess = _s(timeout=timeout)
    if auth_header:
        sess.headers["Authorization"] = auth_header

    total_checks = len(selected_checks) if selected_checks else len(CHECKS)
    done_checks  = 0
    findings     = 0

    yield {"type": "start", "base": base, "total_checks": total_checks}

    for name, fn in CHECKS:
        if selected_checks and name not in selected_checks:
            continue

        yield {"type": "section", "name": name}

        try:
            for event in fn(sess, base):
                if event.get("type") == "finding":
                    findings += 1
                yield event
        except Exception as e:
            yield _info(f"  ⚠️ Check failed: {e}")

        done_checks += 1
        yield {
            "type":     "progress",
            "done":     done_checks,
            "total":    total_checks,
            "percent":  round(done_checks / total_checks * 100),
        }

    yield {
        "type":     "done",
        "findings": findings,
        "checks":   done_checks,
    }
