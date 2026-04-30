from flask import Flask, request, render_template, Response, stream_with_context
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

from core   import resolve_ips
from core12 import SOURCE_MAP, discover_via_spf, discover_via_reverse_ip, discover_via_js, discover_via_github
from core11 import dork_google, dork_bing, dork_duckduckgo, dork_yahoo, dork_ask, dork_baidu, dork_yandex, DORK_TEMPLATES
from core1  import fetch_status_code
from core2  import fetch_headers
from core3  import sub_domain
from core4  import get_domain_info
from core5  import get_all_dns_records
from core6  import get_server_os
from core7  import analyze_website
from core8  import detect_database
from core9  import scan_ports_for_domain
from core10 import (subdomain_from_crtsh, subdomain_from_rapiddns,
                    subdomain_from_hackertarget, subdomain_from_alienvault,
                    subdomain_from_urlscan, subdomain_from_wayback,
                    subdomain_from_commoncrawl, subdomain_from_certspotter,
                    subdomain_from_subfinder, subdomain_from_amass,
                    subdomain_from_jldc, subdomain_from_threatminer,
                    subdomain_from_riddler, subdomain_from_sonar,
                    subdomain_from_shodandb, subdomain_from_leakix,
                    subdomain_from_bufferover, subdomain_from_columbus,
                    subdomain_from_recondev, subdomain_from_securitytrails,
                    subdomain_from_virustotal, subdomain_from_bevigil,
                    subdomain_from_fullhunt, subdomain_from_chaos,
                    subdomain_from_c99)
from core13 import detect_waf
from core14 import run_nuclei_stream
from brute_core import _resolve_one

app = Flask(__name__)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _json(data):
    return app.response_class(json.dumps(data, default=str),
                               mimetype="application/json")


# ─── صفحة رئيسية (GET فقط) ──────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ─── API: IP Resolver ────────────────────────────────────────────────────────
@app.route("/api/resolve-ip", methods=["POST"])
def api_resolve_ip():
    sites = request.form.get("sites", "").split()
    results = resolve_ips(sites) if sites else []
    return _json({"results": results})


# ─── API: HTTP Status Code ───────────────────────────────────────────────────
@app.route("/api/status-code", methods=["POST"])
def api_status_code():
    sites = request.form.get("sites", "").split()
    results = fetch_status_code(sites) if sites else []
    return _json({"results": results})


# ─── API: HTTP Headers ───────────────────────────────────────────────────────
@app.route("/api/headers", methods=["POST"])
def api_headers():
    sites = request.form.get("sites", "").split()
    results = fetch_headers(sites) if sites else []
    return _json({"results": results})


# ─── API: Subdomains Basic ───────────────────────────────────────────────────
@app.route("/api/subdomains", methods=["POST"])
def api_subdomains():
    sites = request.form.get("sites", "").split()
    results = {site: sub_domain(site) for site in sites} if sites else {}
    return _json({"results": results})


# ─── API: Domain Info (WHOIS) ────────────────────────────────────────────────
@app.route("/api/domain-info", methods=["POST"])
def api_domain_info():
    sites = request.form.get("sites", "").split()
    results = get_domain_info(sites) if sites else {}
    return _json({"results": results})


# ─── API: DNS Records ────────────────────────────────────────────────────────
@app.route("/api/dns-records", methods=["POST"])
def api_dns_records():
    sites = request.form.get("sites", "").split()
    results = get_all_dns_records(sites) if sites else {}
    return _json({"results": results})


# ─── API: Server OS ──────────────────────────────────────────────────────────
@app.route("/api/server-os", methods=["POST"])
def api_server_os():
    sites = request.form.get("sites", "").split()
    results = get_server_os(sites) if sites else {}
    return _json({"results": results})


# ─── API: Technology Analysis ────────────────────────────────────────────────
@app.route("/api/tech", methods=["POST"])
def api_tech():
    sites = request.form.get("sites", "").split()
    results = {site: analyze_website(site) for site in sites} if sites else {}
    return _json({"results": results})


# ─── API: Database Detection ─────────────────────────────────────────────────
@app.route("/api/database", methods=["POST"])
def api_database():
    sites = request.form.get("sites", "").split()
    results = {site: detect_database(site) for site in sites} if sites else {}
    return _json({"results": results})


# ─── SSE: Port Scanner (نتائج فورية) ─────────────────────────────────────────
@app.route("/api/port-scan", methods=["POST"])
def api_port_scan():
    sites = request.form.get("sites", "").split()

    def generate():
        for domain in sites:
            result = scan_ports_for_domain(domain, max_threads=200)
            yield _sse({"domain": domain, "ports": result.get(domain, [])})
        yield _sse({"done": True})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── API: Subfinder standalone ───────────────────────────────────────────────
@app.route("/api/subfinder", methods=["POST"])
def api_subfinder():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return _json({"results": [], "total": 0})
    results = sorted(subdomain_from_subfinder(domain))
    return _json({"results": results, "total": len(results)})


# ─── API: Amass standalone ───────────────────────────────────────────────────
@app.route("/api/amass", methods=["POST"])
def api_amass():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return _json({"results": [], "total": 0})
    results = sorted(subdomain_from_amass(domain))
    return _json({"results": results, "total": len(results)})


# ─── SSE: Advanced Subdomain Scanner ─────────────────────────────────────────
@app.route("/api/scan-subdomains", methods=["POST"])
def api_scan_subdomains():
    domain = request.form.get("domain", "").strip()
    if not domain:
        return Response(_sse({"error": "No domain"}), mimetype="text/event-stream")

    def generate():
        all_found = set()

        osint_sources = [
            ("crt.sh",              subdomain_from_crtsh),
            ("RapidDNS",            subdomain_from_rapiddns),
            ("HackerTarget",        subdomain_from_hackertarget),
            ("AlienVault OTX",      subdomain_from_alienvault),
            ("URLScan.io",          subdomain_from_urlscan),
            ("Wayback Machine",     subdomain_from_wayback),
            ("CommonCrawl",         subdomain_from_commoncrawl),
            ("Certspotter",         subdomain_from_certspotter),
            ("JLDC/Anubis",         subdomain_from_jldc),
            ("ThreatMiner",         subdomain_from_threatminer),
            ("Riddler.io",          subdomain_from_riddler),
            ("SonarSearch",         subdomain_from_sonar),
            ("Shodan InternetDB",   subdomain_from_shodandb),
            ("LeakIX",              subdomain_from_leakix),
            ("BufferOver",          subdomain_from_bufferover),
            ("Columbus",            subdomain_from_columbus),
            ("Recon.dev",           subdomain_from_recondev),
            ("SecurityTrails",      subdomain_from_securitytrails),
            ("VirusTotal",          subdomain_from_virustotal),
            ("Bevigil",             subdomain_from_bevigil),
            ("FullHunt",            subdomain_from_fullhunt),
            ("Chaos",               subdomain_from_chaos),
            ("C99",                 subdomain_from_c99),
        ]

        with ThreadPoolExecutor(max_workers=len(osint_sources)) as executor:
            future_to_name = {executor.submit(fn, domain): name for name, fn in osint_sources}
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    results = future.result()
                    new = sorted(results - all_found)
                    all_found |= results
                except Exception:
                    new = []
                yield _sse({"source": name, "subdomains": new, "total": len(all_found)})

        # ── Brute Force — batch streaming ────────────────────────────────────
        import dns.resolver as _dns
        resolver = _dns.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        resolver.timeout = 3
        resolver.lifetime = 3
        batch = []
        try:
            with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [l.strip() for l in f if l.strip()]

            with ThreadPoolExecutor(max_workers=300) as executor:
                futures = {executor.submit(_resolve_one, w, domain, resolver): w for w in wordlist}
                for future in as_completed(futures):
                    sub = future.result()
                    if sub and sub not in all_found:
                        all_found.add(sub)
                        batch.append(sub)
                        if len(batch) >= 100:
                            yield _sse({"source": "Brute Force", "subdomains": sorted(batch), "total": len(all_found)})
                            batch = []
            if batch:
                yield _sse({"source": "Brute Force", "subdomains": sorted(batch), "total": len(all_found)})
        except Exception as e:
            yield _sse({"source": "Brute Force", "error": str(e), "total": len(all_found)})

        yield _sse({"done": True, "total": len(all_found)})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── SSE: Brute Force Subdomain ─────────────────────────────────────────────
@app.route("/api/brute-force", methods=["POST"])
def api_brute_force():
    domain        = request.form.get("domain", "").strip()
    wordlist_path = request.form.get("wordlist", "wordlist.txt").strip() or "wordlist.txt"
    if not domain:
        return Response(_sse({"error": "No domain"}), mimetype="text/event-stream")

    def generate():
        import dns.resolver as _dns
        resolver = _dns.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        resolver.timeout = 3
        resolver.lifetime = 3
        found = set()
        batch = []
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [l.strip() for l in f if l.strip()]
            yield _sse({"status": "running", "total": 0, "words": len(wordlist)})
            with ThreadPoolExecutor(max_workers=300) as executor:
                futures = {executor.submit(_resolve_one, w, domain, resolver): w for w in wordlist}
                for future in as_completed(futures):
                    sub = future.result()
                    if sub and sub not in found:
                        found.add(sub)
                        batch.append(sub)
                        if len(batch) >= 50:
                            yield _sse({"subdomains": sorted(batch), "total": len(found)})
                            batch = []
            if batch:
                yield _sse({"subdomains": sorted(batch), "total": len(found)})
        except Exception as e:
            yield _sse({"error": str(e), "total": len(found)})
        yield _sse({"done": True, "total": len(found)})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── SSE: Advanced Discovery (core12) ───────────────────────────────────────
@app.route("/api/advanced-discover", methods=["POST"])
def api_advanced_discover():
    domain  = request.form.get("domain", "").strip()
    sources = request.form.getlist("sources") or list(SOURCE_MAP.keys())
    if not domain:
        return Response(_sse({"error": "No domain"}), mimetype="text/event-stream")

    def generate():
        all_found = set()
        for key in sources:
            if key not in SOURCE_MAP:
                continue
            name, fn = SOURCE_MAP[key]
            yield _sse({"status": "running", "source": name})
            try:
                results = fn(domain)
                new = sorted(results - all_found)
                all_found |= results
            except Exception as e:
                yield _sse({"source": name, "error": str(e), "total": len(all_found)})
                continue
            yield _sse({"source": name, "subdomains": new, "total": len(all_found)})
        yield _sse({"done": True, "total": len(all_found)})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── SSE: Google Dorking ─────────────────────────────────────────────────────
@app.route("/api/dork", methods=["POST"])
def api_dork():
    domain  = request.form.get("domain", "").strip()
    engines = request.form.getlist("engines") or ["bing", "duckduckgo", "yahoo", "ask", "baidu", "yandex"]
    if not domain:
        return Response(_sse({"error": "No domain"}), mimetype="text/event-stream")

    engine_map = {
        "google":     ("Google",     dork_google),
        "bing":       ("Bing",       dork_bing),
        "duckduckgo": ("DuckDuckGo", dork_duckduckgo),
        "yahoo":      ("Yahoo",      dork_yahoo),
        "ask":        ("Ask",        dork_ask),
        "baidu":      ("Baidu",      dork_baidu),
        "yandex":     ("Yandex",     dork_yandex),
    }

    def generate():
        all_found = set()
        yield _sse({"status": "start", "dorks": [t.format(domain=domain) for t in DORK_TEMPLATES[:6]]})

        for key in engines:
            if key not in engine_map:
                continue
            name, fn = engine_map[key]
            yield _sse({"status": "running", "engine": name})
            try:
                results = fn(domain)
                new = sorted(results - all_found)
                all_found |= results
            except Exception as e:
                new = []
                yield _sse({"engine": name, "error": str(e), "total": len(all_found)})
                continue
            yield _sse({"engine": name, "subdomains": new, "total": len(all_found)})

        yield _sse({"done": True, "total": len(all_found)})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ─── API: WAF Detection ──────────────────────────────────────────────────────
@app.route("/api/waf-detect", methods=["POST"])
def api_waf_detect():
    sites = request.form.get("sites", "").split()
    if not sites:
        return _json({"results": {}})

    results = {}
    with ThreadPoolExecutor(max_workers=min(len(sites), 10)) as executor:
        future_to_domain = {executor.submit(detect_waf, d.strip()): d.strip() for d in sites if d.strip()}
        for future in future_to_domain:
            domain = future_to_domain[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                results[domain] = {"error": str(e)}

    return _json({"results": results})


# ─── SSE: Nuclei Scanner ─────────────────────────────────────────────────────
@app.route("/api/nuclei", methods=["POST"])
def api_nuclei():
    target   = request.form.get("target", "").strip()
    severity = request.form.get("severity", "").strip() or None
    tags     = request.form.get("tags", "").strip() or None
    if not target:
        return Response(_sse({"type": "error", "message": "No target"}),
                        mimetype="text/event-stream")

    def generate():
        for event in run_nuclei_stream(target, severity=severity, tags=tags):
            yield _sse(event)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
