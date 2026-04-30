import requests
from bs4 import BeautifulSoup
import re
import time
import random
import subprocess
import shutil
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from brute_core import brute_force_subdomains

# ─── قائمة User-Agents للتنويع وتجنب الحظر ─────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

def _get_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }

def _is_valid_subdomain(sub, domain):
    """التحقق من صحة النطاق الفرعي وإزالة wildcards"""
    sub = sub.strip().lower()
    if sub.startswith("*."):
        sub = sub[2:]
    if not (sub.endswith(f".{domain}") or sub == domain):
        return None
    if re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$', sub):
        return sub
    return None

def _request_with_retry(url, timeout=25, retries=3):
    """طلب HTTP مع إعادة المحاولة وتأخير تدريجي عند الحظر"""
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=_get_headers(), timeout=timeout)
            if response.status_code == 429:  # Rate Limited
                wait = 5 * (2 ** attempt) + random.uniform(0, 2)
                print(f"[!] Rate limited — waiting {wait:.1f}s...")
                time.sleep(wait)
                continue
            if response.status_code == 200:
                return response
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
    return None


# ─── المصدر 1: crt.sh (Certificate Transparency Logs) ──────────────────────
def subdomain_from_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = _request_with_retry(url, timeout=30)
        subdomains = set()
        if response:
            data = response.json()
            for entry in data:
                for sub in entry.get("name_value", "").split("\n"):
                    valid = _is_valid_subdomain(sub, domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[crt.sh] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[crt.sh] Error: {e}")
        return set()


# ─── المصدر 2: RapidDNS (HTML parsing دقيق بـ BeautifulSoup) ───────────────
def subdomain_from_rapiddns(domain):
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
        response = _request_with_retry(url, timeout=25)
        subdomains = set()
        if response:
            soup = BeautifulSoup(response.text, "lxml")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True)
                valid = _is_valid_subdomain(text, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[RapidDNS] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[RapidDNS] Error: {e}")
        return set()


# ─── المصدر 3: HackerTarget (مصدر إضافي مجاني) ─────────────────────────────
def subdomain_from_hackertarget(domain):
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = _request_with_retry(url, timeout=20)
        subdomains = set()
        if response:
            for line in response.text.splitlines():
                parts = line.split(",")
                if parts:
                    valid = _is_valid_subdomain(parts[0], domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[HackerTarget] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[HackerTarget] Error: {e}")
        return set()


# ─── المصدر 4: AlienVault OTX ───────────────────────────────────────────────
def subdomain_from_alienvault(domain):
    try:
        subdomains = set()
        page = 1
        while True:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns?page={page}&limit=500"
            response = _request_with_retry(url, timeout=20)
            if not response:
                break
            data = response.json()
            entries = data.get("passive_dns", [])
            if not entries:
                break
            for entry in entries:
                for field in ("hostname", "address"):
                    valid = _is_valid_subdomain(entry.get(field, ""), domain)
                    if valid:
                        subdomains.add(valid)
            if not data.get("has_next"):
                break
            page += 1
        print(f"[AlienVault OTX] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[AlienVault OTX] Error: {e}")
        return set()


# ─── المصدر 5: URLScan.io ────────────────────────────────────────────────────
def subdomain_from_urlscan(domain):
    try:
        subdomains = set()
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200&fields=page.domain"
        headers = _get_headers()
        headers["Accept"] = "application/json"
        response = requests.get(url, headers=headers, timeout=20)
        if response and response.status_code == 200:
            data = response.json()
            for result in data.get("results", []):
                hostname = result.get("page", {}).get("domain", "")
                valid = _is_valid_subdomain(hostname, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[URLScan.io] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[URLScan.io] Error: {e}")
        return set()


# ─── المصدر 6: Wayback Machine (أرشيف الإنترنت — مجاني تماماً) ─────────────
def subdomain_from_wayback(domain):
    try:
        subdomains = set()
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=50000"
        )
        response = _request_with_retry(url, timeout=40)
        if response:
            data = response.json()
            for entry in data[1:]:          # السطر الأول header
                original = entry[0]
                try:
                    from urllib.parse import urlparse
                    host = urlparse(original).netloc.split(":")[0].lower()
                    valid = _is_valid_subdomain(host, domain)
                    if valid:
                        subdomains.add(valid)
                except Exception:
                    pass
        print(f"[Wayback Machine] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Wayback Machine] Error: {e}")
        return set()


# ─── المصدر 7: CommonCrawl Index (مجاني تماماً) ─────────────────────────────
def subdomain_from_commoncrawl(domain):
    try:
        subdomains = set()
        # أحدث index متاح
        idx_url = "https://index.commoncrawl.org/collinfo.json"
        r = requests.get(idx_url, timeout=10)
        if not r or r.status_code != 200:
            return set()
        latest = r.json()[0]["cdx-api"]

        url = f"{latest}?url=*.{domain}&output=json&fl=url&limit=5000"
        response = requests.get(url, timeout=30, headers=_get_headers())
        if response and response.status_code == 200:
            from urllib.parse import urlparse
            for line in response.text.strip().splitlines():
                try:
                    entry = __import__('json').loads(line)
                    host = urlparse(entry.get("url", "")).netloc.split(":")[0].lower()
                    valid = _is_valid_subdomain(host, domain)
                    if valid:
                        subdomains.add(valid)
                except Exception:
                    pass
        print(f"[CommonCrawl] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[CommonCrawl] Error: {e}")
        return set()


# ─── المصدر 8: Certspotter ──────────────────────────────────────────────────
def subdomain_from_certspotter(domain):
    try:
        subdomains = set()
        url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
        response = _request_with_retry(url, timeout=20)
        if response:
            data = response.json()
            for entry in data:
                for name in entry.get("dns_names", []):
                    valid = _is_valid_subdomain(name, domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[Certspotter] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Certspotter] Error: {e}")
        return set()



# ─── المصدر 5: Amass (OWASP — أقوى أداة بدون مفاتيح) ───────────────────────
def _get_amass_path():
    local = os.path.join(os.path.dirname(__file__), "amass.exe")
    if os.path.isfile(local):
        return local
    return shutil.which("amass")

def subdomain_from_amass(domain):
    binary = _get_amass_path()
    if not binary:
        print("[Amass] Not found — skipping")
        return set()
    try:
        result = subprocess.run(
            [binary, "enum", "-passive", "-d", domain, "-silent"],
            capture_output=True, text=True, timeout=300
        )
        subdomains = set()
        for line in result.stdout.splitlines():
            valid = _is_valid_subdomain(line.strip(), domain)
            if valid:
                subdomains.add(valid)
        print(f"[Amass] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Amass] Error: {e}")
        return set()


# ─── المصدر 6: subfinder ────────────────────────────────────────────────────
def _get_subfinder_path():
    """البحث عن subfinder.exe في مجلد المشروع أو PATH"""
    local = os.path.join(os.path.dirname(__file__), "subfinder.exe")
    if os.path.isfile(local):
        return local
    return shutil.which("subfinder")

def subdomain_from_subfinder(domain):
    binary = _get_subfinder_path()
    if not binary:
        print("[subfinder] Not found — skipping")
        return set()
    try:
        result = subprocess.run(
            [binary, "-d", domain, "-silent", "-all"],
            capture_output=True, text=True, timeout=180
        )
        subdomains = set()
        for line in result.stdout.splitlines():
            valid = _is_valid_subdomain(line.strip(), domain)
            if valid:
                subdomains.add(valid)
        print(f"[subfinder] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[subfinder] Error: {e}")
        return set()


# ─── المصدر 9: JLDC / Anubis ────────────────────────────────────────────────
def subdomain_from_jldc(domain):
    try:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        response = _request_with_retry(url, timeout=20)
        subdomains = set()
        if response:
            for item in response.json():
                valid = _is_valid_subdomain(item, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[JLDC/Anubis] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[JLDC/Anubis] Error: {e}")
        return set()


# ─── المصدر 10: ThreatMiner ──────────────────────────────────────────────────
def subdomain_from_threatminer(domain):
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5"
        response = _request_with_retry(url, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for item in response.json().get("results", []):
                valid = _is_valid_subdomain(item, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[ThreatMiner] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[ThreatMiner] Error: {e}")
        return set()


# ─── المصدر 11: Riddler.io ───────────────────────────────────────────────────
def subdomain_from_riddler(domain):
    try:
        url = f"https://riddler.io/search/exportcsv?q=pld:{domain}"
        response = _request_with_retry(url, timeout=25)
        subdomains = set()
        if response:
            for line in response.text.splitlines()[1:]:
                parts = line.split(",")
                if len(parts) >= 5:
                    valid = _is_valid_subdomain(parts[4].strip().strip('"'), domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[Riddler.io] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Riddler.io] Error: {e}")
        return set()


# ─── المصدر 12: SonarSearch / Omnisint ──────────────────────────────────────
def subdomain_from_sonar(domain):
    try:
        url = f"https://sonar.omnisint.io/subdomains/{domain}"
        response = _request_with_retry(url, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for item in response.json():
                valid = _is_valid_subdomain(item, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[SonarSearch] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[SonarSearch] Error: {e}")
        return set()


# ─── المصدر 13: Shodan InternetDB (مجاني بدون مفتاح) ───────────────────────
def subdomain_from_shodandb(domain):
    try:
        import socket
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return set()
        url = f"https://internetdb.shodan.io/{ip}"
        response = _request_with_retry(url, timeout=15)
        subdomains = set()
        if response and response.status_code == 200:
            for host in response.json().get("hostnames", []):
                valid = _is_valid_subdomain(host, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[Shodan InternetDB] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Shodan InternetDB] Error: {e}")
        return set()


# ─── المصدر 14: LeakIX ──────────────────────────────────────────────────────
def subdomain_from_leakix(domain):
    try:
        url = f"https://leakix.net/api/subdomains/{domain}"
        headers = _get_headers()
        headers["Accept"] = "application/json"
        response = requests.get(url, headers=headers, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for entry in response.json():
                sub = entry.get("subdomain", "") or entry.get("host", "")
                valid = _is_valid_subdomain(sub, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[LeakIX] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[LeakIX] Error: {e}")
        return set()



# ─── المصدر 15: BufferOver.run (مجاني تماماً) ───────────────────────────────
def subdomain_from_bufferover(domain):
    try:
        url = f"https://dns.bufferover.run/dns?q=.{domain}"
        response = _request_with_retry(url, timeout=15)
        subdomains = set()
        if response and response.status_code == 200:
            data = response.json()
            for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                parts = record.split(",")
                host = parts[-1].strip().lower() if len(parts) >= 2 else parts[0].strip().lower()
                valid = _is_valid_subdomain(host, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[BufferOver] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[BufferOver] Error: {e}")
        return set()


# ─── المصدر 16: Columbus Project (مجاني) ────────────────────────────────────
def subdomain_from_columbus(domain):
    try:
        url = f"https://columbus.elmasy.com/api/subdomains/{domain}"
        response = _request_with_retry(url, timeout=15)
        subdomains = set()
        if response and response.status_code == 200:
            for prefix in response.json():
                if prefix:
                    full = f"{prefix}.{domain}" if not prefix.endswith(f".{domain}") else prefix
                    valid = _is_valid_subdomain(full, domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[Columbus] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Columbus] Error: {e}")
        return set()


# ─── المصدر 17: Recon.dev (مجاني) ───────────────────────────────────────────
def subdomain_from_recondev(domain):
    try:
        url = f"https://recon.dev/api/search?key=free&domain={domain}"
        response = _request_with_retry(url, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            data = response.json()
            for entry in data if isinstance(data, list) else []:
                for raw in entry.get("rawDomains", []):
                    valid = _is_valid_subdomain(raw, domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[Recon.dev] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Recon.dev] Error: {e}")
        return set()


# ─── المصدر 18: SecurityTrails (يحتاج API Key — اختياري) ───────────────────
def subdomain_from_securitytrails(domain):
    import os
    api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if not api_key:
        print("[SecurityTrails] No API key — skipping (set SECURITYTRAILS_API_KEY)")
        return set()
    try:
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false&include_inactive=true"
        headers = _get_headers()
        headers["APIKEY"] = api_key
        response = requests.get(url, headers=headers, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for prefix in response.json().get("subdomains", []):
                full = f"{prefix}.{domain}"
                valid = _is_valid_subdomain(full, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[SecurityTrails] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[SecurityTrails] Error: {e}")
        return set()


# ─── المصدر 19: VirusTotal (يحتاج API Key — اختياري) ───────────────────────
def subdomain_from_virustotal(domain):
    import os
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        print("[VirusTotal] No API key — skipping (set VIRUSTOTAL_API_KEY)")
        return set()
    try:
        subdomains = set()
        cursor = ""
        while True:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
            if cursor:
                url += f"&cursor={cursor}"
            headers = _get_headers()
            headers["x-apikey"] = api_key
            response = requests.get(url, headers=headers, timeout=20)
            if not response or response.status_code != 200:
                break
            data = response.json()
            for item in data.get("data", []):
                valid = _is_valid_subdomain(item.get("id", ""), domain)
                if valid:
                    subdomains.add(valid)
            cursor = data.get("meta", {}).get("cursor", "")
            if not cursor:
                break
        print(f"[VirusTotal] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[VirusTotal] Error: {e}")
        return set()


# ─── المصدر 20: Bevigil OSINT (يحتاج API Key — اختياري) ────────────────────
def subdomain_from_bevigil(domain):
    import os
    api_key = os.environ.get("BEVIGIL_API_KEY", "")
    if not api_key:
        print("[Bevigil] No API key — skipping (set BEVIGIL_API_KEY)")
        return set()
    try:
        url = f"https://osint.bevigil.com/api/{domain}/subdomains/"
        headers = _get_headers()
        headers["X-Access-Token"] = api_key
        response = requests.get(url, headers=headers, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for sub in response.json().get("subdomains", []):
                valid = _is_valid_subdomain(sub, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[Bevigil] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Bevigil] Error: {e}")
        return set()


# ─── المصدر 21: FullHunt (يحتاج API Key — اختياري) ─────────────────────────
def subdomain_from_fullhunt(domain):
    import os
    api_key = os.environ.get("FULLHUNT_API_KEY", "")
    if not api_key:
        print("[FullHunt] No API key — skipping (set FULLHUNT_API_KEY)")
        return set()
    try:
        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        headers = _get_headers()
        headers["X-API-KEY"] = api_key
        response = requests.get(url, headers=headers, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for host in response.json().get("hosts", []):
                valid = _is_valid_subdomain(host, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[FullHunt] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[FullHunt] Error: {e}")
        return set()


# ─── المصدر 22: Chaos (ProjectDiscovery — يحتاج API Key) ────────────────────
def subdomain_from_chaos(domain):
    import os
    api_key = os.environ.get("CHAOS_API_KEY", "")
    if not api_key:
        print("[Chaos] No API key — skipping (set CHAOS_API_KEY)")
        return set()
    try:
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = _get_headers()
        headers["Authorization"] = api_key
        response = requests.get(url, headers=headers, timeout=20)
        subdomains = set()
        if response and response.status_code == 200:
            for prefix in response.json().get("subdomains", []):
                full = f"{prefix}.{domain}"
                valid = _is_valid_subdomain(full, domain)
                if valid:
                    subdomains.add(valid)
        print(f"[Chaos] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Chaos] Error: {e}")
        return set()


# ─── المصدر 23: C99 SubdomainFinder (scraping) ──────────────────────────────
def subdomain_from_c99(domain):
    try:
        url = f"https://subdomainfinder.c99.nl/scans/{domain}"
        response = _request_with_retry(url, timeout=25)
        subdomains = set()
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, "lxml")
            for td in soup.find_all("td"):
                text = td.get_text(strip=True).lower()
                valid = _is_valid_subdomain(text, domain)
                if valid:
                    subdomains.add(valid)
            if not subdomains:
                for a in soup.find_all("a", href=True):
                    text = a.get_text(strip=True).lower()
                    valid = _is_valid_subdomain(text, domain)
                    if valid:
                        subdomains.add(valid)
        print(f"[C99] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[C99] Error: {e}")
        return set()


# ─── الدالة الرئيسية ────────────────────────────────────────────────────────
def sub_domaincore(domain, wordlist_path="wordlist.txt"):
    all_subdomains = set()

    # ── تشغيل مصادر OSINT بالتوازي لتوفير الوقت ──────────────────────────
    osint_sources = [
        subdomain_from_crtsh,
        subdomain_from_rapiddns,
        subdomain_from_hackertarget,
        subdomain_from_alienvault,
        subdomain_from_urlscan,
        subdomain_from_wayback,
        subdomain_from_commoncrawl,
        subdomain_from_certspotter,
        subdomain_from_subfinder,
        subdomain_from_amass,
        subdomain_from_bufferover,
        subdomain_from_columbus,
        subdomain_from_recondev,
        subdomain_from_securitytrails,
        subdomain_from_virustotal,
        subdomain_from_bevigil,
        subdomain_from_fullhunt,
        subdomain_from_chaos,
        subdomain_from_c99,
    ]

    with ThreadPoolExecutor(max_workers=len(osint_sources)) as executor:
        futures = [executor.submit(fn, domain) for fn in osint_sources]
        for future in as_completed(futures):
            try:
                all_subdomains |= future.result()
            except Exception:
                pass

    # ── Brute Force بعد OSINT ─────────────────────────────────────────────
    all_subdomains |= brute_force_subdomains(domain, wordlist_path)

    print(f"\n[✓] Total unique subdomains found: {len(all_subdomains)}")
    return sorted(all_subdomains)