<div align="center">

# ⚡ NETPY

**Network Reconnaissance & Vulnerability Analysis Toolkit**

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-Web%20UI-black?style=flat-square&logo=flask)
![Nuclei](https://img.shields.io/badge/Nuclei-v3.8-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

A powerful web-based reconnaissance and vulnerability analysis toolkit  
built for **bug bounty hunters** and **security researchers**.

</div>

---

## 🚀 Features

| Tool | Description |
|------|-------------|
| 🌐 **IP Resolver** | Resolve domains to IPs with multi-threading |
| 📡 **HTTP Status Code** | Check HTTP status for multiple targets |
| 🔤 **HTTP Headers** | Fetch and analyze response headers |
| 🔗 **Subdomain Discovery** | 23+ OSINT sources (crt.sh, VirusTotal, Shodan...) |
| 🏢 **WHOIS / Domain Info** | Full domain registration details |
| 📋 **DNS Records** | A, MX, TXT, NS, CNAME, SOA records |
| 🖥️ **Server OS Detection** | Fingerprint the server operating system |
| ⚙️ **Tech Fingerprinting** | Detect frameworks, CMS, JS libraries |
| 🗄️ **Database Detection** | Identify backend databases |
| 🔌 **Port Scanner** | Fast multi-threaded port scanning |
| 🔍 **Google Dorking** | 7 search engines dorking automation (streaming) |
| 💪 **Brute Force Subdomains** | Wordlist-based subdomain brute forcing |
| 🛡️ **WAF / CDN Detection** | 30+ WAF signatures + probe payloads |
| 🔬 **Advanced Discovery** | SPF Mining, Reverse IP, JS Mining, GitHub scraping |
| 🔎 **Param & Endpoint Discovery** | Wayback Machine, CommonCrawl, JS Mining for params & API endpoints |
| 🔭 **HTTPX Prober** | Probe hosts/subdomains — status, title, tech stack, IP, CDN, response time |
| 🎯 **Web Fuzzer** | Directory & endpoint fuzzing with custom wordlists, status filters, progress bar |
| 🔐 **API Security Scanner** | OWASP API Top 10 — Auth Bypass, JWT, BOLA/IDOR, CORS, Mass Assignment, GraphQL |
| ☢️ **Nuclei Scanner** | Full vulnerability scanning with 10,000+ templates (CVEs, misconfigs, exposures) |

---

## ⚙️ Installation

### Requirements
- Python 3.10+
- Windows / Linux / macOS

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/hassanhady12/NETPY.git
cd NETPY

# 2. Create virtual environment
python -m venv env

# 3. Activate environment
# Windows:
env\Scripts\activate
# Linux/macOS:
source env/bin/activate

# 4. Install requirements
pip install -r requirements.txt

# 5. Run the app
python app.py
```

Then open your browser at: **http://127.0.0.1:5000**

---

## 🛠️ How It Works

```
Target Domain
     │
     ├── 🌐 IP / Headers / Status / WHOIS / DNS
     ├── 🔗 Subdomain Discovery (23+ OSINT sources + Brute Force)
     ├── 🔌 Port Scanner (multi-threaded)
     ├── 🛡️ WAF / CDN Detection (30+ signatures)
     ├── 🔎 Parameter & Endpoint Discovery
     │        ├── Wayback Machine (historical URLs)
     │        ├── CommonCrawl (crawled URLs)
     │        └── JS File Mining (API endpoints)
     ├── 🔭 HTTPX Prober (status, title, tech, CDN, TLS)
     │        └── Filter by status code · Copy Domains · Copy JSON
     ├── 🎯 Web Fuzzer (directory/file/param bruteforce)
     │        └── Custom wordlist · Match/Filter codes · Progress bar
     ├── 🔐 API Security Scanner (OWASP API Top 10)
     │        ├── Auth Bypass · JWT Weaknesses · BOLA/IDOR
     │        ├── CORS · Security Headers · Sensitive Endpoints
     │        ├── Rate Limiting · Error Disclosure · Mass Assignment
     │        └── GraphQL Introspection · Sensitive Data Exposure
     ├── ☢️  Nuclei Scanner (10,000+ templates)
     ├── 🔍 Google Dorking (7 search engines)
     └── 🔬 Advanced Discovery (SPF, Reverse IP, GitHub)
```

---

## 🔧 External Tools (Optional but Recommended)

Place these executables in the project root directory for full functionality:

| Tool | Download | Purpose |
|------|----------|---------|
| **nuclei.exe** | [ProjectDiscovery](https://github.com/projectdiscovery/nuclei/releases) | Vulnerability scanning (10,000+ templates) |
| **subfinder.exe** | [ProjectDiscovery](https://github.com/projectdiscovery/subfinder/releases) | Subdomain discovery |
| **amass.exe** | [OWASP](https://github.com/owasp-amass/amass/releases) | Advanced subdomain enumeration |
| **httpx.exe** | [ProjectDiscovery](https://github.com/projectdiscovery/httpx/releases) | HTTP probing (status, title, tech, CDN) |

> All tools are cross-platform. Linux/macOS users: use the binary without `.exe`

---

## 📋 Requirements

```
flask>=3.1.0
requests>=2.32.3
dnspython>=2.7.0
python-whois>=0.9.5
beautifulsoup4>=4.12.3
validators>=0.34.0
tldextract>=5.1.3
lxml>=5.3.0
urllib3>=2.0.0
```

---

## 🔐 API Security Scanner — OWASP API Top 10 Coverage

| # | Check | Vulnerability | Severity |
|---|-------|--------------|----------|
| 1 | API Docs Exposure | swagger/openapi/redoc publicly accessible | 🔴 High |
| 2 | API Version Enum | v1/v2/beta/legacy active endpoints | 🟡 Medium |
| 3 | Auth Bypass | Endpoints accessible without authentication | 🔴 Critical |
| 4 | JWT Weaknesses | None algorithm + weak secret bruteforce | 🔴 Critical |
| 5 | BOLA / IDOR | Object ID enumeration without authorization | 🔴 High |
| 6 | HTTP Method Tampering | TRACE/DELETE/PUT enabled | 🟡 Medium |
| 7 | CORS Misconfiguration | Wildcard + credential reflection | 🔴 High |
| 8 | Security Headers | Missing CSP/HSTS/X-Frame/etc | 🔵 Low-Med |
| 9 | Sensitive Endpoints | /admin /debug /actuator exposed | 🔴 Critical |
| 10 | Rate Limiting | No 429 after 20 rapid requests | 🟡 Medium |
| 11 | Error Disclosure | Stack traces / DB errors in response | 🟡 Medium |
| 12 | Sensitive Data | Passwords/keys/PII in API responses | 🔴 High |
| 13 | Mass Assignment | Privileged fields (role=admin) accepted | 🔴 High |
| 14 | GraphQL Introspection | Full schema exposed in production | 🔴 High |

---

## ⚠️ Disclaimer

This tool is intended for **legal security testing and bug bounty hunting only**.  
Only use it on targets you have **explicit permission** to test.  
The author is not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
Made for Bug Bounty Hunters ⚡
</div>
