import requests
import re

# قواميس الكشف عن التقنيات
TECH_SIGNATURES = {
    # Web Servers
    "Nginx":        {"headers": {"Server": r"nginx"}},
    "Apache":       {"headers": {"Server": r"apache"}},
    "IIS":          {"headers": {"Server": r"iis|microsoft-iis"}},
    "LiteSpeed":    {"headers": {"Server": r"litespeed"}},
    "Cloudflare":   {"headers": {"Server": r"cloudflare"}},

    # Programming Languages / Frameworks
    "PHP":          {"headers": {"X-Powered-By": r"php"}, "html": r"\.php"},
    "ASP.NET":      {"headers": {"X-Powered-By": r"asp\.net", "X-AspNet-Version": r".+"}},
    "Express.js":   {"headers": {"X-Powered-By": r"express"}},
    "Laravel":      {"headers": {"Set-Cookie": r"laravel_session"}},
    "Django":       {"headers": {"Set-Cookie": r"csrftoken|django"}},
    "Ruby on Rails":{"headers": {"X-Powered-By": r"phusion passenger|rails"}},

    # CMS
    "WordPress":    {"html": r"wp-content|wp-includes|wordpress"},
    "Joomla":       {"html": r"joomla|/components/com_"},
    "Drupal":       {"html": r"drupal|sites/default/files"},
    "Wix":          {"html": r"wix\.com|wixstatic"},
    "Shopify":      {"html": r"shopify|myshopify\.com"},
    "Magento":      {"html": r"magento|mage/"},

    # JavaScript Frameworks
    "React":        {"html": r"react\.js|reactDOM|__react"},
    "Vue.js":       {"html": r"vue\.js|vue\.min\.js|__vue"},
    "Angular":      {"html": r"angular\.js|ng-version|angular\.min"},
    "jQuery":       {"html": r"jquery[\.\-][\d\.]+\.js"},
    "Bootstrap":    {"html": r"bootstrap[\.\-][\d\.]+"},
    "Next.js":      {"html": r"__next|_next/static"},

    # Analytics & Marketing
    "Google Analytics": {"html": r"google-analytics\.com|gtag\(|_ga"},
    "Google Tag Manager": {"html": r"googletagmanager\.com"},
    "Facebook Pixel":    {"html": r"connect\.facebook\.net|fbq\("},

    # CDN & Security
    "Cloudflare CDN":    {"html": r"cloudflare\.com|cdnjs\.cloudflare"},
    "jsDelivr":          {"html": r"cdn\.jsdelivr\.net"},
    "jQuery CDN":        {"html": r"ajax\.googleapis\.com/ajax/libs/jquery"},

    # Databases (via headers)
    "MySQL":        {"headers": {"X-Powered-By": r"mysql"}},
    "MariaDB":      {"headers": {"X-Powered-By": r"mariadb"}},
}

def analyze_website(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        html = response.text.lower()
        resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        technologies = []

        for tech, sigs in TECH_SIGNATURES.items():
            detected = False

            # فحص الـ Headers
            if "headers" in sigs:
                for header_name, pattern in sigs["headers"].items():
                    val = resp_headers.get(header_name.lower(), "")
                    if val and re.search(pattern, val, re.IGNORECASE):
                        detected = True
                        break

            # فحص الـ HTML
            if not detected and "html" in sigs:
                if re.search(sigs["html"], html, re.IGNORECASE):
                    detected = True

            if detected:
                technologies.append(tech)

        return {"Technologies": technologies if technologies else ["Unknown"]}

    except Exception as e:
        return {"Error": str(e)}