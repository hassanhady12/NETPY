import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


def sub_domain(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        resp = requests.get(url, timeout=10, verify=False,
                            headers={"User-Agent": "Mozilla/5.0"})
        resp.raise_for_status()

        # استخراج الـ root domain
        parsed = urlparse(resp.url)
        root_domain = parsed.netloc.lower()
        # أزل www. للحصول على الـ base domain
        base = root_domain.lstrip("www.").split(":")[0]

        soup = BeautifulSoup(resp.text, 'html.parser')
        subdomains = set()

        for tag in soup.find_all(['a', 'link', 'script', 'img', 'form'], href=True):
            href = tag.get('href') or tag.get('src') or tag.get('action')
            if not href:
                continue
            netloc = urlparse(href).netloc.lower().split(":")[0]
            if netloc and netloc.endswith(base) and netloc != root_domain:
                subdomains.add(netloc)

        # أيضاً فحص src attributes
        for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
            netloc = urlparse(tag['src']).netloc.lower().split(":")[0]
            if netloc and netloc.endswith(base) and netloc != root_domain:
                subdomains.add(netloc)

        return subdomains

    except requests.exceptions.RequestException as e:
        return set()
    except Exception as e:
        return set()
