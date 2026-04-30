import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed


def _resolve_one(word, domain, resolver):
    subdomain = f"{word}.{domain}"
    try:
        resolver.resolve(subdomain, "A", lifetime=3)
        return subdomain
    except Exception:
        return None


def brute_force_subdomains(domain, wordlist_path="wordlist.txt", max_workers=300):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [line.strip() for line in f if line.strip()]

        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
        resolver.timeout = 3
        resolver.lifetime = 3

        subdomains = set()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_resolve_one, word, domain, resolver): word for word in wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)

        print(f"[Brute Force] Found {len(subdomains)} subdomains")
        return subdomains
    except Exception as e:
        print(f"[Brute Force] Error: {e}")
        return set()
