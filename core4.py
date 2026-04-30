import whois
import socket
import validators

def get_domain_info(domains):
    results = {}
    for domain in domains:
        domain = domain.strip()  
        if not validators.domain(domain): 
            results[domain] = {"error": "Invalid domain format"}
            continue

        try:
            ip_addr = socket.gethostbyname(domain)  
            whois_info = whois.whois(domain)  
            results[domain] = {
                "ip": ip_addr,
                "whois": whois_info.text if whois_info else "No whois data available",
            }
        except Exception as e:
            results[domain] = {"error": str(e)}

    return results
