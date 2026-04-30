import dns.resolver

def get_all_dns_records(domains):
    """
    Function to get all DNS records (A, AAAA, CNAME, MX, NS, TXT) for a list of domains.
    """
    results = {}
    
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
    
    for domain in domains:
        domain_results = {
            "A": [],
            "AAAA": [],
            "CNAME": [],
            "MX": [],
            "NS": [],
            "TXT": []
        }

        for record_type in record_types:
            try:
                records = dns.resolver.resolve(domain, record_type)
                domain_results[record_type] = [str(record) for record in records]
            except Exception as e:
                domain_results[record_type] = [f"Error: {str(e)}"]

        # Store the results for this domain
        results[domain] = domain_results
    
    return results
