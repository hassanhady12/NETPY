import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def sub_domain(url):
    try:
    
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url 

        
        res = requests.get(url)
        res.raise_for_status()  

       
        parsed_url = urlparse(res.url)
        protocol = parsed_url.scheme 

        soup = BeautifulSoup(res.text, 'html.parser')

        links = soup.find_all('a')

        subdomains = set() 

        for index, link in enumerate(links, start=1):
            href = link.get('href')
            if href:
               
                parsed_link = urlparse(href)
                
                if parsed_link.netloc: 
                    full_url = f"{protocol}://{parsed_link.netloc}"
                    subdomains.add(full_url)

        return subdomains

    except requests.exceptions.RequestException as e:
        return f"Error = {e}"
