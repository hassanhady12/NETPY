import requests
from requests.exceptions import RequestException, SSLError

def get_server_os(sites):
    """
    Function to get the OS and server information based on HTTP headers.
    """
    results = {}

    for site in sites:
        if not site.startswith(('http://', 'https://')):
            site = 'https://' + site

        try:
            # Send a HEAD request to avoid downloading the entire page
            response = requests.head(site, timeout=10)
            
            # If HEAD request fails, try GET request
            if response.status_code != 200:
                response = requests.get(site, timeout=10)

            # Check for the 'Server' header which may indicate OS and server software
            server_info = response.headers.get('Server', 'Unknown Server')

            # Try to identify the system based on server information
            if 'nginx' in server_info.lower():
                system_info = "Nginx Web Server"
            elif 'apache' in server_info.lower():
                system_info = "Apache Web Server"
            elif 'litespeed' in server_info.lower():
                system_info = "LiteSpeed Web Server"
            elif 'windows' in server_info.lower():
                system_info = "Windows Server"
            elif 'linux' in server_info.lower():
                system_info = "Linux Server"
            else:
                # Check 'X-Powered-By' header for more information
                powered_by = response.headers.get('X-Powered-By', 'Unknown Technology')
                system_info = f"Unknown System, Powered by: {powered_by}"
            
            results[site] = system_info
            
        except SSLError as ssl_error:
            results[site] = f"SSL Error: {str(ssl_error)}"
        except RequestException as e:
            results[site] = f"Error: {str(e)}"
    
    return results
