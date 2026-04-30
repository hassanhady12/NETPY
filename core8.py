import requests

def detect_database(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    
    try:
        response = requests.get(url, timeout=5)
        
        if response.status_code != 200:
            return {"Error": f"Failed to connect: {response.status_code}"}
        
        headers = response.headers
        
        db_types = {
            "X-Powered-By": {
                "PHP": "MySQL or MariaDB",
                "ASP.NET": "MSSQL or Microsoft Access",
                "Express": "MongoDB or PostgreSQL",
                "Ruby on Rails": "PostgreSQL or MySQL",  
            },
            "Server": {
                "nginx": "MySQL or PostgreSQL",
                "Apache": "MySQL or MariaDB",
                "Microsoft-IIS": "MSSQL or Microsoft Access",
                "LiteSpeed": "MySQL or PostgreSQL",  
            },
            "X-Database": {
                "Redis": "Redis Database",
                "SQLite": "SQLite Database",
            }
        }
        
        detected_db = []
        for header, mappings in db_types.items():
            if header in headers:
                for key, db in mappings.items():
                    if key in headers[header]:
                        detected_db.append(db)
        
        if detected_db:
            return {"Database": list(set(detected_db))}
        else:
            return {"Database": "Unknown"}
    
    except requests.exceptions.RequestException as e:
        return {"Error": f"Request failed: {str(e)}"}

