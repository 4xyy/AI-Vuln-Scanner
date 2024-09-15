import requests

def scan_sql_injection(url):
    """Scans a URL for basic SQL Injection vulnerabilities."""
    test_payload = "' OR '1'='1"
    try:
        response = requests.get(f"{url}?id={test_payload}")
        # Check for common SQL error messages indicating vulnerability
        if "SQL syntax" in response.text or "mysql" in response.text or "syntax error" in response.text:
            print("[!] Potential SQL Injection vulnerability detected!")
            return True
        else:
            print("[+] No SQL Injection vulnerability found.")
            return False
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False

