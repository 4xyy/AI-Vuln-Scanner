import requests
from bs4 import BeautifulSoup

def scan_csrf(url):
    """Scans a URL for potential CSRF vulnerabilities."""
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        csrf_vulnerable = False
        for form in forms:
            # Check if CSRF tokens are missing in forms
            if not form.find('input', {'name': 'csrf_token'}) and not form.find('input', {'name': '_token'}):
                print("[!] Potential CSRF vulnerability: Form lacks CSRF token.")
                csrf_vulnerable = True
        if not csrf_vulnerable:
            print("[+] No CSRF vulnerability found.")
        return csrf_vulnerable
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False

