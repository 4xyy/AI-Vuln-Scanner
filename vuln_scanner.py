import requests
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import numpy as np

def scan_sql_injection(url):
    """Scans a URL for basic SQL Injection vulnerabilities."""
    test_payload = "' OR '1'='1"
    try:
        response = requests.get(f"{url}?id={test_payload}")
        if "SQL syntax" in response.text or "mysql" in response.text:
            print("[!] Potential SQL Injection vulnerability detected!")
        else:
            print("[+] No SQL Injection vulnerability found.")
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")

def scan_xss(url):
    """Scans a URL for basic XSS vulnerabilities."""
    test_payload = "<script>alert('xss')</script>"
    try:
        response = requests.get(f"{url}?q={test_payload}")
        if test_payload in response.text:
            print("[!] Potential XSS vulnerability detected!")
        else:
            print("[+] No XSS vulnerability found.")
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")

def ai_analysis(vulnerabilities):
    """Uses a basic AI model to assess vulnerability severity."""
    # Dummy implementation: Replace with a trained model for real use
    print("\nAI Analysis Report:")
    if 'SQL Injection' in vulnerabilities:
        print("[AI] SQL Injection detected, high severity. Immediate action required.")
    if 'XSS' in vulnerabilities:
        print("[AI] XSS detected, medium severity. Review and mitigate.")
    if not vulnerabilities:
        print("[AI] No significant vulnerabilities detected.")

def main():
    print("AI-Powered Web Application Vulnerability Scanner")
    target_url = input("Enter the target URL: ").strip()
    vulnerabilities = []

    # Scanning for SQL Injection
from scanners.sql_injection import scan_sql_injection  # Existing module
from scanners.xss import scan_xss  # Existing module
from scanners.csrf import scan_csrf  # New CSRF module
from scanners.ssrf import scan_ssrf  # New SSRF module

def ai_analysis(vulnerabilities):
    """Placeholder function for AI analysis."""
    print("\nAI Analysis Report:")
    for vuln in vulnerabilities:
        print(f"[AI] Detected {vuln}. Further analysis required.")

def main():
    print("AI-Powered Web Application Vulnerability Scanner")
    target_url = input("Enter the target URL: ").strip()
    vulnerabilities = []

    # Scan for SQL Injection
    print("\nScanning for SQL Injection...")
    if scan_sql_injection(target_url):
        vulnerabilities.append('SQL Injection')

    # Scan for XSS
    print("\nScanning for XSS...")
    if scan_xss(target_url):
        vulnerabilities.append('XSS')

    # Scan for CSRF
    print("\nScanning for CSRF...")
    if scan_csrf(target_url):
        vulnerabilities.append('CSRF')

    # Scan for SSRF
    print("\nScanning for SSRF...")
    if scan_ssrf(target_url):
        vulnerabilities.append('SSRF')

    # AI Analysis of vulnerabilities
    print("\nRunning AI Analysis...")
    ai_analysis(vulnerabilities)

if __name__ == "__main__":
    main()

