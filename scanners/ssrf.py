import requests

def scan_ssrf(url):
    """Scans a URL for potential SSRF vulnerabilities."""
    test_payload = "http://localhost:8080"  # Test payload for SSRF
    try:
        # Example of testing SSRF via URL parameter manipulation
        response = requests.get(f"{url}?redirect={test_payload}")
        # Check if response includes signs of SSRF vulnerability
        if "internal" in response.text or "localhost" in response.text:
            print("[!] Potential SSRF vulnerability detected!")
            return True
        else:
            print("[+] No SSRF vulnerability found.")
            return False
    except requests.RequestException as e:
        print(f"Error scanning URL: {e}")
        return False

