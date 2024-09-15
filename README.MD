AI-Powered Web Application Vulnerability Scanner
Overview: A tool that automates the scanning of web applications for common vulnerabilities (like SQL injection, XSS, CSRF, and SSRF) and leverages AI to provide an analysis of the potential impact and suggested remediation steps. This tool aims to be simple to set up and use, targeting penetration testers who need quick, actionable insights without the complexity of larger enterprise solutions.

Installation:
1. Clone the repository: git clone https://github.com/4xyy/AI-Vuln-Scanner.git
2. cd AI-Vuln-Scanner
3. Set up the environment: python3 -m venv .venv
4. source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
5. pip install -r requirements.txt
6. Run the scanner: python vuln_scanner.py

Usage:
1. Start the scanner: python vuln_scanner.py  
2. Enter the target URL when prompted.

Workflow:
1. Run Scans: Checks for SQL Injection, XSS, CSRF, and SSRF.
2. View Results: Displays vulnerabilities found.
3. AI Analysis: Provides impact assessment and prioritization.
