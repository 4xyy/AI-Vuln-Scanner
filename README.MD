A tool that automates the scanning of web applications for common vulnerabilities (like SQL injection, XSS, CSRF) and leverages AI to provide an analysis of the potential impact and suggested remediation steps. This tool aims to be simple to set up and use, targeting penetration testers who need quick, actionable insights without the complexity of larger enterprise solutions.

Automated Scanning for Multiple Vulnerabilities:

SQL Injection: Detects basic SQL injection vulnerabilities by testing for common SQL error messages.
XSS (Cross-Site Scripting): Scans for basic XSS vulnerabilities by injecting scripts and checking for their presence in the response.
CSRF (Cross-Site Request Forgery): Identifies potential CSRF vulnerabilities by checking for missing anti-CSRF tokens in forms.
SSRF (Server-Side Request Forgery): Tests for SSRF vulnerabilities by attempting to manipulate URLs to access internal resources.
AI-Driven Analysis:

Vulnerability Assessment: Uses AI to provide an initial analysis of detected vulnerabilities, helping prioritize which vulnerabilities need immediate attention.
Modular Design:

Each vulnerability scanner is modularized, allowing easy expansion or modification of scanning capabilities.
User-Friendly CLI:

A simple command-line interface guides users through scanning and analyzing web applications for security vulnerabilities.

Installation:

Clone the Repository:
git clone https://github.com/4xyy/AI-Vuln-Scanner.git
cd AI-Vuln-Scanner
Set Up a Virtual Environment and Install Dependencies:
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install -r requirements.txt
python vuln_scanner.py

Usage:
Run the Scanner: Start the vulnerability scanner by running:
python vuln_scanner.py
Follow the Prompts:

Enter the target URL when prompted to initiate the scanning process.
Example Workflow:
Starting the Scanner:

AI-Powered Web Application Vulnerability Scanner
Enter the target URL: https://example.com
Scanning Process:

The tool will sequentially run checks for SQL Injection, XSS, CSRF, and SSRF vulnerabilities.
For each type, it prints the results, indicating whether a vulnerability was found.
AI Analysis:

After the scans, the AI analysis provides an assessment of detected vulnerabilities.
