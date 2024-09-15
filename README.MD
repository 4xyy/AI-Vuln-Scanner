# AI-Vuln-Scanner

A tool that automates the scanning of web applications for common vulnerabilities (like SQL injection, XSS, CSRF) and leverages AI to provide an analysis of the potential impact and suggested remediation steps. This tool aims to be simple to set up and use, targeting penetration testers who need quick, actionable insights without the complexity of larger enterprise solutions.

## Features
- Scans for common web vulnerabilities like SQL Injection and XSS.
- Provides AI-powered analysis to assess severity and suggest remediation.
- Simple CLI interface for easy use and integration into workflows.

## Installation

Clone the repository and set up a virtual environment:
```bash
git clone https://github.com/4xyy/AI-Vuln-Scanner.git
cd AI-Vuln-Scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python vuln_scanner.py
Follow the prompts to enter the target URL.
