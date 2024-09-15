# AI-Vuln-Scanner

An AI-powered web application vulnerability scanner that automates the detection of common security flaws and provides AI-driven insights for impact assessment and remediation suggestions.

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
