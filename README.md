# Automated Web Vulnerability Detection System

**Automated Web Vulnerability Detection System**

Automated Web Vulnerability Detection System is a Python-based web vulnerability scanner built for authorized security testing, learning, and research. It provides both a browser-based scanner interface and a command-line workflow for identifying common web application security issues.

The project is designed to run locally during development and can also be hosted as a web application so users can access the scanner through a website interface.

## Overview

Automated Web Vulnerability Detection System crawls a target web application, discovers testable endpoints, and runs multiple security checks against the discovered attack surface. The scanner focuses on practical vulnerability signals that are commonly found during web application assessments.

This project includes:

- A Flask-powered web interface
- A command-line scanner
- Modular vulnerability checks
- JSON report generation
- Optional session cookie support for authenticated testing
- A clean browser workflow for launching scans from a hosted website

## Key Features

- **SQL Injection Testing**  
  Tests discovered parameters with SQL injection payloads and checks for database error signatures and time-based behavior.

- **Reflected XSS Testing**  
  Injects XSS payloads into discovered inputs and checks whether payloads are reflected in responses.

- **CSRF Checks**  
  Reviews POST forms for missing CSRF token fields.

- **Security Header Analysis**  
  Checks for missing headers such as Content Security Policy, HSTS, X-Frame-Options, and other recommended browser security controls.

- **Sensitive File Detection**  
  Checks for exposed files and paths such as `.env`, `.git`, backups, configuration files, and other sensitive resources.

- **Web Scanner Dashboard**  
  Provides a visual interface with target input, module selection, scan status, severity counts, logs, and detailed findings.

- **CLI Scanner**  
  Supports terminal-based scanning with custom depth, output file selection, and module skipping options.

## Hosting Plan

This project is intended to be hosted as a website/web application. When deployed, users will be able to open the scanner in a browser, enter an authorized target, select scan modules, and start the assessment from the web interface.

Recommended deployment options include:

- Render
- Railway
- PythonAnywhere
- VPS hosting with Gunicorn and Nginx
- Any platform that supports Python Flask applications

The included `Procfile` is prepared for platforms that run Flask apps through Gunicorn:

```text
web: gunicorn app:app --bind 0.0.0.0:$PORT
```

## Technology Stack

- Python
- Flask
- httpx
- BeautifulSoup
- Playwright
- Colorama
- Jinja2
- Gunicorn

## Requirements

- Python 3.8 or higher
- pip
- Git
- Chromium installed through Playwright

## Installation

Clone the repository:

```bash
git clone https://github.com/Zeminem-hub/AWVDS.git
cd AWVDS
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate the virtual environment.

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Windows Command Prompt:

```cmd
venv\Scripts\activate.bat
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Install Chromium for Playwright:

```bash
python -m playwright install chromium
```

## Running the Web Application Locally

Start the Flask server:

```bash
python app.py
```

Open the scanner:

```text
http://127.0.0.1:8080/scanner
```

If port `8080` is already in use, run the app on another port.

PowerShell example:

```powershell
$env:PORT="8082"
python app.py
```

Then open:

```text
http://127.0.0.1:8082/scanner
```

## Using the Web Scanner

1. Open the scanner page in the browser.
2. Enter a target URL beginning with `http://` or `https://`.
3. Select the crawl depth.
4. Add session cookies if the target requires authentication.
5. Keep all modules enabled for maximum coverage.
6. Click **Start Attack** to begin the authorized scan.
7. Review the severity summary, logs, and detailed findings.

## Running the CLI Scanner

Basic scan:

```bash
python main.py --url http://example.com
```

Scan with custom depth:

```bash
python main.py --url http://example.com --depth 3
```

Save the report to a custom file:

```bash
python main.py --url http://example.com --output results.json
```

Skip selected modules:

```bash
python main.py --url http://example.com --no-sqli
python main.py --url http://example.com --no-xss
python main.py --url http://example.com --no-headers
python main.py --url http://example.com --no-files
```

Show all available options:

```bash
python main.py --help
```

## Project Structure

```text
avwds/
|-- app.py                    # Flask web application
|-- main.py                   # CLI entry point
|-- config.py                 # Project configuration
|-- requirements.txt          # Python dependencies
|-- Procfile                  # Deployment process file
|-- core/
|   `-- crawler.py            # Web crawler
|-- modules/
|   |-- sqli.py               # SQL injection scanner
|   |-- xss.py                # XSS scanner
|   |-- headers.py            # Security header scanner
|   |-- sensitive_files.py    # Sensitive file/path scanner
|   `-- csrf.py               # CSRF checker
|-- reports/
|   `-- generator.py          # JSON report generator
|-- templates/
|   |-- index.html            # Landing page
|   `-- scanner.html          # Scanner dashboard
`-- utils/
    |-- logger.py             # Logging helpers
    `-- payloads.py           # Payload and path lists
```

## Deployment Notes

For hosted deployment:

1. Push the project to GitHub.
2. Connect the repository to a Python hosting provider.
3. Set the start command to use the included `Procfile`, or run:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT
```

4. Install dependencies from `requirements.txt`.
5. Ensure Playwright browser dependencies are installed if the crawler needs browser automation features.

## Security and Legal Notice

This tool is intended only for educational use, authorized testing, and controlled security research.

Only scan applications that you own or have explicit written permission to test. Unauthorized scanning may be illegal and can disrupt real systems. The developer is not responsible for misuse of this project.

## Status

This project is under active development. Future improvements may include hosted deployment, expanded scanner modules, improved reporting, authentication workflows, and scan history.
