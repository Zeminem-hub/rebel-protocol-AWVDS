# Rebel Protocol - AVWDS

Automated Web Vulnerability Detection System built with Python and Flask.

Rebel Protocol helps authorized security testers crawl a web application and check for common vulnerability signals from a single command-line or browser-based workflow.

## Features

- SQL injection detection
- Reflected cross-site scripting detection
- CSRF token checks on POST forms
- Missing security header checks
- Exposed sensitive file/path checks
- Crawl depth control
- Optional session cookie support for authenticated testing
- JSON report output from the CLI
- Web scanner interface with live status, findings, and severity summary

## Requirements

- Python 3.8 or higher
- pip
- Git
- Chromium browser installed through Playwright

## Installation

Clone the project:

```bash
git clone https://github.com/Zeminem-hub/rebel-protocol-AWVDS.git
cd rebel-protocol-AWVDS
```

Create and activate a virtual environment.

Windows:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
python -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
python -m playwright install chromium
```

If `playwright` is not recognized as a command, always use:

```bash
python -m playwright install chromium
```

## Run the Web Scanner

Start the Flask app:

```bash
python app.py
```

Open the scanner in your browser:

```text
http://127.0.0.1:8080/scanner
```

If port `8080` is already in use, start the app on another port.

PowerShell example:

```powershell
$env:PORT="8082"
python app.py
```

Then open:

```text
http://127.0.0.1:8082/scanner
```

## Use the Web Scanner

1. Enter a target URL that starts with `http://` or `https://`.
2. Choose the crawl depth.
3. Add session cookies if the target requires authentication.
4. Keep all modules checked for maximum coverage.
5. Click **Start Attack** to begin the authorized scan.

## Run the CLI Scanner

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

Show all CLI options:

```bash
python main.py --help
```

## Project Structure

```text
avwds/
├── app.py                    # Flask web interface
├── main.py                   # CLI entry point
├── config.py                 # Project settings
├── requirements.txt          # Python dependencies
├── core/
│   └── crawler.py            # Web crawler
├── modules/
│   ├── sqli.py               # SQL injection scanner
│   ├── xss.py                # XSS scanner
│   ├── headers.py            # Security headers scanner
│   ├── sensitive_files.py    # Sensitive file scanner
│   └── csrf.py               # CSRF checker
├── reports/
│   └── generator.py          # JSON report generation
├── templates/
│   ├── index.html            # Landing page
│   └── scanner.html          # Web scanner UI
└── utils/
    ├── logger.py             # Console logging helpers
    └── payloads.py           # Payload and path lists
```

## Important Safety Notice

This project is for educational and authorized security testing only.

Only scan systems that you own or have explicit written permission to test. Unauthorized scanning can be illegal and harmful. The developer is not responsible for misuse of this tool.
