 # 🔴 Rebel Protocol — AVWDS

> Automated Web Vulnerability Detection System built with Python

---

## 📌 What is This?

Rebel Protocol is a command-line security tool that automatically 
scans websites for common vulnerabilities including:

- SQL Injection (SQLi)
- Cross Site Scripting (XSS)
- CSRF vulnerabilities
- Missing Security Headers
- Exposed Sensitive Files (.env, .git, backup files etc.)

---

## 💻 Requirements

- Python 3.8 or higher
- pip
- Git

---

## ⚙️ Installation

### 1. Clone the project
git clone https://github.com/Zeminem-hub/rebel-protocol-AWVDS.git

### 2. Go into the folder
cd rebel-protocol-AWVDS

### 3. Create virtual environment
python -m venv venv

### 4. Activate virtual environment

Windows:
venv\Scripts\activate.bat

Mac/Linux:
source venv/bin/activate

### 5. Install required libraries
pip install -r requirements.txt

### 6. Install browser for crawling
playwright install chromium

---

## 🚀 How to Use

Basic scan:
python main.py --url http://example.com

Scan with custom depth:
python main.py --url http://example.com --depth 3

Save report to custom file:
python main.py --url http://example.com --output results.json

Skip certain scans:
python main.py --url http://example.com --no-sqli
python main.py --url http://example.com --no-xss

See all options:
python main.py --help

---

## 📊 Example Output

    ██████╗ ███████╗██████╗ ███████╗██╗
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██║
    ██████╔╝█████╗  ██████╔╝█████╗  ██║

  [ Initializing Rebel Protocol... System Online ]

  [*] Phase 1: Crawling target website...
  [*] Found 8 testable endpoints
  [CRITICAL] SQL Injection found! → http://example.com/search.php
  [HIGH] XSS found! → http://example.com/comment.php
  [MEDIUM] Missing Header: Content-Security-Policy
  [+] Report saved to: report.json

---

## 📁 Project Structure

avwds/
├── main.py                  ← Entry point
├── config.py                ← Settings
├── setup.py                 ← Package setup
├── requirements.txt         ← Dependencies
├── core/
│   └── crawler.py           ← Web crawler
├── modules/
│   ├── sqli.py              ← SQL Injection scanner
│   ├── xss.py               ← XSS scanner
│   ├── headers.py           ← Headers checker
│   ├── sensitive_files.py   ← File scanner
│   └── csrf.py              ← CSRF checker
├── utils/
│   ├── payloads.py          ← Attack payloads
│   └── logger.py            ← Colored output
└── reports/
    └── generator.py         ← Report generator

---

## ⚠️ Legal Disclaimer

This tool is for educational purposes only.
Only scan websites you own or have explicit written permission to test.
Unauthorized scanning is illegal.
The developer is not responsible for misuse of this tool.

---

