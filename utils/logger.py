from colorama import Fore, Style, init
import datetime

init(autoreset=True)

def info(msg):
    print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")

def success(msg):
    print(f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}")

def warning(msg):
    print(f"{Fore.YELLOW}[!] {msg}{Style.RESET_ALL}")

def error(msg):
    print(f"{Fore.RED}[-] {msg}{Style.RESET_ALL}")

def critical(msg):
    print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL] {msg}{Style.RESET_ALL}")

def log_finding(finding):
    severity = finding.get("severity", "INFO")
    color = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
        "INFO": Fore.WHITE
    }.get(severity, Fore.WHITE)
    
    print(f"{color}[{severity}] {finding['type']} → {finding.get('url', '')}{Style.RESET_ALL}")