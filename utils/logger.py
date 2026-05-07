"""logger.py — Rebel Protocol AWVDS"""
import datetime

class Color:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; BLUE="\033[94m"
    MAGENTA="\033[95m"; CYAN="\033[96m"; WHITE="\033[97m"; BOLD="\033[1m"; RESET="\033[0m"

def _ts(): return datetime.datetime.now().strftime("%H:%M:%S")
def info(msg):     print(f"{Color.CYAN}[{_ts()}] [*] {msg}{Color.RESET}")
def success(msg):  print(f"{Color.GREEN}[{_ts()}] [+] {msg}{Color.RESET}")
def warning(msg):  print(f"{Color.YELLOW}[{_ts()}] [!] {msg}{Color.RESET}")
def error(msg):    print(f"{Color.RED}[{_ts()}] [-] {msg}{Color.RESET}")
def critical(msg): print(f"{Color.BOLD}{Color.RED}[{_ts()}] [CRITICAL] {msg}{Color.RESET}")
def banner(text):  print(f"{Color.MAGENTA}{Color.BOLD}{text}{Color.RESET}")
def vuln(severity, msg):
    c = {"CRITICAL":Color.RED+Color.BOLD,"HIGH":Color.RED,"MEDIUM":Color.YELLOW,"LOW":Color.CYAN,"INFO":Color.WHITE}.get(severity.upper(), Color.WHITE)
    print(f"{c}[{_ts()}] [{severity.upper()}] {msg}{Color.RESET}")
