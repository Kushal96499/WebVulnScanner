# Web Application Vulnerability Scanner + Directory Scanner
# CodTech Internship Task 2
# Developed by: KUSHAL KUMAWAT

# ========== IMPORTS ==========
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
import datetime
import time

# Initialize colorama
init(autoreset=True)

# Basic Payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 'a'='a"]
xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"]

# Wordlist for Directory Bruteforcing
common_dirs = [
    "admin", "login", "dashboard", "uploads", "config", "backup", 
    "secret", "hidden", "server-status", "private", "panel", "portal"
]

# ========== FUNCTIONS ==========

def banner():
    """Displays an animated moving banner for WEB SCANNER."""
    banner_text = r"""
__        __   _     ____                                                
\ \      / /__| |__ | ___|__ _ _ __ ___  ___ _ __   ___ _ __             
 \ \ /\ / / _ \ '_ \| |_/ _ \ '__/ __|/ _ \ '_ \ / _ \ '__|            
  \ V  V /  __/ |_) |  _|  __/ |  \__ \  __/ | | |  __/ |               
   \_/\_/ \___|_.__/|_|  \___|_|  |___/\___|_| |_|\___|_|               
                                                                          
__        ___     _ _                                                   
\ \      / (_)_ _(_) |_ ___ _ _ ___                                      
 \ \ /\ / /| | '_| |  _/ -_) '_(_-<                                      
  \_/\_/ |_|_| |_|__\___|_| /__/                                          
    """
    for char in banner_text:
        print(Fore.LIGHTCYAN_EX + char, end='', flush=True)
        time.sleep(0.0015)

    print(Style.BRIGHT + Fore.YELLOW + "\n========== CodTech Internship - Task 2 ==========")
    print(Style.BRIGHT + Fore.GREEN + "========= WEB APPLICATION VULNERABILITY SCANNER + DIRECTORY SCANNER =========")
    print(Style.BRIGHT + Fore.LIGHTMAGENTA_EX + "============== Developed by: KUSHAL KUMAWAT ==============")
    print(Style.BRIGHT + Fore.CYAN + "-"*90)

def validate_url(url):
    """Checks if the given URL is valid."""
    parsed = urlparse(url)
    return all([parsed.scheme, parsed.netloc])

# --- Vulnerability Scanner Functions ---

def get_forms(url):
    """Fetches all forms from the web page."""
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(Fore.RED + f"[!] Error fetching forms: {e}")
        return []

def get_form_details(form):
    """Extracts useful details from a form."""
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details

def submit_form(form_details, url, payload):
    """Submits payload to the form."""
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}

    for input in inputs:
        if input["type"] in ["text", "search", "email"]:
            data[input["name"]] = payload
        else:
            data[input["name"]] = "test"

    print(Fore.CYAN + f"[*] Submitting payload to {target_url}")

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def save_report(url, vuln_type, payload):
    """Saves the detected vulnerabilities into a file."""
    with open("vulnerability_report.txt", "a") as f:
        f.write(f"Time: {datetime.datetime.now()}\n")
        f.write(f"URL: {url}\n")
        f.write(f"Vulnerability Type: {vuln_type}\n")
        f.write(f"Payload: {payload}\n")
        f.write("="*80 + "\n")

def scan_vulnerabilities(url):
    """Scans the URL for SQL Injection and XSS vulnerabilities."""
    forms = get_forms(url)
    print(Fore.YELLOW + f"[+] Found {len(forms)} form(s) on {url}")

    if not forms:
        return

    for form in forms:
        details = get_form_details(form)

        # SQL Injection Tests
        for payload in sql_payloads:
            response = submit_form(details, url, payload)
            if payload in response.text:
                print(Fore.RED + "[!] SQL Injection vulnerability detected!")
                save_report(url, "SQL Injection", payload)

        # XSS Tests
        for payload in xss_payloads:
            response = submit_form(details, url, payload)
            if payload in response.text:
                print(Fore.RED + "[!] XSS vulnerability detected!")
                save_report(url, "XSS", payload)

# --- Directory Scanner Functions ---

def scan_directories(base_url):
    """Scans for common hidden directories on the website."""
    print(Style.BRIGHT + Fore.YELLOW + "\n[+] Starting Directory Bruteforcing...")
    for dir_name in common_dirs:
        url = urljoin(base_url, dir_name)
        try:
            res = requests.get(url)
            if res.status_code == 200:
                print(Fore.GREEN + f"[+] Found directory/page: {url}")
                with open("directory_report.txt", "a") as f:
                    f.write(f"Time: {datetime.datetime.now()}\n")
                    f.write(f"Found Directory/Page: {url}\n")
                    f.write("="*80 + "\n")
        except:
            pass

# ========== MAIN DRIVER ==========

if __name__ == "__main__":
    banner()
    target_url = input("\nEnter the URL to scan (with http/https): ").strip()

    if not validate_url(target_url):
        print(Fore.RED + "[!] Invalid URL format. Please include http:// or https://")
    else:
        scan_vulnerabilities(target_url)
        scan_directories(target_url)
        print(Style.BRIGHT + Fore.BLUE + "\n[+] Scan Completed Successfully!")
        print(Style.BRIGHT + Fore.CYAN + "Reports saved: 'vulnerability_report.txt' and 'directory_report.txt'")
