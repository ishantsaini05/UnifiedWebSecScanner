import socket
import requests
import subprocess
import shutil

QUICK_PORTS = [80, 443]
FULL_PORTS = [21, 80, 443, 3306]

def scan_ports(domain, profile="Quick"):
    ports = QUICK_PORTS if profile == "Quick" else FULL_PORTS
    open_ports = []

    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            if s.connect_ex((domain, port)) == 0:
                open_ports.append(port)
            s.close()
        except:
            pass

    return open_ports


def check_headers(url):
    issues = []
    r = requests.get(url, timeout=5)

    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security"
    ]

    for h in required:
        if h not in r.headers:
            issues.append(h)

    return issues, dict(r.headers)


def https_redirect(domain):
    try:
        r = requests.get("http://" + domain, allow_redirects=True, timeout=5)
        return r.url.startswith("https://")
    except:
        return False


def fingerprint(url):
    try:
        r = requests.get(url, timeout=5)
        return {
            "Server": r.headers.get("Server", "Unknown"),
            "X-Powered-By": r.headers.get("X-Powered-By", "Unknown")
        }
    except:
        return {}


def tool_exists(tool):
    return shutil.which(tool) is not None


def run_nmap(domain):
    if not tool_exists("nmap"):
        return "Nmap not installed.\nInstall: sudo apt install nmap"
    try:
        return subprocess.check_output(["nmap", "-F", domain]).decode()
    except:
        return "Nmap execution failed"


def run_wpscan(url):
    if not tool_exists("wpscan"):
        return "WPScan not installed.\nInstall: sudo gem install wpscan"
    try:
        return subprocess.check_output(
            ["wpscan", "--url", url, "--no-update"]
        ).decode()
    except:
        return "WPScan execution failed"
