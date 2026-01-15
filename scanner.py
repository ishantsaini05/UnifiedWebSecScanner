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
        server = r.headers.get("Server")
        powered = r.headers.get("X-Powered-By")

        if not server and not powered:
            return {
                "Info": (
                    "Server identification headers are hidden. "
                    "This is a good security practice that reduces "
                    "information disclosure to attackers."
                )
            }

        return {
            "Server": server or "Not Disclosed",
            "X-Powered-By": powered or "Not Disclosed"
        }

    except:
        return {
            "Info": (
                "Server fingerprint could not be retrieved. "
                "Target may be blocking automated requests."
            )
        }


def tool_exists(tool):
    return shutil.which(tool) is not None


def run_nmap(domain):
    if not tool_exists("nmap"):
        return (
            "Nmap scan was not performed because the tool is not installed "
            "on the scanning system.\n\n"
            "Install command:\n"
            "sudo apt install nmap"
        )
    try:
        return subprocess.check_output(
            ["nmap", "-F", domain],
            stderr=subprocess.DEVNULL
        ).decode()
    except:
        return "Nmap execution failed due to an unexpected error."


def run_wpscan(url):
    if not tool_exists("wpscan"):
        return (
            "WPScan was not executed because it is not installed on the system.\n\n"
            "Install command:\n"
            "sudo gem install wpscan"
        )
    try:
        return subprocess.check_output(
            ["wpscan", "--url", url, "--no-update"],
            stderr=subprocess.DEVNULL
        ).decode()
    except:
        return "WPScan execution failed due to an unexpected error."
