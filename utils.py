import requests

PORT_INFO = {
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "desc": (
            "HTTP does not encrypt data. Any attacker on the same network "
            "can intercept or modify traffic (Man-in-the-Middle attack)."
        ),
        "fix": (
            "Step 1: Install an SSL/TLS certificate (Let's Encrypt recommended).\n"
            "Step 2: Force HTTPS redirection.\n\n"
            "Example (Nginx):\n"
            "server {\n"
            "    listen 80;\n"
            "    return 301 https://$host$request_uri;\n"
            "}\n\n"
            "Why this works:\n"
            "All users are automatically redirected to encrypted HTTPS.\n\n"
            "How to verify:\n"
            "Open http://yourdomain.com and confirm it redirects to https://"
        )
    },
    443: {
        "service": "HTTPS",
        "risk": "Safe",
        "desc": (
            "HTTPS encrypts communication between users and the server, "
            "protecting credentials and sensitive data."
        ),
        "fix": (
            "Step 1: Use TLS 1.2 or TLS 1.3 only.\n"
            "Step 2: Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1.\n\n"
            "Why this matters:\n"
            "Older protocols contain known cryptographic weaknesses.\n\n"
            "How to verify:\n"
            "Use https://www.ssllabs.com/ssltest/"
        )
    }
}

SEVERITY_MAP = {
    "Critical": 9.0,
    "High": 7.5,
    "Medium": 5.0,
    "Low": 2.5,
    "Safe": 0.0
}

def calculate_severity(open_ports, header_issues):
    score = 0
    count = 0
    for p in open_ports:
        score += SEVERITY_MAP.get(PORT_INFO[p]["risk"], 2.5)
        count += 1
    score += len(header_issues) * 1.5
    count += len(header_issues)
    return round(score / count, 1) if count else 0.0


def cve_lookup(service):
    """
    Auto CVE + CVSS using NVD API
    """
    results = []
    try:
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={service}&resultsPerPage=2"
        )
        data = requests.get(url, timeout=6).json()

        for v in data.get("vulnerabilities", []):
            cve = v["cve"]["id"]
            metrics = v["cve"].get("metrics", {})
            cvss = "Unknown"

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            results.append({
                "id": cve,
                "cvss": cvss
            })

        return results or [{"id": "No known CVEs", "cvss": "N/A"}]
    except:
        return [{"id": "CVE lookup failed", "cvss": "N/A"}]
