from jinja2 import Template
from utils import PORT_INFO, calculate_severity, cve_lookup
import os

def generate_report(data):
    severity = calculate_severity(data["ports"], data["issues"])
    risk_level = (
        "CRITICAL" if severity >= 8 else
        "HIGH" if severity >= 6 else
        "MEDIUM" if severity >= 4 else
        "LOW"
    )

    cves = {}
    for p in data["ports"]:
        service = PORT_INFO[p]["service"]
        cves[p] = cve_lookup(service)

    html = Template("""
<!DOCTYPE html>
<html>
<head>
<title>Web Security Assessment Report</title>
<style>
body {
    font-family: 'Segoe UI', Arial;
    background: #eef1f5;
    padding: 30px;
}
.header {
    background: linear-gradient(135deg, #1e1e2f, #2c3e50);
    color: white;
    padding: 30px;
    border-radius: 14px;
    margin-bottom: 25px;
}
.card {
    background: #ffffff;
    padding: 25px;
    border-radius: 14px;
    margin-bottom: 25px;
    box-shadow: 0 6px 16px rgba(0,0,0,0.08);
}
.badge {
    padding: 6px 14px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 13px;
}
.LOW { background: #2ecc71; color: white; }
.MEDIUM { background: #f1c40f; }
.HIGH { background: #e67e22; color: white; }
.CRITICAL { background: #e74c3c; color: white; }
pre {
    background: #f4f6f8;
    padding: 16px;
    border-radius: 10px;
}
.footer {
    background: #111827;
    color: white;
    padding: 25px;
    border-radius: 14px;
    text-align: center;
}
.footer a {
    display: inline-block;
    margin-top: 10px;
    padding: 10px 18px;
    background: #25D366;
    color: white;
    text-decoration: none;
    border-radius: 25px;
    font-weight: bold;
}
</style>
</head>

<body>

<div class="header">
<h1>Web Security Assessment Report</h1>
<p><b>Target:</b> {{ target }}</p>
<p><b>Date:</b> {{ date }}</p>
<p><b>Scan Type:</b> Unauthenticated External Assessment</p>
<p>This scan was performed without login access, simulating an external attacker.</p>
<p><b>Overall Risk:</b> <span class="badge {{ risk_level }}">{{ risk_level }}</span></p>
<p><b>Severity Score:</b> {{ severity }}/10</p>
</div>

<div class="card">
<p>
This report explains the identified security risks in simple language.
Each issue includes step-by-step remediation so even beginners can
understand and fix the problem safely.
</p>
</div>

<div class="card">
<h2>Open Ports – Risk Explanation & Fix</h2>
{% for p in ports %}
<h3>Port {{ p }} – {{ info[p].service }}</h3>
<p><b>Risk Level:</b> {{ info[p].risk }}</p>

<p><b>What is the problem?</b><br>{{ info[p].desc }}</p>

<p><b>How to Secure (Step-by-Step):</b></p>
<pre>{{ info[p].fix }}</pre>

<p><b>Related CVEs & CVSS Scores:</b></p>
<ul>
{% for c in cves[p] %}
<li>{{ c.id }} – CVSS: {{ c.cvss }}</li>
{% endfor %}
</ul>
{% endfor %}
</div>

<div class="card">
<h2>Security Header Issues</h2>
<ul>{% for i in issues %}<li>{{ i }}</li>{% endfor %}</ul>
</div>

<div class="card">
<h2>Server Fingerprint</h2>
<pre>{{ fingerprint }}</pre>
</div>

<div class="card">
<h2>Nmap Scan</h2>
<pre>{{ nmap }}</pre>
</div>

<div class="card">
<h2>WPScan</h2>
<pre>{{ wpscan }}</pre>
</div>

<div class="footer">
<b>Security Analyst: Ishant Saini</b><br>
<a href="https://wa.me/919625254286" target="_blank">
📞 Contact Admin on WhatsApp
</a>
<p style="margin-top:15px;font-size:13px;">
Disclaimer: This report does not guarantee the absence of vulnerabilities.
Findings are based on the scope and time of assessment.
</p>
</div>

</body>
</html>
""").render(
        **data,
        info=PORT_INFO,
        severity=severity,
        risk_level=risk_level,
        cves=cves
    )

    os.makedirs("reports", exist_ok=True)
    with open("reports/report.html", "w", encoding="utf-8") as f:
        f.write(html)

    return {
        "target": data["target"],
        "date": data["date"],
        "severity": severity,
        "risk_level": risk_level,
        "ports": data["ports"],
        "issues": data["issues"],
        "port_details": [
            {
                "port": p,
                "service": PORT_INFO[p]["service"],
                "risk": PORT_INFO[p]["risk"],
                "desc": PORT_INFO[p]["desc"],
                "fix": PORT_INFO[p]["fix"],
                "cves": cves[p]
            } for p in data["ports"]
        ]
    }
