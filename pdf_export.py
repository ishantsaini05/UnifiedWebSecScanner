from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor

def generate_pdf(report_data):
    c = canvas.Canvas("reports/report.pdf", pagesize=A4)
    width, height = A4

    margin_x = 50
    y = height - 50

    # Colors
    dark = HexColor("#111827")
    gray = HexColor("#374151")
    green = HexColor("#16a34a")
    blue = HexColor("#2563eb")

    # =========================
    # TITLE
    # =========================
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(dark)
    c.drawString(margin_x, y, "Web Security Assessment Report")
    y -= 35

    # =========================
    # EXECUTIVE SUMMARY
    # =========================
    c.setFont("Helvetica-Bold", 15)
    c.drawString(margin_x, y, "Executive Summary")
    y -= 22

    c.setFont("Helvetica", 11)
    c.setFillColor(gray)

    c.drawString(margin_x, y, f"Target: {report_data['target']}")
    y -= 15

    c.drawString(margin_x, y, f"Date: {report_data['date']}")
    y -= 15

    c.drawString(
        margin_x,
        y,
        "Scan Type: Unauthenticated External Assessment"
    )
    y -= 14

    c.drawString(
        margin_x,
        y,
        "This scan was performed without login access, simulating an external attacker."
    )
    y -= 18

    c.drawString(
        margin_x,
        y,
        f"Overall Risk: {report_data['risk_level']}"
    )
    y -= 15

    c.drawString(
        margin_x,
        y,
        f"Severity Score: {report_data['severity']}/10"
    )
    y -= 22

    c.drawString(
        margin_x,
        y,
        "This report explains the identified security risks in simple language."
    )
    y -= 14
    c.drawString(
        margin_x,
        y,
        "Each issue includes clear remediation steps so even beginners can fix them safely."
    )
    y -= 30

    # =========================
    # OPEN PORTS SECTION
    # =========================
    c.setFont("Helvetica-Bold", 15)
    c.setFillColor(dark)
    c.drawString(margin_x, y, "Open Ports – Risk Explanation & Fix")
    y -= 22

    c.setFont("Helvetica", 11)
    c.setFillColor(gray)

    for p in report_data["port_details"]:
        if y < 120:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 11)
            c.setFillColor(gray)

        c.setFont("Helvetica-Bold", 12)
        c.drawString(
            margin_x,
            y,
            f"Port {p['port']} – {p['service']} (Risk: {p['risk']})"
        )
        y -= 16

        c.setFont("Helvetica", 11)
        c.drawString(margin_x + 20, y, "What is the problem?")
        y -= 14
        c.drawString(margin_x + 40, y, p["desc"])
        y -= 18

        c.drawString(margin_x + 20, y, "How to Secure (Step-by-Step):")
        y -= 14

        for line in p["fix"].split("\n"):
            c.drawString(margin_x + 40, y, line)
            y -= 12

        y -= 10

        if p["cves"]:
            c.drawString(margin_x + 20, y, "Related CVEs & CVSS Scores:")
            y -= 14
            for cve in p["cves"]:
                c.drawString(
                    margin_x + 40,
                    y,
                    f"{cve['id']} – CVSS: {cve['cvss']}"
                )
                y -= 12

        y -= 20

    # =========================
    # HEADER ISSUES
    # =========================
    if y < 120:
        c.showPage()
        y = height - 50

    c.setFont("Helvetica-Bold", 15)
    c.setFillColor(dark)
    c.drawString(margin_x, y, "Security Header Issues")
    y -= 20

    c.setFont("Helvetica", 11)
    c.setFillColor(gray)

    if report_data["issues"]:
        for i in report_data["issues"]:
            c.drawString(margin_x + 20, y, f"- {i}")
            y -= 14
    else:
        c.drawString(margin_x + 20, y, "No critical security header issues detected.")
        y -= 14

    y -= 20

    # =========================
    # SERVER FINGERPRINT
    # =========================
    c.setFont("Helvetica-Bold", 15)
    c.setFillColor(dark)
    c.drawString(margin_x, y, "Server Fingerprint")
    y -= 20

    c.setFont("Helvetica", 11)
    c.setFillColor(gray)
    c.drawString(margin_x + 20, y, str(report_data.get("fingerprint", {})))
    y -= 30

    # =========================
    # NMAP & WPSCAN
    # =========================
    c.setFont("Helvetica-Bold", 15)
    c.drawString(margin_x, y, "Nmap Scan Result")
    y -= 20

    c.setFont("Helvetica", 10)
    for line in report_data.get("nmap", "").split("\n"):
        c.drawString(margin_x + 20, y, line)
        y -= 12

    y -= 20

    c.setFont("Helvetica-Bold", 15)
    c.drawString(margin_x, y, "WPScan Result")
    y -= 20

    c.setFont("Helvetica", 10)
    for line in report_data.get("wpscan", "").split("\n"):
        c.drawString(margin_x + 20, y, line)
        y -= 12

    # =========================
    # FOOTER
    # =========================
    c.showPage()

    c.setFont("Helvetica-Bold", 16)
    c.setFillColor(dark)
    c.drawString(margin_x, height - 80, "Security Analyst")

    c.setFont("Helvetica", 13)
    c.drawString(margin_x, height - 110, "Ishant Saini")

    c.setFillColor(blue)
    c.drawString(margin_x, height - 140, "📞 Contact Admin on WhatsApp")

    c.linkURL(
        "https://wa.me/919625254286",
        (margin_x, height - 145, margin_x + 260, height - 125),
        relative=0
    )

    c.setFont("Helvetica", 9)
    c.setFillColor(gray)
    c.drawString(
        margin_x,
        60,
        "Disclaimer: This report does not guarantee the absence of vulnerabilities. "
        "Findings are based on the scope and time of assessment."
    )

    c.save()
