import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, shutil, os
from scanner import *
from report import generate_report
from pdf_export import generate_pdf
from datetime import datetime

REPORT_HTML = "reports/report.html"

last_report_data = None

def start_scan():
    output.delete(1.0, tk.END)
    html_btn.pack_forget()
    pdf_btn.pack_forget()
    progress.start()
    threading.Thread(target=run_scan, daemon=True).start()

def run_scan():
    global last_report_data

    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Error", "Please enter a target URL")
        progress.stop()
        return

    domain = url.replace("https://", "").replace("http://", "").strip("/")

    output.insert(tk.END, f"Starting scan for {url}\n\n")

    ports = scan_ports(domain)
    issues, headers = check_headers(url)

    data = {
        "target": url,
        "date": datetime.now().strftime("%d %b %Y %H:%M"),
        "ports": ports,
        "issues": issues,
        "redirect": https_redirect(domain),
        "fingerprint": fingerprint(url),
        "nmap": run_nmap(domain),
        "wpscan": run_wpscan(url)
    }

    last_report_data = generate_report(data)

    output.insert(tk.END, "✔ Scan completed successfully\n")
    output.insert(
        tk.END,
        "✔ Report ready. You can download it in HTML or PDF format.\n\n"
    )

    progress.stop()
    html_btn.pack(pady=4)
    pdf_btn.pack(pady=4)

def download_html():
    path = filedialog.asksaveasfilename(
        defaultextension=".html",
        filetypes=[("HTML files", "*.html")]
    )
    if path:
        shutil.copy(REPORT_HTML, path)
        messagebox.showinfo("Saved", "HTML report downloaded successfully")

def download_pdf():
    if last_report_data:
        generate_pdf(last_report_data)
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")]
        )
        if path:
            shutil.copy("reports/report.pdf", path)
            messagebox.showinfo("Saved", "PDF report downloaded successfully")

# ---------------- GUI ---------------- #

root = tk.Tk()
root.title("Unified Web Security Assessment Tool")
root.geometry("760x560")
root.configure(bg="#121212")

style = ttk.Style()
style.theme_use("default")
style.configure("TProgressbar", background="#00ffcc")

def dark(widget):
    try:
        widget.configure(bg="#121212", fg="#ffffff")
    except:
        pass

tk.Label(root, text="Target URL", font=("Segoe UI", 11, "bold")).pack(pady=6)
dark(root.children[list(root.children)[-1]])

url_entry = tk.Entry(root, width=65, bg="#1e1e1e", fg="#00ffcc", insertbackground="white")
url_entry.pack(pady=4)

tk.Button(
    root, text="Start Full Security Scan",
    command=start_scan,
    bg="#00ffcc", fg="#000", font=("Segoe UI", 10, "bold")
).pack(pady=8)

progress = ttk.Progressbar(root, mode="indeterminate")
progress.pack(fill="x", padx=20, pady=6)

output = tk.Text(
    root, height=16,
    bg="#1e1e1e", fg="#dcdcdc",
    insertbackground="white"
)
output.pack(fill="both", expand=True, padx=10, pady=10)

html_btn = tk.Button(
    root, text="Download HTML Report",
    command=download_html,
    bg="#2ecc71", fg="#000", font=("Segoe UI", 10, "bold")
)

pdf_btn = tk.Button(
    root, text="Download PDF Report",
    command=download_pdf,
    bg="#3498db", fg="#fff", font=("Segoe UI", 10, "bold")
)

root.mainloop()
