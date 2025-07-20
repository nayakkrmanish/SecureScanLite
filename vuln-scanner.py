"""
SecureScanLite v2.0 - Enhanced Web Security Analyzer 🔒

Author: Manish Kumar Nayak
Certified Security Operations Center Analyst
Web Security Trainee at Albus Security, Ludhiana

© 2025 Manish Kumar Nayak. All rights reserved.
"""

import requests
from prettytable import PrettyTable
import socket
import ssl
import re
from colorama import Fore, Style, init

# initial welcoming
init(autoreset=True)

def print_banner():
    print(Fore.CYAN + """
╔════════════════════════════════════════════╗
║              🔍 VULNSCAN                   ║
║        by Manish Kumar Nayak  🔐           ║
╚════════════════════════════════════════════╝
""")

#process begings
def check_https(site_url):
    if site_url.startswith("https://"):
        print("🔒 HTTPS is enabled.\n")
    else:
        print("⚠️ HTTPS is NOT enabled. Use HTTPS for secure communication.\n")

#redirection checking for https and http
def check_redirect_to_https(site_url):
    try:
        if site_url.startswith("http://"):
            https_url = site_url.replace("http://", "https://", 1)
            res = requests.get(site_url, allow_redirects=True)
            if res.url.startswith("https://"):
                print("🔁 Site redirects to HTTPS ✅\n")
            else:
                print("🚫 Site does NOT redirect to HTTPS ❌\n")
    except:
        print("⚠️ Unable to check redirection.\n")

#ssl certificate check
def check_ssl_certificate(site_url):
    hostname = site_url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("📜 SSL certificate is valid ✅\n")
    except Exception as e:
        print(f"❌ SSL certificate check failed: {e}\n")

#header vertification
def check_security_headers(site_url):
    try:
        res = requests.get(site_url)
        headers = res.headers
        table = PrettyTable()
        table.field_names = ["🔐 Security Header", "✅ Present", "📋 Header Value"]

        key_headers = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]

        for header in key_headers:
            if header in headers:
                table.add_row([header, "✅ Yes", headers[header]])
            else:
                table.add_row([header, "❌ No", "🚫 Not Set"])

        print(table, "\n")
    except Exception as err:
        print(f"❌ Error fetching headers: {err}\n")

#cookies security presence
def check_cookies_security(site_url):
    try:
        res = requests.get(site_url)
        cookies = res.cookies
        if not cookies:
            print("🍪 No cookies set by server.\n")
            return
        for cookie in cookies:
            print(f"🍪 Cookie: {cookie.name}")
            if cookie.secure:
                print("   🔒 Secure: Yes")
            else:
                print("   ⚠️ Secure: No (should be enabled)")
            if cookie.has_nonstandard_attr("HttpOnly"):
                print("   🔐 HttpOnly: Yes\n")
            else:
                print("   ⚠️ HttpOnly: No (should be enabled)\n")
    except:
        print("⚠️ Could not analyze cookies.\n")

#presence of any suspicious scripts
def check_suspicious_scripts(site_url):
    try:
        res = requests.get(site_url)
        scripts = re.findall(r'<script[^>]*src=["\']?([^"\'>]+)', res.text, re.IGNORECASE)
        suspicious = [s for s in scripts if "http://" in s or "unknown" in s]
        if suspicious:
            print("🚨 Suspicious external scripts found:")
            for script in suspicious:
                print(f"   ❗ {script}")
            print()
        else:
            print("🧼 No suspicious scripts found.\n")
    except:
        print("⚠️ Could not scan scripts.\n")

#ending
if __name__ == "__main__":
    print_banner()
    url = input("🌐 Enter the website URL (with http:// or https://): ").strip()
    print("\n📊 Starting Security Analysis...\n")

    check_https(url)
    check_redirect_to_https(url)
    check_ssl_certificate(url)
    check_security_headers(url)
    check_cookies_security(url)
    check_suspicious_scripts(url)

    print("✅ Scan Complete! Stay Secure, Stay Smart. 🔐")
