
# 🔐 SecureScanLite

**A lightweight Python-based web security analyzer for quick HTTPS, header, SSL, and cookie audits.**

> 🛠️ Built with ❤️ by **Manish Kumar Nayak**  
> 🎓 Developed as part of the **Summer Internship Training Program at CipherSchools**

---

## 🧠 About the Project

**SecureScanLite** is a command-line utility designed to help security analysts, bug bounty hunters, and developers perform **basic web security hygiene checks** on any website. It focuses on analyzing critical security features like:

- HTTPS enforcement  
- SSL certificate validity  
- HTTP security headers  
- Cookie flags  
- Suspicious external scripts

Built entirely in **Python**, this tool simplifies routine security assessments without relying on bulky scanners — making it **portable, fast, and beginner-friendly**. 

---

## 🚀 Features

🔒 **HTTPS Check** – Detects if the site is using secure protocol  
🔁 **HTTP to HTTPS Redirection** – Checks if non-secure URLs redirect to HTTPS  
📜 **SSL Certificate Validation** – Verifies certificate presence and trust  
🛡️ **Security Headers Scan** – Reports if essential HTTP response headers are set  
🍪 **Cookie Security Flags** – Scans for `Secure` and `HttpOnly` flags  
🧼 **Suspicious Script Detection** – Flags potentially malicious external scripts

---

## 📌 Technologies Used

- Python 3.x
- [`requests`](https://pypi.org/project/requests/)
- [`prettytable`](https://pypi.org/project/prettytable/)
- [`colorama`](https://pypi.org/project/colorama/)
- Standard libraries: `ssl`, `socket`, `re`

---

## 🖥️ Demo Screenshot<img width="816" height="713" alt="image" src="https://github.com/user-attachments/assets/e6446e5d-0174-4228-a22c-e48a5c37cd3a" />


```
╔════════════════════════════════════════════╗
║                🔍  CHECK                    ║
║       Web Security Scanner Utility          ║
║      by Manish Kumar Nayak 🔐              ║
║ Certified SOC Analyst | Albus Security      ║
╚════════════════════════════════════════════╝

🌐 Enter the website URL (with http:// or https://): https://example.com

📊 Starting Security Analysis...

🔒 HTTPS is enabled.
🔁 Site redirects to HTTPS ✅
📜 SSL certificate is valid ✅

+---------------------------+---------+-------------------------------+
| 🔐 Security Header        | ✅ Present | 📋 Header Value               |
+---------------------------+---------+-------------------------------+
| Content-Security-Policy   | ✅ Yes  | default-src 'self'             |
| X-Frame-Options           | ❌ No   | 🚫 Not Set                     |
| ...                       |         |                               |
+---------------------------+---------+-------------------------------+

🍪 Cookie: sessionid
   🔒 Secure: Yes
   🔐 HttpOnly: Yes

✅ Scan Complete! Stay Secure, Stay Smart. 🔐
```

---

## ⚙️ Installation

### 🐍 Python Requirements
Make sure you have **Python 3.x** installed. Then install dependencies:

```bash
pip install requests prettytable colorama
```

---

## ▶️ How to Run

```bash
python check.py
```

📥 Enter the full website URL (include `http://` or `https://`) when prompted.

---

## 📚 Use Cases

- Quick security posture checks during penetration tests  
- Intern-level SOC analyst practice  
- Validate headers after web deployments  
- Educational demo in cybersecurity classes/workshops  
- Portfolio project for resumes or GitHub

---

## 👨‍💻 Author Info

**👤 Manish Kumar Nayak**  
Certified Security Operations Center Analyst  
Web Security Trainee at **Albus Security**, Ludhiana  

📬 Email: *secops.manish@gmail.com*  
🔗 LinkedIn: *https://www.linkedin.com/in/nayakkrmanish/*

---

## 🎓 Internship Acknowledgment

> 🧑‍🎓 This project was developed as a part of the  
> **Summer Internship Training Program at CipherSchools (2025)**  
> under the mentorship and guidance of cybersecurity professionals.

---

## 🏷️ GitHub Tags

```
python  web-security  headers  ssl  soc-analyst  bugbounty  vulnerability  internship-project  cipher-schools
```

---

## 📄 License

```
© 2025 Manish Kumar Nayak. All rights reserved.
This tool is intended for educational and ethical testing purposes only.
```
