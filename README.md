<div align="center">

# 🛡️ 用户信息管理平台 · 安全加固版

**User Management Platform — Secure Hardened Edition**

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-Hardened-brightgreen)](#-security-fixes-applied)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-ff69b4)](#-contributing)

**A deliberately vulnerable → hardened Flask application for cybersecurity education.**

Compare the original [Class01](http://192.168.145.130:5000/) (vulnerable) against this hardened
version to understand real-world Web security flaws and their mitigations.

**[🔬 Vulnerability Report](VULN_REPORT.md)** ·
**[🚀 Quick Start](#-quick-start)** ·
**[📋 Security Fixes](#-security-fixes-applied)**

</div>

---

## 📋 Table of Contents

- [✨ Overview](#-overview)
- [🚀 Quick Start](#-quick-start)
- [🔐 Default Accounts](#-default-accounts)
- [🛡️ Security Fixes Applied](#️-security-fixes-applied)
- [🌐 API Endpoints](#-api-endpoints)
- [⚙️ Configuration](#️-configuration)
- [📁 Project Structure](#-project-structure)
- [🧪 Testing the Fixes](#-testing-the-fixes)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Overview

This project demonstrates **13 common Web security vulnerabilities** (based on
OWASP Top 10 principles) and their corresponding fixes in a simple Flask user
management application. It is designed as a **hands-on cybersecurity training
tool** — instructors can deploy the vulnerable version for penetration testing
exercises and use the hardened version as the reference solution.

| Aspect | Original (Class01) | Hardened (This Repo) |
|--------|-------------------|---------------------|
| 🔑 Password Storage | Plaintext | pbkdf2:sha256 hashed |
| 🚦 Brute-Force Protection | None | 5 req/min per IP |
| 🔒 Session Security | Minimal | HttpOnly + SameSite + TTL |
| 🛡️ CSRF Protection | None | Flask-WTF |
| 📝 Security Headers | None | 5 headers injected |

---

## 🚀 Quick Start

### Prerequisites

- Python **3.8+**
- `pip` (Python package manager)
- *(Optional)* `virtualenv` for isolated environments

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/chilianzhe1470/Class01repair.git
cd Class01repair

# 2. (Recommended) Create and activate a virtual environment
python -m venv venv
source venv/bin/activate    # Linux / macOS
# venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Run the Application

```bash
# Development mode (debug enabled, detailed error pages)
FLASK_ENV=development python app.py

# Production mode (debug off, security-hardened)
python app.py
```

The server starts at **http://localhost:8080**.

> 💡 **Tip:** Set a custom port with the `PORT` environment variable:
> ```bash
> PORT=9000 python app.py
> ```

---

## 🔐 Default Accounts

| Username | Password | Role      | Email               | Phone       | Balance |
|----------|----------|-----------|---------------------|-------------|---------|
| `admin`  | `admin123` | Admin     | admin@example.com | 13800138000 | 99999   |
| `alice`  | `alice2025`| User      | alice@example.com | 13900139001 | 100     |

> ⚠️ **Demo only.** These credentials are intentionally simple for classroom
> exercises. Never use weak or default passwords in production environments.

---

## 🛡️ Security Fixes Applied

| # | Vulnerability | Severity | Fix | CWE |
|---|--------------|----------|-----|-----|
| 01 | **Plaintext Password Storage** | 🔴 Critical | `werkzeug.security` pbkdf2:sha256 hashing | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) |
| 02 | **Plaintext Password Transmission** | 🔴 Critical | HSTS header + HTTPS enforcement | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| 03 | **Brute-Force Attack Surface** | 🔴 Critical | Flask-Limiter (5 req/min/IP) | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) |
| 04 | **Weak Secret Key** | 🟡 High | `secrets.token_hex(32)` (256-bit) | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) |
| 05 | **Debug Mode Exposure** | 🟡 High | Environment-gated debug mode | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| 06 | **Client-Side Password Leakage** | 🔴 Critical | Stripped from template context | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| 07 | **Hardcoded Credentials in Comments** | 🔴 Critical | Removed | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| 08 | **Session Cookie Misconfiguration** | 🟡 High | HttpOnly + SameSite=Lax + 2 h TTL | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) |
| 09 | **Missing Security Headers** | 🟡 High | 5 security headers injected | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| 10 | **CSRF Vulnerability** | 🟡 High | Flask-WTF token validation | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| 11 | **User Enumeration via Error Messages** | 🟡 High | Uniform "invalid credentials" | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) |
| 12 | **Missing Input Validation** | 🟢 Medium | maxlength + 16 KB body limit | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| 13 | **Timing Side-Channel Attack** | 🟢 Medium | Constant-time comparison via HMAC | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) |

📖 **Detailed analysis of each vulnerability → [VULN_REPORT.md](VULN_REPORT.md)**

---

## 🌐 API Endpoints

| Method | Path       | Description                        | Auth Required | Rate Limited |
|--------|------------|------------------------------------|:-------------:|:------------:|
| GET    | `/`        | Home page (user profile if logged in) | No         | No           |
| GET    | `/login`   | Display login form                 | No            | No           |
| POST   | `/login`   | Authenticate user                  | No            | ✅ 5/min     |
| GET    | `/logout`  | Clear session & redirect to home   | No            | No           |

---

## ⚙️ Configuration

All configuration is handled through **environment variables**:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | Auto-generated (256-bit) | Flask session signing key |
| `FLASK_ENV` | `production` | Set to `development` for debug mode |
| `PORT` | `8080` | Server listening port |
| `HTTPS_ENABLED` | `false` | Set to `true` when behind HTTPS |
| `REDIS_URL` | `memory://` | Storage backend for rate-limiter |

Example `.env` file:

```ini
SECRET_KEY=your-strong-secret-key-here
FLASK_ENV=development
PORT=8080
HTTPS_ENABLED=false
```

---

## 📁 Project Structure

```
Class01repair/
├── app.py                    # Flask application (hardened)
├── requirements.txt          # Python dependencies
├── VULN_REPORT.md            # Full vulnerability analysis report
├── .env.example              # Environment variable template
├── .gitignore
├── LICENSE                   # MIT License
├── README.md                 # This file
├── templates/
│   ├── base.html             # Base layout (nav, container)
│   ├── index.html            # Home page (profile / login prompt)
│   └── login.html            # Login form (CSRF protected)
└── static/
    └── css/
        └── style.css         # Application styles
```

---

## 🧪 Testing the Fixes

### Verify password hashing (not plaintext)

```python
python -c "
from werkzeug.security import check_password_hash
hash = 'pbkdf2:sha256:600000\$...'  # Replace with actual hash from source
print(check_password_hash(hash, 'admin123'))  # True
"
```

### Verify rate limiting

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "Request $i: %{http_code}\n" \
    -X POST -d "username=admin&password=wrong" \
    http://localhost:8080/login
done
# Requests 1-5 should return 200, requests 6+ return 429
```

### Verify security headers

```bash
curl -s -I http://localhost:8080/ | grep -E '^(X-|Strict-|Cache-)'
# Expected: X-Content-Type-Options, X-Frame-Options,
#           X-XSS-Protection, Strict-Transport-Security, Cache-Control
```

---

## 🤝 Contributing

Contributions are welcome! This project is designed for educational purposes,
and improvements — whether fixing bugs, adding new vulnerability demos, or
enhancing documentation — are greatly appreciated.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-idea`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-idea`)
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. See [LICENSE](LICENSE) for more information.

---

<div align="center">

**Made for cybersecurity education** · Built with [Flask](https://flask.palletsprojects.com/)

*This project is intended for legal educational use only. The authors are not
responsible for misuse of the techniques demonstrated herein.*

</div>
