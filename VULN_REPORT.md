# User Management Platform — Vulnerability Analysis & Security Hardening Report

> **Course:** Web Application Security — Vulnerability Discovery & Remediation  
> **Version:** Original (vulnerable) → Hardened (secure)  
> **Objective:** Identify, exploit, and fix common Web security vulnerabilities through
> side-by-side comparison of code patterns.

---

## Table of Contents

1. [Vulnerability Overview](#1-vulnerability-overview)
2. [V-01: Plaintext Password Storage](#2-v-01-plaintext-password-storage)
3. [V-02: Plaintext Password Transmission](#3-v-02-plaintext-password-transmission)
4. [V-03: Unrestricted Brute-Force Attack](#4-v-03-unrestricted-brute-force-attack)
5. [V-04: Weak Session Secret Key](#5-v-04-weak-session-secret-key)
6. [V-05: Debug Mode Information Leakage](#6-v-05-debug-mode-information-leakage)
7. [V-06: Password Leakage in Client-Side Rendering](#7-v-06-password-leakage-in-client-side-rendering)
8. [V-07: Hardcoded Credentials in HTML Comments](#8-v-07-hardcoded-credentials-in-html-comments)
9. [V-08: Session Security Misconfiguration](#9-v-08-session-security-misconfiguration)
10. [V-09: Missing Security Response Headers](#10-v-09-missing-security-response-headers)
11. [V-10: Cross-Site Request Forgery (CSRF)](#11-v-10-cross-site-request-forgery-csrf)
12. [V-11: User Enumeration via Error Messages](#12-v-11-user-enumeration-via-error-messages)
13. [V-12: Missing Input Validation](#13-v-12-missing-input-validation)
14. [V-13: Timing Side-Channel Attack](#13-v-13-timing-side-channel-attack)
15. [Security Development Checklist](#15-security-development-checklist)
16. [Recommended Tools & Resources](#16-recommended-tools--resources)

---

## 1. Vulnerability Overview

| # | Vulnerability | CVSS Severity | CWE Reference | Root Cause | Fix Applied |
|---|--------------|:-------------:|:-------------:|------------|-------------|
| 01 | Plaintext Password Storage | **🔴 Critical** | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Stored passwords as raw strings in source | `werkzeug.security` pbkdf2:sha256 hashing |
| 02 | Plaintext Password Transmission | **🔴 Critical** | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | HTTP without TLS encryption | HSTS header + HTTPS requirement |
| 03 | Unrestricted Brute-Force Attack | **🔴 Critical** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | No rate limiting on `/login` | Flask-Limiter (5 req/min/IP) |
| 04 | Weak Session Secret Key | **🟡 High** | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | Hardcoded `"dev-key-2025"` | `secrets.token_hex(32)` (256-bit) |
| 05 | Debug Mode Leakage | **🟡 High** | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `debug=True` always on | Environment-gated activation |
| 06 | Client-Side Password Leakage | **🔴 Critical** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `password` field in template context | Stripped via `_sanitize_user()` |
| 07 | Hardcoded Credentials in HTML | **🔴 Critical** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | `<!-- admin / admin123 -->` in login.html | Comment removed |
| 08 | Session Cookie Misconfig. | **🟡 High** | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | No HttpOnly / SameSite / expiry | Session config hardened |
| 09 | Missing Security Headers | **🟡 High** | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | No response headers set | 5 headers injected via middleware |
| 10 | CSRF Vulnerability | **🟡 High** | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | No anti-CSRF token | Flask-WTF `csrf_token()` |
| 11 | User Enumeration | **🟡 High** | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | Distinct error messages | Unified "invalid credentials" |
| 12 | Missing Input Validation | **🟢 Medium** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | Unbounded input fields | maxlength + 16 KB body limit |
| 13 | Timing Side-Channel | **🟢 Medium** | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | `==` string comparison | `check_password_hash()` (constant-time) |

---

## 2. V-01: Plaintext Password Storage

**CWE:** [CWE-312 — Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)  
**CVSS 3.1:** 9.1 (Critical) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`  
**OWASP Top 10:** A02:2021 — Cryptographic Failures

### Description

User passwords were stored as **plaintext strings** directly in the application
source code. Any party with read access to the codebase (via source code leak,
Git repository exposure, server file read, or insider threat) could instantly
obtain every user's password in cleartext.

### Attack Scenario

1. Attacker gains read access to `app.py` through any means (misconfigured
   `.git` directory exposed via web, server-side file disclosure vulnerability,
   compromised CI/CD pipeline, or physical access to a developer workstation).
2. Opens the file and immediately reads:
   ```python
   USERS = {
       "admin": {"password": "admin123", ...},
       "alice": {"password": "alice2025", ...},
   }
   ```
3. Uses these credentials to log in as any user — or attempts **credential
   stuffing** on other services where the same passwords may be reused.

### ❌ Vulnerable Code

```python
# app.py (original)
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",  # <-- PLAINTEXT
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",  # <-- PLAINTEXT
    },
}

# Password verification using direct string equality
if USERS[username]["password"] == password:
    session["username"] = username
```

### ✅ Fix

```python
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),  # hashed
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),  # hashed
    },
}

# Verification uses constant-time comparison against the hash
if user and check_password_hash(user["password_hash"], password):
    session["username"] = username
```

### How It Works

`generate_password_hash()` uses the **pbkdf2:sha256** algorithm with a random
salt by default (600,000 iterations in Werkzeug 3.x). The output format is:

```
pbkdf2:sha256:600000$<salt>$<hash>
```

- **Salt** is randomly generated for every call — identical passwords produce
  completely different hashes.
- **Hash** is derived through an intentionally slow, one-way function.
- `check_password_hash()` extracts the salt from the stored hash, re-computes
  it with the candidate password, and compares using **`hmac.compare_digest`**
  (constant-time, preventing timing side-channels).

---

## 3. V-02: Plaintext Password Transmission

**CWE:** [CWE-319 — Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)  
**CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10:** A02:2021 — Cryptographic Failures

### Description

The login form submits credentials over **plain HTTP** without TLS encryption.
An attacker positioned on the same network (Wi-Fi, same LAN, or with access to
an upstream router) can capture the full HTTP request body and recover the
password.

### Attack Scenario

1. Attacker sets up packet capture (e.g., Wireshark, tcpdump, or ARP-spoofs
   the local network).
2. Victim submits the login form → packet capture reveals:
   ```
   POST /login HTTP/1.1
   Host: 192.168.145.130:5000
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=admin123
   ```
3. Attacker now has valid credentials — no decryption needed.

### ❌ Vulnerable Code

No HTTPS configuration is present. The application binds to `0.0.0.0:5000` and
serves all traffic over raw HTTP.

### ✅ Fix

```python
@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response
```

**Additional production recommendations:**

- Deploy behind a reverse proxy (Nginx, Caddy) terminating TLS.
- Use [Let's Encrypt](https://letsencrypt.org/) for free automated certificates.
- Set `SESSION_COOKIE_SECURE = True` so cookies are never sent over HTTP.

---

## 4. V-03: Unrestricted Brute-Force Attack

**CWE:** [CWE-307 — Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)  
**CVSS 3.1:** 7.3 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`  
**OWASP Top 10:** A07:2021 — Identification and Authentication Failures

### Description

The `/login` endpoint imposes **no request rate limit**. An attacker can use
automated tools (Burp Suite Intruder, Hydra, Medusa, or a simple shell script)
to try thousands of passwords per minute until one succeeds.

### Attack Scenario

1. Attacker intercepts a login POST request in Burp Suite.
2. Sends to **Intruder** with a common password wordlist (e.g., `rockyou.txt`).
3. Sets the payload position: `password=§§`.
4. Launches the attack — fires requests as fast as the network allows.
5. Compares response lengths/content to identify the correct password.

**Illustrative Burp Suite configuration:**

```
Target:  POST http://192.168.145.130:5000/login
Payload: rockyou.txt  (14 million passwords, ~50 MB)
Position: username=admin&password=§payload§
```

### ❌ Vulnerable Code

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    # No rate limiting — thousands of attempts per minute
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # ...
```

### ✅ Fix

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    # Exceeding 5 requests per minute from the same IP returns HTTP 429
```

### How It Works

`Flask-Limiter` tracks request counts per **client IP address** (via
`get_remote_address`). Once the limit is reached, subsequent requests receive
a **429 Too Many Requests** response before the view function is ever called.
The `override_defaults=False` parameter ensures the global default limits
(Azure: 200/day, 50/hour) are also respected.

---

## 5. V-04: Weak Session Secret Key

**CWE:** [CWE-330 — Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)  
**CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10:** A02:2021 — Cryptographic Failures

### Description

The Flask application's `secret_key` was hardcoded as `"dev-key-2025"`.
Flask uses this key to **cryptographically sign session cookies** via
`itsdangerous`. A guessable key lets an attacker forge arbitrary session data
and impersonate any user.

### Attack Scenario

1. Attacker obtains the source code (or guesses the weak key).
2. Crafts a forged Flask session cookie:
   ```python
   from itsdangerous import URLSafeTimedSerializer
   s = URLSafeTimedSerializer("dev-key-2025", salt="cookie-session")
   forged = s.dumps({"username": "admin"})
   ```
3. Sets this cookie in their browser → application trusts `session["username"]`
   and displays the admin profile.

### ❌ Vulnerable Code

```python
app.secret_key = "dev-key-2025"
```

### ✅ Fix

```python
import secrets

# Prefer environment variable; generate a strong fallback
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

`secrets.token_hex(32)` produces a **256-bit** cryptographically random string
— practically impossible to guess or brute-force.

---

## 6. V-05: Debug Mode Information Leakage

**CWE:** [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)  
**CVSS 3.1:** 6.2 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`  
**OWASP Top 10:** A05:2021 — Security Misconfiguration

### Description

Flask's built-in Werkzeug debugger (activated by `debug=True`) provides an
**interactive console** that executes arbitrary Python code on the server when
an exception occurs. The debugger also displays the full stack trace with
local variable values, source code snippets, and environment details.

### Attack Scenario

1. Attacker triggers an exception (e.g., visiting a crafted URL that causes
   a server-side error).
2. The debugger page is shown with an interactive Python shell.
3. Attacker uses the shell to execute:
   ```python
   import os; os.environ  # Read environment variables including SECRET_KEY
   open("app.py").read()  # Read source code
   ```
4. Gains access to all secrets and the full codebase.

### ❌ Vulnerable Code

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

### ✅ Fix

```python
# Production: debug=False  (default)
# Development: FLASK_ENV=development python app.py
debug_mode = os.environ.get("FLASK_ENV") == "development"
app.run(debug=debug_mode, host="0.0.0.0", port=8080)
```

**Note:** Werkzeug's debugger **PIN** (`Debugger PIN: xxx-xxx-xxx`) provides
some protection, but the PIN can be reliably computed if an attacker has file
read access — PIN-based security should never be relied upon in production.

---

## 7. V-06: Password Leakage in Client-Side Rendering

**CWE:** [CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)  
**CVSS 3.1:** 7.5 (High) — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10:** A04:2021 — Insecure Design

### Description

After successful login, the server passed the **entire user dictionary** —
including the `password` field — to the template engine. The template then
rendered the password as visible text on the page. Anyone who viewed the page
source or looked at the screen could read the user's password.

### Attack Scenario

1. User logs in as `admin`.
2. The index page renders all user fields, including:
   ```html
   <li><span class="info-label">密码：</span>admin123</li>
   ```
3. A passerby glances at the screen, or a co-worker views the source during
   a screen-share session — the password is leaked.

### ❌ Vulnerable Code

```python
# app.py — passes the full user dict (including password) to template
user_info = USERS[username]
return render_template("index.html", user=user_info)
```

```html
<!-- index.html — renders every field including password -->
<li><span class="info-label">密码：</span>{{ user.password }}</li>
```

### ✅ Fix

```python
# Define public fields — password is deliberately excluded
PUBLIC_FIELDS = frozenset({"username", "role", "email", "phone", "balance"})

def _sanitize_user(user):
    if user is None:
        return None
    return {k: v for k, v in user.items() if k in PUBLIC_FIELDS}
```

```html
<!-- index.html — password field is absent from the template -->
<li><span class="info-label">用户名：</span>{{ user.username }}</li>
<li><span class="info-label">邮箱：</span>{{ user.email }}</li>
<li><span class="info-label">手机：</span>{{ user.phone }}</li>
```

---

## 8. V-07: Hardcoded Credentials in HTML Comments

**CWE:** [CWE-798 — Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)  
**CVSS 3.1:** 8.6 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`  
**OWASP Top 10:** A07:2021 — Identification and Authentication Failures

### Description

The login page's HTML contained a comment that **explicitly revealed the admin
username and password** to anyone who viewed the page source. This is
equivalent to taping the administrator's password to the login screen.

### Attack Scenario

1. Attacker navigates to the login page.
2. Opens browser Developer Tools or uses **View Page Source**.
3. Finds: `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->`
4. Immediately logs in as `admin`.

### ❌ Vulnerable Code

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
{% extends "base.html" %}
```

### ✅ Fix

The comment line is removed. There is no legitimate reason to include
credentials — even in comments — in any deliverable.

---

## 9. V-08: Session Security Misconfiguration

**CWE:** [CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)  
**CVSS 3.1:** 6.1 (Medium) — `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N`  
**OWASP Top 10:** A05:2021 — Security Misconfiguration

### Description

Flask session cookies were created with **default settings** — no `HttpOnly`
flag (accessible via JavaScript → XSS stealing), no `SameSite` attribute
(vulnerable to CSRF), and no explicit expiration time (session could remain
valid indefinitely).

### ❌ Vulnerable Code

```python
# No session configuration — Flask defaults:
#   SESSION_COOKIE_HTTPONLY  = False
#   SESSION_COOKIE_SAMESITE  = None
#   SESSION_COOKIE_SECURE    = False
#   PERMANENT_SESSION_LIFETIME = 31 days
```

### ✅ Fix

```python
from datetime import timedelta

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,           # Not accessible via JS
    SESSION_COOKIE_SAMESITE="Lax",          # Mitigates CSRF
    SESSION_COOKIE_SECURE=False,            # True in production (HTTPS)
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # Session expires
)
```

---

## 10. V-09: Missing Security Response Headers

**CWE:** [CWE-693 — Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)  
**CVSS 3.1:** 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**OWASP Top 10:** A05:2021 — Security Misconfiguration

### Description

The application returned HTTP responses with **no security-related headers**.
Browsers therefore fell back to permissive defaults, making the application
vulnerable to clickjacking, MIME-type confusion attacks, and content caching
of sensitive pages.

### ✅ Fix

```python
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response
```

| Header | Purpose |
|--------|---------|
| `X-Content-Type-Options: nosniff` | Prevents browsers from MIME-type sniffing — forces them to honor the declared `Content-Type`. Mitigates drive-by download attacks. |
| `X-Frame-Options: DENY` | Blocks the page from being rendered in an `<iframe>`, `<frame>`, or `<object>` — prevents clickjacking. |
| `X-XSS-Protection: 1; mode=block` | Enables the browser's built-in reflected XSS filter (legacy, but still beneficial on older browsers). |
| `Strict-Transport-Security: max-age=31536000` | Instructs browsers to _only_ communicate with the server over HTTPS for the next year — prevents SSL-strip attacks. |
| `Cache-Control: no-store` | Prevents browsers and intermediate proxies from caching the response — critical for pages containing session-dependent content. |

---

## 11. V-10: Cross-Site Request Forgery (CSRF)

**CWE:** [CWE-352 — Cross-Site Request Forgery](https://cwe.mitre.org/data/definitions/352.html)  
**CVSS 3.1:** 6.5 (Medium) — `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`  
**OWASP Top 10:** A01:2021 — Broken Access Control

### Description

The login form does not include a CSRF token. An attacker can craft a malicious
page that automatically submits a POST request to the login endpoint from the
victim's browser — and because the request carries the victim's cookies, the
server cannot distinguish it from a legitimate request.

### ❌ Vulnerable Code

```html
<form method="POST" action="/login">
    <!-- No anti-CSRF token -->
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">登录</button>
</form>
```

### ✅ Fix

```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)
```

```html
<form method="POST" action="{{ url_for('login') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <input type="text" name="username" required>
    <input type="password" name="password" required>
    <button type="submit">登录</button>
</form>
```

Flask-WTF generates a unique, cryptographically random token per session,
embedded as a hidden field. On POST, the server validates that the submitted
token matches the one stored in the session — a cross-origin attacker cannot
read or predict this value.

---

## 12. V-11: User Enumeration via Error Messages

**CWE:** [CWE-204 — Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)  
**CVSS 3.1:** 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP Top 10:** A05:2021 — Security Misconfiguration

### Description

Distinguishing between "user not found" and "wrong password" error messages
allows an attacker to **enumerate valid usernames** by iterating through a
list and observing which ones trigger which message. Once valid usernames are
identified, the attacker can focus their brute-force efforts on those accounts.

### ❌ Vulnerable Code

```python
# Example of what distinguishable errors look like:
if username not in USERS:
    return render_template("login.html", error="用户不存在")
else:
    return render_template("login.html", error="密码错误")
```

### ✅ Fix

```python
# Always return the same generic message regardless of which field is wrong.
return render_template("login.html", error="用户名或密码错误")
```

The response is identical whether the username exists or not. An attacker
cannot distinguish the two cases by examining the response body, status code,
or any other observable output.

---

## 13. V-12: Missing Input Validation

**CWE:** [CWE-20 — Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)  
**CVSS 3.1:** 5.3 (Medium) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`  
**OWASP Top 10:** A04:2021 — Insecure Design

### Description

Input fields had **no length restrictions**. An attacker could submit extremely
long strings, potentially causing:
- **Resource exhaustion** (large string processing overhead).
- **Disk/log flooding** (if input is written to audit logs).
- **Memory-based denial of service.**

### ❌ Vulnerable Code

```html
<input type="text" name="username" placeholder="请输入用户名" required>
```

### ✅ Fix

```html
<!-- Client-side constraints -->
<input type="text" name="username" maxlength="50" required>
<input type="password" name="password" minlength="6" required>
```

```python
# Server-side — request body limit
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB
```

---

## 14. V-13: Timing Side-Channel Attack

**CWE:** [CWE-208 — Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)  
**CVSS 3.1:** 3.7 (Low) — `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP Top 10:** A02:2021 — Cryptographic Failures

### Description

Python's `==` operator compares strings **character by character** and returns
immediately on the first mismatch. An attacker can measure the response time
for thousands of candidate passwords — even a **microsecond-scale** difference
can reveal how many characters matched, allowing progressive character-by-
character password inference.

### ❌ Vulnerable Code

```python
# Early-exit on first mismatched character — timing varies by input
USERS[username]["password"] == password
```

### ✅ Fix

```python
check_password_hash(user["password_hash"], password)
```

`check_password_hash()` internally uses **`hmac.compare_digest(a, b)`** —
a constant-time comparison function. The function takes **exactly the same
amount of time** regardless of how many characters match, eliminating the
timing side-channel.

---

## 15. Security Development Checklist

### Code-level checks

- [ ] **Password storage** — Use bcrypt / pbkdf2 / argon2 (never plaintext)
- [ ] **TLS everywhere** — HTTPS for all connections (enforce via HSTS)
- [ ] **Rate limiting** — Throttle authentication endpoints
- [ ] **Secret key** — Use cryptographically random values (≥ 256-bit)
- [ ] **Debug mode** — Disable in production environments
- [ ] **Template context** — Never pass sensitive fields to templates
- [ ] **Hardcoded secrets** — Zero credentials in source code or comments
- [ ] **Session cookies** — HttpOnly + SameSite + Secure + finite TTL
- [ ] **Security headers** — X-Frame-Options, HSTS, CSP, etc.
- [ ] **CSRF protection** — Token-based validation for state-changing requests
- [ ] **Error messages** — Uniform messages to prevent user enumeration
- [ ] **Input validation** — Server-side + client-side length/type constraints
- [ ] **Constant-time comparison** — Use `hmac.compare_digest` for secrets
- [ ] **Payload limits** — Enforce maximum request body size
- [ ] **Logging** — Log auth failures (never log passwords)

### Infrastructure checks

- [ ] **Dependency scanning** — Keep libraries updated (`pip-audit`, Dependabot)
- [ ] **Static analysis** — Run Bandit / Semgrep on every commit
- [ ] **Penetration testing** — Regular security testing of all endpoints

---

## 16. Recommended Tools & Resources

### Security Testing Tools

| Tool | Purpose | Link |
|------|---------|------|
| **Burp Suite** | Web proxy, intercept, intruder (password brute-forcing) | [portswigger.net](https://portswigger.net/burp) |
| **OWASP ZAP** | Automated vulnerability scanning | [owasp.org/zap](https://www.zapproxy.org/) |
| **Wireshark** | Network traffic analysis (password sniffing) | [wireshark.org](https://www.wireshark.org/) |
| **Hydra** | Network login cracker (brute-force) | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) |
| **sqlmap** | Automated SQL injection detection | [sqlmap.org](https://sqlmap.org/) |
| **Nmap** | Network discovery and port scanning | [nmap.org](https://nmap.org/) |
| **Nikto** | Web server scanner | [cirt.net/Nikto2](https://www.cirt.net/Nikto2) |
| **Bandit** | Python security linter (SAST) | [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) |

### Security Standards & References

| Resource | Description | Link |
|----------|-------------|------|
| **OWASP Top 10 (2021)** | Web application security risks | [owasp.org/Top10](https://owasp.org/www-project-top-ten/) |
| **OWASP Cheat Sheet Series** | Developer security reference | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| **CWE** | Common Weakness Enumeration | [cwe.mitre.org](https://cwe.mitre.org/) |
| **SANS 25** | Most dangerous software errors | [sans.org/top25](https://www.sans.org/top25-software-errors/) |

---

> **Disclaimer**  
> This report is intended **exclusively for cybersecurity education and authorized
> penetration testing**. The techniques described herein should only be applied
> to systems you own or have explicit written permission to test. Unauthorized
> access to computer systems is illegal under the Computer Fraud and Abuse Act
> (CFAA) and equivalent laws in other jurisdictions.
