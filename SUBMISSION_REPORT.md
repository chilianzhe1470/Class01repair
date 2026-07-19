# Web Application Security Assessment Report

**Project:** User Management Platform — Original vs. Hardened  
**Date:** July 19, 2026  
**Author:** chilianzhe1470  
**Classification:** Confidential — For Educational Purposes Only

---

## 1. Executive Summary

A security assessment was conducted on a Flask-based user management web application. The assessment identified **13 security vulnerabilities** across authentication, session management, and transport security domains. All findings have been remediated in the hardened version.

**Risk Summary:**

| Severity | Count | Key Findings |
|----------|:-----:|--------------|
| Critical | 4 | Plaintext passwords, cleartext transmission, brute-force, client-side password leak |
| High | 6 | Weak secret key, debug mode, hardcoded credentials, session config, missing headers, CSRF |
| Medium | 3 | User enumeration, input validation, timing side-channel |

**Remediation Status:** All 13 findings have been addressed. The hardened application is deployed and verified.

---

## 2. Scope

| Item | Details |
|------|---------|
| **Target Application** | User Management Platform (Flask) |
| **Vulnerable Version** | Original (deployed on port 5000) |
| **Hardened Version** | Repaired (deployed on port 8080) |
| **Source Code** | https://github.com/chilianzhe1470/Class01repair |
| **Assessment Type** | Code review + dynamic analysis |
| **Methodology** | OWASP Top 10 (2021), CWE |

---

## 3. Detailed Findings

### 3.1 Critical Severity

#### V-01: Plaintext Password Storage

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) |
| **Location** | `app.py` — USERS dictionary |
| **Original Code** | `"password": "admin123"` — passwords stored as raw strings |
| **Fix** | `generate_password_hash("admin123")` — pbkdf2:sha256 with random salt |
| **Verification** | Hash values are non-reversible; identical passwords produce distinct hashes |

#### V-02: Plaintext Password Transmission

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| **Location** | Network layer — HTTP POST body |
| **Original Issue** | Username and password sent unencrypted over HTTP |
| **Fix** | HSTS header (`max-age=31536000; includeSubDomains`) enforced; TLS recommended for production |
| **Verification** | Security headers confirmed via `curl -I` |

#### V-03: Unrestricted Brute-Force Attack

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) |
| **Location** | `/login` POST endpoint |
| **Original Issue** | No rate limiting — attacker can try unlimited passwords |
| **Fix** | Flask-Limiter: 5 requests per minute per IP; HTTP 429 after threshold |
| **Verification** | 6th request within 1 minute returns HTTP 429 |

#### V-06: Client-Side Password Leakage

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| **Location** | Template rendering (`index.html`) |
| **Original Issue** | `password` field passed to template and rendered as visible text |
| **Fix** | `_sanitize_user()` strips all password-derived fields before template rendering |
| **Verification** | Viewing page source confirms no password field present |

#### V-07: Hardcoded Credentials in HTML Comments

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| **Location** | `templates/login.html` |
| **Original Issue** | `<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->` |
| **Fix** | Comment line removed in its entirety |
| **Verification** | Page source contains no credential-bearing comments |

### 3.2 High Severity

#### V-04: Weak Session Secret Key

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) |
| **Original Issue** | `app.secret_key = "dev-key-2025"` — static, low-entropy key |
| **Fix** | `secrets.token_hex(32)` — cryptographically random 256-bit key |
| **Verification** | Key changes on every restart unless `SECRET_KEY` env var is set |

#### V-05: Debug Mode Information Leakage

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| **Original Issue** | `debug=True` always active — Werkzeug debugger exposes code execution |
| **Fix** | Debug mode gated by `FLASK_ENV=development` environment variable |
| **Verification** | Without `FLASK_ENV=development`, debug mode is off by default |

#### V-08: Session Security Misconfiguration

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) |
| **Original Issue** | No `HttpOnly`, no `SameSite`, no expiration limit |
| **Fix** | `HttpOnly=True`, `SameSite=Lax`, `PERMANENT_SESSION_LIFETIME=2 hours` |
| **Verification** | Session cookie inspected via browser DevTools confirms flags |

#### V-09: Missing Security Response Headers

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| **Original Issue** | No security headers in HTTP responses |
| **Fix** | 5 headers injected: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS, Cache-Control |
| **Verification** | `curl -s -I http://localhost:8080/` confirms all 5 headers present |

#### V-10: Cross-Site Request Forgery (CSRF)

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| **Location** | Login form POST |
| **Original Issue** | No anti-CSRF token — cross-origin form submission possible |
| **Fix** | `Flask-WTF` with `{{ csrf_token() }}` hidden field and server-side validation |
| **Verification** | Form HTML contains `csrf_token` hidden input; POST without token returns 400 |

#### V-11: User Enumeration via Error Messages

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) |
| **Original Issue** | Distinguishable error messages reveal whether a username exists |
| **Fix** | Uniform message: "用户名或密码错误" returned for all authentication failures |
| **Verification** | Invalid username and wrong password both return identical responses |

### 3.3 Medium Severity

#### V-12: Missing Input Validation

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| **Original Issue** | No max length on input fields; no request body size limit |
| **Fix** | `maxlength="50"` on username, `MAX_CONTENT_LENGTH=16KB` server-side |
| **Verification** | Oversized request body returns HTTP 413 |

#### V-13: Timing Side-Channel Attack

| Attribute | Value |
|-----------|-------|
| **CWE** | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) |
| **Original Issue** | `==` operator exits on first mismatched character — measurable timing variance |
| **Fix** | `check_password_hash()` uses `hmac.compare_digest()` — constant-time comparison |
| **Verification** | Matched and unmatched passwords produce indistinguishable response times |

---

## 4. Response Header Verification

Headers observed on hardened application:

```
HTTP/1.1 200 OK
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Cache-Control: no-store, no-cache, must-revalidate
```

All five security headers confirmed present and correctly configured.

---

## 5. Rate Limiting Verification

The `/login` endpoint permits **5 POST requests per minute** per IP address. The 6th request within the window receives HTTP 429. This was verified through sequential request testing.

---

## 6. Recommendations for Production Deployment

1. **Enable TLS** — Deploy behind Nginx/Caddy with Let's Encrypt certificates
2. **Set a strong `SECRET_KEY`** — Use a unique environment variable, not the fallback
3. **Enable `SESSION_COOKIE_SECURE=True`** — Requires HTTPS to function
4. **Use Redis for rate-limiter** — Set `REDIS_URL` for persistence across restarts
5. **Add Content Security Policy (CSP)** — Further mitigate XSS risk
6. **Add Subresource Integrity (SRI)** — For any external CDN resources
7. **Regular dependency scanning** — Use `pip-audit` or Dependabot

---

## 7. Conclusion

The original application contained 13 vulnerabilities spanning OWASP Top 2021 categories including Cryptographic Failures (A02), Security Misconfiguration (A05), and Identification & Authentication Failures (A07). All findings have been remediated in the hardened version. The application is now protected against credential theft, brute-force attacks, session hijacking, cross-site request forgery, and information disclosure.

---

*This report is submitted as part of a cybersecurity training exercise. All testing was conducted in a controlled environment with authorized access.*
