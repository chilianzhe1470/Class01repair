# 用户管理平台 — 漏洞分析与安全加固报告

> **课程名称：** Web 应用安全 — 漏洞发现与修复  
> **版本对比：** 原始漏洞版 → 安全加固版  
> **报告目标：** 通过代码对比，识别并修复常见的 Web 安全漏洞

---

## 目录

1. [漏洞总览](#1-漏洞总览)
2. [V-01：明文密码存储](#2-v-01明文密码存储)
3. [V-02：明文密码传输](#3-v-02明文密码传输)
4. [V-03：暴力破解无限制](#4-v-03暴力破解无限制)
5. [V-04：弱会话密钥](#5-v-04弱会话密钥)
6. [V-05：调试模式信息泄露](#6-v-05调试模式信息泄露)
7. [V-06：前端页面泄露密码](#7-v-06前端页面泄露密码)
8. [V-07：HTML 注释泄露凭据](#8-v-07html-注释泄露凭据)
9. [V-08：会话安全配置缺失](#9-v-08会话安全配置缺失)
10. [V-09：安全响应头缺失](#10-v-09安全响应头缺失)
11. [V-10：跨站请求伪造](#11-v-10跨站请求伪造)
12. [V-11：登录错误枚举用户](#12-v-11登录错误枚举用户)
13. [V-12：输入校验缺失](#13-v-12输入校验缺失)
14. [V-13：时序侧信道攻击](#13-v-13时序侧信道攻击)
15. [V-14：注册功能 SQL 注入](#14-v-14注册功能-sql-注入)
16. [V-15：搜索功能 SQL 注入](#15-v-15搜索功能-sql-注入)
17. [安全开发检查清单](#17-安全开发检查清单)
18. [推荐工具与资源](#18-推荐工具与资源)

---

## 1. 漏洞总览

| # | 漏洞名称 | 严重程度 | CWE 编号 | 根因 | 修复方案 |
|---|---------|:--------:|:--------:|------|---------|
| 01 | 明文密码存储 | 🔴 严重 | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | 密码以原始字符串存储在源码中 | `werkzeug.security` pbkdf2:sha256 哈希 |
| 02 | 明文密码传输 | 🔴 严重 | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | 无 TLS 加密的 HTTP 传输 | HSTS 响应头 + 强制 HTTPS |
| 03 | 暴力破解无限制 | 🔴 严重 | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) | `/login` 接口无频率限制 | Flask-Limiter（每 IP 每分钟 5 次） |
| 04 | 弱会话密钥 | 🟡 高危 | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) | 硬编码 `"dev-key-2025"` | `secrets.token_hex(32)`（256 位） |
| 05 | 调试模式泄露 | 🟡 高危 | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | `debug=True` 始终开启 | 环境变量控制开关 |
| 06 | 前端展示密码 | 🔴 严重 | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | `password` 字段传递到模板 | 通过 `_sanitize_user()` 剥离敏感字段 |
| 07 | 注释泄露凭据 | 🔴 严重 | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | HTML 注释包含 `admin / admin123` | 移除注释行 |
| 08 | 会话配置缺失 | 🟡 高危 | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | 无 HttpOnly / SameSite / 过期时间 | 加固会话配置 |
| 09 | 安全头缺失 | 🟡 高危 | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | 未设置任何安全响应头 | 中间件注入 5 项安全头 |
| 10 | CSRF 漏洞 | 🟡 高危 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | 无防跨站请求伪造令牌 | Flask-WTF `csrf_token()` |
| 11 | 用户枚举 | 🟡 高危 | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | 错误信息可区分用户是否存在 | 统一返回"用户名或密码错误" |
| 12 | 输入校验缺失 | 🟢 中危 | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | 输入框无长度限制 | maxlength + 16 KB 请求体限制 |
| 13 | 时序攻击 | 🟢 中危 | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) | 使用 `==` 逐字符比较字符串 | `check_password_hash()` 常量时间比较 |
| **14** | **注册 SQL 注入** | 🔴 严重 | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | f-string 拼接 SQL INSERT 语句 | 参数化查询（`?` 占位符） |
| **15** | **搜索 SQL 注入** | 🔴 严重 | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | f-string 拼接 SQL SELECT 语句 | 参数化查询（`?` 占位符） |
| **16** | **文件上传 RCE** | 🔴 严重 | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | 无文件类型校验 | 扩展名白名单仅允许图片 |
| **17** | **路径遍历** | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | 使用原始文件名 | UUID 重命名 |
| **18** | **存储型 XSS** | 🟡 高危 | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | 可上传 HTML/SVG 文件 | 仅允许图片格式 |
| **19** | **越权访问个人中心** | 🔴 严重 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | user_id 从 URL 参数获取 | 从 session 获取，强制登录 |
| **20** | **越权充值** | 🔴 严重 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | user_id 从表单获取，无金额校验 | 从 session 获取，金额>0 |
| **21** | **路径遍历读取源码** | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | 未校验 name 参数，直接拼接路径 | 白名单+路径规范化 |
| **22** | **路径遍历读取系统文件** | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | 无 ../ 过滤，可读取任意文件 | 前缀检查拒绝越界路径 |

---

## 2. V-01：明文密码存储

**CWE：** [CWE-312 — 敏感信息明文存储](https://cwe.mitre.org/data/definitions/312.html)  
**CVSS 3.1：** 9.1（严重）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`  
**OWASP Top 10：** A02:2021 — 密码学失败

### 漏洞描述

用户密码以**明文**形式直接存储在 `USERS` 字典中。任何获得代码读取权限的人（通过源码泄露、Git 仓库暴露、服务器文件读取等）都能立即获取所有用户的密码。

### 攻击场景

1. 攻击者通过任意手段（配置不当的 `.git` 目录暴露、文件包含漏洞、CI/CD 泄露等）读取 `app.py`
2. 直接看到所有用户的明文密码：
   ```python
   USERS = {
       "admin": {"password": "admin123", ...},
       "alice": {"password": "alice2025", ...},
   }
   ```
3. 使用获取的凭据登录系统，或在其他平台进行撞库攻击

### ❌ 漏洞代码

```python
# app.py（原始版本）
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",  # <-- 明文
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",  # <-- 明文
    },
}

# 使用直接字符串相等性验证密码
if USERS[username]["password"] == password:
    session["username"] = username
```

### ✅ 修复方案

```python
from werkzeug.security import generate_password_hash, check_password_hash

USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),  # 已哈希
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),  # 已哈希
    },
}

# 使用常量时间比较验证哈希
if user and check_password_hash(user["password_hash"], password):
    session["username"] = username
```

### 原理说明

`generate_password_hash()` 默认使用 **pbkdf2:sha256** 算法，每次调用生成随机盐值（Werkzeug 3.x 迭代 600,000 次）。输出格式为：

```
pbkdf2:sha256:600000$<盐值>$<哈希>
```

- **盐值**：每次调用随机生成，相同密码产生完全不同的哈希值
- **哈希**：通过刻意缓慢的单向函数推导得出
- **验证**：`check_password_hash()` 从存储的哈希中提取盐值，重新计算后通过 **`hmac.compare_digest`** 进行常量时间比较

---

## 3. V-02：明文密码传输

**CWE：** [CWE-319 — 敏感信息明文传输](https://cwe.mitre.org/data/definitions/319.html)  
**CVSS 3.1：** 7.5（高危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10：** A02:2021 — 密码学失败

### 漏洞描述

登录表单通过**明文 HTTP** 提交，密码在网络中未经加密传输。位于同一网络的攻击者（Wi-Fi、同一 LAN 或上游路由器）可以捕获 HTTP 请求体，直接获取密码。

### 攻击场景

1. 攻击者在同一网络设置抓包（Wireshark、tcpdump 或 ARP 欺骗）
2. 受害者提交登录表单 → 抓包结果：
   ```
   POST /login HTTP/1.1
   Host: 192.168.145.130:5000
   Content-Type: application/x-www-form-urlencoded

   username=admin&password=admin123
   ```
3. 攻击者直接获得有效凭据，无需解密

### ❌ 漏洞代码

应用未配置 HTTPS，所有流量通过裸 HTTP 传输。

### ✅ 修复方案

```python
@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response
```

**生产环境建议：**

- 部署反向代理（Nginx、Caddy）终止 TLS
- 使用 [Let's Encrypt](https://letsencrypt.org/) 获取免费证书
- 设置 `SESSION_COOKIE_SECURE = True`，确保 Cookie 不通过 HTTP 发送

---

## 4. V-03：暴力破解无限制

**CWE：** [CWE-307 — 认证尝试次数限制不当](https://cwe.mitre.org/data/definitions/307.html)  
**CVSS 3.1：** 7.3（高危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L`  
**OWASP Top 10：** A07:2021 — 身份认证与授权失败

### 漏洞描述

`/login` 接口**无任何请求频率限制**。攻击者可利用自动化工具（Burp Suite Intruder、Hydra、Medusa 或简单脚本）每分钟尝试数千个密码。

### 攻击场景

1. 攻击者在 Burp Suite 中截获登录 POST 请求
2. 发送到 **Intruder**，加载常见密码字典（如 `rockyou.txt`）
3. 设置 Payload 位置：`password=§§`
4. 发起攻击——以网络允许的最快速度发送请求
5. 对比响应长度/内容，识别正确密码

**Burp Suite 配置示例：**

```
Target:  POST http://192.168.145.130:5000/login
Payload: rockyou.txt（约 1400 万条密码，~50 MB）
Position: username=admin&password=§payload§
```

### ❌ 漏洞代码

```python
@app.route("/login", methods=["GET", "POST"])
def login():
    # 无速率限制 —— 每分钟可尝试数千次
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # ...
```

### ✅ 修复方案

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    # 同一 IP 每分钟超过 5 次请求返回 HTTP 429
```

### 原理说明

`Flask-Limiter` 基于**客户端 IP 地址**（通过 `get_remote_address`）跟踪请求计数。达到限制后，后续请求在进入视图函数前直接返回 **429 Too Many Requests**。

---

## 5. V-04：弱会话密钥

**CWE：** [CWE-330 — 使用不充分的随机值](https://cwe.mitre.org/data/definitions/330.html)  
**CVSS 3.1：** 7.5（高危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10：** A02:2021 — 密码学失败

### 漏洞描述

Flask 应用的 `secret_key` 被硬编码为 `"dev-key-2025"`。Flask 使用该密钥通过 `itsdangerous` 对会话 Cookie 进行**加密签名**。可猜测的密钥使攻击者能够伪造任意会话数据，冒充任何用户。

### 攻击场景

1. 攻击者获取源代码（或猜出弱密钥）
2. 构造伪造的 Flask 会话 Cookie：
   ```python
   from itsdangerous import URLSafeTimedSerializer
   s = URLSafeTimedSerializer("dev-key-2025", salt="cookie-session")
   forged = s.dumps({"username": "admin"})
   ```
3. 在浏览器中设置此 Cookie → 应用信任 `session["username"]`，显示管理员页面

### ❌ 漏洞代码

```python
app.secret_key = "dev-key-2025"
```

### ✅ 修复方案

```python
import secrets

# 优先使用环境变量，否则生成强随机备用密钥
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

`secrets.token_hex(32)` 产生 **256 位**密码学安全随机字符串，几乎不可猜测或暴力破解。

---

## 6. V-05：调试模式信息泄露

**CWE：** [CWE-489 — 调试代码处于活动状态](https://cwe.mitre.org/data/definitions/489.html)  
**CVSS 3.1：** 6.2（中危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`  
**OWASP Top 10：** A05:2021 — 安全配置错误

### 漏洞描述

Flask 的 Werkzeug 调试器（由 `debug=True` 激活）在发生异常时提供**交互式控制台**，可执行任意 Python 代码。调试器还显示完整调用栈、局部变量值、源码片段及环境信息。

### 攻击场景

1. 攻击者触发异常（例如访问精心构造的 URL 导致服务端错误）
2. 调试器页面显示交互式 Python Shell
3. 攻击者在 Shell 中执行：
   ```python
   import os; os.environ  # 读取环境变量，包括 SECRET_KEY
   open("app.py").read()  # 读取源码
   ```
4. 获取所有密钥和完整代码库

### ❌ 漏洞代码

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

### ✅ 修复方案

```python
# 生产环境：debug=False（默认）
# 开发环境：FLASK_ENV=development python app.py
debug_mode = os.environ.get("FLASK_ENV") == "development"
app.run(debug=debug_mode, host="0.0.0.0", port=8080)
```

**注意：** Werkzeug 调试器的 **PIN 码**（`Debugger PIN: xxx-xxx-xxx`）提供一定保护，但如果攻击者拥有文件读取权限，PIN 可以被可靠计算——生产中绝不能依赖 PIN 安全性。

---

## 7. V-06：前端页面泄露密码

**CWE：** [CWE-200 — 敏感信息泄露](https://cwe.mitre.org/data/definitions/200.html)  
**CVSS 3.1：** 7.5（高危）— `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10：** A04:2021 — 不安全设计

### 漏洞描述

登录成功后，服务端将**完整的用户字典**（包括 `password` 字段）传递给模板引擎。模板将密码渲染为页面上的可见文字。任何查看页面源码或看到屏幕的人都能读取用户的密码。

### 攻击场景

1. 用户以 `admin` 身份登录
2. 首页渲染所有用户字段，包括：
   ```html
   <li><span class="info-label">密码：</span>admin123</li>
   ```
3. 路过者看到屏幕，或同事在屏幕共享时查看源码 —— 密码泄露

### ❌ 漏洞代码

```python
# app.py —— 将完整用户字典（含密码）传递给模板
user_info = USERS[username]
return render_template("index.html", user=user_info)
```

```html
<!-- index.html —— 渲染包括密码在内的所有字段 -->
<li><span class="info-label">密码：</span>{{ user.password }}</li>
```

### ✅ 修复方案

```python
# 定义公开字段 —— password 被刻意排除
PUBLIC_FIELDS = frozenset({"username", "role", "email", "phone", "balance"})

def _sanitize_user(user):
    if user is None:
        return None
    return {k: v for k, v in user.items() if k in PUBLIC_FIELDS}
```

```html
<!-- index.html —— 密码字段已从模板中移除 -->
<li><span class="info-label">用户名：</span>{{ user.username }}</li>
<li><span class="info-label">邮箱：</span>{{ user.email }}</li>
<li><span class="info-label">手机：</span>{{ user.phone }}</li>
```

---

## 8. V-07：HTML 注释泄露凭据

**CWE：** [CWE-798 — 使用硬编码凭据](https://cwe.mitre.org/data/definitions/798.html)  
**CVSS 3.1：** 8.6（高危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L`  
**OWASP Top 10：** A07:2021 — 身份认证与授权失败

### 漏洞描述

登录页面的 HTML 中包含一条注释，**明确写出了管理员用户名和密码**，任何查看页面源代码的人都能看到。

### 攻击场景

1. 攻击者访问登录页面
2. 打开浏览器开发者工具或查看页面源代码
3. 发现：`<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->`
4. 立即以 `admin` 身份登录

### ❌ 漏洞代码

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
{% extends "base.html" %}
```

### ✅ 修复方案

直接移除该注释行。在任何交付物中都没有合理理由包含凭据——即使在注释中也不行。

---

## 9. V-08：会话安全配置缺失

**CWE：** [CWE-1004 — 缺少 HttpOnly 标志的敏感 Cookie](https://cwe.mitre.org/data/definitions/1004.html)  
**CVSS 3.1：** 6.1（中危）— `AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N`  
**OWASP Top 10：** A05:2021 — 安全配置错误

### 漏洞描述

Flask 会话 Cookie 使用**默认设置**——无 `HttpOnly` 标志（可通过 JavaScript 访问 → XSS 窃取），无 `SameSite` 属性（易受 CSRF 攻击），无明确过期时间（会话可能无限期有效）。

### ❌ 漏洞代码

```python
# 无会话配置 —— Flask 默认值：
#   SESSION_COOKIE_HTTPONLY  = False
#   SESSION_COOKIE_SAMESITE  = None
#   SESSION_COOKIE_SECURE    = False
#   PERMANENT_SESSION_LIFETIME = 31 天
```

### ✅ 修复方案

```python
from datetime import timedelta

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,           # 不可通过 JS 访问
    SESSION_COOKIE_SAMESITE="Lax",          # 缓解 CSRF
    SESSION_COOKIE_SECURE=False,            # 生产环境置为 True（需 HTTPS）
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),  # 2 小时过期
)
```

---

## 10. V-09：安全响应头缺失

**CWE：** [CWE-693 — 防护机制失效](https://cwe.mitre.org/data/definitions/693.html)  
**CVSS 3.1：** 5.3（中危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`  
**OWASP Top 10：** A05:2021 — 安全配置错误

### 漏洞描述

应用返回的 HTTP 响应中**未设置任何安全相关头部**。浏览器因此采用宽松的默认行为，使应用易受点击劫持、MIME 类型混淆攻击以及敏感页面缓存。

### ✅ 修复方案

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

| 响应头 | 作用 |
|--------|------|
| `X-Content-Type-Options: nosniff` | 阻止浏览器进行 MIME 类型嗅探，强制使用声明的 `Content-Type` |
| `X-Frame-Options: DENY` | 禁止页面在 `<iframe>`、`<frame>` 或 `<object>` 中渲染——防止点击劫持 |
| `X-XSS-Protection: 1; mode=block` | 启用浏览器内置反射型 XSS 过滤器 |
| `Strict-Transport-Security: max-age=31536000` | 指示浏览器在接下来一年内仅通过 HTTPS 通信——防止 SSL-strip 攻击 |
| `Cache-Control: no-store` | 阻止浏览器和代理缓存响应——对包含会话依赖内容的页面至关重要 |

---

## 11. V-10：跨站请求伪造

**CWE：** [CWE-352 — 跨站请求伪造](https://cwe.mitre.org/data/definitions/352.html)  
**CVSS 3.1：** 6.5（中危）— `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N`  
**OWASP Top 10：** A01:2021 — 越权控制

### 漏洞描述

登录表单未包含 CSRF 令牌。攻击者可以构造恶意页面，自动从受害者浏览器向登录端点提交 POST 请求——由于请求携带受害者的 Cookie，服务端无法将其与合法请求区分。

### ❌ 漏洞代码

```html
<form method="POST" action="/login">
    <!-- 无防 CSRF 令牌 -->
    <input type="text" name="username">
    <input type="password" name="password">
    <button type="submit">登录</button>
</form>
```

### ✅ 修复方案

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

Flask-WTF 为每个会话生成唯一的密码学安全令牌，嵌入为隐藏字段。POST 请求时，服务端验证提交的令牌与会话中存储的是否匹配——跨源攻击者无法读取或预测此值。

---

## 12. V-11：登录错误枚举用户

**CWE：** [CWE-204 — 可观察的响应差异](https://cwe.mitre.org/data/definitions/204.html)  
**CVSS 3.1：** 5.3（中危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP Top 10：** A05:2021 — 安全配置错误

### 漏洞描述

如果"用户不存在"和"密码错误"返回不同的错误信息，攻击者可以通过遍历用户名列表并观察哪些触发哪种信息来**枚举有效用户名**。一旦确认有效用户名，攻击者可集中爆破目标账号。

### ❌ 漏洞代码

```python
# 可区分错误信息的示例：
if username not in USERS:
    return render_template("login.html", error="用户不存在")
else:
    return render_template("login.html", error="密码错误")
```

### ✅ 修复方案

```python
# 无论哪个字段错误，始终返回相同通用信息
return render_template("login.html", error="用户名或密码错误")
```

无论用户名是否存在，响应内容完全相同。攻击者无法通过检查响应体、状态码或任何其他可观察输出区分两种情况。

---

## 13. V-12：输入校验缺失

**CWE：** [CWE-20 — 输入验证不当](https://cwe.mitre.org/data/definitions/20.html)  
**CVSS 3.1：** 5.3（中危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`  
**OWASP Top 10：** A04:2021 — 不安全设计

### 漏洞描述

输入框**无长度限制**。攻击者可提交超长字符串，可能导致：
- **资源耗尽**（处理超长字符串的开销）
- **日志填满**（如果输入被写入审计日志）
- **内存拒绝服务**

### ❌ 漏洞代码

```html
<input type="text" name="username" placeholder="请输入用户名" required>
```

### ✅ 修复方案

```html
<!-- 客户端限制 -->
<input type="text" name="username" maxlength="50" required>
<input type="password" name="password" minlength="6" required>
```

```python
# 服务端 —— 请求体限制
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB
```

---

## 14. V-13：时序侧信道攻击

**CWE：** [CWE-208 — 可观察的时序差异](https://cwe.mitre.org/data/definitions/208.html)  
**CVSS 3.1：** 3.7（低危）— `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N`  
**OWASP Top 10：** A02:2021 — 密码学失败

### 漏洞描述

Python 的 `==` 运算符**逐字符**比较字符串，在第一个不匹配处立即返回。攻击者可以测量数千个候选密码的响应时间——即使**微秒级**的差异也能揭示匹配了多少字符，从而逐字符推断密码。

### ❌ 漏洞代码

```python
# 第一个不匹配字符处提前返回 —— 响应时间因输入而异
USERS[username]["password"] == password
```

### ✅ 修复方案

```python
check_password_hash(user["password_hash"], password)
```

`check_password_hash()` 内部使用 **`hmac.compare_digest(a, b)`**——常量时间比较函数。无论匹配多少个字符，该函数耗时**完全相同**，消除了时序侧信道。

---

## 14. V-14：注册功能 SQL 注入

**CWE：** [CWE-89 — SQL 注入](https://cwe.mitre.org/data/definitions/89.html)  
**CVSS 3.1：** 9.8（严重）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`  
**OWASP Top 10：** A03:2021 — 注入

### 漏洞描述

注册功能使用 **f-string 字符串拼接**构建 SQL INSERT 语句，未对用户输入做任何过滤或转义。攻击者可在输入框中嵌入恶意 SQL 代码，实现任意 SQL 语句执行。

### 攻击场景

攻击者在手机号字段中注入恶意 SQL：
```
'); DELETE FROM users; --
```
拼接后的 SQL 语句变为：
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'test123', 'hacker@hack.com', ''); DELETE FROM users; --')
```
这将导致 **users 表中所有数据被删除**。

### ❌ 漏洞代码

```python
# app.py（原始版本）
sql = (
    f"INSERT INTO users (username, password, email, phone) "
    f"VALUES ('{username}', '{password}', '{email}', '{phone}')"
)
conn.execute(sql)
```

### ✅ 修复方案

```python
# 使用参数化查询 —— 用户输入仅作为数据传递，不会改变 SQL 语义
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
conn.execute(sql, (username, password, email, phone))
```

### 验证结果

| 测试项 | 结果 |
|--------|------|
| 正常注册 | ✅ 成功（HTTP 302） |
| 注入 `' OR '1'='1` | ✅ 被拦截，插入为字面值 |
| 注入 `'); DELETE FROM users;--` | ✅ 被拦截（CSRF 校验先拒绝，参数化后SQL安全） |

---

## 15. V-15：搜索功能 SQL 注入

**CWE：** [CWE-89 — SQL 注入](https://cwe.mitre.org/data/definitions/89.html)  
**CVSS 3.1：** 7.5（高危）— `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**OWASP Top 10：** A03:2021 — 注入

### 漏洞描述

搜索功能使用 **f-string 字符串拼接**构建 SQL 查询语句，攻击者可通过精心构造的关键词参数执行恶意 SQL，读取数据库中的敏感数据（包括其他用户的密码）。

### 攻击场景

攻击者在搜索框中输入 UNION 注入语句：
```
' UNION SELECT id, username, password, phone FROM users --
```
拼接后的 SQL 语句变为：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
  OR email LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
```
该查询将**返回所有用户的密码字段**，导致全部凭据泄露。

### 实测结果

攻击前使用 UNION 注入成功获取到密码：
```
共找到 4 条结果
ID: 1, 用户名: admin, 密码: admin123    ← 密码泄露
ID: 2, 用户名: alice, 密码: alice2025    ← 密码泄露
```

### ❌ 漏洞代码

```python
# app.py（原始版本）
sql = (
    f"SELECT id, username, email, phone FROM users "
    f"WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
)
conn.execute(sql)
```

### ✅ 修复方案

```python
# 使用参数化查询 —— keyword 仅作为 LIKE 模式的参数传递
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
like_pattern = f"%{keyword}%"
conn.execute(sql, (like_pattern, like_pattern))
```

### 验证结果

| 测试项 | 结果 |
|--------|------|
| 正常搜索 `admin` | ✅ 返回 1 条结果 |
| 注入 `' UNION SELECT ...` | ✅ 返回 0 条结果，密码未泄露 |
| 注入 `' OR '1'='1` | ✅ 返回 0 条结果（字面匹配） |

---

## 17. 安全开发检查清单

### 代码层面

- [ ] **密码存储** — 使用 bcrypt / pbkdf2 / argon2（杜绝明文）
- [ ] **全站 TLS** — 所有连接使用 HTTPS（通过 HSTS 强制执行）
- [ ] **速率限制** — 对认证端点进行限流
- [ ] **密钥强度** — 使用密码学安全随机值（≥ 256 位）
- [ ] **调试模式** — 生产环境关闭
- [ ] **模板上下文** — 绝不将敏感字段传递给模板
- [ ] **硬编码密钥** — 源码和注释中零凭据
- [ ] **会话 Cookie** — HttpOnly + SameSite + Secure + 有限时效
- [ ] **安全响应头** — X-Frame-Options、HSTS、CSP 等
- [ ] **CSRF 防护** — 状态变更请求需令牌验证
- [ ] **错误信息** — 统一提示，防止用户枚举
- [ ] **输入验证** — 服务端 + 客户端的长度/类型限制
- [ ] **常量时间比较** — 对密钥使用 `hmac.compare_digest`
- [ ] **请求体限制** — 强制最大请求大小
- [ ] **日志记录** — 记录认证失败（绝不记录密码）
- [ ] **SQL 注入防护** — 始终使用参数化查询或 ORM，杜绝字符串拼接

### 基础设施层面

- [ ] **依赖扫描** — 保持库更新（`pip-audit`、Dependabot）
- [ ] **静态分析** — 每次提交运行 Bandit / Semgrep
- [ ] **渗透测试** — 定期对所有端点进行安全测试

---

## 18. 推荐工具与资源

### 安全测试工具

| 工具 | 用途 | 链接 |
|------|------|------|
| **Burp Suite** | Web 代理、拦截、爆破 | [portswigger.net](https://portswigger.net/burp) |
| **OWASP ZAP** | 自动化漏洞扫描 | [owasp.org/zap](https://www.zapproxy.org/) |
| **Wireshark** | 网络流量分析（密码嗅探） | [wireshark.org](https://www.wireshark.org/) |
| **Hydra** | 网络登录破解（暴力破解） | [github.com/vanhauser-thc/thc-hydra](https://github.com/vanhauser-thc/thc-hydra) |
| **sqlmap** | SQL 注入自动检测 | [sqlmap.org](https://sqlmap.org/) |
| **Nmap** | 网络发现与端口扫描 | [nmap.org](https://nmap.org/) |
| **Nikto** | Web 服务器扫描器 | [cirt.net/Nikto2](https://www.cirt.net/Nikto2) |
| **Bandit** | Python 安全静态分析 | [github.com/PyCQA/bandit](https://github.com/PyCQA/bandit) |

### 安全标准与参考

| 资源 | 说明 | 链接 |
|------|------|------|
| **OWASP Top 10 (2021)** | Web 应用安全风险 | [owasp.org/Top10](https://owasp.org/www-project-top-ten/) |
| **OWASP Cheat Sheet** | 开发者安全速查表 | [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/) |
| **CWE** | 通用弱点枚举 | [cwe.mitre.org](https://cwe.mitre.org/) |
| **SANS 25** | 最危险的软件错误 | [sans.org/top25](https://www.sans.org/top25-software-errors/) |

---

> **免责声明**  
> 本报告**仅供网络安全教育和授权渗透测试使用**。所述技术仅应应用于您拥有或获得明确书面授权的系统。未经授权访问计算机系统违反相关法律法规。
