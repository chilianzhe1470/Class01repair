# CSRF 与 XSS 漏洞检测与修复报告

**项目名称：** 用户信息管理平台  
**评估日期：** 2026年7月24日  
**报告作者：** chilianzhe1470  
**仓库地址：** https://github.com/chilianzhe1470/Classrepair  
**密级：** 内部 — 仅限教学使用

---

## 1. 总体摘要

对 Flask 用户管理应用中的**密码修改功能**（`/change-password`）进行了安全检测。该功能存在**严重的 CSRF 漏洞**，同时结合已有的功能模块存在**存储型 XSS 风险**。

**检测结果：**

| 漏洞类型 | 严重程度 | CWE 编号 | 修复版状态 |
|---------|:--------:|:--------:|:----------:|
| CSRF — 无 Token 校验 | 🔴 严重 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | ✅ 已修复 |
| CSRF — 无原密码验证 | 🔴 严重 | [CWE-620](https://cwe.mitre.org/data/definitions/620.html) | ✅ 已修复 |
| CSRF — 任意用户密码可改 | 🔴 严重 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | ✅ 已修复 |
| 存储型 XSS（用户名） | 🟡 高危 | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | ✅ 已缓解 |

---

## 2. 新增功能说明

新增路由 `/change-password` 支持密码修改：

| 属性 | 漏洞版(5000) | 修复版(8080) |
|------|:-----------:|:-----------:|
| CSRF Token 校验 | ❌ 无 | ✅ Flask-WTF |
| 需原密码验证 | ❌ 不需要 | ✅ `check_password_hash` |
| 目标用户来源 | 表单 `username` | `session["username"]` |
| 新密码哈希存储 | ❌ 明文存储 | ✅ pbkdf2:sha256 |

---

## 3. 漏洞详情

### 3.1 V-CSRF-01：无 CSRF Token 校验

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| **CVSS 3.1** | 8.8（高危） |
| **风险描述** | `/change-password` 接口无任何 CSRF 防护（无 Token、无 Referer 检查、无 SameSite 限制），攻击者可构造恶意页面诱导已登录用户访问，自动提交修改密码请求。 |

#### 攻击场景

攻击者构造以下恶意页面，诱导已登录的管理员访问：

```html
<form action="http://target:5000/change-password" method="POST">
  <input name="username" value="admin">
  <input name="new_password" value="hacker123">
</form>
<script>document.forms[0].submit();</script>
```

**危害：** 管理员密码被重置为 `hacker123`，账户被攻击者完全接管。

#### 漏洞代码

```python
@app.route("/change-password", methods=["POST"])
def change_password():
    # 漏洞：无 CSRF Token 校验
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    USERS[username]["password"] = new_password
```

---

### 3.2 V-CSRF-02：无原密码验证

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-620](https://cwe.mitre.org/data/definitions/620.html) |
| **CVSS 3.1** | 7.5（高危） |
| **风险描述** | 修改密码不需要验证原密码，一旦 CSRF 攻击成功或攻击者获得短暂访问权限，可立即重置密码。 |

#### 攻击场景

```bash
# 无需原密码，直接修改 admin 密码
curl -s -X POST http://target:5000/change-password \
  -d "username=admin&new_password=hacked123"
# 直接用新密码登录成功
curl -s -X POST http://target:5000/login \
  -d "username=admin&password=hacked123"
# → 欢迎回来，admin！（登录成功）
```

---

### 3.3 V-CSRF-03：可修改任意用户密码

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| **CVSS 3.1** | 8.8（高危） |
| **风险描述** | `username` 参数从表单获取，已登录的任何用户都可以修改其他用户的密码（水平越权）。 |

#### 攻击场景

```bash
# alice 登录后（普通用户）
curl -s -b /tmp/alice_cookies.txt -X POST http://target:5000/change-password \
  -d "username=admin&new_password=hacked123"
# admin 密码被修改，alice 可登录 admin 账户
```

**漏洞版验证结果：** alice 成功将 admin 密码从 `admin123` 改为 `hacked999`，随后使用新密码登录 admin 成功。

---

### 3.4 V-XSS-01：存储型 XSS（用户名）

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **CVSS 3.1** | 6.1（中危） |
| **风险描述** | 用户名未经过滤存储在数据库中，如果攻击者注册包含 `<script>` 的用户名，在首页、导航栏、个人中心等处渲染时可触发 XSS。 |

---

## 4. 修复方案

### 4.1 添加 CSRF Token 校验

```python
# 修复版：Flask-WTF 自动校验所有 POST 请求的 CSRF Token
csrf = CSRFProtect(app)
```

```html
<!-- 修复版：表单中包含 csrf_token -->
<form method="POST" action="{{ url_for('change_password') }}">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    ...
</form>
```

### 4.2 添加原密码验证

```python
# 验证原密码
if not check_password_hash(user_data["password_hash"], old_password):
    return "原密码错误", 403
```

### 4.3 从 Session 获取用户身份

```python
# 修复版：从 session 获取当前用户
current_user = session["username"]
# 拒绝表单中的 username 参数
```

### 4.4 新密码哈希存储

```python
# 修复版：新密码使用 pbkdf2:sha256 哈希存储
user_data["password_hash"] = generate_password_hash(new_password)
```

---

## 5. 检测过程与结果

### 5.1 测试工具

- **工具：** `curl` 命令行
- **目标漏洞版：** http://192.168.145.130:5000
- **目标修复版：** http://192.168.145.130:8080

### 5.2 测试结果

| # | 测试项 | 漏洞版(5000) | 修复版(8080) |
|:-:|:-------|:-----------:|:-----------:|
| 1 | 水平越权 — alice 改 admin 密码 | ✅ 成功（302） | ✅ 从 session 取值，无法越权 |
| 2 | 无原密码修改 | ✅ 不需原密码 | ✅ 需原密码（403 拒绝） |
| 3 | 正常修改密码 | ✅ 成功 | ✅ 成功（302） |
| 4 | CSRF Token 缺失 | ✅ 仍可执行 | ✅ 被拒绝（400） |
| 5 | 原密码错误 | ✅ 仍可执行 | ✅ 被拒绝（403） |

### 5.3 代码对比

```diff
# ❌ 漏洞版 — 无CSRF、无原密码、表单取username
- @app.route("/change-password", methods=["POST"])
- def change_password():
-     username = request.form.get("username", "")
-     new_password = request.form.get("new_password", "")
-     USERS[username]["password"] = new_password

# ✅ 修复版 — CSRF Token、需原密码、session取用户
+ @app.route("/change-password", methods=["POST"])
+ def change_password():
+     if "username" not in session: return redirect(url_for("login"))
+     current_user = session["username"]
+     if not check_password_hash(user_data["password_hash"], old_password):
+         return "原密码错误", 403
+     user_data["password_hash"] = generate_password_hash(new_password)
```

---

## 6. 安全建议

1. **CSRF Token 必须** — 所有状态变更的 POST 请求必须包含 CSRF Token
2. **原密码验证** — 修改密码等敏感操作必须验证原密码
3. **身份来源统一** — 操作目标用户必须从 session 获取，拒绝 URL/表单参数
4. **密码哈希存储** — 任何存储到数据库的密码必须使用盐值哈希
5. **输入过滤** — 用户名等展示在页面的字段应过滤 HTML 标签
6. **CSP 头** — 添加 Content-Security-Policy 响应头限制脚本执行

---

## 7. 结论

本次评估发现并修复了 3 类 CSRF/XSS 安全漏洞：

| 漏洞类型 | CWE | CVSS | 状态 |
|---------|:---:|:----:|:----:|
| CSRF 无 Token 校验 | 352 | 8.8（高危） | ✅ 已修复 |
| 无原密码验证 | 620 | 7.5（高危） | ✅ 已修复 |
| 任意用户密码可修改 | 639 | 8.8（高危） | ✅ 已修复 |

修复前，攻击者可构造恶意页面诱导管理员访问，在其不知情下重置密码为攻击者指定值，实现账户完全接管；已登录的普通用户也可直接修改管理员密码。修复后，所有 POST 请求强制 CSRF Token 校验，修改密码需验证原密码且目标用户从 session 获取，所有攻击路径被彻底阻断。

---

*本报告作为网络安全实训课程作业提交。所有测试均在授权环境下进行。*
