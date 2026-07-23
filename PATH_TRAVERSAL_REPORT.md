# 文件包含与路径遍历漏洞检测与修复报告

**项目名称：** 用户信息管理平台  
**评估日期：** 2026年7月23日  
**报告作者：** chilianzhe1470  
**仓库地址：** https://github.com/chilianzhe1470/Classrepair  
**密级：** 内部 — 仅限教学使用

---

## 1. 总体摘要

对 Flask 用户管理应用中的**动态页面加载功能**（`/page`）进行了安全检测。该功能存在**严重的文件包含与路径遍历漏洞**，攻击者可利用 `../` 序列读取服务器上任意文件。

**检测结果：**

| 漏洞类型 | 严重程度 | CWE 编号 | 修复版状态 |
|---------|:--------:|:--------:|:----------:|
| 路径遍历读取源码 | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ✅ 已修复 |
| 路径遍历读取数据库 | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ✅ 已修复 |
| 路径遍历读取系统文件 | 🔴 严重 | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ✅ 已修复 |
| 无白名单校验 | 🔴 严重 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | ✅ 已修复 |
| 文件内容直接渲染（XSS） | 🟡 高危 | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | ✅ 已缓解 |

---

## 2. 新增功能说明

新增路由 `/page` 支持动态页面加载：

| 属性 | 漏洞版(5000) | 修复版(8080) |
|------|:-----------:|:-----------:|
| `name` 参数校验 | ❌ 无校验 | ✅ 白名单 + 正则 |
| `../` 过滤 | ❌ 不处理 | ✅ 路径规范化检查 |
| 文件后缀 | ❌ 先无后缀尝试，再加.html | ✅ 固定加 .html |
| 可访问范围 | 📂 整个文件系统 | 📁 仅 pages/ 目录 |
| 日志记录 | ❌ 无 | ✅ 记录非法请求 |

---

## 3. 漏洞详情

### 3.1 V-PT-01：路径遍历读取应用源码

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **CVSS 3.1** | 7.5（高危） |
| **风险描述** | 攻击者可通过 `../app.py` 读取 Flask 应用全部源代码，获取 Secret Key、数据库路径、业务逻辑等敏感信息 |

#### 攻击场景

```bash
# 读取源码，泄露 Secret Key 和密码
curl -s "http://target:5000/page?name=../app.py"
```

**攻击结果：** 页面中直接显示 `secret_key = "dev-key-2025"` 和 `"password": "admin123"` 等敏感信息。

#### 漏洞代码

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    # 漏洞：直接拼接用户输入到文件路径，无任何校验
    filepath = os.path.join("pages", name)
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            content = f.read()
        return render_template("index.html", page_content=content)
```

---

### 3.2 V-PT-02：路径遍历读取数据库文件

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **CVSS 3.1** | 9.1（严重） |
| **风险描述** | 攻击者可下载 SQLite 数据库文件 `users.db`，获取所有用户的明文密码 |

#### 攻击场景

```bash
# 下载数据库文件
curl -s "http://target:5000/page?name=../data/users.db" -o stolen.db
# 使用 sqlite3 打开即可查看所有用户密码
sqlite3 stolen.db "SELECT * FROM users;"
```

---

### 3.3 V-PT-03：路径遍历读取系统文件

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| **CVSS 3.1** | 6.5（中危） |
| **风险描述** | 攻击者可读取 Unix 系统文件如 `/etc/passwd`，获取系统用户列表 |

#### 攻击场景

```bash
# 读取系统用户列表
curl -s "http://target:5000/page?name=../../../etc/passwd"
# 输出 root:x:0:0:root:/root:/bin/bash 等系统信息
```

---

### 3.4 V-PT-04：无白名单校验

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| **风险描述** | 没有白名单限制，任何名称都可作为页面名尝试加载，扩大攻击面 |

---

## 4. 检测过程与结果

### 4.1 测试工具

- **工具：** `curl` 命令行
- **目标漏洞版：** http://192.168.145.130:5000
- **目标修复版：** http://192.168.145.130:8080

### 4.2 测试结果

| # | 测试项 | 漏洞版(5000) | 修复版(8080) |
|:-:|:-------|:-----------:|:-----------:|
| 1 | 正常请求 `help` | ✅ 显示帮助中心 | ✅ 显示帮助中心 |
| 2 | 读取 `../app.py` 源码 | ✅ 泄露源码（含密码） | ✅ 拒绝："无权访问" |
| 3 | 读取 `../../../etc/passwd` | ✅ 泄露系统用户列表 | ✅ 拒绝："页面不存在" |
| 4 | 读取 `../.gitignore` | ✅ 读取成功 | ✅ 拒绝 |
| 5 | 非法页面名 `about` | ✅ 返回"页面不存在" | ✅ 返回"页面不存在" |

---

## 5. 代码对比

### 5.1 漏洞版（5000 端口）

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")
    filepath = os.path.join("pages", name)

    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("index.html", page_content=content)

    filepath_html = filepath + ".html"
    if os.path.exists(filepath_html):
        with open(filepath_html, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("index.html", page_content=content)

    return render_template("index.html", page_content="页面不存在")
```

### 5.2 修复版（8080 端口）

```python
@app.route("/page")
def page():
    name = request.args.get("name", "")

    # 安全措施 1 & 2：白名单 + 正则校验
    ALLOWED_PAGES = {"help", "about", "contact", "faq"}
    if name not in ALLOWED_PAGES:
        logger.warning("非法页面请求: '%s'", name)
        return render_template("index.html", page_content="页面不存在或无权访问")

    # 安全措施 3：规范化路径并检查是否在 pages/ 目录内
    base_dir = os.path.abspath("pages")
    filepath = os.path.normpath(os.path.join(base_dir, f"{name}.html"))

    if not filepath.startswith(base_dir):
        logger.warning("路径越界尝试: '%s'", name)
        return render_template("index.html", page_content="页面不存在或无权访问")

    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return render_template("index.html", page_content=content)

    return render_template("index.html", page_content="页面不存在")
```

### 5.3 修复要点

| 安全措施 | 漏洞版 | 修复版 |
|---------|:-----:|:-----:|
| 白名单校验 | ❌ 无 | ✅ 仅允许 help/about/contact/faq |
| `../` 过滤 | ❌ 无 | ✅ 路径规范化+前缀检查 |
| 仅允许 .html | ❌ 尝试无后缀 | ✅ 固定加 .html |
| 非法请求日志 | ❌ 无 | ✅ 记录所有非法请求 |
| 错误信息 | "页面不存在" | "页面不存在或无权访问" |

---

## 6. 安全建议

1. **白名单机制** — 所有动态页面加载应使用白名单，而非黑名单
2. **路径规范化** — 使用 `os.path.normpath` 和 `os.path.abspath` 规范化路径
3. **前缀检查** — 检查最终路径是否在允许的基准目录内
4. **最小权限** — 应用使用最小系统权限运行，限制可读取的文件范围
5. **日志审计** — 记录所有非法文件访问尝试，及时发现攻击行为
6. **替代方案** — 考虑使用数据库存储动态页面内容而非文件系统

---

## 7. 结论

本次评估发现并修复了 4 类文件包含与路径遍历漏洞：

| 漏洞类型 | CWE | CVSS | 状态 |
|---------|:---:|:----:|:----:|
| 路径遍历读取源码 | 22 | 7.5（高危） | ✅ 已修复 |
| 路径遍历读取数据库 | 22 | 9.1（严重） | ✅ 已修复 |
| 路径遍历读取系统文件 | 22 | 6.5（中危） | ✅ 已修复 |
| 无白名单校验 | 284 | 5.3（中危） | ✅ 已修复 |

修复前，攻击者可通过 `../app.py` 直接获取应用源码（含 Secret Key 和密码），通过 `../data/users.db` 下载完整数据库，通过 `../../../etc/passwd` 读取系统文件。修复后仅允许白名单内的页面名称通过路径规范化检查后加载，所有路径穿越攻击被彻底拦截。

---

*本报告作为网络安全实训课程作业提交。所有测试均在授权环境下进行。*
