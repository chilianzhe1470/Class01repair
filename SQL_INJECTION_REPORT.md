# SQL 注入漏洞检测与修复报告

**项目名称：** 用户信息管理平台  
**评估日期：** 2026年7月20日  
**报告作者：** chilianzhe1470  
**仓库地址：** https://github.com/chilianzhe1470/Classrepair  
**密级：** 内部 — 仅限教学使用

---

## 1. 总体摘要

对 Flask 用户管理应用中的**注册功能**和**搜索功能**进行了 SQL 注入漏洞检测。两个功能均使用 f-string 字符串拼接构建 SQL 语句，存在严重的 SQL 注入风险。

**检测结果：**

| 功能模块 | 漏洞类型 | 严重程度 | CWE 编号 | 状态 |
|---------|---------|:--------:|:--------:|:----:|
| 注册 `/register` | SQL 注入（INSERT） | 🔴 严重 | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | ✅ 已修复 |
| 搜索 `/search` | SQL 注入（SELECT） | 🔴 严重 | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | ✅ 已修复 |

**修复方案：** 将 f-string 字符串拼接替换为**参数化查询**（`?` 占位符），用户输入仅作为参数传递。

---

## 2. 漏洞详情

### 2.1 V-SQL-01：注册功能 SQL 注入

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| **CVSS 3.1** | 9.8（严重） — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **风险描述** | 注册表单数据通过 f-string 拼接 SQL，攻击者可注入任意 SQL 语句 |
| **漏洞位置** | `app.py` — `register()` 函数 |
| **攻击方式** | 在任意输入框中嵌入恶意 SQL 代码 |
| **危害等级** | 可导致数据删除、篡改、泄露 |

#### 攻击场景示例

攻击者在手机号字段输入：
```
'); DELETE FROM users; --
```

拼接后的 SQL：
```sql
INSERT INTO users (username, password, email, phone)
VALUES ('hacker', 'test123', 'hacker@hack.com', ''); DELETE FROM users; --')
```

执行结果：**users 表全部数据被删除**。

#### ❌ 漏洞代码

```python
# 存在 SQL 注入漏洞
sql = (
    f"INSERT INTO users (username, password, email, phone) "
    f"VALUES ('{username}', '{password}', '{email}', '{phone}')"
)
conn.execute(sql)
```

#### ✅ 修复代码

```python
# 使用参数化查询 —— 安全
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
conn.execute(sql, (username, password, email, phone))
```

---

### 2.2 V-SQL-02：搜索功能 SQL 注入

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) |
| **CVSS 3.1** | 7.5（高危） — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **风险描述** | 搜索关键词通过 f-string 拼接 SQL，攻击者可注入 UNION 查询窃取密码 |
| **漏洞位置** | `app.py` — `search()` 函数 |
| **攻击方式** | 在搜索框中输入 UNION 查询语句 |
| **危害等级** | 可导致全部用户密码泄露 |

#### 攻击场景示例

攻击者在搜索框输入：
```
' UNION SELECT id, username, password, phone FROM users --
```

拼接后的 SQL：
```sql
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
  OR email LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
```

#### 攻击实测结果

使用 UNION 注入成功获取数据库中所有用户的密码：

```
ID: 1, 用户名: admin, 密码: admin123     ← 密码泄露
ID: 2, 用户名: alice, 密码: alice2025    ← 密码泄露
```

#### ❌ 漏洞代码

```python
# 存在 SQL 注入漏洞
sql = (
    f"SELECT id, username, email, phone FROM users "
    f"WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
)
conn.execute(sql)
```

#### ✅ 修复代码

```python
# 使用参数化查询 —— 安全
sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
like_pattern = f"%{keyword}%"
conn.execute(sql, (like_pattern, like_pattern))
```

---

## 3. 漏洞检测过程

### 3.1 检测工具

- **工具：** `curl` 命令行 + 浏览器开发者工具
- **方法：** 黑盒测试（模拟攻击者视角）

### 3.2 检测步骤

| 步骤 | 操作 | 预期 | 结果 |
|------|------|------|:----:|
| 1 | 正常搜索 `admin` | 返回 admin 用户 | ✅ |
| 2 | UNION 注入获取密码 | 泄露密码 `admin123` | ✅ 确认漏洞 |
| 3 | 恒真注入 `' OR '1'='1` | 返回全部用户 | ✅ 确认漏洞 |
| 4 | 注册注入 `'); DELETE FROM users;--` | 尝试删除表数据 | ✅ 确认注入点存在 |
| 5 | 修复后重测 UNION 注入 | 返回 0 条结果 | ✅ 修复成功 |
| 6 | 修复后重测恒真注入 | 返回 0 条结果 | ✅ 修复成功 |
| 7 | 修复后验证正常搜索 | 返回正确结果 | ✅ 功能正常 |
| 8 | 修复后验证正常注册 | HTTP 302 成功 | ✅ 功能正常 |

### 3.3 后台 SQL 日志（修复前）

```
2026-07-20 [INFO] 执行 SQL: SELECT id, username, email, phone FROM users
  WHERE username LIKE '%admin%' OR email LIKE '%admin%'              ← 正常搜索

2026-07-20 [INFO] 执行 SQL: SELECT id, username, email, phone FROM users
  WHERE username LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
  OR email LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
  ← UNION注入成功，返回了密码字段

2026-07-20 [INFO] 执行 SQL: INSERT INTO users (username, password, email, phone)
  VALUES ('hacker', 'test123', 'hacker@hack.com', '');DELETE FROM users;--')
  ← 注册注入，恶意SQL被拼接执行
```

### 3.4 后台 SQL 日志（修复后）

```
2026-07-20 [INFO] 执行 SQL（参数化）: SELECT id, username, email, phone FROM users
  WHERE username LIKE ? OR email LIKE ?
  ← 使用 ? 占位符，用户输入仅作为参数传递

2026-07-20 [INFO] 执行 SQL（参数化）: INSERT INTO users (...)
  VALUES (?, ?, ?, ?)
  ← 参数化查询，恶意输入无法改变SQL语义
```

---

## 4. 修复方案对比

| 对比项 | 修复前（f-string 拼接） | 修复后（参数化查询） |
|--------|----------------------|-------------------|
| **注册 SQL** | `f"VALUES ('{username}', ...)"` | `VALUES (?, ?, ?, ?)` |
| **搜索 SQL** | `f"LIKE '%{keyword}%'"` | `LIKE ?` |
| **用户输入处理** | 直接嵌入 SQL 语句 | 作为参数传递 |
| **SQL 注入风险** | 🔴 严重存在 | ✅ 完全消除 |
| **正常功能** | ✅ 正常 | ✅ 正常 |

---

## 5. 修复验证结果

### 5.1 搜索功能验证

```bash
# 正常搜索（应正常工作）
$ curl -s "http://localhost:8080/search?keyword=admin"
→ 共找到 1 条结果（admin 用户）

# UNION注入获取密码（应被拦截）
$ curl -s "http://localhost:8080/search?keyword=' UNION SELECT id,username,password,phone FROM users --"
→ 无搜索结果（密码未泄露 ✅）

# 恒真注入（应被拦截）
$ curl -s "http://localhost:8080/search?keyword=test' OR '1'='1"
→ 无搜索结果（未返回全部用户 ✅）
```

### 5.2 注册功能验证

```bash
# 正常注册（应正常工作）
$ curl -X POST ... -d "username=newuser&password=pass123&email=...&phone=..."
→ HTTP 302（跳转登录页 ✅）

# 恶意SQL注入注册（应被拦截）
$ curl -X POST ... -d "username=ha&password=...&email=...&phone=');DELETE FROM users;--"
→ HTTP 400（CSRF校验拒绝，参数化后SQL安全 ✅）
```

---

## 6. 代码对比

### 6.1 注册功能

```diff
# ❌ 修复前 — 存在 SQL 注入
- sql = f"INSERT INTO users (...) VALUES ('{username}', '{password}', '{email}', '{phone}')"
- conn.execute(sql)

# ✅ 修复后 — 参数化查询
+ sql = "INSERT INTO users (...) VALUES (?, ?, ?, ?)"
+ conn.execute(sql, (username, password, email, phone))
```

### 6.2 搜索功能

```diff
# ❌ 修复前 — 存在 SQL 注入
- sql = f"SELECT ... WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
- conn.execute(sql)

# ✅ 修复后 — 参数化查询
+ sql = "SELECT ... WHERE username LIKE ? OR email LIKE ?"
+ conn.execute(sql, (like_pattern, like_pattern))
```

---

## 7. 安全建议

1. **始终使用参数化查询** — 所有 SQL 操作都应使用 `?` 占位符传递参数
2. **使用 ORM 框架** — 如 Flask-SQLAlchemy 可从根本上杜绝 SQL 拼接
3. **最小权限原则** — 数据库连接使用只读账号（查询）和读写账号（写入）分离
4. **输入验证** — 对输入内容进行类型、长度、格式校验
5. **WAF 防护** — 部署 Web 应用防火墙（如 ModSecurity）作为额外防护层
6. **定期代码审计** — 使用 Bandit、Semgrep 等工具自动检测 SQL 拼接模式

---

## 8. 结论

本次评估发现并修复了 2 处 SQL 注入漏洞：

| 漏洞 | CWE | CVSS | 修复方式 |
|------|:---:|:----:|---------|
| 注册 SQL 注入 | 89 | 9.8（严重） | 参数化查询 |
| 搜索 SQL 注入 | 89 | 7.5（高危） | 参数化查询 |

修复前，攻击者可通过 UNION 注入直接获取数据库中所有用户的密码（`admin123`、`alice2025`），也可通过注册注入执行任意 SQL 语句。修复后，用户输入仅作为数据参数传递，无法改变 SQL 语句结构，注入攻击完全失效。所有正常功能经测试仍正常工作。

---

*本报告作为网络安全实训课程作业提交。所有测试均在授权环境下进行。*
