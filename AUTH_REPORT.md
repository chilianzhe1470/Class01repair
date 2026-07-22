# 越权漏洞检测与修复报告

**项目名称：** 用户信息管理平台  
**评估日期：** 2026年7月21日  
**报告作者：** chilianzhe1470  
**仓库地址：** https://github.com/chilianzhe1470/Classrepair  
**密级：** 内部 — 仅限教学使用

---

## 1. 总体摘要

对 Flask 用户管理应用中的**个人中心**（`/profile`）和**充值功能**（`/recharge`）进行了越权漏洞检测。两个功能均存在**严重的越权访问漏洞**，涵盖未授权访问、水平越权、垂直越权等类型。

**检测结果：**

| 漏洞类型 | 严重程度 | CWE 编号 | 修复版状态 |
|---------|:--------:|:--------:|:----------:|
| 未授权访问个人资料 | 🔴 严重 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | ✅ 已修复 |
| 水平越权查看他人资料 | 🔴 严重 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | ✅ 已修复 |
| 未授权充值 | 🔴 严重 | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | ✅ 已修复 |
| 水平越权为他人充值 | 🔴 严重 | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | ✅ 已修复 |
| 负数金额（扣款） | 🟡 高危 | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) | ✅ 已修复 |
| 垂直越权（普通用户操作管理员） | 🔴 严重 | [CWE-285](https://cwe.mitre.org/data/definitions/285.html) | ✅ 已修复 |

---

## 2. 新增功能说明

### 2.1 个人中心 `/profile`

| 属性 | 漏洞版(5000) | 修复版(8080) |
|------|:-----------:|:-----------:|
| 用户身份来源 | URL 参数 `user_id` | `session["username"]` |
| 登录校验 | ❌ 不需要登录 | ✅ 必须登录 |
| 可查看的用户 | 任意 `user_id` | 仅当前登录用户 |

### 2.2 充值功能 `/recharge`

| 属性 | 漏洞版(5000) | 修复版(8080) |
|------|:-----------:|:-----------:|
| 用户身份来源 | 表单参数 `user_id` | `session["username"]` |
| 登录校验 | ❌ 不需要登录 | ✅ 必须登录 |
| 可充值的用户 | 任意 `user_id` | 仅当前登录用户 |
| 金额校验 | ❌ 无校验 | ✅ 必须大于零 |
| CSRF 防护 | ❌ 无 | ✅ Flask-WTF |

---

## 3. 漏洞详情

### 3.1 V-AUTH-01：未授权访问个人资料

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| **CVSS 3.1** | 7.5（高危） |
| **风险描述** | 未登录用户可直接通过 `/profile?user_id=1` 查看任意用户的邮箱、手机、余额等敏感信息 |
| **漏洞位置** | `app.py` — `profile()` 路由 |

#### 攻击场景

```bash
# 无需登录，直接查看管理员资料
curl -s "http://target:5000/profile?user_id=1"
# 返回: admin, admin@example.com, 13800138000, 余额 99999

# 查看普通用户 alice 的资料
curl -s "http://target:5000/profile?user_id=2"
# 返回: alice, alice@example.com, 13900139001, 余额 100
```

#### 漏洞代码

```python
@app.route("/profile")
def profile():
    # 漏洞：不检查 session，user_id 从 URL 获取
    user_id = request.args.get("user_id", "1")
    username = ID_TO_USER.get(int(user_id))
    profile_user = USERS[username]
    return render_template("profile.html", profile=profile_user)
```

#### 修复方案

```python
@app.route("/profile")
def profile():
    # 修复：先检查登录状态
    if "username" not in session:
        return redirect(url_for("login"))
    # 从 session 获取当前用户
    current_user = session["username"]
    user_data = USERS.get(current_user)
```

---

### 3.2 V-AUTH-02：水平越权查看他人资料

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| **CVSS 3.1** | 6.5（中危） |
| **风险描述** | 已登录用户可通过修改 URL 中的 `user_id` 参数，查看其他用户的资料 |

#### 攻击场景

```bash
# alice 登录后修改 URL 查看 admin 资料
curl -s -b /tmp/alice_cookies.txt "http://target:5000/profile?user_id=1"
# admin 的邮箱、手机、余额全部暴露
```

#### 修复方案

修复版完全忽略 URL 中的 `user_id` 参数，用户身份始终从 `session` 获取：
```python
# 修复版代码中不使用任何 URL 参数
# 始终从 session 获取当前用户
current_user = session["username"]
```

---

### 3.3 V-AUTH-03：未授权充值

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) |
| **CVSS 3.1** | 9.1（严重） |
| **风险描述** | 未登录用户可直接通过 POST 请求为任意用户充值 |

#### 攻击场景

```bash
# 无需登录，直接给 admin 充值 5000 元
curl -s -X POST http://target:5000/recharge \
  -d "user_id=1&amount=5000"
# admin 余额从 99999 变为 104999
```

#### 修复方案

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    # 修复：先检查登录状态
    if "username" not in session:
        return redirect(url_for("login"))
    # 从 session 获取当前用户
    current_user = session["username"]
```

---

### 3.4 V-AUTH-04：水平越权为他人充值

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-639](https://cwe.mitre.org/data/definitions/639.html) |
| **CVSS 3.1** | 8.7（高危） |
| **风险描述** | 充值表单通过隐藏字段 `user_id` 指定充值目标，攻击者可修改该字段为他人充值 |

#### 攻击场景

```bash
# 修改表单中的 user_id 隐藏字段
curl -s -X POST http://target:5000/recharge \
  -d "user_id=2&amount=9999"
# 给别人充值成功
```

#### 修复方案

```html
<!-- 漏洞版：表单包含 user_id 隐藏字段 -->
<input type="hidden" name="user_id" value="{{ user_id }}">

<!-- 修复版：没有 user_id 字段，始终从 session 获取 -->
{# 注意：没有 user_id 隐藏字段，充值目标从 session 获取 #}
```

---

### 3.5 V-AUTH-05：负数金额扣款

| 属性 | 内容 |
|------|------|
| **CWE 编号** | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| **CVSS 3.1** | 7.5（高危） |
| **风险描述** | 充值接口未对金额进行正负校验，攻击者可输入负数实现扣款。配合越权漏洞可清空他人账户 |

#### 攻击场景

```bash
# 输入负数扣除 admin 余额
curl -s -X POST http://target:5000/recharge \
  -d "user_id=1&amount=-50000"
# admin 余额从 104999 变为 54999
```

#### 修复方案

```python
# 校验金额必须为正数
if amount <= 0:
    return "充值金额必须大于零", 400
```

---

## 4. 漏洞检测过程

### 4.1 检测工具

- **工具：** `curl` 命令行
- **目标漏洞版：** http://192.168.145.130:5000
- **目标修复版：** http://192.168.145.130:8080

### 4.2 检测步骤与结果

| # | 测试项 | 漏洞版(5000) | 修复版(8080) |
|:-:|:-------|:-----------:|:-----------:|
| 1 | 未登录访问 `/profile?user_id=1` | ✅ 返回 admin 完整资料 | ✅ 重定向到登录页 |
| 2 | 未登录查看 alice (`user_id=2`) | ✅ 返回 alice 资料 | ✅ 重定向到登录页 |
| 3 | 未登录充值 admin 余额 | ✅ 成功（99999→104999） | ✅ 被拒绝（400） |
| 4 | 水平越权查看他人资料 | ✅ 可查看 | ✅ 始终显示当前用户 |
| 5 | 水平越权为他人充值 | ✅ 成功 | ✅ 被忽略（始终当前用户） |
| 6 | 负数金额扣款（-50000） | ✅ 成功扣款 | ✅ 被拒绝（400） |
| 7 | 正常充值 100 元 | ✅ 成功 | ✅ 成功 |

---

## 5. 代码对比

### 5.1 个人中心 `/profile`

```diff
# ❌ 漏洞版 — 从 URL 参数获取 user_id，无登录校验
- @app.route("/profile")
- def profile():
-     user_id = request.args.get("user_id", "1")
-     username = ID_TO_USER.get(int(user_id))
-     profile_user = USERS[username]
-     return render_template("profile.html", profile=profile_user, user_id=user_id)

# ✅ 修复版 — 从 session 获取当前用户，有登录校验
+ @app.route("/profile")
+ def profile():
+     if "username" not in session:
+         return redirect(url_for("login"))
+     current_user = session["username"]
+     user_data = USERS.get(current_user)
+     profile_info = _sanitize_user(user_data)
+     return render_template("profile.html", profile=profile_info, user_id=user_id)
```

### 5.2 充值 `/recharge`

```diff
# ❌ 漏洞版 — 从表单获取 user_id，无校验
- @app.route("/recharge", methods=["POST"])
- def recharge():
-     user_id = request.form.get("user_id", "1")
-     amount = float(request.form.get("amount", "0"))
-     username = ID_TO_USER.get(int(user_id))
-     USERS[username]["balance"] += amount

# ✅ 修复版 — 从 session 获取用户，校验金额
+ @app.route("/recharge", methods=["POST"])
+ def recharge():
+     if "username" not in session:
+         return redirect(url_for("login"))
+     current_user = session["username"]
+     amount = float(request.form.get("amount", "0"))
+     if amount <= 0:
+         return "充值金额必须大于零", 400
+     user_data["balance"] += amount
```

### 5.3 充值表单模板

```diff
# ❌ 漏洞版：包含 user_id 隐藏字段，可被篡改
- <input type="hidden" name="user_id" value="{{ user_id }}">
- <input type="number" name="amount">

# ✅ 修复版：无 user_id 字段，金额有最小限制
+ <input type="number" name="amount" min="0.01">
```

---

## 6. 安全建议

1. **统一身份来源** — 所有涉及用户数据的操作必须从 `session` 获取用户身份，绝不从 URL/表单参数读取 `user_id`
2. **强制登录校验** — 每个受保护的页面和接口必须先验证 `session` 是否存在登录用户
3. **禁止参数传递用户标识** — 充值、修改资料等操作的 `user_id` 不应出现在表单或 URL 中
4. **敏感操作二次确认** — 涉及资金的操作应要求用户输入密码或进行二次确认
5. **金额校验** — 充值金额必须为正数，提现等操作应有单独的接口和逻辑
6. **操作审计日志** — 所有涉及用户数据的变更应记录操作者、目标用户、变更内容
7. **角色权限模型** — 如需管理员可操作所有用户，应实现基于角色的权限控制（RBAC）

---

## 7. 结论

本次评估发现并修复了 6 类越权安全漏洞：

| 漏洞类型 | CWE | CVSS | 状态 |
|---------|:---:|:----:|:----:|
| 未授权访问个人资料 | 284 | 7.5（高危） | ✅ 已修复 |
| 水平越权查看他人资料 | 639 | 6.5（中危） | ✅ 已修复 |
| 未授权充值 | 284 | 9.1（严重） | ✅ 已修复 |
| 水平越权为他人充值 | 639 | 8.7（高危） | ✅ 已修复 |
| 负数金额扣款 | 20 | 7.5（高危） | ✅ 已修复 |
| 垂直越权（普通用户操作管理员） | 285 | 9.1（严重） | ✅ 已修复 |

修复前，攻击者无需登录即可查看任意用户资料、为任意账号充值，甚至可以通过负数金额扣款清空他人余额。修复后，所有操作强制登录校验，用户身份统一从 `session` 获取，充值金额必须为正数，越权攻击完全失效。

---

*本报告作为网络安全实训课程作业提交。所有测试均在授权环境下进行。*
