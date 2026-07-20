<div align="center">

# 🛡️ 用户信息管理平台 · 安全加固版

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/许可证-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/安全-已加固-brightgreen)](#-修复的漏洞清单)

**一个用于网络安全教学的 Flask 应用 —— 从漏洞版到加固版的对比实践。**

将原始漏洞版 [Class01](http://192.168.145.130:5000/) 与加固版进行对比，理解真实的 Web 安全漏洞及其修复方法。

**[🔬 漏洞分析报告](VULN_REPORT.md)** ·
**[🚀 快速开始](#-快速开始)** ·
**[📋 修复清单](#-修复的漏洞清单)**

</div>

---

## 📋 目录

- [✨ 项目概述](#-项目概述)
- [🚀 快速开始](#-快速开始)
- [🔐 默认账号](#-默认账号)
- [🛡️ 修复的漏洞清单](#️-修复的漏洞清单)
- [🌐 API 接口](#-api-接口)
- [⚙️ 配置说明](#️-配置说明)
- [📁 项目结构](#-项目结构)
- [🧪 验证修复效果](#-验证修复效果)
- [🤝 贡献指南](#-贡献指南)
- [📄 许可证](#-许可证)

---

## ✨ 项目概述

本项目在简单的 Flask 用户管理应用中演示 **13 种常见 Web 安全漏洞**（基于 OWASP Top 10），并逐一给出对应修复方案。适用于**网络安全实训课程** —— 教师可部署漏洞版用于渗透测试练习，加固版作为参考答案。

| 对比项 | 原始漏洞版 (Class01) | 本仓库 (加固版) |
|--------|-------------------|-----------------|
| 🔑 密码存储 | 明文 | pbkdf2:sha256 哈希 |
| 🚦 爆破防护 | 无 | 每 IP 每分钟 5 次 |
| 🔒 会话安全 | 基础配置 | HttpOnly + SameSite + 过期时间 |
| 🛡️ CSRF 防护 | 无 | Flask-WTF |
| 📝 安全响应头 | 无 | 注入 5 项安全头 |

---

## 🚀 快速开始

### 环境要求

- Python **3.8+**
- `pip`（Python 包管理器）
- *（可选）* `virtualenv` 创建隔离环境

### 安装步骤

```bash
# 1. 克隆仓库
git clone https://github.com/chilianzhe1470/Classrepair.git
cd Classrepair

# 2.（推荐）创建并激活虚拟环境
python -m venv venv
source venv/bin/activate    # Linux / macOS
# venv\Scripts\activate     # Windows

# 3. 安装依赖
pip install --upgrade pip
pip install -r requirements.txt
```

### 启动应用

```bash
# 开发模式（开启调试，显示详细错误）
FLASK_ENV=development python app.py

# 生产模式（关闭调试，安全加固）
python app.py
```

服务默认运行于 **http://localhost:8080**。

> 💡 **提示：** 使用 `PORT` 环境变量可指定端口：
> ```bash
> PORT=9000 python app.py
> ```

---

## 🔐 默认账号

| 用户名 | 密码 | 角色 | 邮箱 | 手机 | 余额 |
|--------|------|------|------|------|------|
| `admin` | `admin123` | 管理员 | admin@example.com | 13800138000 | 99999 |
| `alice` | `alice2025` | 普通用户 | alice@example.com | 13900139001 | 100 |

> ⚠️ **仅限演示使用。** 这些凭据为课堂练习而设计，生产中切勿使用弱密码或默认密码。

---

## 🛡️ 修复的漏洞清单

| # | 漏洞名称 | 严重程度 | 修复方案 | CWE 编号 |
|---|---------|:--------:|---------|:--------:|
| 01 | **明文密码存储** | 🔴 严重 | `werkzeug.security` pbkdf2:sha256 哈希 | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) |
| 02 | **明文密码传输** | 🔴 严重 | HSTS 响应头 + 强制 HTTPS | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) |
| 03 | **暴力破解** | 🔴 严重 | Flask-Limiter（每 IP 每分钟 5 次） | [CWE-307](https://cwe.mitre.org/data/definitions/307.html) |
| 04 | **弱会话密钥** | 🟡 高危 | `secrets.token_hex(32)` 256 位随机密钥 | [CWE-330](https://cwe.mitre.org/data/definitions/330.html) |
| 05 | **调试模式泄露** | 🟡 高危 | 环境变量控制调试模式开关 | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) |
| 06 | **前端展示密码** | 🔴 严重 | 模板渲染前剥离密码字段 | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| 07 | **注释泄露凭据** | 🔴 严重 | 移除 HTML 中的管理员账号注释 | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| 08 | **会话配置缺失** | 🟡 高危 | HttpOnly + SameSite=Lax + 2 小时过期 | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) |
| 09 | **安全响应头缺失** | 🟡 高危 | 注入 5 项安全响应头 | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) |
| 10 | **CSRF 漏洞** | 🟡 高危 | Flask-WTF CSRF 令牌校验 | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) |
| 11 | **用户枚举** | 🟡 高危 | 统一返回"用户名或密码错误" | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) |
| 12 | **输入校验缺失** | 🟢 中危 | maxlength + 16 KB 请求体限制 | [CWE-20](https://cwe.mitre.org/data/definitions/20.html) |
| 13 | **时序攻击** | 🟢 中危 | `check_password_hash()` 常量时间比较 | [CWE-208](https://cwe.mitre.org/data/definitions/208.html) |

📖 **每个漏洞的详细分析见 [VULN_REPORT.md](VULN_REPORT.md)。**

---

## 🌐 API 接口

| 方法 | 路径 | 说明 | 需登录 | 限流 |
|------|------|------|:-----:|:----:|
| GET | `/` | 首页（已登录则展示个人信息） | 否 | 否 |
| GET | `/login` | 显示登录表单 | 否 | 否 |
| POST | `/login` | 用户认证 | 否 | ✅ 每分钟 5 次 |
| GET | `/logout` | 清除会话并重定向到首页 | 否 | 否 |
| GET | `/register` | 显示注册表单 | 否 | 否 |
| POST | `/register` | 用户注册（SQLite 存储） | 否 | 否 |
| GET | `/search` | 按用户名或邮箱搜索用户 | 否 | 否 |

---

## ⚙️ 配置说明

所有配置通过**环境变量**进行：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SECRET_KEY` | 自动生成（256 位） | Flask 会话签名密钥 |
| `FLASK_ENV` | `production` | 设为 `development` 开启调试模式 |
| `PORT` | `8080` | 服务监听端口 |
| `HTTPS_ENABLED` | `false` | 部署 HTTPS 时设为 `true` |
| `REDIS_URL` | `memory://` | 限流器存储后端 |

`.env` 文件示例：

```ini
SECRET_KEY=your-strong-secret-key-here
FLASK_ENV=development
PORT=8080
HTTPS_ENABLED=false
```

---

## 📁 项目结构

```
Classrepair/
├── app.py                    # Flask 应用主文件（加固版）
├── requirements.txt          # Python 依赖清单
├── VULN_REPORT.md            # 漏洞分析报告（完整版）
├── SUBMISSION_REPORT.md      # 安全评估报告（可提交版）
├── .env.example              # 环境变量模板
├── .gitignore
├── LICENSE                   # MIT 许可证
├── README.md                 # 本文件
├── data/
│   └── users.db              # SQLite 用户数据库（注册数据）
├── templates/
│   ├── base.html             # 基础布局（导航栏、主容器）
│   ├── index.html            # 首页（个人信息 / 搜索 / 登录提示）
│   ├── login.html            # 登录表单（含 CSRF 保护）
│   └── register.html         # 注册表单
└── static/
    └── css/
        └── style.css         # 应用样式表
```

---

## 🧪 验证修复效果

### 验证密码哈希存储

```bash
python -c "
from werkzeug.security import check_password_hash
# 从 app.py 中复制实际的哈希值替换下方字符串
hash = 'pbkdf2:sha256:600000\$...'
print(check_password_hash(hash, 'admin123'))  # 输出 True
"
```

### 验证登录限流

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "第 $i 次请求: HTTP %{http_code}\n" \
    -X POST -d "username=admin&password=wrong" \
    http://localhost:8080/login
done
# 前 5 次返回 200，第 6 次起返回 429
```

### 验证安全响应头

```bash
curl -s -I http://localhost:8080/ | grep -E '^(X-|Strict-|Cache-)'
# 应包含：X-Content-Type-Options, X-Frame-Options,
#          X-XSS-Protection, Strict-Transport-Security, Cache-Control
```

---

## 🤝 贡献指南

欢迎贡献！本项目为教学目的而设计，任何改进——修复 Bug、添加新的漏洞演示、完善文档——都深受欢迎。

1. Fork 本仓库
2. 创建特性分支（`git checkout -b feature/你的想法`）
3. 提交更改（`git commit -m '添加某个特性'`）
4. 推送到分支（`git push origin feature/你的想法`）
5. 发起 Pull Request

---

## 📄 许可证

本项目基于 **MIT 许可证** 发布。详见 [LICENSE](LICENSE)。

---

<div align="center">

**用于网络安全教学** · 基于 [Flask](https://flask.palletsprojects.com/) 构建

*本项目仅供合法教学使用。作者不对滥用其中技术的行为承担责任。*

</div>
