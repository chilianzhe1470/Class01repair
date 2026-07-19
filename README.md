# 用户信息管理平台 — 安全加固版

> 原项目：[Class01](http://192.168.145.130:5000/) (漏洞版)  
> 此项目为安全加固后的修复版本，用于对比学习 Web 安全漏洞的修复方法。

## 漏洞修复清单

| # | 漏洞 | 修复方式 |
|---|------|---------|
| 1 | 明文密码存储 | `werkzeug.security` 哈希存储 |
| 2 | 明文密码传输 | HSTS 头 + HTTPS 建议 |
| 3 | 暴力破解 | Flask-Limiter 限流 |
| 4 | 弱 Secret Key | `secrets.token_hex(32)` |
| 5 | 调试模式泄露 | 环境变量控制 |
| 6 | 密码前端泄露 | 移除 password 字段传递 |
| 7 | HTML 注释泄露凭据 | 移除注释 |
| 8 | Session 安全缺失 | HttpOnly + SameSite + 过期时间 |
| 9 | 安全响应头缺失 | X-Frame-Options, HSTS 等 |
| 10 | CSRF 防护缺失 | Flask-WTF |

详细分析见 [VULN_REPORT.md](./VULN_REPORT.md)

## 环境要求

- Python 3.8+
- pip

## 快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动（开发模式）
FLASK_ENV=development python app.py

# 3. 启动（生产模式 - 推荐）
python app.py
```

访问 `http://localhost:8080`

## 默认账号

| 用户名 | 密码 | 角色 | 说明 |
|--------|------|------|------|
| admin | admin123 | 管理员 | 可查看所有功能 |
| alice | alice2025 | 普通用户 | 标准用户权限 |

> ⚠️ **安全提示**：部署到生产环境前，请务必：
> - 配置 HTTPS（推荐使用 Nginx + Let's Encrypt）
> - 设置环境变量 `SECRET_KEY` 为强随机字符串
> - 将 `SESSION_COOKIE_SECURE` 设为 `True`

## 项目结构

```
Class01repair/
├── app.py                 # Flask 主应用（安全版）
├── requirements.txt       # 依赖清单
├── VULN_REPORT.md         # 漏洞实训报告
├── .gitignore
├── templates/
│   ├── base.html          # 基础模板
│   ├── index.html         # 首页
│   └── login.html         # 登录页
└── static/
    └── css/
        └── style.css      # 样式文件
```
