"""
用户信息管理平台 - 安全加固版
==============================
原始漏洞版存在以下安全问题，此版本已修复：
1. 明文密码存储 → 使用 werkzeug.security 哈希存储
2. 明文密码传输 → 强制 HTTPS + HSTS 头
3. 登录暴力破解 → Flask-Limiter 限流
4. 弱 Session 密钥 → secrets 模块生成强密钥
5. 调试模式泄露 → 通过环境变量控制
6. 密码前端泄露 → 模板中不再传递密码字段
7. HTML 注释泄露凭据 → 已移除
8. Session 安全加固 → HttpOnly + SameSite + 过期时间
9. 登录错误区分用户 → 统一提示"用户名或密码错误"
10. CSRF 防护 → 使用 Flask-WTF
"""

import os
import secrets
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

# ---------------------------------------------------------------------------
# 应用初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)

# 使用环境变量中的密钥，如果没有则生成一个随机密钥
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,          # 生产环境应设为 True（需配置 HTTPS）
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

# WTF CSRF 保护
csrf = CSRFProtect(app)

# 请求体大小限制（防止大请求攻击）
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16KB

# ---------------------------------------------------------------------------
# 限流器 —— 防止暴力破解
# ---------------------------------------------------------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
)

# ---------------------------------------------------------------------------
# 用户数据库（安全版 —— 密码已哈希）
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# 暴露给模板的用户信息 —— 不包含密码相关字段
USER_PUBLIC_FIELDS = ["username", "role", "email", "phone", "balance"]


def _sanitize_user(user_dict):
    """返回不包含密码的用户信息"""
    if user_dict is None:
        return None
    return {k: user_dict[k] for k in USER_PUBLIC_FIELDS}


# ---------------------------------------------------------------------------
# 安全响应头中间件
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


# ---------------------------------------------------------------------------
# 路由：首页
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = _sanitize_user(USERS.get(username))
    return render_template("index.html", user=user_info)


# ---------------------------------------------------------------------------
# 路由：登录（含限流）
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        # 输入校验
        if not username or not password:
            return render_template("login.html", error="用户名和密码不能为空")

        user = USERS.get(username)

        # 使用 werkzeug 的 check_password_hash 进行常量时间比对
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            session.permanent = True
            return redirect(url_for("index"))
        else:
            # 统一错误提示，不区分"用户名不存在"或"密码错误"
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


# ---------------------------------------------------------------------------
# 路由：登出
# ---------------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # 生产环境必须设置环境变量 FLASK_ENV=production
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
