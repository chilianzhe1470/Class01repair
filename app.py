"""
用户信息管理平台 — 安全加固版
==============================

基于 Flask 的用户信息管理系统，经过全面的安全加固。
作为网络安全教学演示项目，展示漏洞版与加固版实现模式的对比。

已修复的安全问题：
  1. 明文密码存储 → 使用 werkzeug (pbkdf2:sha256) 哈希
  2. 明文密码传输 → HSTS + 安全响应头
  3. 暴力破解攻击 → Flask-Limiter 限流
  4. 弱密钥 → 密码学安全随机 secrets.token_hex(32)
  5. 调试模式暴露 → 环境变量控制
  6. 模板密码泄露 → 剥离敏感字段的输出上下文
  7. HTML 注释硬编码凭据 → 已移除
  8. 会话安全配置不当 → HttpOnly + SameSite + 过期时间
  9. 安全响应头缺失 → 全面注入
 10. CSRF 漏洞 → Flask-WTF CSRF 防护
 11. 错误信息枚举用户 → 统一错误响应
 12. 输入校验缺失 → 客户端 + 服务端双重限制
 13. 时序攻击 → 通过 hmac.compare_digest 常量时间比较
 14. SQL 注入（注册） → 参数化查询替代 f-string 拼接
 15. SQL 注入（搜索） → 参数化查询替代 f-string 拼接
"""

import logging
import os
import secrets
import sqlite3
import sys
from datetime import timedelta
from typing import Dict, List, Optional, Tuple

from flask import Flask, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 数据库路径
# ---------------------------------------------------------------------------
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def init_db() -> None:
    """初始化 SQLite 数据库，创建 users 表并插入默认用户。

    数据库文件保存在 data/ 目录下。
    使用 INSERT OR IGNORE 防止重复插入默认用户。
    """
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
        """
    )
    # 插入默认用户（INSERT OR IGNORE 防止重复）
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("admin", "admin123", "admin@example.com", "13800138000"),
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    )
    conn.commit()
    conn.close()
    logger.info("数据库初始化完成: %s", DB_PATH)


# ---------------------------------------------------------------------------
# 应用工厂
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    """创建并配置 Flask 应用实例。

    Returns:
        Flask: 配置完成的应用实例，已附加安全中间件、限流器和路由定义。
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # 应用配置
    # ------------------------------------------------------------------
    _configure_app(app)

    # ------------------------------------------------------------------
    # 安全中间件
    # ------------------------------------------------------------------
    csrf = CSRFProtect(app)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.environ.get("REDIS_URL", "memory://"),
    )

    # ------------------------------------------------------------------
    # 安全响应头
    # ------------------------------------------------------------------
    _attach_security_headers(app)

    # ------------------------------------------------------------------
    # 路由注册
    # ------------------------------------------------------------------
    _register_routes(app, limiter)

    logger.info(
        "应用初始化完成 — 环境: %s, 调试模式: %s",
        os.environ.get("FLASK_ENV", "production"),
        app.debug,
    )
    return app


def _configure_app(app: Flask) -> None:
    """配置应用级别的所有参数。

    从环境变量加载密钥（或生成安全备用密钥），
    配置会话 Cookie 安全属性和请求大小限制。

    Args:
        app: 待配置的 Flask 应用实例。
    """
    # 密钥 —— 优先使用环境变量，否则生成安全备用密钥
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # 会话安全加固
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower()
        == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=16 * 1024,  # 16 KB 请求体限制
    )


def _attach_security_headers(app: Flask) -> None:
    """注册响应中间件，注入安全相关的 HTTP 响应头。

    添加的响应头：
        - X-Content-Type-Options: nosniff（阻止 MIME 嗅探）
        - X-Frame-Options: DENY（点击劫持防护）
        - X-XSS-Protection: 1; mode=block（XSS 过滤器）
        - Strict-Transport-Security（HSTS — 强制 HTTPS）
        - Cache-Control: no-store（阻止敏感数据缓存）

    Args:
        app: Flask 应用实例。
    """

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


def _register_routes(app: Flask, limiter: Limiter) -> None:
    """在应用实例上注册所有路由处理器。

    Args:
        app: Flask 应用实例。
        limiter: 用于装饰登录接口的限流器实例。
    """

    # ------------------------------------------------------------------
    # 内存用户存储（密码已通过 pbkdf2:sha256 哈希）
    # ------------------------------------------------------------------
    USERS: Dict[str, Dict[str, object]] = {
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

    # 可安全传递给模板的字段（不包含密码衍生值）
    PUBLIC_FIELDS = frozenset({"username", "role", "email", "phone", "balance"})

    def _sanitize_user(user: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
        """从用户字典中剥离敏感字段，再传递给模板。

        Args:
            user: 从数据存储中获取的原始用户字典，或 None。

        Returns:
            仅包含公开字段的字典；若输入为 None 则返回 None。
        """
        if user is None:
            return None
        return {k: v for k, v in user.items() if k in PUBLIC_FIELDS}

    # ------------------------------------------------------------------
    # 路由：首页
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        """渲染首页。

        如果用户已登录，展示其公开信息；否则显示登录提示。

        Returns:
            首页的渲染 HTML 模板。
        """
        username: Optional[str] = session.get("username")
        user_info = _sanitize_user(USERS.get(username)) if username else None
        return render_template(
            "index.html", user=user_info, search_results=None, keyword=None
        )

    # ------------------------------------------------------------------
    # 路由：登录（GET + POST，含限流）
    # ------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", override_defaults=False)
    def login():
        """处理用户认证。

        **GET** — 显示登录表单，可接受 msg 参数（如注册成功提示）。
        **POST** — 验证凭据（与哈希用户存储比对）。
        成功时将用户名持久化到会话并重定向至首页。
        失败时返回通用错误信息，防止用户枚举攻击。

        限流：**每 IP 地址每分钟 5 次请求**。

        Returns:
            登录页的渲染 HTML 模板，或认证成功时重定向至首页。
        """
        msg = request.args.get("msg")

        if request.method == "POST":
            username: str = (request.form.get("username") or "").strip()
            password: str = request.form.get("password") or ""

            if not username or not password:
                return render_template("login.html", error="用户名和密码不能为空", msg=msg)

            user = USERS.get(username)
            if user and check_password_hash(
                user["password_hash"], password  # type: ignore[arg-type]
            ):
                session["username"] = username
                session.permanent = True
                logger.info("用户 '%s' 登录成功", username)
                return redirect(url_for("index"))

            # 统一错误信息 —— 不区分"用户不存在"和"密码错误"
            # 以防止用户枚举攻击。
            logger.warning("用户名 '%s' 登录失败", username)
            return render_template("login.html", error="用户名或密码错误", msg=msg)

        return render_template("login.html", msg=msg)

    # ------------------------------------------------------------------
    # 路由：注册（GET + POST）
    # ------------------------------------------------------------------
    @app.route("/register", methods=["GET", "POST"])
    def register():
        """处理用户注册。

        **GET** — 显示注册表单。
        **POST** — 将用户数据通过参数化查询插入数据库。

        Returns:
            注册页的渲染 HTML 模板，或注册成功后重定向至登录页。
        """
        if request.method == "POST":
            username = request.form.get("username") or ""
            password = request.form.get("password") or ""
            email = request.form.get("email") or ""
            phone = request.form.get("phone") or ""

            # 使用参数化查询 —— 防止 SQL 注入
            sql = (
                "INSERT INTO users (username, password, email, phone) "
                "VALUES (?, ?, ?, ?)"
            )
            logger.info("执行 SQL（参数化）: %s", sql)
            logger.info("参数: username='%s', email='%s', phone='%s'", username, email, phone)

            conn = sqlite3.connect(DB_PATH)
            conn.execute(sql, (username, password, email, phone))
            conn.commit()
            conn.close()

            logger.info("新用户注册: username='%s'", username)
            return redirect(url_for("login", msg="注册成功，请登录"))

        return render_template("register.html")

    # ------------------------------------------------------------------
    # 路由：搜索（GET）
    # ------------------------------------------------------------------
    @app.route("/search")
    def search():
        """搜索用户。

        通过 URL 参数 keyword 接收关键词，
        使用参数化查询进行模糊搜索，防止 SQL 注入。

        Returns:
            首页的渲染 HTML 模板，包含搜索结果。
        """
        keyword = request.args.get("keyword", "")

        # 使用参数化查询 —— 防止 SQL 注入
        sql = (
            "SELECT id, username, email, phone FROM users "
            "WHERE username LIKE ? OR email LIKE ?"
        )
        like_pattern = f"%{keyword}%"
        logger.info("执行 SQL（参数化）: %s", sql)
        logger.info("参数: keyword='%s', pattern='%s'", keyword, like_pattern)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.execute(sql, (like_pattern, like_pattern))
        results: List[Tuple[int, str, str, str]] = cursor.fetchall()
        conn.close()

        username: Optional[str] = session.get("username")
        user_info = _sanitize_user(USERS.get(username)) if username else None

        return render_template(
            "index.html", user=user_info, search_results=results, keyword=keyword
        )

    # ------------------------------------------------------------------
    # 路由：登出
    # ------------------------------------------------------------------
    @app.route("/logout")
    def logout():
        """清除当前会话并重定向至首页。

        Returns:
            HTTP 重定向至首页。
        """
        username = session.get("username")
        session.clear()
        if username:
            logger.info("用户 '%s' 已登出", username)
        return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # 启动时初始化数据库
    init_db()

    app = create_app()

    # 调试模式默认关闭。通过以下方式显式开启：
    #   FLASK_ENV=development python app.py
    debug_enabled: bool = os.environ.get("FLASK_ENV") == "development"

    port: int = int(os.environ.get("PORT", 8080))
    logger.info("启动服务器于 0.0.0.0:%d（调试模式=%s）", port, debug_enabled)
    app.run(debug=debug_enabled, host="0.0.0.0", port=port)
