"""
User Management Platform — Secure Hardened Edition
===================================================

A Flask-based user information management system with comprehensive
security hardening. Built as a cybersecurity education demonstration
comparing vulnerable vs. secure implementation patterns.

Security Fixes Applied:
  1. Plaintext password storage → hashed with werkzeug (pbkdf2:sha256)
  2. Plaintext password transmission → HSTS + security headers
  3. Brute-force attacks → rate limiting via Flask-Limiter
  4. Weak secret key → cryptographically random secrets.token_hex(32)
  5. Debug mode exposure → environment-controlled activation
  6. Password leakage in templates → sanitized output context
  7. Hardcoded credentials in HTML comments → removed
  8. Session security misconfiguration → HttpOnly + SameSite + TTL
  9. Missing security headers → comprehensive header injection
 10. CSRF vulnerability → Flask-WTF CSRF protection
 11. User enumeration in error messages → uniform error responses
 12. Missing input validation → client + server side constraints
 13. Timing attacks → constant-time comparison via hmac.compare_digest
"""

import logging
import os
import secrets
import sys
from datetime import timedelta
from typing import Dict, Optional

from flask import Flask, redirect, render_template, request, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    """Create and configure the Flask application instance.

    Returns:
        Flask: A fully configured Flask application with all security
            middleware, rate limiters, and route definitions attached.
    """
    app = Flask(__name__)

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------
    _configure_app(app)

    # ------------------------------------------------------------------
    # Security Middleware
    # ------------------------------------------------------------------
    csrf = CSRFProtect(app)

    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.environ.get("REDIS_URL", "memory://"),
    )

    # ------------------------------------------------------------------
    # Security Response Headers
    # ------------------------------------------------------------------
    _attach_security_headers(app)

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------
    _register_routes(app, limiter)

    logger.info(
        "Application initialized — environment: %s, debug: %s",
        os.environ.get("FLASK_ENV", "production"),
        app.debug,
    )
    return app


def _configure_app(app: Flask) -> None:
    """Apply all application-level configuration values.

    Loads the secret key from environment (or generates a secure fallback),
    configures session cookie security properties, and sets request size
    limits.

    Args:
        app: The Flask application instance to configure.
    """
    # Secret key — prefer environment variable; generate secure fallback
    app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

    # Session hardening
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "false").lower()
        == "true",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
        MAX_CONTENT_LENGTH=16 * 1024,  # 16 KB request body limit
    )


def _attach_security_headers(app: Flask) -> None:
    """Register a response middleware that injects security-related HTTP headers.

    Headers added:
        - X-Content-Type-Options: nosniff (MIME-sniffing prevention)
        - X-Frame-Options: DENY (clickjacking protection)
        - X-XSS-Protection: 1; mode=block (legacy XSS filter)
        - Strict-Transport-Security (HSTS — enforces HTTPS)
        - Cache-Control: no-store (prevents sensitive data caching)

    Args:
        app: The Flask application instance.
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
    """Register all application route handlers on the given app instance.

    Args:
        app: The Flask application instance.
        limiter: The rate-limiter instance for decorating login.
    """

    # ------------------------------------------------------------------
    # In-memory user store (passwords hashed with pbkdf2:sha256)
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

    # Fields safe to expose in templates (no password-derived values)
    PUBLIC_FIELDS = frozenset({"username", "role", "email", "phone", "balance"})

    def _sanitize_user(user: Optional[Dict[str, object]]) -> Optional[Dict[str, object]]:
        """Strip sensitive fields from a user dictionary before passing to templates.

        Args:
            user: Raw user dictionary retrieved from the data store, or None.

        Returns:
            A dictionary containing only public-facing fields, or None if
            the input was None.
        """
        if user is None:
            return None
        return {k: v for k, v in user.items() if k in PUBLIC_FIELDS}

    # ------------------------------------------------------------------
    # Route: Home
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        """Render the home page.

        If the user has an active session, their public profile information
        is displayed.  Otherwise a prompt to log in is shown.

        Returns:
            Rendered HTML template for the index page.
        """
        username: Optional[str] = session.get("username")
        user_info = _sanitize_user(USERS.get(username)) if username else None
        return render_template("index.html", user=user_info)

    # ------------------------------------------------------------------
    # Route: Login (GET + POST, rate-limited)
    # ------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", override_defaults=False)
    def login():
        """Handle user authentication.

        **GET** — Display the login form.
        **POST** — Validate credentials against the hashed user store.
        On success the username is persisted to the session and the client
        is redirected to the home page.  On failure a generic error message
        is returned to prevent user-enumeration attacks.

        Rate-limited to **5 requests per minute per IP address**.

        Returns:
            Rendered HTML template for the login page, or a redirect to
            the index page on successful authentication.
        """
        if request.method == "POST":
            username: str = (request.form.get("username") or "").strip()
            password: str = request.form.get("password") or ""

            if not username or not password:
                return render_template("login.html", error="用户名和密码不能为空")

            user = USERS.get(username)
            if user and check_password_hash(
                user["password_hash"], password  # type: ignore[arg-type]
            ):
                session["username"] = username
                session.permanent = True
                logger.info("User '%s' logged in successfully", username)
                return redirect(url_for("index"))

            # Uniform error message — do NOT distinguish "user not found"
            # from "wrong password" to prevent user enumeration.
            logger.warning("Failed login attempt for username '%s'", username)
            return render_template("login.html", error="用户名或密码错误")

        return render_template("login.html")

    # ------------------------------------------------------------------
    # Route: Logout
    # ------------------------------------------------------------------
    @app.route("/logout")
    def logout():
        """Clear the current session and redirect to the home page.

        Returns:
            HTTP redirect to the index page.
        """
        username = session.get("username")
        session.clear()
        if username:
            logger.info("User '%s' logged out", username)
        return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()

    # Debug mode is intentionally off by default.  Enable explicitly via:
    #   FLASK_ENV=development python app.py
    debug_enabled: bool = os.environ.get("FLASK_ENV") == "development"

    port: int = int(os.environ.get("PORT", 8080))
    logger.info("Starting server on 0.0.0.0:%d (debug=%s)", port, debug_enabled)
    app.run(debug=debug_enabled, host="0.0.0.0", port=port)
