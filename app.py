import os
import re
import time
import uuid
import secrets
import logging
import pytz
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError
from sqlalchemy import text, inspect as sa_inspect

# ── Logging & Timezone ───────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)
PH_TZ = pytz.timezone("Asia/Manila")

def get_ph_now():
    return datetime.now(PH_TZ)

# ── App Config ───────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY environment variable is required.")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "True").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///security.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_TIME_LIMIT=3600,
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

TRUST_PROXY = os.environ.get("TRUST_PROXY", "False").lower() == "true"

# =======================
# Models
# =======================
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="viewer")
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    active_session_token = db.Column(db.String(100), nullable=True)
    last_seen = db.Column(db.DateTime, default=get_ph_now)

    def is_locked(self):
        return self.locked_until and self.locked_until > get_ph_now()

class AccessLog(db.Model):
    __tablename__ = "access_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=get_ph_now)
    ip_address = db.Column(db.String(45))
    username = db.Column(db.String(80))
    action = db.Column(db.String(50))
    success = db.Column(db.Boolean)
    details = db.Column(db.Text)

# =======================
# Helpers & Hooks
# =======================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            log_action("unauthorized_access", session.get("username"), False, "Non-admin access")
            flash("Admin access required.", "error")
            return redirect(url_for("camera"))
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    if TRUST_PROXY and request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

def sanitize_input(value):
    return re.sub(r"[^\w\s-]", "", str(value or "").strip())[:80]

def log_action(action, username=None, success=False, details=""):
    try:
        log = AccessLog(
            ip_address=get_client_ip(),
            username=sanitize_input(username) if username else None,
            action=action,
            success=success,
            details=str(details)[:500]
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to log: {e}")

@app.before_request
def validate_session():
    public_routes = {"login", "static", "logout", "not_found"}
    if request.endpoint in public_routes: return
    
    if "user_id" not in session or "session_token" not in session:
        return redirect(url_for("login"))
    
    user = User.query.get(session.get("user_id"))
    if not user or user.is_locked() or user.active_session_token != session.get("session_token"):
        session.clear()
        return redirect(url_for("login"))
    
    if "login_time" in session:
        login_time = datetime.fromisoformat(session["login_time"]).replace(tzinfo=PH_TZ)
        if get_ph_now() - login_time > timedelta(minutes=30):
            session.clear()
            return redirect(url_for("login"))
            
    user.last_seen = get_ph_now()
    db.session.commit()
    g.current_user = user

@app.context_processor
def inject_globals():
    return dict(session=session, now=get_ph_now)

# (Add your existing route implementations here, using get_ph_now() instead of datetime.utcnow())

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
