import os
import re
import time
import uuid
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps
import cv2  # Added for camera streaming

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    g,
    make_response
)
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError
from sqlalchemy import text, inspect as sa_inspect

# ── Logging ──────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── App Config ───────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is required. "
        "Generate a strong random string and set it before starting the app."
    )

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
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    def is_locked(self):
        return self.locked_until and self.locked_until > datetime.utcnow()

class AccessLog(db.Model):
    __tablename__ = "access_log"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    username = db.Column(db.String(80))
    action = db.Column(db.String(50))
    success = db.Column(db.Boolean)
    details = db.Column(db.Text)

# =======================
# Helpers
# =======================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            log_action("unauthorized_access", session.get("username"), False, "Non-admin accessed admin route")
            flash("Admin access required.", "error")
            return redirect(url_for("camera"))
        return f(*args, **kwargs)
    return decorated_function

def get_client_ip():
    if TRUST_PROXY and request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

def sanitize_input(value):
    if not value:
        return ""
    return re.sub(r"[^\w\s-]", "", str(value).strip())[:80]

def validate_password(password):
    if not password or len(password) < 8:
        return "Password must be at least 8 characters long."
    return None

def log_action(action, username=None, success=False, details=""):
    if not db_ready:
        return
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
        logger.error(f"Failed to log action: {e}")

# =======================
# Database Init
# =======================
def auto_migrate():
    try:
        with app.app_context():
            inspector = sa_inspect(db.engine)
            columns = [col["name"] for col in inspector.get_columns("user")]
            dialect = db.engine.dialect.name
            table_name = '"user"' if dialect == "postgresql" else "user"
            
            with db.engine.connect() as conn:
                if "active_session_token" not in columns:
                    logger.info("Adding active_session_token column...")
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN active_session_token VARCHAR(100)"))
                    conn.commit()
                    logger.info("active_session_token added.")
                if "last_seen" not in columns:
                    logger.info("Adding last_seen column...")
                    col_type = "TIMESTAMP" if dialect == "postgresql" else "DATETIME"
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN last_seen {col_type}"))
                    conn.commit()
                    logger.info("last_seen added.")
    except Exception as e:
        logger.warning(f"Migration note: {e}")
        logger.info("If this is a fresh DB, tables will be created by db.create_all().")

def init_db_with_retry(max_retries=10, delay=3):
    for attempt in range(max_retries):
        try:
            with app.app_context():
                db.create_all()
                auto_migrate()
                if not User.query.filter_by(username="admin").first():
                    admin_password = os.environ.get("ADMIN_PASSWORD")
                    if not admin_password:
                        admin_password = secrets.token_urlsafe(16)
                        logger.warning("=" * 60)
                        logger.warning("ADMIN_PASSWORD environment variable not set!")
                        logger.warning(f"Temporary admin password: {admin_password}")
                        logger.warning("Log in immediately and change this password.")
                        logger.warning("=" * 60)
                    admin = User(
                        username="admin",
                        password_hash=generate_password_hash(admin_password),
                        role="admin"
                    )
                    db.session.add(admin)
                    db.session.commit()
                    logger.info("Admin user created.")
                logger.info("Database initialized successfully.")
                return True
        except OperationalError as e:
            logger.warning(f"DB connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
        except Exception as e:
            logger.error(f"Unexpected error during DB init: {e}")
            return False
    logger.error("WARNING: Could not connect to database after all retries.")
    return False

db_ready = init_db_with_retry()

# =======================
# Global Hooks
# =======================
@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Added blob: data: and explicit allowance to resolve streaming issues with CSP
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "frame-ancestors 'none';"
    )
    response.headers["X-Frame-Options"] = "DENY"
    return response

@app.before_request
def validate_session():
    public_routes = {"login", "static", "logout", "not_found"}
    if request.endpoint in public_routes:
        return
    if "user_id" not in session or "session_token" not in session:
        return redirect(url_for("login"))
    try:
        user = User.query.get(session.get("user_id"))
        if not user:
            session.clear()
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))
        if user.is_locked():
            session.clear()
            flash("Account locked. Contact administrator.", "error")
            return redirect(url_for("login"))
        if user.active_session_token != session.get("session_token"):
            session.clear()
            flash("Session invalidated. Please log in again.", "error")
            return redirect(url_for("login"))
        if "login_time" in session:
            login_time = datetime.fromisoformat(session["login_time"])
            if datetime.utcnow() - login_time > timedelta(minutes=30):
                session.clear()
                flash("Session expired. Please log in again.", "error")
                return redirect(url_for("login"))
        user.last_seen = datetime.utcnow()
        db.session.commit()
        g.current_user = user
    except Exception as e:
        db.session.rollback()
        session.clear()
        flash("Session error. Please log in again.", "error")
        return redirect(url_for("login"))

@app.context_processor
def inject_globals():
    return dict(session=session, now=datetime.utcnow)

# =======================
# Camera Streaming Logic
# =======================
def gen_frames():
    # Read camera source from environment variable.
    # Set CAMERA_URL to an RTSP stream e.g. "rtsp://user:pass@192.168.1.10:554/stream"
    # Leave unset (or set to "0") to use the local webcam (index 0).
    camera_url = os.environ.get("CAMERA_URL", "0")
    source = int(camera_url) if camera_url.isdigit() else camera_url

    camera = cv2.VideoCapture(source)
    if not camera.isOpened():
        logger.error(f"Failed to open camera source: {source}")
        return

    try:
        while True:
            success, frame = camera.read()
            if not success:
                logger.warning("Camera read failed, stopping stream.")
                break
            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue
            frame = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
    finally:
        camera.release()

# =======================
# Routes
# =======================
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("camera"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if "user_id" in session:
        try:
            user = User.query.get(session["user_id"])
            if user and user.active_session_token == session.get("session_token") and not user.is_locked():
                return redirect(url_for("camera"))
        except Exception:
            pass
        session.clear()

    if request.method == "POST":
        username = sanitize_input(request.form.get("username"))
        password = request.form.get("password", "")
        try:
            user = User.query.filter_by(username=username).first()
            if not user:
                log_action("login_attempt", username, False, "User not found")
                flash("Invalid credentials", "error")
                return redirect(url_for("login"))
            if user.is_locked():
                log_action("login_attempt", username, False, "Account locked")
                flash("Account temporarily locked. Try again later.", "error")
                return redirect(url_for("login"))

            if check_password_hash(user.password_hash, password):
                new_token = str(uuid.uuid4())
                session.clear()
                session["user_id"] = user.id
                session["username"] = user.username
                session["role"] = user.role
                session["session_token"] = new_token
                session["login_time"] = datetime.utcnow().isoformat()
                session.modified = True

                user.failed_attempts = 0
                user.locked_until = None
                user.active_session_token = new_token
                user.last_seen = datetime.utcnow()
                db.session.commit()

                log_action("login_attempt", username, True, "Successful login")
                return redirect(url_for("camera"))
            else:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    log_action("login_attempt", username, False, "Account locked after 5 failed attempts")
                    flash("Too many failed attempts. Account locked for 15 minutes.", "error")
                else:
                    log_action("login_attempt", username, False, f"Failed attempt {user.failed_attempts}/5")
                    flash("Invalid credentials", "error")
                db.session.commit()
                return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Login error: {e}")
            flash("An error occurred. Please try again.", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/camera")
def camera():
    if "user_id" not in session:
        return redirect(url_for("login"))
    log_action("camera_view", session.get("username"), True, "Viewed camera feed")
    return render_template("camera.html")

@app.route("/video_feed")
def video_feed():
    if "user_id" not in session:
        return "Unauthorized", 401
    from flask import Response
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    try:
        pagination = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    except Exception as e:
        logger.error(f"Error loading logs: {e}")
        flash("Error loading logs", "error")
        pagination = None
    return render_template("logs.html", pagination=pagination)

@app.route("/users")
@admin_required
def users():
    try:
        all_users = User.query.order_by(User.username).all()
    except Exception as e:
        logger.error(f"Error loading users: {e}")
        flash("Error loading users", "error")
        all_users = []
    return render_template("users.html", users=all_users)

@app.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    username = sanitize_input(request.form.get("username"))
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    if not username or not password:
        flash("Username and password required", "error")
        return redirect(url_for("users"))
    pwd_error = validate_password(password)
    if pwd_error:
        flash(pwd_error, "error")
        return redirect(url_for("users"))
    if User.query.filter_by(username=username).first():
        flash("Username already exists", "error")
        return redirect(url_for("users"))
    if role not in ["viewer", "admin"]:
        role = "viewer"
    new_user = User(username=username, password_hash=generate_password_hash(password), role=role)
    db.session.add(new_user)
    db.session.commit()
    log_action("user_management", session.get("username"), True, f"Created user {username} with role {role}")
    flash(f"User {username} created successfully", "success")
    return redirect(url_for("users"))

@app.route("/users/reset-password/<int:user_id>", methods=["POST"])
@admin_required
def reset_password(user_id):
    user = User.query.get_or_404(user_id)
    new_password = request.form.get("new_password", "")
    if not new_password:
        flash("Password cannot be empty", "error")
        return redirect(url_for("users"))
    pwd_error = validate_password(new_password)
    if pwd_error:
        flash(pwd_error, "error")
        return redirect(url_for("users"))
    user.password_hash = generate_password_hash(new_password)
    user.failed_attempts = 0
    user.locked_until = None
    user.active_session_token = None
    db.session.commit()
    log_action("user_management", session.get("username"), True, f"Reset password for {user.username}")
    flash(f"Password reset for {user.username}", "success")
    return redirect(url_for("users"))

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == "admin":
        flash("Cannot delete the default admin account", "error")
        return redirect(url_for("users"))
    if user.id == session.get("user_id"):
        flash("Cannot delete your own account", "error")
        return redirect(url_for("users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    log_action("user_management", session.get("username"), True, f"Deleted user {username}")
    flash(f"User {username} deleted", "success")
    return redirect(url_for("users"))

@app.route("/users/unlock/<int:user_id>", methods=["POST"])
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    log_action("user_management", session.get("username"), True, f"Unlocked account {user.username}")
    flash(f"Account {user.username} unlocked", "success")
    return redirect(url_for("users"))

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        user = User.query.get(session["user_id"])
        if not user or not check_password_hash(user.password_hash, current_password):
            flash("Current password is incorrect.", "error")
            return redirect(url_for("change_password"))
        if new_password != confirm_password:
            flash("New passwords do not match.", "error")
            return redirect(url_for("change_password"))
        pwd_error = validate_password(new_password)
        if pwd_error:
            flash(pwd_error, "error")
            return redirect(url_for("change_password"))
        user.password_hash = generate_password_hash(new_password)
        new_token = str(uuid.uuid4())
        user.active_session_token = new_token
        session["session_token"] = new_token
        db.session.commit()
        log_action("password_change", session.get("username"), True, "User changed their password")
        flash("Password changed successfully. Please use your new password next time.", "success")
        return redirect(url_for("camera"))
    return render_template("change_password.html")

@app.route("/logout")
def logout():
    if "user_id" in session:
        try:
            user = User.query.get(session["user_id"])
            if user:
                user.active_session_token = None
                db.session.commit()
        except Exception:
            pass
        log_action("logout", session.get("username"), True, "User logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.errorhandler(404)
def not_found(e):
    log_action("page_not_found", session.get("username"), False, f"404 on {request.path}")
    return render_template("404.html"), 404

@app.errorhandler(429)
def rate_limited(e):
    log_action("rate_limit", session.get("username"), False, "Rate limit exceeded")
    flash("Too many requests. Please slow down.", "error")
    return redirect(url_for("login")), 429

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
