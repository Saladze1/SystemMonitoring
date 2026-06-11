import os
import re
import time
import uuid
import secrets
import logging
import pytz
import json
import threading
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_sock import Sock
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import OperationalError
from sqlalchemy import text, inspect as sa_inspect
import cv2
import numpy as np

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

# WebSocket support
sock = Sock(app)

# Latest frame (JPEG bytes) and a lock for thread safety
latest_frame = None
frame_lock = threading.Lock()

# 2. Redis Configuration for Rate Limiting
redis_url = os.environ.get("REDIS_URL")
if redis_url:
    app.config["RATELIMIT_STORAGE_URL"] = redis_url
    app.config["RATELIMIT_STRATEGY"] = "fixed-window" # or "moving-window"
else:
    # Fallback to in-memory (not ideal for production)
    app.config["RATELIMIT_STORAGE_URL"] = "memory://"

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

class NetworkDevice(db.Model):
    __tablename__ = "network_device"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False)
    mac = db.Column(db.String(17))
    hostname = db.Column(db.String(255))
    vendor = db.Column(db.String(255))
    open_ports = db.Column(db.Text)   # JSON list
    os_name = db.Column(db.String(255))
    last_seen = db.Column(db.DateTime, default=get_ph_now)

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
    # Skip for WebSocket endpoint (by path, because endpoint is None for sock routes)
    if request.path == "/ws/ingest":
        return
    
    public_routes = {"login", "static", "logout", "not_found"}
    if request.endpoint in public_routes:
        return
    
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
    if request.method == "POST":
        username = sanitize_input(request.form.get("username", ""))
        password = request.form.get("password", "")
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.is_locked():
            flash("Account is temporarily locked. Try again later.", "error")
            log_action("login_locked", username, False, "Account locked")
            return redirect(url_for("login"))
        
        if user and check_password_hash(user.password_hash, password):
            # Successful login
            user.failed_attempts = 0
            user.locked_until = None
            session_token = secrets.token_urlsafe(32)
            user.active_session_token = session_token
            db.session.commit()
            
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            session["session_token"] = session_token
            session["login_time"] = get_ph_now().isoformat()
            session.permanent = True
            
            log_action("login", username, True, "Successful login")
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("camera"))
        else:
            # Failed login
            if user:
                user.failed_attempts += 1
                if user.failed_attempts >= 5:
                    user.locked_until = get_ph_now() + timedelta(minutes=15)
                    flash("Too many failed attempts. Account locked for 15 minutes.", "error")
                    log_action("login_locked", username, False, "Locked after 5 failures")
                db.session.commit()
            log_action("login", username, False, "Invalid credentials")
            flash("Invalid username or password.", "error")
        return redirect(url_for("login"))
    
    return render_template("login.html")

@app.route("/logout")
def logout():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        if user:
            user.active_session_token = None
            db.session.commit()
            log_action("logout", session.get("username"), True, "User logged out")
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/camera")
def camera():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("camera.html")

@app.route("/logs")
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    filter_type = request.args.get("filter", "all")
    per_page = 20
    
    query = AccessLog.query
    now_ph = get_ph_now()
    
    if filter_type == "today":
        start = datetime(now_ph.year, now_ph.month, now_ph.day, tzinfo=PH_TZ)
        query = query.filter(AccessLog.timestamp >= start)
    elif filter_type == "week":
        week_ago = now_ph - timedelta(days=7)
        query = query.filter(AccessLog.timestamp >= week_ago)
    
    pagination = query.order_by(AccessLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    for log in pagination.items:
        log.display_time = log.timestamp.astimezone(PH_TZ).strftime('%Y-%m-%d %I:%M:%S %p')
    
    return render_template("logs.html", pagination=pagination, filter_type=filter_type)

@app.route("/logs/delete_old", methods=["POST"])
@admin_required
def delete_old_logs():
    now_ph = get_ph_now()
    cutoff = now_ph - timedelta(days=7)
    deleted_count = AccessLog.query.filter(AccessLog.timestamp < cutoff).delete()
    db.session.commit()
    log_action("delete_old_logs", session.get("username"), True, f"Deleted {deleted_count} logs older than 7 days")
    flash(f"Deleted {deleted_count} old log entries.", "success")
    return redirect(url_for("logs"))

# WebSocket endpoint for the agent
@sock.route('/ws/ingest')
def ingest_video(ws):
    global latest_frame
    try:
        key = ws.receive()
        expected = os.environ.get("INGEST_KEY", "")
        
        # Debug prints – will appear in Railway logs
        print(f"[SERVER] Received key repr: {repr(key)}")
        print(f"[SERVER] Expected key repr: {repr(expected)}")
        
        if key != expected:
            ws.send("INVALID KEY")
            ws.close()
            return
        ws.send("OK")
    except Exception as e:
        logger.error(f"WebSocket handshake error: {e}")
        return

    while True:
        try:
            frame_bytes = ws.receive()
            if not frame_bytes:
                break
            with frame_lock:
                latest_frame = frame_bytes
        except Exception as e:
            logger.error(f"WebSocket receive error: {e}")
            break
    ws.close()

# Endpoint for the agent to push device scans
@app.route('/ingest/devices', methods=['POST'])
@csrf.exempt
def ingest_devices():
    key = request.headers.get('X-Ingest-Key')
    if key != os.environ.get("INGEST_KEY"):
        return "Unauthorized", 401

    data = request.get_json()
    devices = data.get('devices', [])

    NetworkDevice.query.delete()
    for d in devices:
        device = NetworkDevice(
            ip=d['ip'],
            mac=d.get('mac', 'N/A'),
            hostname=d.get('hostname', ''),
            vendor=d.get('vendor', 'Unknown'),
            open_ports=json.dumps(d.get('open_ports', [])),
            os_name=d.get('os', 'Unknown'),
            last_seen=get_ph_now()
        )
        db.session.add(device)
    db.session.commit()
    log_action("device_scan", "agent", True, f"Updated {len(devices)} devices")
    return "OK", 200

# MJPEG stream for browsers
@app.route('/video_feed')
def video_feed():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    def generate():
        global latest_frame
        while True:
            try:
                with frame_lock:
                    frame = latest_frame
                if frame is not None:
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
                else:
                    placeholder = cv2.imencode('.jpg', np.zeros((480, 640, 3), np.uint8))[1].tobytes()
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n\r\n' + placeholder + b'\r\n')
            except Exception as e:
                logger.error(f"Video feed error: {e}")
                placeholder = cv2.imencode('.jpg', np.zeros((480, 640, 3), np.uint8))[1].tobytes()
                yield (b'--frame\r\n'
                       b'Content-Type: image/jpeg\r\n\r\n' + placeholder + b'\r\n')
            time.sleep(0.033)

    return Response(generate(), mimetype='multipart/x-mixed-replace; boundary=frame')
@app.route("/users")
@admin_required
def users():
    all_users = User.query.all()
    return render_template("users.html", users=all_users)

@app.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    username = sanitize_input(request.form.get("username", ""))
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    
    if not username or not password:
        flash("Username and password required.", "error")
        return redirect(url_for("users"))
    
    if User.query.filter_by(username=username).first():
        flash("Username already exists.", "error")
        return redirect(url_for("users"))
    
    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()
    log_action("add_user", session.get("username"), True, f"Added user {username}")
    flash(f"User {username} added.", "success")
    return redirect(url_for("users"))

@app.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user and user.username != session.get("username"):
        db.session.delete(user)
        db.session.commit()
        log_action("delete_user", session.get("username"), True, f"Deleted user {user.username}")
        flash(f"User {user.username} deleted.", "success")
    else:
        flash("Cannot delete yourself.", "error")
    return redirect(url_for("users"))

@app.route("/users/update_role/<int:user_id>", methods=["POST"])
@admin_required
def update_role(user_id):
    user = User.query.get(user_id)
    if user and user.username != session.get("username"):
        new_role = request.form.get("role")
        if new_role in ["admin", "viewer"]:
            user.role = new_role
            db.session.commit()
            log_action("update_role", session.get("username"), True, f"User {user.username} role -> {new_role}")
            flash(f"Role updated for {user.username}.", "success")
    else:
        flash("Cannot change your own role here.", "error")
    return redirect(url_for("users"))

@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("login"))
    
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        
        if not check_password_hash(user.password_hash, current):
            flash("Current password is incorrect.", "error")
            log_action("change_password", user.username, False, "Incorrect current password")
            return redirect(url_for("change_password"))
        
        if len(new) < 8:
            flash("New password must be at least 8 characters.", "error")
            return redirect(url_for("change_password"))
        
        if new != confirm:
            flash("New passwords do not match.", "error")
            return redirect(url_for("change_password"))
        
        user.password_hash = generate_password_hash(new)
        user.active_session_token = None
        db.session.commit()
        log_action("change_password", user.username, True, "Password changed")
        session.clear()
        flash("Password changed. Please log in again.", "success")
        return redirect(url_for("login"))
    
    return render_template("change_password.html")

@app.route('/devices')
@admin_required
def devices():
    all_devices = NetworkDevice.query.order_by(NetworkDevice.ip).all()
    return render_template('devices.html', devices=all_devices)

# =======================
# Error handlers
# =======================
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(429)
def ratelimit_exceeded(e):
    flash("Too many requests. Please slow down.", "error")
    return redirect(url_for("login"))

# =======================
# Database initialization
# =======================
def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            admin = User(
                username="admin",
                password_hash=generate_password_hash("admin123"),
                role="admin"
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Created default admin user: admin / admin123")

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
