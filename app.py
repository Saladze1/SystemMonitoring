from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from sqlalchemy.exc import OperationalError
import os
import re
import time

app = Flask(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-before-production')

# SECURITY FIX: Session config - browser closes = session dies
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True,  # Only send over HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_TYPE=None  # Client-side session, server doesn't store it
)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///security.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='viewer')
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    username = db.Column(db.String(80))
    action = db.Column(db.String(50))
    success = db.Column(db.Boolean)
    details = db.Column(db.Text)

def init_db_with_retry(max_retries=10, delay=3):
    """Initialize DB with retry logic for Railway's parallel startup."""
    for attempt in range(max_retries):
        try:
            with app.app_context():
                db.create_all()
                if not User.query.filter_by(username='admin').first():
                    admin = User(
                        username='admin',
                        password_hash=generate_password_hash('admin123'),
                        role='admin'
                    )
                    db.session.add(admin)
                    db.session.commit()
                    print("Admin user created.")
                print("Database initialized successfully.")
                return True
        except OperationalError as e:
            print(f"DB connection attempt {attempt + 1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                time.sleep(delay)
            else:
                print("WARNING: Could not connect to database after all retries.")
                return False
        except Exception as e:
            print(f"Unexpected error during DB init: {e}")
            return False
    return False

# Run DB init with retry
db_ready = init_db_with_retry()

def sanitize_input(text):
    if not text:
        return ''
    return re.sub(r'[^\w\-]', '', text.strip())[:80]

def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_action(action, username=None, success=False, details=''):
    if not db_ready:
        return
    try:
        log = AccessLog(
            ip_address=get_client_ip(),
            username=sanitize_input(username) if username else None,
            action=action,
            success=success,
            details=details[:500]
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Failed to log action: {e}")

def is_account_locked(user):
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False

# SECURITY FIX: Global session validation - runs before EVERY request
@app.before_request
def validate_session():
    """Ensure session is valid on every request. Kill dead/invalid sessions."""
    # List of routes that don't need auth
    public_routes = ['login', 'static']

    if request.endpoint in public_routes:
        return

    # Check if user claims to be logged in
    if 'user_id' in session:
        # Verify user still exists in DB (prevents using stale session after user deletion)
        try:
            user = User.query.get(session.get('user_id'))
            if not user:
                # User was deleted, kill session
                session.clear()
                flash('Session expired. Please log in again.', 'error')
                return redirect(url_for('login'))

            # Check if account got locked since login
            if is_account_locked(user):
                session.clear()
                flash('Account has been locked. Please contact an administrator.', 'error')
                return redirect(url_for('login'))

            # Store user in g for easy access
            g.current_user = user

        except Exception as e:
            # DB error - don't crash, just clear session and redirect
            session.clear()
            flash('Session error. Please log in again.', 'error')
            return redirect(url_for('login'))
    else:
        # No session, redirect to login (except for public routes)
        if request.endpoint not in public_routes and request.method == 'GET':
            return redirect(url_for('login'))

@app.context_processor
def inject_globals():
    return dict(session=session, now=datetime.utcnow())

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('camera'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    # If already logged in, redirect
    if 'user_id' in session:
        try:
            user = User.query.get(session['user_id'])
            if user and not is_account_locked(user):
                return redirect(url_for('camera'))
        except:
            pass
        session.clear()

    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password', '')

        # CRASH FIX: Wrap ENTIRE login logic in try/except with rollback
        try:
            user = User.query.filter_by(username=username).first()

            if not user:
                log_action('login_attempt', username, False, 'User not found')
                flash('Invalid credentials', 'error')
                return redirect(url_for('login'))

            if is_account_locked(user):
                log_action('login_attempt', username, False, 'Account locked')
                flash('Account temporarily locked. Try again later.', 'error')
                return redirect(url_for('login'))

            if check_password_hash(user.password_hash, password):
                # SUCCESS: Reset failed attempts and create session
                user.failed_attempts = 0
                user.locked_until = None
                db.session.commit()

                # SECURITY FIX: Don't use permanent session - dies when browser closes
                session.clear()  # Clear any old session data first
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role
                # Don't set session.permanent = True - this makes it expire with browser

                log_action('login_attempt', username, True, 'Successful login')
                return redirect(url_for('camera'))
            else:
                # WRONG PASSWORD: Increment counter
                user.failed_attempts += 1

                if user.failed_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    log_action('login_attempt', username, False, 'Account locked after 5 failed attempts')
                    flash('Too many failed attempts. Account locked for 15 minutes.', 'error')
                else:
                    log_action('login_attempt', username, False, f'Failed attempt {user.failed_attempts}/5')
                    flash('Invalid credentials', 'error')

                db.session.commit()
                return redirect(url_for('login'))

        except Exception as e:
            # CRASH FIX: Always rollback on any error, then redirect safely
            db.session.rollback()
            print(f"Login error: {e}")
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/camera')
def camera():
    if 'user_id' not in session:
        log_action('unauthorized_access', None, False, 'Unauthenticated access to /camera')
        return redirect(url_for('login'))

    log_action('camera_view', session.get('username'), True, 'Viewed camera feed')
    return render_template('camera.html')

@app.route('/logs')
def logs():
    if 'user_id' not in session:
        log_action('unauthorized_access', None, False, 'Unauthenticated access to /logs')
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        log_action('unauthorized_access', session.get('username'), False, 'Non-admin tried to access logs')
        return redirect(url_for('camera'))

    try:
        all_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(1000).all()
    except Exception as e:
        flash('Error loading logs', 'error')
        all_logs = []

    return render_template('logs.html', logs=all_logs)

@app.route('/users')
def users():
    if 'user_id' not in session or session.get('role') != 'admin':
        log_action('unauthorized_access', session.get('username'), False, 'Non-admin tried to access user management')
        return redirect(url_for('camera'))

    try:
        all_users = User.query.order_by(User.username).all()
    except Exception as e:
        flash('Error loading users', 'error')
        all_users = []

    return render_template('users.html', users=all_users)

@app.route('/users/add', methods=['POST'])
def add_user():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('camera'))

    username = sanitize_input(request.form.get('username'))
    password = request.form.get('password', '')
    role = request.form.get('role', 'viewer')

    if not username or not password:
        flash('Username and password required', 'error')
        return redirect(url_for('users'))

    if User.query.filter_by(username=username).first():
        flash('Username already exists', 'error')
        return redirect(url_for('users'))

    if role not in ['viewer', 'admin']:
        role = 'viewer'

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    log_action('user_management', session.get('username'), True, f'Created user {username} with role {role}')
    flash(f'User {username} created successfully', 'success')
    return redirect(url_for('users'))

@app.route('/users/reset-password/<int:user_id>', methods=['POST'])
def reset_password(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('camera'))

    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password', '')

    if not new_password:
        flash('Password cannot be empty', 'error')
        return redirect(url_for('users'))

    user.password_hash = generate_password_hash(new_password)
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    log_action('user_management', session.get('username'), True, f'Reset password for {user.username}')
    flash(f'Password reset for {user.username}', 'success')
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('camera'))

    user = User.query.get_or_404(user_id)

    if user.username == 'admin':
        flash('Cannot delete the default admin account', 'error')
        return redirect(url_for('users'))

    if user.id == session.get('user_id'):
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('users'))

    username = user.username
    db.session.delete(user)
    db.session.commit()

    log_action('user_management', session.get('username'), True, f'Deleted user {username}')
    flash(f'User {username} deleted', 'success')
    return redirect(url_for('users'))

@app.route('/users/unlock/<int:user_id>', methods=['POST'])
def unlock_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('camera'))

    user = User.query.get_or_404(user_id)
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()

    log_action('user_management', session.get('username'), True, f'Unlocked account {user.username}')
    flash(f'Account {user.username} unlocked', 'success')
    return redirect(url_for('users'))

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action('logout', session.get('username'), True, 'User logged out')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found(e):
    log_action('unauthorized_access', session.get('username'), False, f'404 on {request.path}')
    return redirect(url_for('login'))

@app.errorhandler(429)
def rate_limited(e):
    log_action('login_attempt', None, False, 'Rate limit exceeded')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)