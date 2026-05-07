from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import re

app = Flask(__name__)

# Security: Strong secret key from env only
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY environment variable must be set")

# Security: Session config
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# Database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///security.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Rate limiting (5 login attempts per minute per IP)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Models
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

# Create tables + default admin
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

# Helpers
def sanitize_input(text):
    """Remove any non-alphanumeric characters except underscore and hyphen"""
    if not text:
        return ''
    return re.sub(r'[^\w\-]', '', text.strip())[:80]

def get_client_ip():
    """Get real IP even behind proxy"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def log_action(action, username=None, success=False, details=''):
    log = AccessLog(
        ip_address=get_client_ip(),
        username=sanitize_input(username) if username else None,
        action=action,
        success=success,
        details=details[:500]
    )
    db.session.add(log)
    db.session.commit()

def is_account_locked(user):
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False

# Context processor for templates
@app.context_processor
def inject_user():
    return dict(session=session)

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('camera'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('camera'))
    
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password', '')
        
        # Log attempt regardless
        user = User.query.filter_by(username=username).first()
        
        if not user:
            log_action('login_attempt', username, False, 'User not found')
            flash('Invalid credentials', 'error')
            return redirect(url_for('login'))
        
        # Check lockout
        if is_account_locked(user):
            log_action('login_attempt', username, False, f'Account locked until {user.locked_until}')
            flash('Account temporarily locked. Try again later.', 'error')
            return redirect(url_for('login'))
        
        if check_password_hash(user.password_hash, password):
            # Success: reset failed attempts
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            log_action('login_attempt', username, True, 'Successful login')
            return redirect(url_for('camera'))
        else:
            # Failed: increment counter
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
    
    all_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(1000).all()
    return render_template('logs.html', logs=all_logs)

@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action('logout', session.get('username'), True, 'User logged out')
    session.clear()
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
