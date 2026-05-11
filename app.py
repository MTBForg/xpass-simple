from flask import Flask, render_template, request, redirect, flash, url_for, session
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import json
import os
import re
import base64
from io import BytesIO
from flask import send_file
from flask_wtf import FlaskForm, CSRFProtect
from flask_session import Session
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import RequestEntityTooLarge
from flask_migrate import Migrate
import pyotp
import qrcode
from dotenv import load_dotenv

# XPass crypto module — per-user zero-knowledge encryption
from crypto import (
    generate_salt, derive_master_key, derive_auth_hash,
    generate_user_encryption_key, encrypt_user_key, decrypt_user_key,
    generate_rsa_keypair, encrypt_private_key, decrypt_private_key,
    generate_folder_key, encrypt_folder_key, decrypt_folder_key,
    wrap_folder_key_for_recipient, unwrap_folder_key,
    encrypt_credential, decrypt_credential, derive_export_key,
)
from cryptography.fernet import Fernet

# Load .env into environment
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'), override=True)
FORCE_2FA = os.getenv("FORCE_2FA", "False").lower() == "true"


app = Flask(__name__)

# Use env variable for Flask secret key
app.secret_key = os.getenv("FLASK_SECRET_KEY")

# Use env variable for database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DB_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max

# Cookie security settings
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # set to True in production
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Session configuration (server-side to store keys securely)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

app.permanent_session_lifetime = timedelta(minutes=30)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)


csrf = CSRFProtect(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

class LoginForm(FlaskForm):
    identifier = StringField("Email or Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

ALLOWED_EXTENSIONS = {'enc', 'json'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Association table for User-Group many-to-many relationship
user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

# --- Models ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')

    # Authentication
    auth_hash = db.Column(db.String(255), nullable=False)
    auth_salt = db.Column(db.LargeBinary, nullable=False)

    # Per-user encryption infrastructure
    encrypted_user_key = db.Column(db.LargeBinary, nullable=True)
    user_key_salt = db.Column(db.LargeBinary, nullable=True)
    user_key_iterations = db.Column(db.Integer, default=600_000)
    rsa_public_key = db.Column(db.Text, nullable=True)
    encrypted_rsa_private_key = db.Column(db.LargeBinary, nullable=True)

    # 2FA
    twofa_secret = db.Column(db.String(32))
    twofa_enabled = db.Column(db.Boolean, default=False)

    # Relationships
    folders = db.relationship('Folder', back_populates='user', cascade='all, delete-orphan')
    credentials = db.relationship('Credential', back_populates='user', cascade='all, delete-orphan')
    notifications = db.relationship('Notification', back_populates='recipient', cascade='all, delete-orphan')
    shared_folders = db.relationship('SharedFolder', back_populates='user', cascade='all, delete-orphan')
    logins = db.relationship('LoginLog', back_populates='user', cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)

class Folder(db.Model):
    __tablename__ = 'folder'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Per-folder encryption key
    encrypted_folder_key = db.Column(db.LargeBinary, nullable=True)

    user = db.relationship('User', back_populates='folders')
    parent = db.relationship('Folder', remote_side=[id], backref=db.backref('children', cascade='all, delete-orphan'))
    credentials = db.relationship('Credential', back_populates='folder', cascade='all, delete-orphan')
    shared_with = db.relationship('SharedFolder', back_populates='folder', cascade='all, delete-orphan')

    def __init__(self, **kwargs):
        super(Folder, self).__init__(**kwargs)

class SharedFolder(db.Model):
    __tablename__ = 'shared_folder'
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # RSA-wrapped folder key envelope for recipient
    encrypted_folder_key_envelope = db.Column(db.LargeBinary, nullable=True)

    folder = db.relationship('Folder', back_populates='shared_with')
    user = db.relationship('User', back_populates='shared_folders')

    def __init__(self, **kwargs):
        super(SharedFolder, self).__init__(**kwargs)

class Credential(db.Model):
    __tablename__ = 'credential'
    id = db.Column(db.Integer, primary_key=True)
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=True)
    password = db.Column(db.Text, nullable=False)
    notes = db.Column(db.Text)

    folder = db.relationship('Folder', back_populates='credentials')
    user = db.relationship('User', back_populates='credentials')

    def __init__(self, **kwargs):
        super(Credential, self).__init__(**kwargs)

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    recipient = db.relationship('User', back_populates='notifications')

    def __init__(self, **kwargs):
        super(Notification, self).__init__(**kwargs)

class LoginLog(db.Model):
    __tablename__ = 'login_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip_address = db.Column(db.String(45))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='logins')

    def __init__(self, **kwargs):
        super(LoginLog, self).__init__(**kwargs)

class Group(db.Model):
    __tablename__ = 'group'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    members = db.relationship('User', secondary=user_groups, backref=db.backref('user_groups', lazy='dynamic'))

    def __init__(self, **kwargs):
        super(Group, self).__init__(**kwargs)

with app.app_context():
    db.create_all()

# --- Helpers ---
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.')
            return redirect(url_for('login'))

        if FORCE_2FA:
            # Force re-fetch to avoid stale data
            db.session.expire_all()
            user = User.query.get(session['user_id'])

            # Allow specific endpoints without 2FA
            exempt_endpoints = {
                'enable_2fa', 'confirm_2fa', 'get_qr', 'logout', 'static'
            }

            if not user.twofa_enabled and request.endpoint not in exempt_endpoints:
                flash("🔐 Please enable 2FA to continue.")
                return redirect(url_for('enable_2fa'))
            print("2FA CHECK >>", FORCE_2FA, request.endpoint)

        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admins only.')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return login_required(wrapper)
@app.context_processor
def inject_notifications():
    if 'user_id' in session:
        notes = Notification.query.filter_by(recipient_id=session['user_id'], is_read=False)\
                                  .order_by(Notification.timestamp.desc()).limit(5).all()
    else:
        notes = []
    return dict(global_notifications=notes)

# Access Check
def has_folder_access(user_id, folder):
    if folder.user_id == user_id:
        return True
    if SharedFolder.query.filter_by(folder_id=folder.id, shared_with_user_id=user_id).first():
        return True
    parent = folder.parent
    while parent:
        if SharedFolder.query.filter_by(folder_id=parent.id, shared_with_user_id=user_id).first():
            return True
        parent = parent.parent
    return False


def get_folder_key_for_user(folder, user_id, uek):
    """
    Resolve the folder key for a user. Two paths:
    1. Owner: decrypt folder.encrypted_folder_key with their UEK
    2. Shared user: decrypt the RSA envelope in SharedFolder using their RSA private key
    """
    if folder.user_id == user_id:
        # Owner path — decrypt folder key with UEK
        if not folder.encrypted_folder_key:
            return None
        return decrypt_folder_key(folder.encrypted_folder_key, uek)

    # Shared user path — find the envelope
    share = SharedFolder.query.filter_by(folder_id=folder.id, shared_with_user_id=user_id).first()
    if not share:
        # Check parent folders (inherited sharing)
        parent = folder.parent
        while parent:
            share = SharedFolder.query.filter_by(folder_id=parent.id, shared_with_user_id=user_id).first()
            if share:
                break
            parent = parent.parent

    if not share or not share.encrypted_folder_key_envelope:
        return None

    # Decrypt RSA private key, then unwrap the folder key
    user = User.query.get(user_id)
    master_key_b64 = session.get('master_key')
    if not master_key_b64:
        return None
    master_key = base64.urlsafe_b64decode(master_key_b64)
    master_key = master_key_b64.encode() if isinstance(master_key_b64, str) else master_key_b64
    # Actually, the master_key stored in session is already the derived Fernet key (base64-encoded bytes)
    private_pem = decrypt_private_key(user.encrypted_rsa_private_key, master_key_b64.encode())
    return unwrap_folder_key(share.encrypted_folder_key_envelope, private_pem)


def get_session_uek():
    """Get the user encryption key from the session."""
    uek_b64 = session.get('uek')
    if not uek_b64:
        return None
    return uek_b64.encode() if isinstance(uek_b64, str) else uek_b64


def setup_user_keys(password: str):
    """
    Generate all cryptographic material for a new user.
    Returns a dict with all fields to set on the User model.
    """
    # Auth path — separate salt and hash
    auth_salt = generate_salt()
    auth_hash = derive_auth_hash(password, auth_salt)

    # Encryption path — separate salt
    user_key_salt = generate_salt()
    master_key = derive_master_key(password, user_key_salt)

    # Generate User Encryption Key
    uek = generate_user_encryption_key()
    encrypted_uek = encrypt_user_key(uek, master_key)

    # Generate RSA keypair
    public_pem, private_pem = generate_rsa_keypair()
    encrypted_private = encrypt_private_key(private_pem, master_key)

    return {
        'auth_hash': auth_hash,
        'auth_salt': auth_salt,
        'encrypted_user_key': encrypted_uek,
        'user_key_salt': user_key_salt,
        'user_key_iterations': 600_000,
        'rsa_public_key': public_pem.decode(),
        'encrypted_rsa_private_key': encrypted_private,
    }

with app.app_context():
    db.create_all()





# Routes
@limiter.limit("5 per minute")

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.permanent = True
    form = LoginForm()

    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        password = form.password.data

        user = User.query.filter(
            (User.email == identifier) | (User.username == identifier)
        ).first()

        if user:
            # Derive auth hash and compare
            computed_hash = derive_auth_hash(password, user.auth_salt)
            
            if computed_hash == user.auth_hash:
                # Derive master key and decrypt UEK
                master_key = derive_master_key(password, user.user_key_salt, user.user_key_iterations)
                try:
                    uek = decrypt_user_key(user.encrypted_user_key, master_key)
                except Exception:
                    flash('❌ Vault decryption failed. Contact admin.')
                    return render_template('login.html', form=form)

                # 2FA check
                if FORCE_2FA and user.twofa_enabled:
                    session['pending_2fa_user_id'] = user.id
                    session['pending_uek'] = uek.decode()
                    session['pending_master_key'] = master_key.decode()
                    return redirect(url_for('verify_2fa'))

                # Store keys in session
                session['user_id'] = user.id
                session['username'] = user.username
                session['email'] = user.email
                session['role'] = user.role
                session['uek'] = uek.decode()            # UEK for vault operations
                session['master_key'] = master_key.decode()  # For RSA private key decryption

                db.session.add(LoginLog(
                    user_id=user.id,
                    ip_address=request.remote_addr,
                    timestamp=datetime.utcnow()
                ))
                db.session.commit()

                flash(f'✅ Welcome, {user.username}!')
                return redirect(url_for('index'))

        flash('❌ Invalid email/username or password.')

    return render_template('login.html', form=form)


@csrf.exempt
@app.route('/notifications/clear', methods=['POST'])
def clear_notifications():
    if request.method == 'POST' and 'user_id' in session:
        Notification.query.filter_by(recipient_id=session['user_id'], is_read=False).update({'is_read': True})
        db.session.commit()
        return '', 204
    return '', 400

@app.route('/enable_2fa')
@login_required
def enable_2fa():
    user = User.query.get(session['user_id'])

    if user.twofa_enabled:
        flash("2FA is already enabled.")
        return redirect(url_for('index'))

    if not user.twofa_secret:
        # Generate secret and save
        secret = pyotp.random_base32()
        user.twofa_secret = secret
        db.session.commit()

    # This will return the QR as image from separate endpoint
    return render_template("enable_2fa.html")
@app.route('/qrcode')
@login_required
def get_qr():
    user = User.query.get(session['user_id'])

    if not user.twofa_secret:
        return "No 2FA secret found. Please re-enable 2FA.", 404

    uri = pyotp.TOTP(user.twofa_secret).provisioning_uri(name=user.email, issuer_name="XPASS")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')


@app.route('/confirm_2fa', methods=['POST'])
@login_required
def confirm_2fa():
    code = request.form.get('otp')
    user = User.query.get(session['user_id'])
    totp = pyotp.TOTP(user.twofa_secret)

    if totp.verify(code):
        user.twofa_enabled = True
        db.session.commit()

        # Refresh session to ensure clean state
        session['user_id'] = user.id
        session['username'] = user.username
        session['email'] = user.email
        session['role'] = user.role

        flash("✅ 2FA has been enabled!")
        return redirect(url_for('index'))
    else:
        flash("❌ Invalid code.")
        return redirect(url_for('enable_2fa'))


@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        code = request.form.get('otp')
        user = User.query.get(session['pending_2fa_user_id'])
        totp = pyotp.TOTP(user.twofa_secret)

        if totp.verify(code):
            # Finalize login
            session['user_id'] = user.id
            session['username'] = user.username
            session['email'] = user.email
            session['role'] = user.role
            session['uek'] = session.pop('pending_uek', None)
            session['master_key'] = session.pop('pending_master_key', None)
            session.pop('pending_2fa_user_id', None)

            # Log login
            db.session.add(LoginLog(user_id=user.id, ip_address=request.remote_addr))
            db.session.commit()

            flash(f"✅ Welcome, {user.username}!")
            return redirect(url_for('index'))
        else:
            flash("❌ Invalid 2FA code.")

    return render_template("verify_2fa.html")



@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

@app.route('/credentials', methods=['GET', 'POST'])
@login_required
def credentials():
    user_id = session['user_id']
    folders = Folder.query.filter_by(user_id=user_id).all()
    cred_id = request.args.get('edit_cred', type=int)
    edit_cred = Credential.query.get(cred_id) if cred_id else None
    folder_id_default = request.args.get('folder_id', type=int)

    if request.method == 'POST':
        name = request.form['name']
        url = request.form['url']
        password = request.form['password']
        notes = request.form['notes']
        folder_id = request.form['folder_id']
        username = request.form['username']
        
        folder = Folder.query.get(folder_id)
        if not folder:
            flash("Folder not found.")
            return redirect(url_for('credentials'))
            
        folder_key = get_folder_key_for_user(folder, user_id, get_session_uek())
        if not folder_key:
            flash('Error: Could not retrieve folder encryption key.')
            return redirect(url_for('view', folder_id=folder_id))

        encrypted_pw = encrypt_credential(password, folder_key)

        if edit_cred and edit_cred.user_id == user_id:
            edit_cred.name = name
            edit_cred.url = url
            edit_cred.username = username
            edit_cred.password = encrypted_pw
            edit_cred.notes = notes
            edit_cred.folder_id = folder_id
            flash('Credential updated!')
        else:
            new_cred = Credential(
                name=name,
                url=url,
                username=username,
                password=encrypted_pw,
                notes=notes,
                folder_id=folder_id,
                user_id=user_id
            )
            db.session.add(new_cred)
            flash('Credential added!')

        db.session.commit()
        return redirect(url_for('view', folder_id=folder_id))

    if edit_cred:
        folder_key = get_folder_key_for_user(edit_cred.folder, user_id, get_session_uek())
        try:
            edit_cred.decrypted_password = decrypt_credential(edit_cred.password, folder_key) if folder_key else ''
        except:
            edit_cred.decrypted_password = ''

    # ✅ Show only own credentials
    own_credentials = Credential.query.filter_by(user_id=user_id).all()
    uek = get_session_uek()
    for cred in own_credentials:
        folder_key = get_folder_key_for_user(cred.folder, user_id, uek)
        try:
            cred.decrypted_password = decrypt_credential(cred.password, folder_key) if folder_key else '[No Key]'
        except:
            cred.decrypted_password = '[Decryption Failed]'

    return render_template(
        'index.html',
        folders=folders,
        credentials=own_credentials,
        edit_cred=edit_cred,
        folder_id_default=folder_id_default
    )


@app.route('/search_credentials')
@login_required
def search_credentials():
    query = request.args.get('q', '').strip().lower()
    user_id = session['user_id']

    if not query:
        flash("Please enter a search term.")
        return redirect(url_for('view'))

    # Get all folder IDs user owns
    own_folders = Folder.query.filter_by(user_id=user_id).all()
    own_folder_ids = {f.id for f in own_folders}

    # Get folder IDs shared with user
    shared_links = SharedFolder.query.filter_by(shared_with_user_id=user_id).all()
    shared_folder_ids = {link.folder_id for link in shared_links}

    # All folders user can access
    accessible_folder_ids = own_folder_ids | shared_folder_ids

    # Search credentials in those folders
    results = Credential.query.filter(
        Credential.folder_id.in_(accessible_folder_ids)
    ).all()

    # Filter manually based on query
    filtered = [
        cred for cred in results
        if query in cred.name.lower() or query in cred.url.lower() or query in (cred.notes or '').lower()
    ]

    uek = get_session_uek()
    # Decrypt and build folder paths
    for cred in filtered:
        folder_key = get_folder_key_for_user(cred.folder, user_id, uek)
        try:
            cred.decrypted_password = decrypt_credential(cred.password, folder_key) if folder_key else '[No Key]'
        except:
            cred.decrypted_password = '[Decryption Failed]'

        # Build folder path
        path_parts = []
        current = cred.folder
        while current:
            path_parts.insert(0, current.name)
            current = current.parent
        cred.folder_path = " / " + " / ".join(path_parts)

    # ✅ RETURN TEMPLATE!
    return render_template('search_results.html', results=filtered, query=query)

@app.route('/')
@login_required
def index():
    return redirect(url_for('view'))


@app.route('/view')
@login_required
def view():
    folder_id = request.args.get('folder_id', type=int)
    user_id = session['user_id']
    current_folder = Folder.query.get(folder_id) if folder_id else None

    if current_folder and not has_folder_access(user_id, current_folder):
        flash("You don't have access to this folder.")
        return redirect(url_for('index'))

    is_owner = current_folder and current_folder.user_id == user_id

    # ✅ Subfolders filtering
    if folder_id is None:
        # Root level — only show user's own folders
        subfolders = Folder.query.filter_by(parent_id=None, user_id=user_id).all()
    else:
        # Inside a folder — show all accessible subfolders (including shared)
        raw_subfolders = Folder.query.filter_by(parent_id=folder_id).all()
        subfolders = [f for f in raw_subfolders if has_folder_access(user_id, f)]

    # ✅ Credentials filtering — same logic
    raw_credentials = Credential.query.filter_by(folder_id=folder_id).all()
    credentials = [c for c in raw_credentials if has_folder_access(user_id, c.folder)]

    uek = get_session_uek()
    for cred in credentials:
        folder_key = get_folder_key_for_user(cred.folder, user_id, uek)
        try:
            cred.decrypted_password = decrypt_credential(cred.password, folder_key) if folder_key else '[No Key]'
        except:
            cred.decrypted_password = '[Decryption Failed]'

    return render_template('view.html',
                           current_folder=current_folder,
                           subfolders=subfolders,
                           credentials=credentials,
                           is_owner=is_owner)


@app.route('/share_folder', methods=['POST'])
@login_required
def share_folder():
    folder_id = request.form.get('folder_id')
    user_id = request.form.get('shared_with_user_id')

    if not folder_id or not user_id:
        flash("❌ Folder and user must be selected.")
        return redirect(url_for('folders'))

    folder_id = int(folder_id)
    user_id = int(user_id)

    # Prevent sharing non-existing folders
    folder = Folder.query.get(folder_id)
    if not folder:
        flash("❌ Selected folder does not exist.")
        return redirect(url_for('folders'))
    
  # First, fetch the folder (if not already fetched)
    folder = Folder.query.get_or_404(folder_id)

    # Prevent duplicates
    existing = SharedFolder.query.filter_by(folder_id=folder_id, shared_with_user_id=user_id).first()
    if existing:
        flash('Already shared.')
    else:
        shared_user = User.query.get(user_id)
        if not shared_user or not shared_user.rsa_public_key:
            flash("Cannot share with this user (missing RSA public key).")
            return redirect(url_for('folders'))
            
        # Owner needs to retrieve the folder key to wrap it
        folder_key = get_folder_key_for_user(folder, session['user_id'], get_session_uek())
        if not folder_key:
            flash("Error: Could not retrieve folder encryption key for sharing.")
            return redirect(url_for('folders'))
            
        envelope = wrap_folder_key_for_recipient(folder_key, shared_user.rsa_public_key.encode())

        shared = SharedFolder(
            folder_id=folder_id,
            shared_with_user_id=user_id,
            encrypted_folder_key_envelope=envelope
        )
        db.session.add(shared)

        # Create and add notification
        new_note = Notification(
            recipient_id=user_id,
            message=f"📁 Folder '{folder.name}' shared with you by {session.get('username', 'Someone')}"
        )
        db.session.add(new_note)

        db.session.commit()
        flash('Folder shared successfully!')

    return redirect(url_for('folders'))


@app.route('/shared')
@login_required
def shared():
    user_id = session['user_id']
    shared_links = SharedFolder.query.filter_by(shared_with_user_id=user_id).all()
    folders = [link.folder for link in shared_links]
    return render_template('shared.html', folders=folders)
@app.route('/manage_sharing')
@login_required
def manage_sharing():
    user_id = session['user_id']
    # Only show folders you own
    folders = Folder.query.filter(
    Folder.user_id == session['user_id'],
    Folder.shared_with.any()
).all()
    return render_template('manage_sharing.html', folders=folders)
@app.route('/unshare_folder', methods=['POST'])
@login_required
def unshare_folder():
    folder_id = int(request.form['folder_id'])
    user_id = int(request.form['shared_with_user_id'])

    folder = Folder.query.get_or_404(folder_id)

    # Only folder owner can unshare
    if folder.user_id != session['user_id']:
        flash("❌ Only the folder owner can unshare.")
        return redirect(url_for('folders'))

    # Remove the sharing entry
    shared = SharedFolder.query.filter_by(folder_id=folder_id, shared_with_user_id=user_id).first()
    if shared:
        db.session.delete(shared)

        # Add unshare notification
        note = Notification(
            recipient_id=user_id,
            message=f"❌ Folder '{folder.name}' was unshared by {session.get('username', 'someone')}"
        )
        db.session.add(note)

        db.session.commit()
        print(">>> Notification added:", note.message)
        flash("✅ User unshared successfully.")
    else:
        flash("⚠️ This user was not shared with this folder.")

    return redirect(url_for('manage_sharing'))


@app.route('/folders', methods=['GET', 'POST'])
@login_required
def folders():
    if request.method == 'POST':
        name = request.form['name']
        parent_id = request.form.get('parent_id') or None
        if parent_id == '':
            parent_id = None
        existing = Folder.query.filter_by(name=name, parent_id=parent_id, user_id=session['user_id']).first()
        if existing:
            flash(f'❌ Folder "{name}" already exists under the same parent.')
            return redirect(url_for('folders'))

        new_folder = Folder(name=name, parent_id=parent_id, user_id=session['user_id'])
        
        # Generate new per-folder key and encrypt it with user's UEK
        folder_key = generate_folder_key()
        new_folder.encrypted_folder_key = encrypt_folder_key(folder_key, get_session_uek())
        
        db.session.add(new_folder)
        db.session.commit()
        flash('Folder created successfully!')
        return redirect(url_for('folders'))
    parent_id = request.args.get('parent_id', type=int)
    all_folders = Folder.query.filter_by(user_id=session['user_id']).all()
    users = User.query.all()
   
    return render_template('folders.html', folders=all_folders, users=users, parent_id=parent_id)

@app.route('/delete_cred/<int:id>')
@login_required
def delete_cred(id):
    cred = Credential.query.get_or_404(id)
    if cred.user_id != session['user_id']:
        flash("You can't delete this credential.")
        return redirect(url_for('index'))
    folder_id = cred.folder_id
    db.session.delete(cred)
    db.session.commit()
    flash('Credential deleted!')
    return redirect(url_for('view', folder_id=folder_id))

@app.route('/delete_folder/<int:id>')
@login_required
def delete_folder(id):
    folder = Folder.query.get_or_404(id)

    if folder.user_id != session['user_id']:
        flash("You don't have permission to delete this folder.")
        return redirect(url_for('folders'))

    if folder.children or folder.credentials:
        flash('❌ Folder is not empty. Delete contents first.','danger ')
        return redirect(url_for('folders'))

    # ✅ Delete any shared links before deleting the folder
    SharedFolder.query.filter_by(folder_id=folder.id).delete()

    db.session.delete(folder)
    db.session.commit()
    flash('✅ Folder deleted successfully!')
    return redirect(url_for('folders'))



@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        # Manual user creation
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        if not username or not email or not password:
            flash("❌ All fields are required.")
            return redirect(url_for('manage_users'))

        if (
            len(password) < 6 or
            not any(c.islower() for c in password) or
            not any(c.isupper() for c in password) or
            not any(c.isdigit() for c in password) or
            not any(not c.isalnum() for c in password)
        ):
            flash("❌ Password must include uppercase, lowercase, number, and special character.")
            return redirect(url_for('manage_users'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('❌ Username or Email already exists.')
        else:
            user_keys = setup_user_keys(password)
            user = User(
                username=username,
                email=email,
                role=role,
                **user_keys
            )
            db.session.add(user)
            db.session.commit()
            flash('✅ User created!')

    # Load user data and stats
    users = User.query.all()
    return render_template(
        'admin_users.html',
        users=users,
        total_users=len(users),
        admin_count=User.query.filter_by(role='admin').count(),
        total_creds=Credential.query.count(),
        total_folders=Folder.query.count(),
        login_logs=LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(20).all()
    )


@app.route('/admin/reset_password/<int:id>', methods=['POST'])
@admin_required
def reset_password(id):
    user = User.query.get_or_404(id)
    new_password = request.form['new_password']

    # ✅ Password must include: 1 lowercase, 1 uppercase, 1 digit, 1 special, min 6 chars
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+={}\[\]:;"\'<>,.?/~`\\|-]).{6,}$'

    if not re.match(pattern, new_password):
        flash("❌ Password must be at least 6 characters long and include 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character.")
        return redirect(url_for('manage_users'))

    user_keys = setup_user_keys(new_password)
    for key, value in user_keys.items():
        setattr(user, key, value)
        
    db.session.commit()
    flash("✅ Password has been reset! Note: Previous vault data is unrecoverable (Zero-Knowledge Architecture).")
    return redirect(url_for('manage_users'))
@app.route('/admin/edit_user', methods=['POST'])
@admin_required
def edit_user():
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    role = request.form.get('role')

    # Validate form data
    if not all([user_id, username, email, role]):
        flash("❌ All fields are required.")
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)

    # Optional: Validate email format
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        flash("❌ Invalid email format.")
        return redirect(url_for('manage_users'))

    user.username = username.strip()
    user.email = email.strip()
    user.role = role.strip().lower()

    db.session.commit()
    flash("✅ User details updated successfully!")
    return redirect(url_for('manage_users'))


@app.route('/admin/update_role/<int:id>', methods=['POST'])
@admin_required
def update_role(id):
    user = User.query.get_or_404(id)
    user.role = request.form['role']
    db.session.commit()
    flash('User role updated!')
    return redirect(url_for('manage_users'))

@app.route('/admin/delete_user/<int:id>', methods=['POST'])
@admin_required
def delete_user(id):
    user = User.query.get_or_404(id)

    if user.id == session['user_id']:
        flash("❌ You can't delete yourself.")
        return redirect(url_for('manage_users'))

    if user.credentials or Folder.query.filter_by(user_id=user.id).count() > 0:
        flash("❌ Cannot delete user with saved credentials or folders.")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash("✅ User deleted successfully.")
    return redirect(url_for('manage_users'))


@app.route('/import_export', methods=['GET', 'POST'])
@login_required
def import_export():
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form.get('import_password')
        target_folder_id = request.form.get('import_folder_id', type=int)

        if not file or not allowed_file(file.filename):
            flash("❌ Invalid file type. Only .json allowed.")
            return redirect(url_for('import_export'))

        if file and password and target_folder_id:
            try:
                content = json.loads(file.read())
                salt = base64.b64decode(content['salt'])
                encrypted = content['cipher'].encode()

                key = derive_export_key(password, salt)
                f = Fernet(key)
                decrypted = f.decrypt(encrypted)
                data = json.loads(decrypted)

                target_folder = Folder.query.get(target_folder_id)
                folder_key = get_folder_key_for_user(target_folder, session['user_id'], get_session_uek())
                if not folder_key:
                    raise ValueError("Cannot access target folder encryption key")

                for item in data:
                    new_cred = Credential(
                        folder_id=target_folder_id,  # 👈 overwrite destination
                        user_id=session['user_id'],
                        name=item['name'],
                        url=item['url'],
                        username=item.get('username', ''),
                        password=encrypt_credential(item['password'], folder_key),
                        notes=item.get('notes', '')
                    )
                    db.session.add(new_cred)
                db.session.commit()
                flash(f'✅ {len(data)} credentials imported into selected folder.')
            except Exception as e:
                flash(f"❌ Failed to import: {str(e)}")
        else:
            flash("❌ File, password and folder selection required.")

        return redirect(url_for('import_export'))

    folders = Folder.query.filter_by(user_id=session['user_id']).all()
    return render_template('import_export.html', folders=folders)



@app.route('/export_credentials', methods=['POST'])
@login_required
def export_credentials():
    password = request.form.get('export_password')
    folder_id = request.form.get('export_folder_id', type=int)

    if not password:
        flash("❌ Export password required")
        return redirect(url_for('import_export'))

    if not folder_id:
        flash("❌ Folder must be selected for export")
        return redirect(url_for('import_export'))

    folder = Folder.query.get(folder_id)
    folder_key = get_folder_key_for_user(folder, session['user_id'], get_session_uek())
    if not folder_key:
        flash("❌ Cannot access folder encryption key")
        return redirect(url_for('import_export'))

    creds = Credential.query.filter_by(user_id=session['user_id'], folder_id=folder_id).all()
    if not creds:
        flash("❌ No credentials found in selected folder")
        return redirect(url_for('import_export'))

    data = [
        {
            "name": c.name,
            "url": c.url,
            "username": c.username,
            "password": decrypt_credential(c.password, folder_key),
            "notes": c.notes,
            "folder_id": folder_id  # retain original
        }
        for c in creds
    ]

    json_data = json.dumps(data).encode()
    salt = os.urandom(16)
    key = derive_export_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(json_data)

    final = {
        "salt": base64.b64encode(salt).decode(),
        "cipher": encrypted_data.decode()
    }

    return send_file(
        BytesIO(json.dumps(final).encode()),
        download_name=f'credentials_folder_{folder_id}.json',
        as_attachment=True,
        mimetype='application/json'
    )


@app.route('/admin/groups', methods=['GET', 'POST'])
@admin_required
def manage_groups():
    if request.method == 'POST':
        name = request.form.get('group_name')
        if name:
            if not Group.query.filter_by(name=name).first():
                new_group = Group(name=name)
                db.session.add(new_group)
                db.session.commit()
                flash(f"✅ Group '{name}' created.")
            else:
                flash(f"❌ Group '{name}' already exists.")
        return redirect(url_for('manage_groups'))
    
    groups = Group.query.all()
    users = User.query.all()
    return render_template("admin_groups.html", groups=groups, users=users)

@app.route('/admin/rename_group/<int:group_id>', methods=['POST'])
@admin_required
def rename_group(group_id):
    group = Group.query.get_or_404(group_id)
    new_name = request.form.get('new_name')
    if new_name:
        group.name = new_name
        db.session.commit()
        flash(f"✅ Group renamed to '{new_name}'.")
    return redirect(url_for('manage_groups'))

@app.route('/admin/delete_group/<int:group_id>', methods=['POST'])
@admin_required
def delete_group(group_id):
    group = Group.query.get_or_404(group_id)
    name = group.name
    db.session.delete(group)
    db.session.commit()
    flash(f"✅ Group '{name}' deleted.")
    return redirect(url_for('manage_groups'))

@app.route('/admin/update_group_members/<int:group_id>', methods=['POST'])
@admin_required
def update_group_members(group_id):
    group = Group.query.get_or_404(group_id)
    user_ids = request.form.getlist('user_ids')
    
    # Update members
    group.members = []
    for uid in user_ids:
        u = User.query.get(int(uid))
        if u:
            group.members.append(u)
    
    db.session.commit()
    flash(f"✅ Members updated for group '{group.name}'.")
    return redirect(url_for('manage_groups'))

@app.route('/admin/reset_2fa/<int:id>', methods=['POST'])
@admin_required
def reset_2fa(id):
    user = User.query.get_or_404(id)

    if user.role == 'admin' and user.id == session['user_id']:
        flash("❌ You can't reset your own 2FA.")
        return redirect(url_for('manage_users'))

    user.twofa_enabled = False
    user.twofa_secret = None
    db.session.commit()

    flash(f"✅ 2FA has been reset for {user.username}.")
    return redirect(url_for('manage_users'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)