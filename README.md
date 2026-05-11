<img width="1890" height="957" alt="XPass Header" src="https://github.com/user-attachments/assets/ec35f599-d418-400d-8d7e-23863f47a311" />

# 🔐 XPASS – Zero-Knowledge Password Manager

XPASS is a **Zero-Knowledge, Flask + MySQL** based password management system designed for maximum security and self-hosted privacy. It implements a robust per-user cryptographic key hierarchy ensuring that even with database access, no one (not even admins) can read user passwords without their Master Password.

---

## 🧭 Features Overview

### 🛡️ Zero-Knowledge Architecture
- **Master Password Privacy**: Your Master Password is never stored. It is used only to derive encryption keys in-memory.
- **Key Hierarchy**: A multi-layered encryption scheme (Master Key → UEK → Folder Key → Credentials).
- **RSA Secure Sharing**: Share folders with other users using asymmetric RSA encryption.

### 🧑‍💼 Admin & Audit
- **Admin Dashboard**: Comprehensive user management (creation, role management, account status).
- **Audit Logs**: Real-time tracking of login attempts and system activity.
- **Notifications**: Instant alerts for folder sharing and security events.

### 📁 Advanced Organization
- **Hierarchical Folders**: Infinite nesting of folders for clean organization.
- **Secure sharing**: Grant access to folders while maintaining encryption integrity.
- **Import / Export**: Password-protected exports for backups.

---

## 🔒 Security Architecture

XPASS uses a per-user key hierarchy to isolate data:

1.  **Master Password** → Derives **Master Key** (PBKDF2-HMAC-SHA256, 600k iterations).
2.  **Master Key** → Encrypts **User Encryption Key (UEK)** and **RSA Private Key**.
3.  **UEK** → Encrypts **Folder Keys**.
4.  **Folder Keys** → Encrypt individual **Credentials** (AES-128 via Fernet).
5.  **RSA Envelope** → Wraps Folder Keys for secure sharing between users.

---

## 🚀 Quick Setup Guide

### 🧩 1. Clone & Prepare
```bash
git clone https://github.com/vibecodetimes/xpass-simple/
cd xpass-simple
pip install -r requirements.txt
```

### 🗄️ 2. Database Setup (MySQL)
Create the database and user:
```sql
CREATE DATABASE xpass;
CREATE USER 'xpass'@'localhost' IDENTIFIED BY 'Xpass123';
GRANT ALL PRIVILEGES ON xpass.* TO 'xpass'@'localhost';
FLUSH PRIVILEGES;
```

### ⚙️ 3. Configuration
Create a `.env` file in the root directory:
```ini
FLASK_SECRET_KEY=your_random_secret_key
SQLALCHEMY_DB_URI=mysql+pymysql://xpass:Xpass123@localhost/xpass
FORCE_2FA=False
```

### 👤 4. Create Admin User
```bash
python3 create_admin.py
```
This script will prompt for credentials and initialize the cryptographic infrastructure for the first administrator.

### ▶️ 5. Run the Application
```bash
python3 app.py
```
Visit `http://127.0.0.1:5000` to log in.

---

## 🧱 Tech Stack

| Layer | Technology |
|-------|-------------|
| **Backend** | Flask 3.x, SQLAlchemy ORM |
| **Database** | MySQL / MariaDB |
| **Symmetric Enc** | Fernet (AES-128 CBC + HMAC-SHA256) |
| **Asymmetric Enc** | RSA-2048 (OAEP Padding) |
| **Key Derivation** | PBKDF2-HMAC-SHA256 (600,000 iterations) |
| **2FA** | PyOTP (TOTP) + QRCode |
| **Session** | Server-side Filesystem Sessions |

---

## 🧠 Production Hardening

- **HTTPS**: Always deploy behind a reverse proxy (Nginx/Apache) with SSL.
- **Secure Cookies**: Set `SESSION_COOKIE_SECURE=True` in `.env` when using HTTPS.
- **Environment**: Set `FLASK_ENV=production` and use `gunicorn` to serve the app.
- **Database**: Ensure MySQL is configured with strong passwords and restricted network access.

---

## 💖 Support the Project

If you find **XPASS** useful, consider supporting its development!

[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/mumair590)

---
© 2024 XPass Security Team. Built for Privacy.
