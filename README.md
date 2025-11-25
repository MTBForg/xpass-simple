<img width="1890" height="957" alt="image" src="https://github.com/user-attachments/assets/ec35f599-d418-400d-8d7e-23863f47a311" />



# 🔐 XPASS – Self-Hosted Encrypted Password Manager

XPASS is a **Flask + MySQL** based password management system built for **secure, offline, and LAN-based deployments**.  
It offers **encrypted password storage**, **folder-based organization**, **optional 2FA**, and an **Admin Dashboard** for managing users and auditing system activity.

---
---

## 🧭 Features Overview

### 🧑‍💼 Admin Panel
- 👥 Manage Users – Create, reset, disable accounts  
- 🔐 2FA Control – Enable or disable Two-Factor Authentication  
- 📊 Audit Dashboard – View users, folders, admins, and recent logins  

### 📁 Folder Management
- 🗂️ Folder-based credential organization  
- 🤝 Secure folder sharing with other users  
- 📤 Import / 📥 Export folder data  

### 🛡️ Security Highlights
- ✅ **Encrypted Storage** – AES encryption for every credential  
- ✅ **Self-Hosted Privacy** – Full control of data  
- ✅ **Optional 2FA** – Add another security layer  
- ✅ **Audit Overview** – System activity and stats  
- ✅ **Offline & LAN-Friendly** – No Internet required  
- ✅ **Lightweight & Fast** – Pure Flask stack  
- ✅ **Modern UI** – Responsive, Bootstrap-based  

---
## 🚀 Quick Setup Guide

### 🧩 1. Clone the Repository
```bash
git clone https://github.com/vibecodetimes/xpass-simple/
cd xpass-simple
```

---

### 🐍 2. Install Python and Pip
Ensure Python 3.9+ and pip3 are installed:
```bash
sudo apt install python3 python3-pip -y
```

---

### 📦 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

### 🗄️ 4. Install MySQL (Skip if you already have it)
```bash
sudo apt install mysql-server -y
```

---

### 🧰 5. Create Database and User
Login to MySQL:
```bash
sudo mysql -u root -p
```
*(Press Enter if no root password is set)*

Then execute:
```sql
CREATE DATABASE xpass;
CREATE USER 'xpass'@'localhost' IDENTIFIED BY 'Xpass123';
GRANT ALL PRIVILEGES ON xpass.* TO 'xpass'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Restart MySQL service:
```bash
sudo systemctl restart mysql
sudo systemctl enable mysql
```

If you already have MySQL installed, simply edit your `.env` file later:
```bash
SQLALCHEMY_DB_URI=mysql+pymysql://youruser:yourpassword@localhost/yourdb
```

---

### 🔐 6. Generate Environment & Admin User
```bash
python3 create_env.py
python3 create_admin.py
```

These scripts will:
- Create a `.env` file with secure random keys and database credentials  
- Create the first **Admin user**

After setup, remove the scripts:
```bash
rm create_env.py create_admin.py
```

---

### ▶️ 7. Run the Application
```bash
python3 app.py
```

Then open your browser:
```
http://127.0.0.1:5000
```

---

## ⚙️ Configuration Notes
- Environment variables are loaded from `.env`
- To enable forced 2FA, edit:
  ```ini
  FORCE_2FA=True
  ```
- Session cookies are HTTPOnly and Same-Site protected
- Encryption uses **PBKDF2 + Fernet (AES-128)**



## 🧱 Tech Stack

| Layer | Technology |
|-------|-------------|
| **Backend** | Flask (Python 3.9+) |
| **Database** | MySQL (SQLAlchemy ORM) |
| **Security** | Fernet (AES-128), PBKDF2-HMAC, CSRF |
| **Frontend** | HTML / CSS / Bootstrap |
| **Optional** | PyOTP + QRCode (for 2FA) |

---

## 🧩 Post-Installation

### 🔒 Restrict Access to `.env`
```bash
chmod 600 .env
```

### 🧼 Remove Setup Scripts
```bash
rm create_env.py create_admin.py
```

### ⚙️ For Production
- Set `SESSION_COOKIE_SECURE=True` after enabling HTTPS  
- Use **Gunicorn + Nginx** for deployment  
- Enable SSL (HTTPS) via **Let’s Encrypt** or your own certificate  

---

## 🧠 Troubleshooting

| Issue | Solution |
|-------|-----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| MySQL connection refused | Check `.env` → DB credentials |
| Session/login not working | Temporarily set `SESSION_COOKIE_SECURE=False` |
| 2FA not working | Ensure `FORCE_2FA=True` and system clock is accurate |



## 💖 Support the Project

If you find **XPASS** useful, consider supporting its development!  

☕ **Donate via PayPal:**  
[![PayPal](https://img.shields.io/badge/Donate-PayPal-blue.svg)](https://paypal.me/mumair590)

Your support helps keep XPASS free, secure, and improving 💫
