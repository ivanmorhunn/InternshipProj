# Project 3 — MeshCloud

## What This Is

MeshCloud is a self-hosted private cloud storage application built with Flask and SQLite. It runs on a Raspberry Pi and is accessible from any device on the Headscale mesh network (Project 2). Users can register, upload/download files, organize folders, message each other, and share files — all without relying on any third-party cloud service.

An admin panel allows the server operator to manage users, view audit logs, monitor system health, and handle account recovery.

---

## Features

- User registration and login with bcrypt password hashing
- File upload, download, folder organization, and trash/restore
- Storage quotas per user (default 500MB)
- File extension and malware signature blocking
- User-to-user messaging and friend system
- File transfer requests between users
- Account recovery via security questions and admin-generated tokens
- Login lockout after repeated failed attempts (with escalating lockout times)
- Admin panel: user management, session viewer, audit logs, system health (CPU/RAM/disk)
- Full audit logging of all security-relevant events

---

## Prerequisites

- Python 3.8 or higher
- pip
- Any modern web browser

Check your Python version:
```bash
python3 --version
```

---

## File Structure

```
project3-meshcloud/
├── README.md               ← You are here
├── app.py                  ← Main Flask application (all backend logic)
├── requirements.txt        ← Python dependencies
├── admin.conf.example      ← Admin credentials format (copy and rename)
├── .gitignore
└── static/
    ├── index.html          ← Main user-facing web interface
    └── admin.html          ← Admin panel interface
```

The following are generated automatically at runtime (not included in repo):
- `meshcloud.db` — SQLite database (created on first run)
- `admin.conf` — Admin credentials (you create this from the example)
- `storage/` — User file storage directory
- `trash/` — Deleted files directory

---

## Setup Instructions

### Step 1: Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/meshcloud-internship.git
cd meshcloud-internship/project3-meshcloud
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

If you're on a system that requires it:
```bash
pip install -r requirements.txt --break-system-packages
```

### Step 3: Configure Admin Credentials

```bash
# Copy the example config
cp admin.conf.example admin.conf

# Edit it with your desired admin username and password
nano admin.conf
```

The file format is:
```
ADMIN_USERNAME=admin
ADMIN_PASSWORD=yourpasswordhere
```

> **Note**: If you skip this step, the app will auto-create `admin.conf` with the default credentials `admin` / `changeme123` on first run. Change these immediately.

### Step 4: Run the Application

```bash
python3 app.py
```

You should see:
```
[MeshCloud] Created config at /path/to/admin.conf   (only on first run)
 * Running on http://0.0.0.0:5000
```

### Step 5: Open in Browser

- **User interface**: http://localhost:5000
- **Admin panel**: http://localhost:5000/admin

If running on a Raspberry Pi and accessing from another device on the same network or Headscale mesh, replace `localhost` with the Pi's IP address:
- http://192.168.1.X:5000  (local network)
- http://100.64.0.X:5000   (Headscale mesh IP)

---

## Creating Your First Account

1. Go to http://localhost:5000
2. Click **Register**
3. Fill in username, password, and a security question/answer (used for account recovery)
4. Log in

---

## Admin Panel

1. Go to http://localhost:5000/admin
2. Log in with the credentials from your `admin.conf`

From the admin panel you can:
- View all registered users and their storage usage
- Lock/unlock accounts
- Reset login lockouts
- Generate account recovery codes
- View active sessions
- Read the full audit log
- Monitor CPU, RAM, and disk usage (requires `psutil`, included in requirements)

---

## Stopping the Server

Press `Ctrl+C` in the terminal where the app is running.

---

## Running on a Raspberry Pi (Recommended Setup)

To keep MeshCloud running in the background after you close the terminal:

```bash
# Install screen
sudo apt install screen -y

# Start a named session
screen -S meshcloud

# Run the app
python3 app.py

# Detach from screen (app keeps running): Ctrl+A then D

# Reattach later
screen -r meshcloud
```

Alternatively, create a systemd service for automatic startup — see the Headscale README for an example of how systemd service files work.

---

## Security Notes

- `admin.conf` and `meshcloud.db` are listed in `.gitignore` and should **never** be committed to GitHub
- The app blocks uploads of executable file types (`.exe`, `.sh`, `.php`, etc.) and scans for malware signatures
- All passwords are hashed with bcrypt — the plaintext is never stored
- Sessions expire and are tracked by IP and device name
- All login attempts, file operations, and admin actions are logged in the audit log
