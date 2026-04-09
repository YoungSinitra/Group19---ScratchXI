# 🛡️ Campus Security Alert System

A real-time campus security web application built with Flask, SQLite, and Flask-SocketIO.

---

## 📁 Project Structure

```
campus_security_system/
│
├── app.py                    # Main Flask application
│
├── templates/
│   ├── login.html            # Login page
│   ├── register.html         # Registration page
│   ├── dashboard.html        # Main user dashboard (live alerts)
│   ├── report_incident.html  # Incident report form
│   ├── admin_dashboard.html  # Admin control panel
│   └── chat.html             # Real-time chat page
│
├── static/
│   ├── style.css             # All CSS styling
│   ├── script.js             # Dashboard SocketIO logic
│   └── chat.js               # Chat SocketIO logic
│
├── database/
│   ├── schema.sql            # SQLite table definitions
│   └── database.db           # Auto-created on first run
│
└── README.md                 # This file
```

---

## ⚙️ Setup Instructions

### Step 1 — Make sure Python is installed

```bash
python --version
# Should show Python 3.8 or higher
```

### Step 2 — Install required packages

```bash
pip install flask flask-socketio
```

### Step 3 — Navigate to the project folder

```bash
cd campus_security_system
```

### Step 4 — Run the application

```bash
python app.py
```

The app will:
1. Automatically create the `database.db` file on first run
2. Seed a default admin account
3. Start the server at `http://localhost:5000`

### Step 5 — Open in your browser

```
http://localhost:5000
```

---

## 👤 Default Accounts

| Role           | Email               | Password  |
|----------------|---------------------|-----------|
| Security Admin | admin@campus.edu    | admin123  |

You can register new student/staff accounts from the `/register` page.

---

## 🔑 User Roles

| Role            | Can Do                                                  |
|-----------------|----------------------------------------------------------|
| `student`       | View dashboard, report incidents, use chat              |
| `staff`         | Same as student                                          |
| `security_admin`| All of above + manage alerts, update status, broadcast  |

---

## 📡 How Real-Time Works (SocketIO)

```
User reports incident
        ↓
Flask saves to database
        ↓
Flask calls socketio.emit('receive_alert', data)
        ↓
ALL connected browsers receive the event
        ↓
JavaScript updates the page — no refresh needed!
```

### Key SocketIO Events

| Event Name           | Direction          | Purpose                              |
|----------------------|--------------------|--------------------------------------|
| `receive_alert`      | Server → All       | New incident reported                |
| `alert_status_update`| Server → All       | Admin changed alert status           |
| `alert_deleted`      | Server → All       | Admin deleted a false alert          |
| `send_message`       | Client → Server    | User sends a chat message            |
| `receive_message`    | Server → All       | Broadcast chat message to everyone   |
| `broadcast_alert`    | Client → Server    | Admin sends emergency broadcast      |
| `emergency_broadcast`| Server → All       | Emergency message shown on all pages |

---

## 🛠️ Troubleshooting

**Port already in use:**
```bash
# Change port in app.py:
socketio.run(app, debug=True, host='0.0.0.0', port=5001)
```

**Database issues:**
```bash
# Delete and recreate:
rm database/database.db
python app.py
```

**Missing packages:**
```bash
pip install flask flask-socketio eventlet
```

---

## 🧩 How to Extend This Project

- **Add image uploads** — Use Flask's `request.files` and save to `/static/uploads/`
- **Add email notifications** — Use `smtplib` or Flask-Mail
- **Add a map view** — Embed Google Maps API in the dashboard
- **Add push notifications** — Use browser Notification API in JavaScript
- **Deploy online** — Use Render.com or Railway.app (free hosting)

---

## 📚 Technologies Used

- **Flask** — Python web framework
- **Flask-SocketIO** — Real-time WebSocket communication
- **SQLite** — Lightweight database (no setup required)
- **Jinja2** — HTML templating (built into Flask)
- **Socket.IO (JS)** — Browser-side real-time library
- **DM Sans + Syne** — Google Fonts

---

*Built as a university group project. Feel free to modify and extend!*
