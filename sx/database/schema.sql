-- ScratchXI Campus Security Alert System — Database Schema
-- Roles: student | staff | security | admin
-- SQLite — uses CREATE TABLE IF NOT EXISTS for safe re-runs

-- ─── Users ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'student',
    -- 'student' | 'staff' | 'security' | 'admin'
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Alerts (Incidents) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT    NOT NULL,
    location      TEXT    NOT NULL,
    campus        TEXT,
    block         TEXT,
    description   TEXT    NOT NULL,
    reported_by   INTEGER NOT NULL REFERENCES users(id),
    severity      TEXT    NOT NULL DEFAULT 'medium',
    -- 'low' | 'medium' | 'high' | 'critical'
    priority      TEXT    NOT NULL DEFAULT 'medium',
    -- 'low' | 'medium' | 'high' | 'critical'
    status        TEXT    NOT NULL DEFAULT 'open',
    -- 'open' | 'assigned' | 'under_investigation' | 'requires_reinforcements'
    -- | 'escalated' | 'false_alarm' | 'resolved' | 'closed'
    image_filename TEXT,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Assignments ───────────────────────────────────────────
-- Admin assigns an incident to a security officer.
-- One incident can be reassigned (old row stays for audit log).
CREATE TABLE IF NOT EXISTS assignments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    security_id   INTEGER NOT NULL REFERENCES users(id),
    assigned_by   INTEGER NOT NULL REFERENCES users(id),
    task_status   TEXT    NOT NULL DEFAULT 'assigned',
    -- 'assigned' | 'accepted' | 'in_progress' | 'submitted'
    notes         TEXT,   -- admin notes to security at time of assignment
    assigned_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    accepted_at   DATETIME,
    submitted_at  DATETIME,
    is_active     INTEGER NOT NULL DEFAULT 1  -- 0 when reassigned (soft history)
);

-- ─── Feedback (Investigation Reports) ─────────────────────
-- Security submits this after attending an incident.
CREATE TABLE IF NOT EXISTS feedback (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    assignment_id INTEGER REFERENCES assignments(id),
    submitted_by  INTEGER NOT NULL REFERENCES users(id),
    notes         TEXT    NOT NULL,
    status_update TEXT    NOT NULL,
    -- dropdown: 'Under Investigation' | 'Investigation Completed'
    -- | 'Requires Reinforcements' | 'Escalated' | 'Incident Resolved'
    -- | 'False Alarm' | 'Unable to Access Location' | 'Emergency Response Requested'
    submitted_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Evidence (Photo Uploads) ──────────────────────────────
-- Photo evidence attached by security after investigation.
CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    uploaded_by   INTEGER NOT NULL REFERENCES users(id),
    filename      TEXT    NOT NULL,
    uploaded_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    caption       TEXT
);

-- ─── Alert Updates Audit Log ───────────────────────────────
CREATE TABLE IF NOT EXISTS alert_updates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id),
    updated_by  INTEGER NOT NULL REFERENCES users(id),
    status      TEXT    NOT NULL,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Messages (Chat) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id     INTEGER NOT NULL REFERENCES users(id),
    receiver_role TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    is_deleted    INTEGER NOT NULL DEFAULT 0,
    room          TEXT    NOT NULL DEFAULT 'main_chat',
    -- 'main_chat' | 'private_admin_security'
    timestamp     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Deleted Messages Log ─────────────────────────────────
CREATE TABLE IF NOT EXISTS deleted_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id    INTEGER NOT NULL,
    deleted_by    INTEGER NOT NULL REFERENCES users(id),
    reason        TEXT,
    deleted_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Broadcasts ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS broadcasts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    message    TEXT    NOT NULL,
    sent_by    INTEGER NOT NULL REFERENCES users(id),
    sent_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Security Attendance Register ─────────────────────────
CREATE TABLE IF NOT EXISTS attendance (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    security_id   INTEGER NOT NULL REFERENCES users(id),
    clock_in      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    clock_out     DATETIME,
    availability  TEXT NOT NULL DEFAULT 'available',
    -- 'available' | 'unavailable'
    date_str      TEXT NOT NULL,  -- YYYY-MM-DD for easy daily queries
    is_active     INTEGER NOT NULL DEFAULT 1  -- 1 = currently clocked in
);

-- ─── Password Reset Tokens ────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token      TEXT    NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ─── Security Audit Log ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    user_name  TEXT,
    action     TEXT NOT NULL,
    detail     TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
