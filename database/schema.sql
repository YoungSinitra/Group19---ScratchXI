-- ScratchXI Campus Security Alert System — Database Schema
-- Roles: student | staff | security | admin
-- PostgreSQL — uses CREATE TABLE IF NOT EXISTS for safe re-runs

-- ─── Users ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    name          TEXT    NOT NULL,
    email         TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'student',
    -- 'student' | 'staff' | 'security' | 'admin'
    is_banned     INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMP DEFAULT NOW()
);

-- ─── Alerts (Incidents) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id            SERIAL PRIMARY KEY,
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
    record_type   TEXT    DEFAULT 'incident',
    created_at    TIMESTAMP DEFAULT NOW()
);

-- ─── Assignments ───────────────────────────────────────────
-- Admin assigns an incident to a security officer.
-- One incident can be reassigned (old row stays for audit log).
CREATE TABLE IF NOT EXISTS assignments (
    id            SERIAL PRIMARY KEY,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    security_id   INTEGER NOT NULL REFERENCES users(id),
    assigned_by   INTEGER NOT NULL REFERENCES users(id),
    task_status   TEXT    NOT NULL DEFAULT 'assigned',
    -- 'assigned' | 'accepted' | 'in_progress' | 'submitted'
    notes         TEXT,
    assigned_at   TIMESTAMP DEFAULT NOW(),
    accepted_at   TIMESTAMP,
    submitted_at  TIMESTAMP,
    is_active     INTEGER NOT NULL DEFAULT 1
);

-- ─── Feedback (Investigation Reports) ─────────────────────
CREATE TABLE IF NOT EXISTS feedback (
    id            SERIAL PRIMARY KEY,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    assignment_id INTEGER REFERENCES assignments(id),
    submitted_by  INTEGER NOT NULL REFERENCES users(id),
    notes         TEXT    NOT NULL,
    status_update TEXT    NOT NULL,
    submitted_at  TIMESTAMP DEFAULT NOW()
);

-- ─── Evidence (Photo Uploads) ──────────────────────────────
CREATE TABLE IF NOT EXISTS evidence (
    id            SERIAL PRIMARY KEY,
    alert_id      INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    uploaded_by   INTEGER NOT NULL REFERENCES users(id),
    filename      TEXT    NOT NULL,
    uploaded_at   TIMESTAMP DEFAULT NOW(),
    caption       TEXT
);

-- ─── Alert Updates Audit Log ───────────────────────────────
CREATE TABLE IF NOT EXISTS alert_updates (
    id          SERIAL PRIMARY KEY,
    alert_id    INTEGER NOT NULL REFERENCES alerts(id),
    updated_by  INTEGER NOT NULL REFERENCES users(id),
    status      TEXT    NOT NULL,
    timestamp   TIMESTAMP DEFAULT NOW()
);

-- ─── Messages (Chat) ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id            SERIAL PRIMARY KEY,
    sender_id     INTEGER NOT NULL REFERENCES users(id),
    receiver_role TEXT    NOT NULL,
    message       TEXT    NOT NULL,
    is_deleted    INTEGER NOT NULL DEFAULT 0,
    room          TEXT    NOT NULL DEFAULT 'main_chat',
    timestamp     TIMESTAMP DEFAULT NOW()
);

-- ─── Deleted Messages Log ─────────────────────────────────
CREATE TABLE IF NOT EXISTS deleted_messages (
    id            SERIAL PRIMARY KEY,
    message_id    INTEGER NOT NULL,
    deleted_by    INTEGER NOT NULL REFERENCES users(id),
    reason        TEXT,
    deleted_at    TIMESTAMP DEFAULT NOW()
);

-- ─── Broadcasts ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS broadcasts (
    id         SERIAL PRIMARY KEY,
    message    TEXT    NOT NULL,
    sent_by    INTEGER NOT NULL REFERENCES users(id),
    sent_at    TIMESTAMP DEFAULT NOW()
);

-- ─── Security Attendance Register ─────────────────────────
CREATE TABLE IF NOT EXISTS attendance (
    id            SERIAL PRIMARY KEY,
    security_id   INTEGER NOT NULL REFERENCES users(id),
    clock_in      TIMESTAMP NOT NULL DEFAULT NOW(),
    clock_out     TIMESTAMP,
    availability  TEXT NOT NULL DEFAULT 'available',
    campus        TEXT,
    shift         TEXT,
    date_str      TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1
);

-- ─── Password Reset Tokens ────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token      TEXT    NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

-- ─── Security Audit Log ───────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER,
    user_name  TEXT,
    action     TEXT NOT NULL,
    detail     TEXT,
    ip_address TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
