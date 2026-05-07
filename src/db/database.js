const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, '..', '..', 'data');
const DB_PATH = path.join(DB_DIR, 'heaptruffle.db');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
    -- Users table for RBAC
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'analyst',
        created_at TEXT NOT NULL,
        last_login TEXT
    );

    -- Authorized targets
    CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL UNIQUE,
        label TEXT,
        authorized_by TEXT,
        notes TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
    );

    -- Scan jobs
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        domain TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        error TEXT,
        created_by TEXT,
        finding_count INTEGER DEFAULT 0,
        risk_score INTEGER DEFAULT 0
    );

    -- Findings with full forensic evidence
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        confidence INTEGER NOT NULL DEFAULT 50,
        category TEXT,
        classification TEXT,
        description TEXT,
        recommendation TEXT,
        source_type TEXT DEFAULT 'heap',
        page_url TEXT,
        found_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
    );

    -- AI reports
    CREATE TABLE IF NOT EXISTS ai_reports (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL UNIQUE,
        summary TEXT,
        generated_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
    );

    -- Audit logs
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        user_id TEXT,
        detail TEXT,
        ip TEXT,
        timestamp TEXT NOT NULL
    );

    -- Scan comparisons
    CREATE TABLE IF NOT EXISTS scan_comparisons (
        id TEXT PRIMARY KEY,
        scan_a TEXT NOT NULL,
        scan_b TEXT NOT NULL,
        new_findings TEXT,
        removed_findings TEXT,
        severity_changes TEXT,
        created_at TEXT NOT NULL
    );
`);

// Fix #17: Generate a strong random password on first boot instead of using a weak default
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const adminExists = db.prepare(`SELECT id FROM users WHERE role='admin' LIMIT 1`).get();
if (!adminExists) {
    // Generate a memorable but secure random password (12 hex chars)
    const randomPass = crypto.randomBytes(6).toString('hex'); // e.g. "a3f9e2d1c4b5"
    const hash = bcrypt.hashSync(randomPass, 10);
    db.prepare(`INSERT INTO users (id,username,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?)`)
      .run(uuidv4(), 'admin', 'admin@heaptruffle.local', hash, 'admin', new Date().toISOString());
    console.log('\n╔══════════════════════════════════════════════╗');
    console.log('║  🔐 HeapTruffle — First-Boot Admin Credentials  ║');
    console.log(`║  Username : admin                              ║`);
    console.log(`║  Password : ${randomPass}                   ║`);
    console.log('║  ⚠️  Save this password — it will not show again  ║');
    console.log('╚══════════════════════════════════════════════╝\n');
}

module.exports = db;
