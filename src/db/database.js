const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DB_DIR = path.join(__dirname, '..', '..', 'data');
const DB_PATH = path.join(DB_DIR, 'heaptruffle.db');

if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
}

const db = new Database(DB_PATH);

// Enable WAL mode for performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// --- Schema Creation ---
db.exec(`
    CREATE TABLE IF NOT EXISTS scan_jobs (
        id TEXT PRIMARY KEY,
        target_url TEXT NOT NULL,
        domain TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        error TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        artifact_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        score INTEGER NOT NULL DEFAULT 0,
        category TEXT,
        description TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS ai_reports (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL UNIQUE,
        summary TEXT,
        generated_at TEXT,
        FOREIGN KEY (scan_id) REFERENCES scan_jobs(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        detail TEXT,
        timestamp TEXT NOT NULL
    );
`);

module.exports = db;
