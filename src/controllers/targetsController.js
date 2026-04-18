/**
 * targetsController.js — Authorized target domain management.
 */
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');

function getTargets(req, res) {
    const targets = db.prepare(`SELECT * FROM targets ORDER BY created_at DESC`).all();
    res.json({ targets });
}

function addTarget(req, res) {
    const { domain, label, notes, authorized_by } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required.' });

    // Normalize domain
    let normalized = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();

    const existing = db.prepare(`SELECT id FROM targets WHERE domain = ?`).get(normalized);
    if (existing) return res.status(409).json({ error: 'Target domain already exists.' });

    const id = uuidv4();
    db.prepare(`INSERT INTO targets (id,domain,label,authorized_by,notes,is_active,created_at) VALUES (?,?,?,?,?,1,?)`)
      .run(id, normalized, label || normalized, authorized_by || req.user.username, notes || '', new Date().toISOString());

    db.prepare(`INSERT INTO audit_logs (action, user_id, detail, timestamp) VALUES (?,?,?,?)`)
      .run('TARGET_ADDED', req.user.id, `Target ${normalized} added`, new Date().toISOString());

    res.status(201).json({ message: 'Target added successfully.', id });
}

function deleteTarget(req, res) {
    const { id } = req.params;
    const target = db.prepare(`SELECT domain FROM targets WHERE id = ?`).get(id);
    if (!target) return res.status(404).json({ error: 'Target not found.' });

    db.prepare(`DELETE FROM targets WHERE id = ?`).run(id);
    db.prepare(`INSERT INTO audit_logs (action, user_id, detail, timestamp) VALUES (?,?,?,?)`)
      .run('TARGET_REMOVED', req.user.id, `Target ${target.domain} removed`, new Date().toISOString());

    res.json({ success: true });
}

function toggleTarget(req, res) {
    const { id } = req.params;
    const target = db.prepare(`SELECT * FROM targets WHERE id = ?`).get(id);
    if (!target) return res.status(404).json({ error: 'Target not found.' });

    const newStatus = target.is_active ? 0 : 1;
    db.prepare(`UPDATE targets SET is_active = ? WHERE id = ?`).run(newStatus, id);
    res.json({ success: true, is_active: newStatus });
}

/**
 * Validates if a URL's domain is in the authorized targets list.
 * Returns true if authorization is not enforced (no targets exist) or domain is allowed.
 */
function isAuthorizedDomain(domain) {
    const count = db.prepare(`SELECT COUNT(*) as c FROM targets`).get().c;
    if (count === 0) return true; // open mode
    const found = db.prepare(`SELECT id FROM targets WHERE domain = ? AND is_active = 1`).get(domain);
    return !!found;
}

module.exports = { getTargets, addTarget, deleteTarget, toggleTarget, isAuthorizedDomain };
