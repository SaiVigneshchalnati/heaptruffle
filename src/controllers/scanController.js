/**
 * scanController.js — Handles scan job lifecycle: create, execute, store, retrieve.
 */
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { captureArtifacts, extractSnapshotText } = require('../services/browserWorker');
const { analyzeArtifacts } = require('../services/analysisEngine');
const { generateSecurityReport } = require('../services/aiService');

/**
 * POST /api/scan
 * Initiates a full scan: browser capture → analysis → AI report → persistence.
 */
async function startScan(req, res) {
    let { url } = req.body;

    if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'A valid URL is required.' });
    }

    if (!url.startsWith('http')) {
        url = 'https://' + url;
    }

    let domain;
    try {
        domain = new URL(url).hostname;
    } catch (_) {
        return res.status(400).json({ error: 'Invalid URL format.' });
    }

    const scanId = uuidv4();
    const createdAt = new Date().toISOString();

    // Persist scan job as 'running'
    db.prepare(`
        INSERT INTO scan_jobs (id, target_url, domain, status, created_at)
        VALUES (?, ?, ?, 'running', ?)
    `).run(scanId, url, domain, createdAt);

    // Audit log
    db.prepare(`INSERT INTO audit_logs (action, detail, timestamp) VALUES (?, ?, ?)`)
        .run('SCAN_STARTED', `Scan ${scanId} started for ${domain}`, createdAt);

    try {
        // --- Browser Acquisition ---
        const { snapshotText, runtimeArtifacts } = await captureArtifacts(url);
        const heapText = extractSnapshotText(snapshotText);

        // --- Analysis Engine ---
        const { findings, stats } = analyzeArtifacts(heapText, runtimeArtifacts);

        // --- Persist findings ---
        const insertFinding = db.prepare(`
            INSERT INTO findings (id, scan_id, raw_value, artifact_type, severity, score, category, description)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);
        const insertMany = db.transaction((items) => {
            for (const f of items) {
                insertFinding.run(uuidv4(), scanId, f.raw_value, f.artifact_type, f.risk_label || f.severity, f.final_score || f.score, f.category, f.description);
            }
        });
        insertMany(findings);

        // --- AI Report ---
        const aiSummary = await generateSecurityReport(domain, findings);
        db.prepare(`
            INSERT INTO ai_reports (id, scan_id, summary, generated_at)
            VALUES (?, ?, ?, ?)
        `).run(uuidv4(), scanId, aiSummary, new Date().toISOString());

        // --- Mark scan complete ---
        const completedAt = new Date().toISOString();
        db.prepare(`UPDATE scan_jobs SET status='completed', completed_at=? WHERE id=?`).run(completedAt, scanId);
        db.prepare(`INSERT INTO audit_logs (action, detail, timestamp) VALUES (?, ?, ?)`)
            .run('SCAN_COMPLETED', `Scan ${scanId} completed — ${findings.length} findings`, completedAt);

        return res.json({
            scanId,
            domain,
            status: 'completed',
            stats,
            findings,
            aiReport: aiSummary,
            runtimeArtifacts: {
                networkRequestCount: runtimeArtifacts.networkRequests.length,
                loadedScriptCount: runtimeArtifacts.loadedScripts.length,
                localStorageKeyCount: runtimeArtifacts.localStorageKeys.length,
            },
        });

    } catch (err) {
        const failedAt = new Date().toISOString();
        db.prepare(`UPDATE scan_jobs SET status='failed', completed_at=?, error=? WHERE id=?`)
            .run(failedAt, err.message, scanId);
        db.prepare(`INSERT INTO audit_logs (action, detail, timestamp) VALUES (?, ?, ?)`)
            .run('SCAN_FAILED', `Scan ${scanId} failed: ${err.message}`, failedAt);

        console.error('[scanController] Scan failed:', err);
        return res.status(500).json({ error: 'Scan failed: ' + err.message });
    }
}

/**
 * GET /api/scans
 * Returns paginated list of all past scan jobs.
 */
function getScans(req, res) {
    const limit = parseInt(req.query.limit) || 20;
    const offset = parseInt(req.query.offset) || 0;
    const scans = db.prepare(`
        SELECT s.*, COUNT(f.id) as finding_count
        FROM scan_jobs s
        LEFT JOIN findings f ON s.id = f.scan_id
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT ? OFFSET ?
    `).all(limit, offset);
    res.json({ scans });
}

/**
 * GET /api/scans/:id
 * Returns full detail of a single scan including findings and AI report.
 */
function getScanById(req, res) {
    const { id } = req.params;
    const scan = db.prepare(`SELECT * FROM scan_jobs WHERE id = ?`).get(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });

    const findings = db.prepare(`SELECT * FROM findings WHERE scan_id = ? ORDER BY score DESC`).all(id);
    const report = db.prepare(`SELECT * FROM ai_reports WHERE scan_id = ?`).get(id);

    res.json({ scan, findings, aiReport: report?.summary || null });
}

/**
 * DELETE /api/scans/:id
 * Deletes a scan and all associated data.
 */
function deleteScan(req, res) {
    const { id } = req.params;
    const scan = db.prepare(`SELECT id FROM scan_jobs WHERE id = ?`).get(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });

    db.prepare(`DELETE FROM scan_jobs WHERE id = ?`).run(id);
    db.prepare(`INSERT INTO audit_logs (action, detail, timestamp) VALUES (?, ?, ?)`)
        .run('SCAN_DELETED', `Scan ${id} deleted`, new Date().toISOString());

    res.json({ success: true });
}

/**
 * GET /api/audit-logs
 * Returns recent audit log entries.
 */
function getAuditLogs(req, res) {
    const logs = db.prepare(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 100`).all();
    res.json({ logs });
}

module.exports = { startScan, getScans, getScanById, deleteScan, getAuditLogs };
