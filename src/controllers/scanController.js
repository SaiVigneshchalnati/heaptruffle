/**
 * scanController.js — Full scan lifecycle, history, comparison, dashboard stats, PDF export.
 */
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { captureArtifacts, extractSnapshotText } = require('../services/browserWorker');
const { analyzeArtifacts } = require('../services/analysisEngine');
const { generateSecurityReport } = require('../services/aiService');
const { generatePDFReport } = require('../services/pdfService');
const { isAuthorizedDomain } = require('./targetsController');

/* ─── POST /api/scan ─────────────────────────── */
async function startScan(req, res) {
    let { url } = req.body;
    if (!url || typeof url !== 'string')
        return res.status(400).json({ error: 'A valid URL is required.' });
    if (!url.startsWith('http')) url = 'https://' + url;

    let domain;
    try { domain = new URL(url).hostname; }
    catch (_) { return res.status(400).json({ error: 'Invalid URL format.' }); }

    if (!isAuthorizedDomain(domain))
        return res.status(403).json({ error: `Domain "${domain}" is not in the authorized target list. Add it first.` });

    const scanId = uuidv4();
    const createdAt = new Date().toISOString();
    const userId = req.user?.id || null;

    db.prepare(`INSERT INTO scan_jobs (id,target_url,domain,status,created_at,created_by) VALUES (?,?,?,'running',?,?)`)
      .run(scanId, url, domain, createdAt, userId);
    db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
      .run('SCAN_STARTED', userId, `Scan ${scanId} started for ${domain}`, createdAt);

    try {
        const { snapshotText, runtimeArtifacts } = await captureArtifacts(url);
        const heapText = extractSnapshotText(snapshotText);
        const { findings, stats } = analyzeArtifacts(heapText, runtimeArtifacts);

        // Persist findings with new enriched schema
        const ins = db.prepare(`
            INSERT INTO findings
              (id,scan_id,raw_value,artifact_type,severity,score,confidence,category,classification,description,recommendation,source_type,page_url,found_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        `);
        db.transaction(items => {
            for (const f of items)
                ins.run(uuidv4(), scanId, f.raw_value, f.artifact_type,
                    f.risk_label || f.severity, f.final_score || f.score,
                    f.confidence || 50, f.category, f.classification,
                    f.description, f.recommendation, f.source_type || 'heap',
                    url, f.found_at || createdAt);
        })(findings);

        // AI Report
        const aiSummary = await generateSecurityReport(domain, findings);
        db.prepare(`INSERT INTO ai_reports (id,scan_id,summary,generated_at) VALUES (?,?,?,?)`)
          .run(uuidv4(), scanId, aiSummary, new Date().toISOString());

        const completedAt = new Date().toISOString();
        db.prepare(`UPDATE scan_jobs SET status='completed',completed_at=?,finding_count=?,risk_score=? WHERE id=?`)
          .run(completedAt, findings.length, stats.totalScore, scanId);
        db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
          .run('SCAN_COMPLETED', userId, `Scan ${scanId} — ${findings.length} findings, score ${stats.totalScore}`, completedAt);

        return res.json({
            scanId, domain, status: 'completed', stats, findings, aiReport: aiSummary,
            runtimeArtifacts: {
                networkRequestCount: runtimeArtifacts.networkRequests.length,
                loadedScriptCount:   runtimeArtifacts.loadedScripts.length,
                localStorageKeyCount: runtimeArtifacts.localStorageKeys.length,
            },
        });
    } catch (err) {
        const failedAt = new Date().toISOString();
        db.prepare(`UPDATE scan_jobs SET status='failed',completed_at=?,error=? WHERE id=?`).run(failedAt, err.message, scanId);
        db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
          .run('SCAN_FAILED', userId, `Scan ${scanId} failed: ${err.message}`, failedAt);
        console.error('[scanController] Scan failed:', err.message);
        return res.status(500).json({ error: 'Scan failed: ' + err.message });
    }
}

/* ─── GET /api/scans ─────────────────────────── */
function getScans(req, res) {
    const limit  = Math.min(parseInt(req.query.limit)  || 20, 100);
    const offset = parseInt(req.query.offset) || 0;
    const scans = db.prepare(`
        SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?
    `).all(limit, offset);
    const total = db.prepare(`SELECT COUNT(*) as c FROM scan_jobs`).get().c;
    res.json({ scans, total });
}

/* ─── GET /api/scans/:id ─────────────────────── */
function getScanById(req, res) {
    const scan = db.prepare(`SELECT * FROM scan_jobs WHERE id=?`).get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    const findings = db.prepare(`SELECT * FROM findings WHERE scan_id=? ORDER BY score DESC`).all(req.params.id);
    const report   = db.prepare(`SELECT * FROM ai_reports WHERE scan_id=?`).get(req.params.id);
    res.json({ scan, findings, aiReport: report?.summary || null });
}

/* ─── DELETE /api/scans/:id ──────────────────── */
function deleteScan(req, res) {
    const scan = db.prepare(`SELECT id FROM scan_jobs WHERE id=?`).get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    db.prepare(`DELETE FROM scan_jobs WHERE id=?`).run(req.params.id);
    db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
      .run('SCAN_DELETED', req.user?.id, `Scan ${req.params.id} deleted`, new Date().toISOString());
    res.json({ success: true });
}

/* ─── GET /api/scans/compare?a=id1&b=id2 ────── */
function compareScans(req, res) {
    const { a, b } = req.query;
    if (!a || !b) return res.status(400).json({ error: 'Two scan IDs are required: ?a=...&b=...' });

    const findingsA = db.prepare(`SELECT * FROM findings WHERE scan_id=?`).all(a);
    const findingsB = db.prepare(`SELECT * FROM findings WHERE scan_id=?`).all(b);

    const setA = new Map(findingsA.map(f => [`${f.artifact_type}::${f.raw_value}`, f]));
    const setB = new Map(findingsB.map(f => [`${f.artifact_type}::${f.raw_value}`, f]));

    const newFindings     = findingsB.filter(f => !setA.has(`${f.artifact_type}::${f.raw_value}`));
    const removedFindings = findingsA.filter(f => !setB.has(`${f.artifact_type}::${f.raw_value}`));
    const severityChanges = [];

    for (const [key, fb] of setB) {
        const fa = setA.get(key);
        if (fa && fa.severity !== fb.severity) {
            severityChanges.push({ artifact: key, from: fa.severity, to: fb.severity });
        }
    }

    res.json({
        scanA: a, scanB: b,
        summary: {
            newCount:     newFindings.length,
            removedCount: removedFindings.length,
            changedCount: severityChanges.length,
        },
        newFindings,
        removedFindings,
        severityChanges,
    });
}

/* ─── GET /api/dashboard ────────────────────── */
function getDashboardStats(req, res) {
    const totalScans    = db.prepare(`SELECT COUNT(*) as c FROM scan_jobs WHERE status='completed'`).get().c;
    const totalFindings = db.prepare(`SELECT COUNT(*) as c FROM findings`).get().c;
    const sevCounts     = db.prepare(`
        SELECT severity, COUNT(*) as count FROM findings GROUP BY severity
    `).all();
    const catCounts     = db.prepare(`
        SELECT classification, COUNT(*) as count FROM findings
        WHERE classification IS NOT NULL GROUP BY classification ORDER BY count DESC LIMIT 7
    `).all();
    const recentScans   = db.prepare(`
        SELECT id,domain,target_url,status,created_at,finding_count,risk_score
        FROM scan_jobs ORDER BY created_at DESC LIMIT 6
    `).all();
    const topTargets    = db.prepare(`
        SELECT domain, COUNT(*) as scan_count, MAX(risk_score) as max_risk
        FROM scan_jobs WHERE status='completed'
        GROUP BY domain ORDER BY max_risk DESC LIMIT 5
    `).all();
    const trendData     = db.prepare(`
        SELECT substr(created_at,1,10) as day, COUNT(*) as scans, SUM(finding_count) as findings
        FROM scan_jobs WHERE status='completed' AND created_at >= datetime('now','-14 days')
        GROUP BY day ORDER BY day ASC
    `).all();

    res.json({ totalScans, totalFindings, sevCounts, catCounts, recentScans, topTargets, trendData });
}

/* ─── GET /api/scans/:id/pdf ────────────────── */
async function downloadPDF(req, res) {
    const scan = db.prepare(`SELECT * FROM scan_jobs WHERE id=?`).get(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    const findings = db.prepare(`SELECT * FROM findings WHERE scan_id=? ORDER BY score DESC`).all(req.params.id);
    const report   = db.prepare(`SELECT summary FROM ai_reports WHERE scan_id=?`).get(req.params.id);

    try {
        const pdfBuffer = await generatePDFReport(scan, findings, report?.summary || null);
        res.set({
            'Content-Type': 'application/pdf',
            'Content-Disposition': `attachment; filename="heaptruffle-${scan.domain}-${req.params.id.slice(0,8)}.pdf"`,
            'Content-Length': pdfBuffer.length,
        });
        res.send(pdfBuffer);
        db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
          .run('REPORT_DOWNLOADED', req.user?.id, `PDF report downloaded for ${req.params.id}`, new Date().toISOString());
    } catch (err) {
        console.error('[PDF]', err.message);
        res.status(500).json({ error: 'PDF generation failed.' });
    }
}

/* ─── GET /api/audit-logs ───────────────────── */
function getAuditLogs(req, res) {
    const logs = db.prepare(`SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200`).all();
    res.json({ logs });
}

module.exports = { startScan, getScans, getScanById, deleteScan, compareScans, getDashboardStats, downloadPDF, getAuditLogs };
