/**
 * scanController.js — Full scan lifecycle, history, comparison, dashboard stats, PDF export.
 * The scan ALWAYS completes with results — even if heap extraction fails.
 */
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { captureArtifacts, extractSnapshotText } = require('../services/browserWorker');
const { analyzeArtifacts } = require('../services/analysisEngine');
const { generateSecurityReport } = require('../services/aiService');
const { generatePDFReport } = require('../services/pdfService');

// SSRF protection — block private/internal addresses
const PRIVATE_IP_RE = /^(localhost|127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|\[::1\])/i;

function isPrivateHost(hostname) {
    return PRIVATE_IP_RE.test(hostname);
}

/* ─── POST /api/scan ─────────────────────────── */
async function startScan(req, res) {
    let { url } = req.body;
    if (!url || typeof url !== 'string')
        return res.status(400).json({ error: 'A valid URL is required.' });
    if (!url.startsWith('http')) url = 'https://' + url;

    let domain;
    try { domain = new URL(url).hostname; }
    catch (_) { return res.status(400).json({ error: 'Invalid URL format.' }); }


    const scanId = uuidv4();
    const createdAt = new Date().toISOString();
    const userId = req.user?.id || null;

    db.prepare(`INSERT INTO scan_jobs (id,target_url,domain,status,created_at,created_by) VALUES (?,?,?,'running',?,?)`)
      .run(scanId, url, domain, createdAt, userId);
    db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
      .run('SCAN_STARTED', userId, `Scan ${scanId} started for ${domain}`, createdAt);

    // ── captureArtifacts NEVER throws — it always returns a result with heapStatus ──
    const { snapshotText, heapStatus, runtimeArtifacts } = await captureArtifacts(url);

    // Describe what happened with the heap
    const heapStatusMessages = {
        success:        'Heap snapshot captured successfully.',
        partial_load:   'Page failed to fully load; heap snapshot may be incomplete.',
        heap_empty:     'Heap snapshot was captured but returned empty data.',
        heap_failed:    'Heap extraction failed (CDP timeout or V8 error). Results based on network/script artifacts only.',
        browser_failed: 'Browser failed to launch or connect. Results unavailable.',
    };
    const heapNote = heapStatusMessages[heapStatus] || `Heap status: ${heapStatus}`;

    // Extract and analyse — works fine with empty heapText (runtime artifacts still run)
    const heapText = extractSnapshotText(snapshotText);
    const { findings, stats } = analyzeArtifacts(heapText, runtimeArtifacts);

    // Add a synthetic informational finding if heap failed, so the UI shows something meaningful
    if (heapStatus !== 'success' && heapStatus !== 'partial_load') {
        findings.unshift({
            id: uuidv4(),
            scan_id: scanId,
            raw_value: heapNote,
            artifact_type: 'heap_extraction_status',
            severity: 'info',
            score: 0,
            confidence: 100,
            category: 'Scan Quality',
            classification: 'Diagnostic',
            description: `The heap snapshot could not be fully extracted for this target. Reason: ${heapNote}`,
            recommendation: 'This may occur on heavily protected or SPA sites (e.g. x.com, Twitter). The scan still ran network, script, and localStorage analysis.',
            source_type: 'system',
            page_url: url,
            found_at: createdAt,
        });
    }

    // Persist findings
    const ins = db.prepare(`
        INSERT INTO findings
          (id,scan_id,raw_value,artifact_type,severity,score,confidence,category,classification,description,recommendation,source_type,page_url,found_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `);
    db.transaction(items => {
        for (const f of items)
            ins.run(
                f.id || uuidv4(), scanId,
                f.raw_value, f.artifact_type,
                f.risk_label || f.severity,
                f.final_score ?? f.score ?? 0,
                f.confidence || 50,
                f.category, f.classification,
                f.description, f.recommendation,
                f.source_type || 'heap',
                url, f.found_at || createdAt
            );
    })(findings);

    // AI Report
    let aiSummary;
    try {
        aiSummary = await generateSecurityReport(domain, findings);
    } catch (aiErr) {
        console.warn('[scanController] AI report failed:', aiErr.message);
        aiSummary = `## Scan Note\n${heapNote}\n\nAI report generation failed: ${aiErr.message}`;
    }

    db.prepare(`INSERT INTO ai_reports (id,scan_id,summary,generated_at) VALUES (?,?,?,?)`)
      .run(uuidv4(), scanId, aiSummary, new Date().toISOString());

    const completedAt = new Date().toISOString();

    // Scan always completes — heap failure is recorded in the `error` field for transparency
    const errorNote = heapStatus !== 'success' ? heapNote : null;
    db.prepare(`UPDATE scan_jobs SET status='completed',completed_at=?,finding_count=?,risk_score=?,error=? WHERE id=?`)
      .run(completedAt, findings.length, stats.totalScore, errorNote, scanId);
    db.prepare(`INSERT INTO audit_logs (action,user_id,detail,timestamp) VALUES (?,?,?,?)`)
      .run('SCAN_COMPLETED', userId,
           `Scan ${scanId} — ${findings.length} findings, score ${stats.totalScore}, heapStatus: ${heapStatus}`,
           completedAt);

    return res.json({
        scanId, domain, status: 'completed',
        heapStatus,
        heapNote,
        stats,
        findings,
        aiReport: aiSummary,
        runtimeArtifacts: {
            networkRequestCount:   runtimeArtifacts.networkRequests.length,
            loadedScriptCount:     runtimeArtifacts.loadedScripts.length,
            localStorageKeyCount:  runtimeArtifacts.localStorageKeys.length,
        },
    });
}

/* ─── GET /api/scans ─────────────────────────── */
function getScans(req, res) {
    const limit  = Math.min(parseInt(req.query.limit)  || 20, 100);
    const offset = parseInt(req.query.offset) || 0;
    const isAdmin = req.user.role === 'admin';

    // Fix #16: Non-admin users only see their own scans
    const scans = isAdmin
        ? db.prepare(`SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(limit, offset)
        : db.prepare(`SELECT * FROM scan_jobs WHERE created_by=? ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(req.user.id, limit, offset);
    const total = isAdmin
        ? db.prepare(`SELECT COUNT(*) as c FROM scan_jobs`).get().c
        : db.prepare(`SELECT COUNT(*) as c FROM scan_jobs WHERE created_by=?`).get(req.user.id).c;
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
    if (!scan) return res.status(404).json({ error: 'Scan not found.' }); // Fix #9: removed double semicolon
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
