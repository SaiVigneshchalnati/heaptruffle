/**
 * pdfService.js — Generates downloadable PDF forensic reports using PDFKit.
 */
const PDFDocument = require('pdfkit');

const COLORS = {
    primary: '#8b5cf6',
    dark: '#1a1a2e',
    critical: '#ff3b30',
    high: '#ff9500',
    medium: '#ffd60a',
    low: '#30d158',
    text: '#2d3748',
    muted: '#718096',
    white: '#ffffff',
    border: '#e2e8f0',
};

function severityColor(sev) {
    return COLORS[sev?.toLowerCase()] || COLORS.muted;
}

/**
 * Generates a PDF report buffer for a completed scan.
 */
function generatePDFReport(scan, findings, aiReport) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50, size: 'A4' });
        const chunks = [];
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);

        const pageWidth = doc.page.width - 100;

        // ─── HEADER ─────────────────────────────────────────────
        doc.rect(0, 0, doc.page.width, 80).fill(COLORS.dark);
        doc.fill(COLORS.primary).fontSize(22).font('Helvetica-Bold').text('HeapTruffle', 50, 22);
        doc.fill(COLORS.white).fontSize(9).font('Helvetica').text('AI-Assisted Browser Memory Forensics Platform', 50, 50);
        doc.fill(COLORS.white).fontSize(9).text('CONFIDENTIAL — SECURITY REPORT', { align: 'right' }, 50, 28, { width: pageWidth });

        doc.moveDown(4);

        // ─── TITLE ───────────────────────────────────────────────
        doc.fill(COLORS.text).fontSize(18).font('Helvetica-Bold').text('Forensic Scan Report', { align: 'center' });
        doc.moveDown(0.4);
        doc.fill(COLORS.muted).fontSize(10).font('Helvetica').text(`Target: ${scan.target_url}`, { align: 'center' });
        doc.moveDown(0.2);
        doc.fill(COLORS.muted).fontSize(10).text(`Generated: ${new Date().toUTCString()}`, { align: 'center' });

        doc.moveDown(1.5);
        rule(doc, pageWidth);
        doc.moveDown(0.8);

        // ─── SCAN METADATA ───────────────────────────────────────
        sectionTitle(doc, '1. Scan Metadata');
        const meta = [
            ['Scan ID', scan.id],
            ['Target URL', scan.target_url],
            ['Domain', scan.domain],
            ['Status', scan.status?.toUpperCase()],
            ['Initiated', scan.created_at],
            ['Completed', scan.completed_at || 'N/A'],
            ['Total Findings', String(findings.length)],
        ];
        infoTable(doc, meta, pageWidth);
        doc.moveDown(1.2);

        // ─── SEVERITY SUMMARY ────────────────────────────────────
        sectionTitle(doc, '2. Severity Distribution');
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        findings.forEach(f => { const s = (f.severity || 'low').toLowerCase(); if (counts[s] !== undefined) counts[s]++; });
        const totalScore = findings.length
            ? Math.round(findings.reduce((s, f) => s + (f.score || 0), 0) / findings.length)
            : 0;

        drawSeverityBox(doc, counts, totalScore, pageWidth);
        doc.moveDown(1.2);

        // ─── AI EXECUTIVE SUMMARY ────────────────────────────────
        if (aiReport) {
            sectionTitle(doc, '3. AI Security Intelligence Summary');
            const cleanReport = aiReport.replace(/#{1,6}\s?/g, '').replace(/\*\*/g, '').replace(/\*/g, '').trim();
            doc.fill(COLORS.text).fontSize(9.5).font('Helvetica').text(cleanReport.slice(0, 2000), {
                width: pageWidth,
                align: 'justify',
                lineGap: 3,
            });
            doc.moveDown(1.2);
        }

        // ─── DETAILED FINDINGS ───────────────────────────────────
        sectionTitle(doc, `${aiReport ? '4' : '3'}. Detailed Findings (${findings.length})`);
        doc.moveDown(0.4);

        const topFindings = findings.slice(0, 40); // limit to 40 in PDF
        topFindings.forEach((f, i) => {
            if (doc.y > doc.page.height - 180) doc.addPage();
            findingBlock(doc, f, i + 1, pageWidth);
        });

        if (findings.length > 40) {
            doc.moveDown(0.5);
            doc.fill(COLORS.muted).fontSize(9).italic()
               .text(`... and ${findings.length - 40} more findings. View full list in the platform dashboard.`);
        }

        doc.moveDown(1.5);

        // ─── RECOMMENDATIONS ─────────────────────────────────────
        sectionTitle(doc, `${aiReport ? '5' : '4'}. Top Recommendations`);
        doc.moveDown(0.4);
        const critHighFindings = findings.filter(f => ['critical','high'].includes(f.severity?.toLowerCase())).slice(0, 8);
        if (critHighFindings.length === 0) {
            doc.fill(COLORS.muted).fontSize(10).text('No critical or high severity findings. Maintain regular forensic scans.');
        } else {
            critHighFindings.forEach((f, i) => {
                doc.fill(COLORS.text).fontSize(10).font('Helvetica-Bold').text(`${i + 1}. ${f.artifact_type?.replace(/_/g, ' ').toUpperCase()}`);
                doc.fill(COLORS.muted).fontSize(9).font('Helvetica').text(f.recommendation || 'Review and remediate.', { indent: 15 });
                doc.moveDown(0.5);
            });
        }

        // ─── FOOTER ──────────────────────────────────────────────
        doc.moveDown(2);
        rule(doc, pageWidth);
        doc.moveDown(0.4);
        doc.fill(COLORS.muted).fontSize(8)
           .text('This report was generated automatically by HeapTruffle v2.0 — AI-Assisted Browser Memory Forensics Platform.', { align: 'center' });
        doc.text('For internal use only. Unauthorized disclosure is prohibited.', { align: 'center' });

        doc.end();
    });
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function sectionTitle(doc, title) {
    doc.fill(COLORS.primary).fontSize(13).font('Helvetica-Bold').text(title);
    doc.moveDown(0.5);
}

function rule(doc, width) {
    doc.moveTo(50, doc.y).lineTo(50 + width, doc.y).strokeColor(COLORS.border).lineWidth(1).stroke();
}

function infoTable(doc, rows, width) {
    rows.forEach(([key, val]) => {
        const y = doc.y;
        doc.fill(COLORS.muted).fontSize(9.5).font('Helvetica-Bold').text(key + ':', 50, y, { width: 120 });
        doc.fill(COLORS.text).fontSize(9.5).font('Helvetica').text(String(val || ''), 175, y, { width: width - 125 });
        doc.moveDown(0.45);
    });
}

function drawSeverityBox(doc, counts, score, width) {
    const boxW = (width - 30) / 4;
    const severities = [
        { label: 'CRITICAL', key: 'critical', color: COLORS.critical },
        { label: 'HIGH', key: 'high', color: COLORS.high },
        { label: 'MEDIUM', key: 'medium', color: COLORS.medium },
        { label: 'LOW', key: 'low', color: COLORS.low },
    ];
    let x = 50;
    const boxY = doc.y;
    severities.forEach(s => {
        doc.roundedRect(x, boxY, boxW, 55, 6).fillAndStroke('#f7fafc', COLORS.border);
        doc.fill(s.color).fontSize(22).font('Helvetica-Bold').text(String(counts[s.key]), x, boxY + 10, { width: boxW, align: 'center' });
        doc.fill(COLORS.muted).fontSize(8).font('Helvetica').text(s.label, x, boxY + 38, { width: boxW, align: 'center' });
        x += boxW + 10;
    });
    doc.y = boxY + 65;
    doc.fill(COLORS.muted).fontSize(9).text(`Overall Risk Score: ${score}/100`, { align: 'right' });
}

function findingBlock(doc, f, index, width) {
    const sev = (f.severity || 'low').toLowerCase();
    const col = severityColor(sev);
    const startY = doc.y;

    doc.rect(50, startY, 4, 50).fill(col);
    doc.fill(COLORS.text).fontSize(10).font('Helvetica-Bold')
       .text(`#${index} — ${(f.artifact_type || '').replace(/_/g, ' ').toUpperCase()}`, 60, startY + 3, { width: width - 80 });
    doc.fill(col).fontSize(8).font('Helvetica-Bold')
       .text(`[${sev.toUpperCase()}]  Score: ${f.score || 0}  Confidence: ${f.confidence || '?'}%`, 60, startY + 18);
    doc.fill(COLORS.muted).fontSize(8).font('Helvetica')
       .text(`Value: ${String(f.raw_value || '').slice(0, 80)}${String(f.raw_value || '').length > 80 ? '...' : ''}`, 60, startY + 32, { width: width - 80 });

    doc.y = startY + 55;
}

module.exports = { generatePDFReport };
