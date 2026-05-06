/**
 * pdfService.js — Generates PDF forensic reports using PDFKit.
 *
 * Blank-page-free approach:
 *  - bufferPages:true is used ONLY to stamp footers at the end.
 *  - During the footer stamp loop, doc.page.margins.bottom is set to 0
 *    so PDFKit's LineWrapper never fires continueOnNewPage().
 *  - All manual page breaks use ensureSpace() which guards against
 *    double-breaks when already at the top of a fresh page.
 */
'use strict';

const PDFDocument = require('pdfkit');

// ─── Constants ────────────────────────────────────────────────────────────────
const M  = 50;                         // margin
const PW = 595.28;                     // A4 width
const PH = 841.89;                     // A4 height
const CW = PW - M * 2;                // content width  (495.28)
const HH = 88;                         // header height
const CT = HH + 16;                    // content-top y  (104)
const SB = PH - 40;                    // safe-bottom y  (801.89) — generous

// ─── Colours ──────────────────────────────────────────────────────────────────
const C = {
    primary:   '#8b5cf6',
    accent:    '#6d28d9',
    dark:      '#0f0e17',
    text:      '#1e293b',
    textLight: '#475569',
    muted:     '#94a3b8',
    white:     '#ffffff',
    border:    '#e2e8f0',
    headBg:    '#f1f5f9',
    rowAlt:    '#f8fafc',

    critical:   '#dc2626', criticalBg: '#fef2f2',
    high:       '#ea580c', highBg:     '#fff7ed',
    medium:     '#d97706', mediumBg:   '#fffbeb',
    low:        '#16a34a', lowBg:      '#f0fdf4',
    info:       '#0ea5e9', infoBg:     '#f0f9ff',
};

function sevCol(s)   { return C[s] || C.muted; }
function sevBg(s)    { return C[s + 'Bg'] || C.rowAlt; }
function sevKey(f)   { return (f.severity || 'low').toLowerCase(); }

// ─── ensureSpace ─────────────────────────────────────────────────────────────
// Adds a new page only when needed AND we are not already at the top.
function ensureSpace(doc, need) {
    if (doc.y > CT + 50 && doc.y + need > SB) {
        doc.addPage();
        drawHeader(doc);
        doc.y = CT;
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────
function generatePDFReport(scan, findings, aiReport) {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({
            size:          'A4',
            margin:        M,
            bufferPages:   true,
            autoFirstPage: true,
            info: {
                Title:    'HeapTruffle Forensic Report',
                Author:   'HeapTruffle v2.0',
                Subject:  `Scan report — ${scan.domain}`,
            },
        });

        const bufs = [];
        doc.on('data',  b => bufs.push(b));
        doc.on('end',   () => resolve(Buffer.concat(bufs)));
        doc.on('error', reject);

        // ── Pre-compute stats ────────────────────────────────────────────────
        const cnt = { critical:0, high:0, medium:0, low:0 };
        findings.forEach(f => { const k = sevKey(f); if (k in cnt) cnt[k]++; });
        const avg = findings.length
            ? Math.round(findings.reduce((a,f) => a + (f.score||0), 0) / findings.length) : 0;

        // ── Page 1 ───────────────────────────────────────────────────────────
        drawHeader(doc);
        doc.y = CT;

        // Title
        doc.fillColor(C.text).font('Helvetica-Bold').fontSize(19)
           .text('Forensic Scan Report', M, doc.y, { width: CW, align: 'center', lineBreak: false });
        doc.y += 26;

        doc.fillColor(C.accent).font('Helvetica').fontSize(9)
           .text(`Target: ${scan.target_url || scan.domain}`, M, doc.y, { width: CW, align: 'center', lineBreak: false });
        doc.y += 14;

        doc.fillColor(C.muted).font('Helvetica').fontSize(8)
           .text(`Generated: ${new Date().toUTCString()}`, M, doc.y, { width: CW, align: 'center', lineBreak: false });
        doc.y += 20;

        hRule(doc);
        doc.y += 14;

        // §1 Metadata
        secHeading(doc, '1', 'Scan Metadata');
        doc.y += 4;
        kvTable(doc, [
            ['Scan ID',        scan.id],
            ['Target URL',     scan.target_url || '—'],
            ['Domain',         scan.domain || '—'],
            ['Status',         (scan.status||'').toUpperCase()],
            ['Initiated',      fmt(scan.created_at)],
            ['Completed',      fmt(scan.completed_at) || 'N/A'],
            ['Total Findings', String(findings.length)],
            ['Avg Risk Score', `${avg} / 100`],
        ]);
        doc.y += 10;

        // §2 Severity distribution
        ensureSpace(doc, 100);
        secHeading(doc, '2', 'Severity Distribution');
        doc.y += 6;
        severityGrid(doc, cnt, avg);
        doc.y += 10;

        // §3 AI Summary
        let sec = 3;
        if (aiReport) {
            ensureSpace(doc, 70);
            secHeading(doc, String(sec++), 'AI Security Intelligence Summary');
            doc.y += 4;
            aiBlock(doc, aiReport);
            doc.y += 8;
        }

        // §4 Detailed Findings
        ensureSpace(doc, 60);
        secHeading(doc, String(sec++), `Detailed Findings  (${findings.length} total)`);
        doc.y += 6;

        if (!findings.length) {
            doc.fillColor(C.muted).font('Helvetica-Oblique').fontSize(9)
               .text('No findings recorded for this scan.', M, doc.y, { width: CW });
            doc.y += 14;
        } else {
            findings.slice(0, 40).forEach((f, i) => {
                ensureSpace(doc, 80);
                findingCard(doc, f, i + 1);
            });
            if (findings.length > 40) {
                ensureSpace(doc, 20);
                doc.y += 4;
                doc.fillColor(C.muted).font('Helvetica-Oblique').fontSize(8.5)
                   .text(
                       `… ${findings.length - 40} more findings — view all in the dashboard.`,
                       M, doc.y, { width: CW, align: 'center' }
                   );
                doc.y += 10;
            }
        }

        doc.y += 6;

        // §5 Recommendations
        ensureSpace(doc, 60);
        secHeading(doc, String(sec++), 'Top Recommendations');
        doc.y += 6;

        const top = findings.filter(f => ['critical','high'].includes(sevKey(f))).slice(0, 8);
        if (!top.length) {
            doc.fillColor(C.muted).font('Helvetica').fontSize(9.5)
               .text('No critical or high severity findings. Maintain regular scans.', M, doc.y, { width: CW });
            doc.y += 14;
        } else {
            top.forEach((f, i) => {
                ensureSpace(doc, 52);
                recoRow(doc, f, i + 1);
            });
        }

        // ── Footer stamp ─────────────────────────────────────────────────────
        // KEY FIX: temporarily set bottom margin to 0 so doc.text() at the
        // very bottom of the page never fires continueOnNewPage().
        const total = doc.bufferedPageRange().count;
        for (let i = 0; i < total; i++) {
            doc.switchToPage(i);
            doc.page.margins.bottom = 0;   // ← prevents auto-page-break
            drawFooter(doc, i + 1, total);
        }

        doc.end();
    });
}

// ═════════════════════════════════════════════════════════════════════════════
//  Drawing helpers
// ═════════════════════════════════════════════════════════════════════════════

function drawHeader(doc) {
    // Dark bar
    doc.save().rect(0, 0, PW, HH).fillColor(C.dark).fill().restore();
    // Purple accent stripe
    doc.save().rect(0, HH - 3, PW, 3).fillColor(C.primary).fill().restore();

    // Logo
    doc.fillColor(C.primary).font('Helvetica-Bold').fontSize(20)
       .text('HeapTruffle', M, 20, { lineBreak: false });
    // Tagline
    doc.fillColor(C.muted).font('Helvetica').fontSize(7.5)
       .text('AI-Assisted Browser Memory Forensics', M, 46, { lineBreak: false });
    // Badge (right-aligned)
    doc.fillColor(C.white).font('Helvetica-Bold').fontSize(7)
       .text('CONFIDENTIAL — SECURITY REPORT', M, 28,
             { width: CW, align: 'right', lineBreak: false });
}

function drawFooter(doc, pageNum, total) {
    const ly = PH - 28;
    const ty = PH - 18;

    // Rule
    doc.save()
       .moveTo(M, ly).lineTo(M + CW, ly)
       .strokeColor(C.border).lineWidth(0.5).stroke()
       .restore();

    // Left text — explicit x,y, no lineBreak, no align that could cause wrap
    doc.fillColor(C.muted).font('Helvetica').fontSize(6.5)
       .text('HeapTruffle v2.0 — Confidential Security Report',
             M, ty, { width: CW * 0.6, lineBreak: false });

    // Right text — compute x manually from string width
    const rightStr = `Page ${pageNum} of ${total}`;
    const rw = doc.widthOfString(rightStr, { font: 'Helvetica', fontSize: 6.5 });
    doc.fillColor(C.muted).font('Helvetica').fontSize(6.5)
       .text(rightStr, M + CW - rw, ty, { lineBreak: false });
}

function hRule(doc) {
    doc.save()
       .moveTo(M, doc.y).lineTo(M + CW, doc.y)
       .strokeColor(C.border).lineWidth(0.7).stroke()
       .restore();
}

function secHeading(doc, num, title) {
    const y  = doc.y;
    const bH = 22;
    // Left accent bar
    doc.save().rect(M, y, 4, bH).fillColor(C.primary).fill().restore();
    // Number chip
    doc.save().rect(M+10, y+2, 18, 18).fillColor('#ede9fe').fill().restore();
    doc.fillColor(C.accent).font('Helvetica-Bold').fontSize(8.5)
       .text(num, M+10, y+6, { width: 18, align: 'center', lineBreak: false });
    // Title
    doc.fillColor(C.text).font('Helvetica-Bold').fontSize(12)
       .text(title, M+34, y+5, { lineBreak: false });
    doc.y = y + bH + 2;
}

function kvTable(doc, rows) {
    const L1 = M;
    const W1 = 140;
    const L2 = M + W1;
    const W2 = CW - W1;
    const RH = 17;

    // Header row
    doc.save().rect(L1, doc.y, CW, RH).fillColor(C.headBg).fill().restore();
    doc.fillColor(C.textLight).font('Helvetica-Bold').fontSize(7.5)
       .text('FIELD', L1+6, doc.y+5, { width: W1-6, lineBreak: false });
    doc.fillColor(C.textLight).font('Helvetica-Bold').fontSize(7.5)
       .text('VALUE', L2+6, doc.y+5, { width: W2-6, lineBreak: false });
    doc.y += RH;

    rows.forEach(([k, v], i) => {
        const ry = doc.y;
        doc.save().rect(L1, ry, CW, RH).fillColor(i%2?C.rowAlt:'#fff').fill().restore();
        doc.fillColor(C.textLight).font('Helvetica-Bold').fontSize(8)
           .text(k, L1+6, ry+5, { width: W1-12, lineBreak: false });
        const vs = String(v||'—'); const disp = vs.length>72 ? vs.slice(0,72)+'…' : vs;
        doc.fillColor(C.text).font('Helvetica').fontSize(8)
           .text(disp, L2+6, ry+5, { width: W2-12, lineBreak: false });
        doc.y = ry + RH;
    });
    // Bottom rule
    doc.save().moveTo(L1,doc.y).lineTo(L1+CW,doc.y)
       .strokeColor(C.border).lineWidth(0.4).stroke().restore();
    doc.y += 1;
}

function severityGrid(doc, cnt, score) {
    const cols = [
        { k:'critical', label:'CRITICAL', col:C.critical, bg:C.criticalBg },
        { k:'high',     label:'HIGH',     col:C.high,     bg:C.highBg     },
        { k:'medium',   label:'MEDIUM',   col:C.medium,   bg:C.mediumBg   },
        { k:'low',      label:'LOW',      col:C.low,      bg:C.lowBg      },
    ];
    const GAP=8, BW=(CW-GAP*3)/4, BH=62, baseY=doc.y;
    let x=M;

    cols.forEach(c => {
        // Card
        doc.save().roundedRect(x,baseY,BW,BH,4).fillColor(c.bg).fill().restore();
        // Top stripe
        doc.save().roundedRect(x,baseY,BW,4,3).fillColor(c.col).fill().restore();
        // Count
        doc.fillColor(c.col).font('Helvetica-Bold').fontSize(24)
           .text(String(cnt[c.k]||0), x, baseY+10, { width:BW, align:'center', lineBreak:false });
        // Label
        doc.fillColor(c.col).font('Helvetica-Bold').fontSize(7)
           .text(c.label, x, baseY+42, { width:BW, align:'center', lineBreak:false });
        x += BW+GAP;
    });

    doc.y = baseY + BH + 8;

    // Risk score bar
    const barY=doc.y, bW=CW, bH=9;
    doc.save().roundedRect(M,barY,bW,bH,3).fillColor(C.border).fill().restore();
    const fillC = score>=75?C.critical : score>=50?C.high : score>=25?C.medium : C.low;
    const fillW = Math.min(score/100,1)*bW;
    if(fillW>0) doc.save().roundedRect(M,barY,fillW,bH,3).fillColor(fillC).fill().restore();
    doc.y = barY+bH+5;
    doc.fillColor(C.textLight).font('Helvetica').fontSize(7.5)
       .text('Overall Risk Score: ', M, doc.y, { continued:true, lineBreak:false });
    doc.fillColor(fillC).font('Helvetica-Bold').fontSize(7.5)
       .text(`${score} / 100`, { lineBreak:false });
    doc.y += 12;
}

function aiBlock(doc, aiReport) {
    const TX = M+12, TW = CW-18, PV=7, FS=9.5, LG=3;

    const clean = aiReport
        .replace(/#{1,6}\s?/g,'').replace(/\*\*/g,'').replace(/\*/g,'')
        .replace(/`/g,'').replace(/\r\n/g,'\n').replace(/\n{3,}/g,'\n\n')
        .trim().slice(0,4000);

    clean.split(/\n\n+/).map(p=>p.trim()).filter(Boolean).forEach((para,pi) => {
        const pH = doc.heightOfString(para, { width:TW-8, lineGap:LG, font:'Helvetica', fontSize:FS });
        const bH = pH + PV*2;

        ensureSpace(doc, bH+4);
        const bY = doc.y;

        doc.save().rect(M,bY,CW,bH).fillColor(pi%2===0?'#faf5ff':'#f5f3ff').fill().restore();
        doc.save().rect(M,bY,4,bH).fillColor(C.primary).fill().restore();
        doc.fillColor(C.text).font('Helvetica').fontSize(FS)
           .text(para, TX, bY+PV, { width:TW-8, align:'justify', lineGap:LG });
        doc.y = bY+bH+4;
    });
    doc.y += 2;
}

function findingCard(doc, f, idx) {
    const sev = sevKey(f);
    const col = sevCol(sev);
    const bg  = sevBg(sev);

    const PW2=66, PAD=10, PV=8;
    const TX = M+PW2+PAD, TW = CW-PW2-PAD-4;

    const artifact = (f.artifact_type||'unknown').replace(/_/g,' ').toUpperCase();
    const catStr   = `Category: ${f.category||'—'}`;
    const rawStr   = String(f.raw_value||'—');
    const valStr   = `Value: ${rawStr.length>82 ? rawStr.slice(0,82)+'…' : rawStr}`;
    const recoStr  = String(f.recommendation||'Review and remediate.');
    const recoDisp = `→ ${recoStr.length>115 ? recoStr.slice(0,115)+'…' : recoStr}`;

    const L1=14, L2=12, L3=12;
    const L4 = doc.heightOfString(recoDisp, { width:TW, font:'Helvetica-Oblique', fontSize:7.5, lineGap:2 });
    const inner = PV+L1+3+L2+3+L3+3+L4+PV;
    const CH = Math.max(inner, PW2);

    const sy = doc.y;

    // Card bg + border
    doc.save().roundedRect(M,sy,CW,CH,4).fillColor(bg).fill().restore();
    doc.save().roundedRect(M,sy,CW,CH,4).strokeColor(col).lineWidth(0.5).stroke().restore();
    // Pill
    doc.save().roundedRect(M,sy,PW2,CH,4).fillColor(col).fill().restore();

    const mid = sy+CH/2;
    doc.fillColor(C.white).font('Helvetica-Bold').fontSize(12)
       .text(`#${idx}`, M, mid-20, { width:PW2, align:'center', lineBreak:false });
    doc.fillColor(C.white).font('Helvetica-Bold').fontSize(6.5)
       .text(sev.toUpperCase(), M, mid-4, { width:PW2, align:'center', lineBreak:false });
    doc.fillColor(C.white).font('Helvetica').fontSize(6.5)
       .text(`Score: ${f.score||0}`, M, mid+9, { width:PW2, align:'center', lineBreak:false });

    // Content rows
    let cy = sy+PV;
    const confLabel = `Conf: ${f.confidence||'?'}%`;

    doc.fillColor(C.text).font('Helvetica-Bold').fontSize(9.5)
       .text(artifact, TX, cy, { width:TW-58, lineBreak:false });
    doc.fillColor(col).font('Helvetica-Bold').fontSize(7)
       .text(confLabel, TX, cy+2, { width:TW, align:'right', lineBreak:false });
    cy += L1+3;

    doc.fillColor(C.textLight).font('Helvetica').fontSize(7.5)
       .text(catStr, TX, cy, { width:TW, lineBreak:false });
    cy += L2+3;

    doc.fillColor(C.textLight).font('Helvetica').fontSize(8)
       .text(valStr, TX, cy, { width:TW, lineBreak:false });
    cy += L3+3;

    doc.fillColor(C.muted).font('Helvetica-Oblique').fontSize(7.5)
       .text(recoDisp, TX, cy, { width:TW, lineGap:2 });

    doc.y = sy+CH+5;
}

function recoRow(doc, f, idx) {
    const sev = sevKey(f);
    const col = sevCol(sev);
    const sy  = doc.y;
    const BAR = 4, NW = 24, TX = M+BAR+NW+8, TW = CW-BAR-NW-8;
    const reco = String(f.recommendation||'Review and remediate.');
    const rd   = reco.length>110 ? reco.slice(0,110)+'…' : reco;
    const RH   = Math.max(doc.heightOfString(rd, { width:TW, fontSize:8.5 }) + 28, 44);

    doc.save().rect(M,sy,BAR,RH).fillColor(col).fill().restore();
    doc.fillColor(col).font('Helvetica-Bold').fontSize(11)
       .text(String(idx), M+BAR+4, sy+RH/2-9, { width:NW, align:'center', lineBreak:false });
    doc.fillColor(C.text).font('Helvetica-Bold').fontSize(9)
       .text((f.artifact_type||'unknown').replace(/_/g,' ').toUpperCase(), TX, sy+6, { width:TW, lineBreak:false });
    doc.fillColor(C.textLight).font('Helvetica').fontSize(8.5)
       .text(rd, TX, sy+22, { width:TW });
    doc.y = Math.max(doc.y, sy+RH)+4;
}

function fmt(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('en-GB', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    catch(_) { return iso; }
}

module.exports = { generatePDFReport };
