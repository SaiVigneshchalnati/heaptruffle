'use strict';
/* ═══════════════════════════════════════════════════════════════════
   HeapTruffle v3.0 — Frontend Controller
   ═══════════════════════════════════════════════════════════════════ */

// ── Auth guard ──────────────────────────────────────────────────────
const TOKEN = localStorage.getItem('ht_token');
const USER  = JSON.parse(localStorage.getItem('ht_user') || 'null');
if (!TOKEN || !USER) { window.location.href = '/'; }

const API = (path, opts = {}) =>
    fetch('/api' + path, {
        ...opts,
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN, ...(opts.headers || {}) },
    }).then(async r => {
        // Only logout on 401 (expired/invalid token). 403 = permission denied — show error, don't logout.
        if (r.status === 401) { logout(); throw new Error('Session expired. Please log in again.'); }
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.error || `Request failed (${r.status})`);
        return j;
    });

function logout() {
    localStorage.removeItem('ht_token'); localStorage.removeItem('ht_user');
    window.location.href = '/';
}

document.addEventListener('DOMContentLoaded', () => {

// ── User badge ──────────────────────────────────────────────────────
document.getElementById('user-name-badge').textContent = USER.username;
document.getElementById('role-badge').textContent = USER.role;
// Hide admin-only nav items for non-admins
if (USER.role !== 'admin') {
    document.querySelectorAll('.admin-only').forEach(el => el.style.display = 'none');
}
document.getElementById('logout-btn').addEventListener('click', logout);

// ── Sidebar toggle ──────────────────────────────────────────────────
const sidebar        = document.getElementById('sidebar');
const mainContent    = document.getElementById('main-content');
const overlay        = document.getElementById('sidebar-overlay');
const toggleBtn      = document.getElementById('menu-toggle-btn');
const closeBtn       = document.getElementById('menu-close-btn');
const isMobile       = () => window.innerWidth <= 768;

function openSidebar() {
    sidebar.classList.remove('collapsed'); sidebar.classList.add('open');
    if (isMobile()) overlay.classList.add('active');
    else mainContent.classList.remove('expanded');
}
function closeSidebar() {
    sidebar.classList.add('collapsed'); sidebar.classList.remove('open');
    overlay.classList.remove('active');
    mainContent.classList.add('expanded');
}
function toggleSidebar() { sidebar.classList.contains('collapsed') ? openSidebar() : closeSidebar(); }

toggleBtn.addEventListener('click', toggleSidebar);
closeBtn.addEventListener('click',  closeSidebar);
overlay.addEventListener('click',   closeSidebar);
window.addEventListener('resize',   () => { if (!isMobile()) overlay.classList.remove('active'); });

// ── AI status ───────────────────────────────────────────────────────
API('/health').then(d => {
    const dot  = document.getElementById('ai-dot');
    const txt  = document.getElementById('ai-status-text');
    const top  = document.getElementById('topbar-ai');
    if (d.aiEnabled) {
        dot.classList.add('active'); txt.textContent = 'AI: Gemini Active';
        top.textContent = '✦ AI Enabled';
    } else {
        dot.classList.add('error'); txt.textContent = 'AI: No Key Set';
        top.textContent = '⊘ AI Disabled';
    }
}).catch(() => {});

// ── View Router ─────────────────────────────────────────────────────
const VIEWS = ['dashboard','scan','history','compare','targets','users','audit'];
let activeView = 'dashboard';

function showView(name) {
    if (!VIEWS.includes(name)) return;
    if (name === 'users' && USER.role !== 'admin') return;
    if (name === 'audit' && USER.role !== 'admin') return;
    VIEWS.forEach(v => document.getElementById('view-' + v)?.classList.toggle('hidden', v !== name));
    document.querySelectorAll('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.view === name));
    activeView = name;
    document.title = 'HeapTruffle — ' + name.charAt(0).toUpperCase() + name.slice(1);
    if (isMobile()) closeSidebar();

    const loaders = { dashboard: loadDashboard, history: loadHistory, compare: loadCompareSelects, targets: loadTargets, users: loadUsers, audit: loadAuditLogs };
    loaders[name]?.();
}

document.querySelectorAll('.nav-item').forEach(btn =>
    btn.addEventListener('click', () => showView(btn.dataset.view)));

// ══════════════════════════════════════════════════════════════
//  DASHBOARD
// ══════════════════════════════════════════════════════════════
let chartSev, chartTrend, chartCat;

async function loadDashboard() {
    try {
        const d = await API('/dashboard');
        document.getElementById('ds-scans').textContent    = d.totalScans;
        document.getElementById('ds-findings').textContent = d.totalFindings;
        const sev = Object.fromEntries((d.sevCounts || []).map(r => [r.severity, r.count]));
        document.getElementById('ds-critical').textContent = sev.critical || 0;
        document.getElementById('ds-high').textContent     = sev.high     || 0;

        renderSevChart(sev);
        renderTrendChart(d.trendData || []);
        renderCatChart(d.catCounts || []);
        renderRecentScans(d.recentScans || []);
        renderTopTargets(d.topTargets  || []);
    } catch (e) { console.error('[Dashboard]', e.message); }
}

const CHART_DEFAULTS = {
    color: '#7a8caa',
    plugins: { legend: { labels: { color: '#7a8caa', font: { family: 'Inter' } } } },
    scales: {
        x: { ticks: { color: '#4a5a73', font: { family: 'Inter', size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#4a5a73', font: { family: 'Inter', size: 11 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
    }
};

function renderSevChart(sev) {
    chartSev?.destroy();
    chartSev = new Chart(document.getElementById('chart-sev'), {
        type: 'doughnut',
        data: {
            labels: ['Critical','High','Medium','Low'],
            datasets: [{ data: [sev.critical||0,sev.high||0,sev.medium||0,sev.low||0],
                backgroundColor: ['#ff3b30','#ff9500','#f5a623','#30d158'],
                borderColor: '#070c18', borderWidth: 3 }]
        },
        options: { plugins: { legend: { labels: { color: '#7a8caa', font: { family: 'Inter' } }, position: 'bottom' } }, cutout: '65%' }
    });
}

function renderTrendChart(data) {
    chartTrend?.destroy();
    chartTrend = new Chart(document.getElementById('chart-trend'), {
        type: 'line',
        data: {
            labels: data.map(d => d.day),
            datasets: [
                { label: 'Scans', data: data.map(d => d.scans), borderColor: '#8b5cf6', backgroundColor: 'rgba(139,92,246,0.1)', tension: 0.4, fill: true },
                { label: 'Findings', data: data.map(d => d.findings), borderColor: '#ec4899', backgroundColor: 'rgba(236,72,153,0.1)', tension: 0.4, fill: true },
            ]
        },
        options: { ...CHART_DEFAULTS, interaction: { intersect: false } }
    });
}

function renderCatChart(cats) {
    chartCat?.destroy();
    chartCat = new Chart(document.getElementById('chart-cat'), {
        type: 'bar',
        data: {
            labels: cats.map(c => (c.classification || 'Other').replace(' Exposure','').replace(' Disclosure','')),
            datasets: [{ label: 'Findings', data: cats.map(c => c.count),
                backgroundColor: 'rgba(139,92,246,0.7)', borderRadius: 6, borderSkipped: false }]
        },
        options: { ...CHART_DEFAULTS, plugins: { legend: { display: false } }, indexAxis: 'y' }
    });
}

function renderRecentScans(scans) {
    const el = document.getElementById('dash-recent-scans');
    if (!scans.length) { el.innerHTML = '<div class="empty-state"><i class="uil uil-history"></i>No scans yet</div>'; return; }
    el.innerHTML = scans.map(s => `
        <div class="mini-item" onclick="showScanDetail('${s.id}')">
            <div>
                <div class="mini-item-domain">${s.domain || s.target_url}</div>
                <div class="mini-item-meta">${fmtDate(s.created_at)}</div>
            </div>
            <span class="mini-badge sev-${s.risk_score >= 85 ? 'critical' : s.risk_score >= 65 ? 'high' : 'medium'}" style="background:rgba(139,92,246,0.15);color:#8b5cf6;border:1px solid rgba(139,92,246,0.3)">
                ${s.finding_count || 0} findings
            </span>
        </div>`).join('');
}

function renderTopTargets(targets) {
    const el = document.getElementById('dash-top-targets');
    if (!targets.length) { el.innerHTML = '<div class="empty-state"><i class="uil uil-shield"></i>No data yet</div>'; return; }
    el.innerHTML = targets.map(t => `
        <div class="mini-item">
            <div>
                <div class="mini-item-domain">${t.domain}</div>
                <div class="mini-item-meta">${t.scan_count} scan(s)</div>
            </div>
            <span class="mini-badge ${riskClass(t.max_risk)}" style="padding:2px 9px;border-radius:12px;font-size:0.65rem;font-weight:800;">
                Score ${t.max_risk || 0}
            </span>
        </div>`).join('');
}

// ══════════════════════════════════════════════════════════════
//  NEW SCAN
// ══════════════════════════════════════════════════════════════
let currentScanId = null;
document.getElementById('scan-btn').addEventListener('click', runScan);

const STEPS = [
    { id: 's1', label: 'Launching headless browser' },
    { id: 's2', label: 'Navigating to target URL' },
    { id: 's3', label: 'Waiting for page to idle (networkidle2)' },
    { id: 's4', label: 'Capturing V8 heap snapshot via CDP' },
    { id: 's5', label: 'Running artifact detection engine (26 patterns)' },
    { id: 's6', label: 'Scoring findings with contextual risk analysis' },
    { id: 's7', label: 'Generating AI security intelligence report' },
    { id: 's8', label: 'Persisting results to database' },
];

async function runScan() {
    if (USER.role === 'viewer') return showToast('Viewers cannot run scans.', 'error');
    const url = document.getElementById('url-input').value.trim();
    if (!url) return showToast('Please enter a target URL.', 'error');

    const btn = document.getElementById('scan-btn');
    btn.disabled = true; btn.innerHTML = '<i class="uil uil-spin-icon"></i> Scanning...';

    document.getElementById('results-section').classList.add('hidden');
    showProgress(true);

    const stepEl = document.getElementById('progress-steps');
    stepEl.innerHTML = STEPS.map((s, i) => `
        <div class="step ${i === 0 ? 'active' : ''}" id="${s.id}">
            <div class="step-icon">${i + 1}</div>
            <span>${s.label}</span>
        </div>`).join('');

    let stepIdx = 0;
    const stepTimer = setInterval(() => {
        if (stepIdx < STEPS.length) {
            const prev = document.getElementById(STEPS[Math.max(0, stepIdx - 1)]?.id);
            if (prev) { prev.classList.remove('active'); prev.classList.add('done'); prev.querySelector('.step-icon').innerHTML = '✓'; }
            const curr = document.getElementById(STEPS[stepIdx]?.id);
            if (curr) curr.classList.add('active');
            document.getElementById('progress-title').textContent = STEPS[stepIdx]?.label;
            stepIdx++;
        }
    }, 4500);

    try {
        const data = await API('/scan', { method: 'POST', body: JSON.stringify({ url }) });
        clearInterval(stepTimer);
        STEPS.forEach(s => { const el = document.getElementById(s.id); if (el) { el.classList.remove('active'); el.classList.add('done'); el.querySelector('.step-icon').innerHTML = '✓'; } });
        document.getElementById('progress-title').textContent = '✅ Scan completed!';
        showProgress(false);

        currentScanId = data.scanId;
        renderResults(data);
        showView('scan');
    } catch (err) {
        clearInterval(stepTimer);
        showProgress(false);
        showToast(err.message, 'error');
    }

    btn.disabled = false; btn.innerHTML = '<i class="uil uil-play-circle"></i> Start Forensic Scan';
}

function showProgress(show) {
    document.getElementById('progress-card').classList.toggle('hidden', !show);
}

function renderResults(data) {
    const { stats, findings = [], aiReport, runtimeArtifacts = {} } = data;
    const c = stats?.counts || {};

    // Stats row
    document.getElementById('stats-row').innerHTML = `
        <div class="stat-card stat-critical"><div class="stat-icon"><i class="uil uil-fire"></i></div><div class="stat-number">${c.critical || 0}</div><div class="stat-label">Critical</div></div>
        <div class="stat-card stat-high"><div class="stat-icon"><i class="uil uil-exclamation-triangle"></i></div><div class="stat-number">${c.high || 0}</div><div class="stat-label">High</div></div>
        <div class="stat-card stat-medium"><div class="stat-icon"><i class="uil uil-info-circle"></i></div><div class="stat-number">${c.medium || 0}</div><div class="stat-label">Medium</div></div>
        <div class="stat-card stat-low"><div class="stat-icon"><i class="uil uil-check-circle"></i></div><div class="stat-number">${c.low || 0}</div><div class="stat-label">Low</div></div>
        <div class="stat-card stat-score"><div class="stat-icon"><i class="uil uil-chart-line"></i></div><div class="stat-number">${stats?.totalScore || 0}</div><div class="stat-label">Risk Score</div></div>`;

    document.getElementById('tab-findings-count').textContent = findings.length;

    allFindings = findings;
    renderFindingsList(findings);

    // AI report
    document.getElementById('ai-report-content').innerHTML = aiReport
        ? marked.parse(aiReport)
        : '<p style="color:var(--text-dim)">No AI report available.</p>';

    // Runtime
    document.getElementById('runtime-grid').innerHTML = `
        <div class="runtime-card"><div class="runtime-label">Network Requests</div><div class="runtime-value">${runtimeArtifacts.networkRequestCount || 0}</div></div>
        <div class="runtime-card"><div class="runtime-label">Loaded Scripts</div><div class="runtime-value">${runtimeArtifacts.loadedScriptCount || 0}</div></div>
        <div class="runtime-card"><div class="runtime-label">LocalStorage Keys</div><div class="runtime-value">${runtimeArtifacts.localStorageKeyCount || 0}</div></div>`;

    document.getElementById('results-section').classList.remove('hidden');
    document.getElementById('btn-download-pdf').onclick = () => downloadPDF(currentScanId, data.domain || 'scan');
}

// ── Findings list ────────────────────────────────────────────────────
let allFindings = [];

function renderFindingsList(findings) {
    const el = document.getElementById('findings-list');
    if (!findings.length) { el.innerHTML = '<div class="empty-state"><i class="uil uil-shield-check"></i>No findings for this filter</div>'; return; }
    el.innerHTML = findings.map((f, i) => `
        <div class="finding-item" style="animation-delay:${i * 0.03}s" onclick="openFindingModal(${i})">
            <span class="severity-badge sev-${f.risk_label || f.severity}">${f.risk_label || f.severity}</span>
            <div class="finding-body">
                <div class="finding-type">${(f.artifact_type || '').replace(/_/g, ' ')}</div>
                <div class="finding-value">${escHtml(f.raw_value || '')}</div>
                <div class="finding-desc">${escHtml(f.description || '')}</div>
            </div>
            <div class="finding-meta">
                <div class="finding-score">${f.final_score || f.score || 0}</div>
                <div class="confidence-bar"><div class="confidence-fill" style="width:${f.confidence || 50}%"></div></div>
                <button class="item-copy-btn" onclick="event.stopPropagation();copyVal('${escAttr(f.raw_value)}')" title="Copy"><i class="uil uil-clipboard-alt"></i></button>
            </div>
        </div>`).join('');
}

document.getElementById('findings-search').addEventListener('input', filterFindings);
document.getElementById('filter-pills').addEventListener('click', e => {
    const pill = e.target.closest('.pill');
    if (!pill) return;
    document.querySelectorAll('.pill').forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    filterFindings();
});

function filterFindings() {
    const q   = document.getElementById('findings-search').value.toLowerCase();
    const sev = document.querySelector('.pill.active')?.dataset.sev || 'all';
    const filtered = allFindings.filter(f => {
        const matchSev = sev === 'all' || (f.risk_label || f.severity) === sev;
        const matchQ   = !q || (f.raw_value || '').toLowerCase().includes(q) || (f.artifact_type || '').toLowerCase().includes(q) || (f.description || '').toLowerCase().includes(q);
        return matchSev && matchQ;
    });
    renderFindingsList(filtered);
}

// ── Tab switching ────────────────────────────────────────────────────
document.getElementById('tab-bar')?.addEventListener('click', e => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    document.querySelectorAll('#tab-bar .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.tab;
    ['tab-findings','tab-ai-report','tab-runtime'].forEach(id => {
        document.getElementById(id)?.classList.toggle('hidden', id !== 'tab-' + tab);
    });
});

// ── Finding modal ────────────────────────────────────────────────────
window.openFindingModal = function(idx) {
    const f = allFindings[idx]; if (!f) return;
    document.getElementById('modal-sev').className = 'severity-badge sev-' + (f.risk_label || f.severity);
    document.getElementById('modal-sev').textContent = (f.risk_label || f.severity)?.toUpperCase();
    document.getElementById('modal-title').textContent = (f.artifact_type || '').replace(/_/g, ' ').toUpperCase();
    document.getElementById('modal-body').innerHTML = `
        <div class="modal-field"><div class="modal-field-label">Raw Value</div><div class="modal-field-value">${escHtml(f.raw_value)}</div></div>
        <div class="modal-field"><div class="modal-field-label">Category</div><div class="modal-field-text">${f.category || '—'}</div></div>
        <div class="modal-field"><div class="modal-field-label">Classification</div><div class="modal-field-text">${f.classification || '—'}</div></div>
        <div class="modal-field"><div class="modal-field-label">Description</div><div class="modal-field-text">${escHtml(f.description || '—')}</div></div>
        <div class="modal-field"><div class="modal-field-label">Risk Score / Confidence</div><div class="modal-field-text">${f.final_score || f.score || 0} / ${f.confidence || '?'}%</div></div>
        <div class="modal-field"><div class="modal-field-label">Source</div><div class="modal-field-text">${f.source_type || 'heap'}</div></div>
        <div class="modal-field"><div class="modal-field-label">Remediation</div><div class="reco-box">${escHtml(f.recommendation || 'No recommendation available.')}</div></div>`;
    document.getElementById('modal-backdrop').classList.remove('hidden');
};
document.getElementById('modal-close').addEventListener('click',    () => document.getElementById('modal-backdrop').classList.add('hidden'));
document.getElementById('modal-backdrop').addEventListener('click', e => { if (e.target.id === 'modal-backdrop') document.getElementById('modal-backdrop').classList.add('hidden'); });

// ══════════════════════════════════════════════════════════════
//  SCAN HISTORY
// ══════════════════════════════════════════════════════════════
async function loadHistory() {
    const el = document.getElementById('history-list');
    el.innerHTML = '<div class="empty-state"><i class="uil uil-spin-icon"></i> Loading...</div>';
    try {
        const { scans } = await API('/scans?limit=50');
        if (!scans.length) { el.innerHTML = '<div class="empty-state"><i class="uil uil-history"></i>No scans yet. Run your first scan!</div>'; return; }
        el.innerHTML = scans.map(s => `
            <div class="history-item">
                <div style="flex:1;min-width:120px">
                    <div class="history-domain">${s.domain || s.target_url}</div>
                    <div class="history-meta">${fmtDate(s.created_at)}</div>
                </div>
                <span class="status-badge status-${s.status}">${s.status}</span>
                <span style="font-size:0.8rem;color:var(--text-muted)">${s.finding_count || 0} findings</span>
                <span style="font-size:0.8rem;color:var(--purple);font-weight:700">Score: ${s.risk_score || 0}</span>
                <div class="history-actions">
                    <button class="btn-outline" onclick="loadScanDetail('${s.id}')"><i class="uil uil-eye"></i> View</button>
                    ${s.status === 'completed' ? `<button class="btn-outline" onclick="downloadPDF('${s.id}','${s.domain}')"><i class="uil uil-file-download"></i> PDF</button>` : ''}
                    <button class="btn-danger" onclick="confirmDelete('${s.id}')"><i class="uil uil-trash"></i></button>
                </div>
            </div>`).join('');
    } catch (e) { el.innerHTML = '<div class="empty-state">Failed to load history.</div>'; }
}

window.loadScanDetail = async function(id) {
    showView('scan');
    try {
        const data = await API('/scans/' + id);
        allFindings = data.findings || [];
        currentScanId = id;
        const c = {};
        allFindings.forEach(f => { const s = f.severity; c[s] = (c[s] || 0) + 1; });
        const total = allFindings.length ? Math.round(allFindings.reduce((s, f) => s + (f.score || 0), 0) / allFindings.length) : 0;
        renderResults({ stats: { counts: c, totalScore: total }, findings: allFindings, aiReport: data.aiReport, runtimeArtifacts: {} });
    } catch (e) { showToast('Failed to load scan: ' + e.message, 'error'); }
};

window.confirmDelete = async function(id) {
    if (!confirm('Delete this scan and all its findings?')) return;
    try { await API('/scans/' + id, { method: 'DELETE' }); loadHistory(); showToast('Scan deleted.'); } catch (e) { showToast(e.message, 'error'); }
};

// ══════════════════════════════════════════════════════════════
//  COMPARE SCANS
// ══════════════════════════════════════════════════════════════
async function loadCompareSelects() {
    try {
        const { scans } = await API('/scans?limit=50');
        const opts = scans.filter(s => s.status === 'completed').map(s => `<option value="${s.id}">${s.domain} — ${fmtDate(s.created_at)}</option>`).join('');
        document.getElementById('compare-scan-a').innerHTML = opts;
        document.getElementById('compare-scan-b').innerHTML = opts;
    } catch (e) {}
}

document.getElementById('btn-compare').addEventListener('click', async () => {
    const a = document.getElementById('compare-scan-a').value;
    const b = document.getElementById('compare-scan-b').value;
    if (!a || !b || a === b) return showToast('Please select two different scans.', 'error');
    try {
        const data = await API(`/scans/compare?a=${a}&b=${b}`);
        const res = document.getElementById('compare-results');
        res.classList.remove('hidden');

        document.getElementById('compare-summary').innerHTML = `
            <div class="diff-card"><div class="diff-num" style="color:var(--critical)">${data.summary.newCount}</div><div class="diff-lbl">New Findings</div></div>
            <div class="diff-card"><div class="diff-num" style="color:var(--low)">${data.summary.removedCount}</div><div class="diff-lbl">Resolved</div></div>
            <div class="diff-card"><div class="diff-num" style="color:var(--high)">${data.summary.changedCount}</div><div class="diff-lbl">Severity Changes</div></div>`;

        renderCompareFindingsList('compare-content-new', data.newFindings || []);
        renderCompareFindingsList('compare-content-removed', data.removedFindings || []);

        const changedEl = document.getElementById('compare-content-changed');
        changedEl.innerHTML = data.severityChanges.length
            ? data.severityChanges.map(c => `<div class="finding-item">
                <div class="finding-body">
                    <div class="finding-type">${c.artifact}</div>
                    <div class="finding-desc">Severity: <span class="severity-badge sev-${c.from}">${c.from}</span> → <span class="severity-badge sev-${c.to}">${c.to}</span></div>
                </div></div>`).join('')
            : '<div class="empty-state"><i class="uil uil-check-circle"></i>No severity changes</div>';
    } catch (e) { showToast(e.message, 'error'); }
});

function renderCompareFindingsList(containerId, findings) {
    const el = document.getElementById(containerId);
    if (!findings.length) { el.innerHTML = '<div class="empty-state"><i class="uil uil-check-circle"></i>None</div>'; return; }
    el.innerHTML = findings.map(f => `
        <div class="finding-item">
            <span class="severity-badge sev-${f.severity}">${f.severity}</span>
            <div class="finding-body">
                <div class="finding-type">${(f.artifact_type || '').replace(/_/g, ' ')}</div>
                <div class="finding-value">${escHtml(f.raw_value || '')}</div>
            </div>
        </div>`).join('');
}

// Compare tab switching
document.querySelector('.compare-tabs')?.addEventListener('click', e => {
    const btn = e.target.closest('.tab-btn');
    if (!btn) return;
    document.querySelectorAll('.compare-tabs .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const tab = btn.dataset.ctab;
    ['new','removed','changed'].forEach(t => {
        document.getElementById('compare-content-' + t)?.classList.toggle('hidden', t !== tab);
    });
});

// ══════════════════════════════════════════════════════════════
//  TARGETS
// ══════════════════════════════════════════════════════════════
async function loadTargets() {
    const el = document.getElementById('targets-list');
    try {
        const { targets } = await API('/targets');
        el.innerHTML = targets.length ? targets.map(t => `
            <div class="target-item">
                <div class="target-domain">${t.domain}</div>
                <div class="target-meta">${t.label || '—'} · Auth: ${t.authorized_by || '—'}</div>
                <span class="active-badge ${t.is_active ? 'active-yes' : 'active-no'}">${t.is_active ? 'Active' : 'Disabled'}</span>
                ${USER.role === 'admin' ? `
                    <button class="btn-outline" onclick="toggleTarget('${t.id}')"><i class="uil uil-toggle-on"></i></button>
                    <button class="btn-danger" onclick="deleteTarget('${t.id}')"><i class="uil uil-trash"></i></button>` : ''}
            </div>`).join('')
            : '<div class="empty-state"><i class="uil uil-shield"></i>No authorized targets yet.</div>';
    } catch (e) {}
}

if (USER.role !== 'admin') document.getElementById('add-target-card')?.style.setProperty('display','none');

document.getElementById('btn-add-target')?.addEventListener('click', async () => {
    const domain = document.getElementById('target-domain').value.trim();
    const label  = document.getElementById('target-label').value.trim();
    const notes  = document.getElementById('target-notes').value.trim();
    if (!domain) return showToast('Domain is required.', 'error');
    try {
        await API('/targets', { method: 'POST', body: JSON.stringify({ domain, label, notes }) });
        document.getElementById('target-domain').value = '';
        document.getElementById('target-label').value  = '';
        document.getElementById('target-notes').value  = '';
        loadTargets(); showToast('Target added!');
    } catch (e) { showToast(e.message, 'error'); }
});

window.deleteTarget = async function(id) {
    if (!confirm('Remove this target?')) return;
    try { await API('/targets/' + id, { method: 'DELETE' }); loadTargets(); showToast('Target removed.'); } catch (e) { showToast(e.message, 'error'); }
};
window.toggleTarget = async function(id) {
    try { await API('/targets/' + id + '/toggle', { method: 'PATCH' }); loadTargets(); } catch (e) { showToast(e.message, 'error'); }
};

// ══════════════════════════════════════════════════════════════
//  USERS (Admin)
// ══════════════════════════════════════════════════════════════
async function loadUsers() {
    const el = document.getElementById('users-list');
    try {
        const { users } = await API('/auth/users');
        el.innerHTML = users.map(u => `
            <div class="user-item">
                <div class="user-avatar">${u.username.charAt(0)}</div>
                <div class="user-info">
                    <div class="user-name">${u.username} <span class="role-badge">${u.role}</span></div>
                    <div class="user-email">${u.email} · Last login: ${u.last_login ? fmtDate(u.last_login) : 'Never'}</div>
                </div>
                ${u.id !== USER.id ? `<button class="btn-danger" onclick="deleteUser('${u.id}')"><i class="uil uil-trash"></i></button>` : ''}
            </div>`).join('');
    } catch (e) {}
}

document.getElementById('btn-create-user')?.addEventListener('click', async () => {
    const username = document.getElementById('new-username').value.trim();
    const email    = document.getElementById('new-email').value.trim();
    const password = document.getElementById('new-password').value;
    const role     = document.getElementById('new-role').value;
    if (!username || !email || !password) return showToast('All fields required.', 'error');
    try {
        await API('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password, role }) });
        document.getElementById('new-username').value = '';
        document.getElementById('new-email').value    = '';
        document.getElementById('new-password').value = '';
        loadUsers(); showToast('User created!');
    } catch (e) { showToast(e.message, 'error'); }
});

window.deleteUser = async function(id) {
    if (!confirm('Delete this user?')) return;
    try { await API('/auth/users/' + id, { method: 'DELETE' }); loadUsers(); showToast('User deleted.'); } catch (e) { showToast(e.message, 'error'); }
};

// ══════════════════════════════════════════════════════════════
//  AUDIT LOGS
// ══════════════════════════════════════════════════════════════
async function loadAuditLogs() {
    const el = document.getElementById('audit-list');
    try {
        const { logs } = await API('/audit-logs');
        el.innerHTML = logs.length ? logs.map(l => `
            <div class="audit-item">
                <span class="audit-action">${l.action}</span>
                <span class="audit-detail">${escHtml(l.detail || '—')}</span>
                <span class="audit-time">${fmtDate(l.timestamp)}</span>
            </div>`).join('')
            : '<div class="empty-state">No audit logs yet.</div>';
    } catch (e) {}
}

// ══════════════════════════════════════════════════════════════
//  PDF Download
// ══════════════════════════════════════════════════════════════
window.downloadPDF = function(scanId, domain) {
    if (!scanId) return showToast('No scan selected.', 'error');
    showToast('Generating PDF report...');
    const a = document.createElement('a');
    a.href = '/api/scans/' + scanId + '/pdf';
    a.download = `heaptruffle-${domain || 'scan'}.pdf`;
    // Add auth header via fetch and blob
    fetch('/api/scans/' + scanId + '/pdf', { headers: { 'Authorization': 'Bearer ' + TOKEN } })
        .then(r => r.blob()).then(blob => {
            const url = URL.createObjectURL(blob);
            a.href = url; a.click(); URL.revokeObjectURL(url);
            showToast('PDF downloaded!');
        }).catch(() => showToast('PDF generation failed.', 'error'));
};

// ══════════════════════════════════════════════════════════════
//  UTILITIES
// ══════════════════════════════════════════════════════════════
window.copyVal = function(val) {
    navigator.clipboard.writeText(val).then(() => showToast('Copied!')).catch(() => {});
};

window.showScanDetail = function(id) {
    window.loadScanDetail(id);
};

function fmtDate(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' }); }
    catch (_) { return iso; }
}

function escHtml(s) { return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escAttr(s) { return String(s || '').replace(/"/g,'&quot;').replace(/'/g,'&#39;'); }

function riskClass(score) {
    if (score >= 85) return 'sev-critical';
    if (score >= 65) return 'sev-high';
    if (score >= 35) return 'sev-medium';
    return 'sev-low';
}

// ── Toast ────────────────────────────────────────────────────────────
function showToast(msg, type = 'success') {
    const t = document.createElement('div');
    t.style.cssText = `position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;padding:0.75rem 1.25rem;
        background:${type === 'error' ? 'rgba(255,59,48,0.15)' : 'rgba(48,209,88,0.15)'};
        border:1px solid ${type === 'error' ? 'rgba(255,59,48,0.35)' : 'rgba(48,209,88,0.35)'};
        color:${type === 'error' ? '#ff6b6b' : '#4ade80'};
        border-radius:12px;font-size:0.85rem;font-weight:600;font-family:Inter,sans-serif;
        box-shadow:0 8px 24px rgba(0,0,0,0.4);animation:fadeIn 0.25s ease;max-width:320px;`;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
}

// ── Init ─────────────────────────────────────────────────────────────
showView('dashboard');

}); // DOMContentLoaded
