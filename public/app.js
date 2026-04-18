/* ============================================================
   HeapTruffle v2 — Frontend Application Controller
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {

    // ==================== SIDEBAR TOGGLE ====================
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('main-content');
    const menuToggleBtn = document.getElementById('menu-toggle-btn');
    const menuCloseBtn = document.getElementById('menu-close-btn');
    const sidebarOverlay = document.getElementById('sidebar-overlay');

    // On desktop (>768px), sidebar starts expanded.
    // On mobile (<768px), sidebar starts hidden.
    function isMobile() { return window.innerWidth <= 768; }

    function openSidebar() {
        sidebar.classList.remove('collapsed');
        sidebar.classList.add('open');
        if (!isMobile()) {
            mainContent.classList.remove('sidebar-collapsed');
        } else {
            sidebarOverlay.classList.add('active');
        }
        menuToggleBtn.querySelector('i').className = 'uil uil-bars';
    }

    function closeSidebar() {
        sidebar.classList.add('collapsed');
        sidebar.classList.remove('open');
        mainContent.classList.add('sidebar-collapsed');
        sidebarOverlay.classList.remove('active');
    }

    function toggleSidebar() {
        if (sidebar.classList.contains('collapsed')) {
            openSidebar();
        } else {
            closeSidebar();
        }
    }

    menuToggleBtn.addEventListener('click', toggleSidebar);
    menuCloseBtn.addEventListener('click', closeSidebar);
    sidebarOverlay.addEventListener('click', closeSidebar);

    // Close sidebar on mobile when a nav item is clicked
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            if (isMobile()) closeSidebar();
        });
    });

    // Handle resize
    window.addEventListener('resize', () => {
        if (!isMobile() && sidebar.classList.contains('collapsed')) {
            // Keep collapsed state on desktop if user explicitly collapsed it
        }
        if (!isMobile()) {
            sidebarOverlay.classList.remove('active');
        }
    });

    // STATE ====================
    let allFindings = [];
    let activeFindings = [];
    let activeSeverityFilter = 'all';
    let activeTextFilter = '';

    // ==================== DOM REFERENCES ====================
    const $ = id => document.getElementById(id);
    const $$ = sel => document.querySelectorAll(sel);

    const form = $('scan-form');
    const urlInput = $('url-input');
    const scanBtn = $('scan-btn');
    const btnText = scanBtn.querySelector('.btn-text');
    const loader = scanBtn.querySelector('.loader');
    const scanStatus = $('scan-status');
    const errorMsg = $('error-message');
    const errorText = $('error-text');
    const resultsSection = $('results-section');

    // Stats
    const statCritical = $('stat-critical');
    const statHigh = $('stat-high');
    const statMedium = $('stat-medium');
    const statLow = $('stat-low');
    const statScore = $('stat-score');
    const findingsBadge = $('findings-badge');

    // Findings tab
    const filterInput = $('filter-input');
    const findingsList = $('findings-list');
    const copyAllBtn = $('copy-all-btn');

    // AI Report tab
    const aiReportBody = $('ai-report-body');

    // Runtime tab
    const runtimeGrid = $('runtime-grid');

    // Scan status steps
    const steps = {
        browser: $('step-browser'),
        capture: $('step-capture'),
        analyze: $('step-analyze'),
        ai: $('step-ai'),
    };

    // ==================== NAVIGATION ====================
    const navItems = $$('.nav-item');
    const views = { scan: $('view-scan'), history: $('view-history'), audit: $('view-audit') };

    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            const target = item.dataset.view;
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            Object.values(views).forEach(v => { v.classList.remove('active'); v.classList.add('hidden'); });
            views[target].classList.remove('hidden');
            views[target].classList.add('active');
            if (target === 'history') loadHistory();
            if (target === 'audit') loadAuditLogs();
        });
    });

    // ==================== TABS ====================
    const tabBtns = $$('.tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            $$('.tab-content').forEach(c => { c.classList.remove('active'); c.classList.add('hidden'); });
            const content = $(`tab-content-${tab}`);
            content.classList.remove('hidden');
            content.classList.add('active');
        });
    });

    // ==================== AI STATUS CHECK ====================
    async function checkAIStatus() {
        try {
            const res = await fetch('/api/health');
            const data = await res.json();
            const dot = $('ai-dot');
            const text = $('ai-status-text');
            if (data.aiEnabled) {
                dot.classList.add('on');
                text.textContent = 'AI: Gemini Active';
            } else {
                dot.classList.add('off');
                text.textContent = 'AI: No Key Set';
            }
        } catch (_) {
            $('ai-status-text').textContent = 'AI: Offline';
        }
    }
    checkAIStatus();

    // ==================== SCAN FORM ====================
    form.addEventListener('submit', async e => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) return;

        setUI('loading');
        hideError();
        resultsSection.classList.add('hidden');

        // Simulate progress steps with timing
        activateStep('browser');
        const stepTimer1 = setTimeout(() => activateStep('capture'), 5000);
        const stepTimer2 = setTimeout(() => activateStep('analyze'), 15000);
        const stepTimer3 = setTimeout(() => activateStep('ai'), 25000);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });

            clearTimeout(stepTimer1);
            clearTimeout(stepTimer2);
            clearTimeout(stepTimer3);

            const data = await response.json();

            if (!response.ok) throw new Error(data.error || 'Scan failed');

            // Mark all steps done
            Object.values(steps).forEach(s => { s.classList.remove('active'); s.classList.add('done'); });

            displayResults(data);

        } catch (err) {
            clearTimeout(stepTimer1);
            clearTimeout(stepTimer2);
            clearTimeout(stepTimer3);
            showError(err.message);
        } finally {
            setUI('idle');
        }
    });

    // ==================== DISPLAY RESULTS ====================
    function displayResults(data) {
        const { stats, findings, aiReport, runtimeArtifacts } = data;

        allFindings = findings;
        activeFindings = findings;

        // Stats
        statCritical.textContent = stats.counts.critical;
        statHigh.textContent = stats.counts.high;
        statMedium.textContent = stats.counts.medium;
        statLow.textContent = stats.counts.low;
        statScore.textContent = stats.totalScore;
        findingsBadge.textContent = findings.length;

        // Reset filters
        activeSeverityFilter = 'all';
        activeTextFilter = '';
        filterInput.value = '';
        $$('.pill').forEach(p => p.classList.remove('active'));
        $$('[data-sev="all"]').forEach(p => p.classList.add('active'));

        // Render findings
        renderFindings(findings);

        // AI Report
        if (aiReport && typeof marked !== 'undefined') {
            aiReportBody.innerHTML = marked.parse(aiReport);
        } else if (aiReport) {
            aiReportBody.innerHTML = `<pre style="white-space:pre-wrap">${escapeHtml(aiReport)}</pre>`;
        } else {
            aiReportBody.innerHTML = '<p class="text-muted">No AI report available.</p>';
        }

        // Runtime Artifacts
        if (runtimeArtifacts) {
            runtimeGrid.innerHTML = `
                <div class="runtime-stat">
                    <div class="runtime-stat-num">${runtimeArtifacts.networkRequestCount}</div>
                    <div class="runtime-stat-label">XHR / Fetch Requests</div>
                </div>
                <div class="runtime-stat">
                    <div class="runtime-stat-num">${runtimeArtifacts.loadedScriptCount}</div>
                    <div class="runtime-stat-label">Loaded JS Scripts</div>
                </div>
                <div class="runtime-stat">
                    <div class="runtime-stat-num">${runtimeArtifacts.localStorageKeyCount}</div>
                    <div class="runtime-stat-label">localStorage Keys</div>
                </div>
            `;
        }

        // Switch to findings tab
        tabBtns.forEach(b => b.classList.remove('active'));
        document.querySelector('[data-tab="findings"]').classList.add('active');
        $$('.tab-content').forEach(c => { c.classList.remove('active'); c.classList.add('hidden'); });
        $('tab-content-findings').classList.remove('hidden');
        $('tab-content-findings').classList.add('active');

        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // ==================== RENDER FINDINGS LIST ====================
    function renderFindings(findings) {
        findingsList.innerHTML = '';

        if (findings.length === 0) {
            findingsList.innerHTML = `
                <div class="empty-state">
                    <i class="uil uil-search-minus"></i>
                    <p>No findings match your current filters.</p>
                </div>`;
            return;
        }

        findings.forEach((f, idx) => {
            const sev = (f.risk_label || f.severity || 'low').toLowerCase();
            const item = document.createElement('div');
            item.className = 'finding-item';
            item.style.animationDelay = `${Math.min(idx * 0.04, 1.2)}s`;

            item.innerHTML = `
                <span class="severity-badge sev-${sev}">${sev}</span>
                <div class="finding-body">
                    <div class="finding-type">${escapeHtml(f.artifact_type || f.category || '')}</div>
                    <div class="finding-value" title="${escapeHtml(f.raw_value)}">${escapeHtml(f.raw_value)}</div>
                    <div class="finding-desc">${escapeHtml(f.description || '')}</div>
                </div>
                <span class="finding-score">${f.final_score || f.score || 0}/100</span>
                <button class="item-copy-btn" title="Copy value"><i class="uil uil-copy"></i></button>
            `;

            item.querySelector('.item-copy-btn').addEventListener('click', e => {
                e.stopPropagation();
                copyToClipboard(f.raw_value, e.currentTarget);
            });

            findingsList.appendChild(item);
        });
    }

    // ==================== FILTERING ====================
    filterInput.addEventListener('input', e => {
        activeTextFilter = e.target.value.toLowerCase();
        applyFilters();
    });

    $$('.pill').forEach(pill => {
        pill.addEventListener('click', () => {
            $$('.pill').forEach(p => p.classList.remove('active'));
            pill.classList.add('active');
            activeSeverityFilter = pill.dataset.sev;
            applyFilters();
        });
    });

    function applyFilters() {
        activeFindings = allFindings.filter(f => {
            const sev = (f.risk_label || f.severity || '').toLowerCase();
            const matchesSev = activeSeverityFilter === 'all' || sev === activeSeverityFilter;
            const matchesText = !activeTextFilter
                || f.raw_value.toLowerCase().includes(activeTextFilter)
                || (f.artifact_type || '').toLowerCase().includes(activeTextFilter)
                || (f.description || '').toLowerCase().includes(activeTextFilter);
            return matchesSev && matchesText;
        });
        renderFindings(activeFindings);
    }

    // ==================== COPY ALL ====================
    copyAllBtn.addEventListener('click', () => {
        if (activeFindings.length === 0) return;
        const text = activeFindings.map(f => `[${(f.risk_label || f.severity || '').toUpperCase()}] ${f.artifact_type}: ${f.raw_value}`).join('\n');
        navigator.clipboard.writeText(text).then(() => {
            const orig = copyAllBtn.innerHTML;
            copyAllBtn.innerHTML = '<i class="uil uil-check"></i> Copied!';
            copyAllBtn.style.color = 'var(--low)';
            setTimeout(() => { copyAllBtn.innerHTML = orig; copyAllBtn.style.color = ''; }, 2000);
        });
    });

    // ==================== SCAN HISTORY ====================
    async function loadHistory() {
        const list = $('history-list');
        list.innerHTML = '<div class="empty-state"><i class="uil uil-spinner-alt"></i><p>Loading...</p></div>';
        try {
            const res = await fetch('/api/scans');
            const { scans } = await res.json();
            if (!scans.length) {
                list.innerHTML = '<div class="empty-state"><i class="uil uil-calendar-slash"></i><p>No scans yet. Run your first scan!</p></div>';
                return;
            }
            list.innerHTML = '';
            scans.forEach(scan => {
                const item = document.createElement('div');
                item.className = 'history-item';
                const date = new Date(scan.created_at).toLocaleString();
                item.innerHTML = `
                    <i class="uil uil-globe" style="font-size:1.5rem;color:var(--text-dim)"></i>
                    <div class="history-domain">
                        <strong>${escapeHtml(scan.domain || scan.target_url)}</strong>
                        <small>${escapeHtml(scan.target_url)} &mdash; ${date}</small>
                    </div>
                    <div class="history-meta">
                        <span class="history-status status-${scan.status}">${scan.status}</span>
                        <div class="history-count">${scan.finding_count || 0} findings</div>
                    </div>
                    <button class="btn btn-danger btn-sm" data-id="${scan.id}" title="Delete" style="padding:0.4rem 0.8rem;font-size:0.8rem">
                        <i class="uil uil-trash-alt"></i>
                    </button>
                `;
                item.querySelector('.btn-danger').addEventListener('click', async e => {
                    e.stopPropagation();
                    if (!confirm('Delete this scan?')) return;
                    await fetch(`/api/scans/${scan.id}`, { method: 'DELETE' });
                    loadHistory();
                });
                list.appendChild(item);
            });
        } catch (err) {
            list.innerHTML = `<div class="empty-state"><i class="uil uil-exclamation-triangle"></i><p>Failed to load history: ${escapeHtml(err.message)}</p></div>`;
        }
    }

    // ==================== AUDIT LOGS ====================
    async function loadAuditLogs() {
        const list = $('audit-list');
        list.innerHTML = '<div class="empty-state"><i class="uil uil-spinner-alt"></i><p>Loading...</p></div>';
        try {
            const res = await fetch('/api/audit-logs');
            const { logs } = await res.json();
            if (!logs.length) {
                list.innerHTML = '<div class="empty-state"><i class="uil uil-file-blank"></i><p>No logs yet.</p></div>';
                return;
            }
            list.innerHTML = '';
            logs.forEach(log => {
                const item = document.createElement('div');
                item.className = 'audit-item';
                const ts = new Date(log.timestamp).toLocaleString();
                item.innerHTML = `
                    <span class="audit-action">${escapeHtml(log.action)}</span>
                    <span class="audit-detail">${escapeHtml(log.detail || '')}</span>
                    <span class="audit-time">${ts}</span>
                `;
                list.appendChild(item);
            });
        } catch (err) {
            list.innerHTML = `<div class="empty-state"><p>Failed to load audit logs.</p></div>`;
        }
    }

    // ==================== UI HELPERS ====================
    function setUI(mode) {
        if (mode === 'loading') {
            scanBtn.disabled = true;
            btnText.classList.add('hidden');
            loader.classList.remove('hidden');
            scanStatus.classList.remove('hidden');
            // Reset steps
            Object.values(steps).forEach(s => { s.classList.remove('active', 'done'); });
        } else {
            scanBtn.disabled = false;
            btnText.classList.remove('hidden');
            loader.classList.add('hidden');
            scanStatus.classList.add('hidden');
        }
    }

    function activateStep(name) {
        // Mark previous steps as done
        const order = ['browser', 'capture', 'analyze', 'ai'];
        const idx = order.indexOf(name);
        order.forEach((s, i) => {
            steps[s].classList.remove('active', 'done');
            if (i < idx) steps[s].classList.add('done');
            if (i === idx) steps[s].classList.add('active');
        });
    }

    function showError(msg) {
        errorText.textContent = msg;
        errorMsg.classList.remove('hidden');
    }

    function hideError() {
        errorMsg.classList.add('hidden');
    }

    function copyToClipboard(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.innerHTML;
            btn.innerHTML = '<i class="uil uil-check"></i>';
            btn.style.color = 'var(--low)';
            setTimeout(() => { btn.innerHTML = orig; btn.style.color = ''; }, 1500);
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
});
