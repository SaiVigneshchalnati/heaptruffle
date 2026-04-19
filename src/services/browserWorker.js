/**
 * browserWorker.js — Handles all Puppeteer browser automation for heap snapshot acquisition.
 * Designed to be fault-tolerant: always returns results, never throws on timeout/CDP failures.
 */
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');
puppeteer.use(StealthPlugin());
const parser = require('heapsnapshot-parser');

/**
 * Launches a headless browser, navigates to the target URL, then captures:
 * - Heap snapshot (if possible)
 * - JS file URLs loaded
 * - Network requests (XHR/Fetch)
 * - Local Storage keys
 * - Console messages
 *
 * Returns a result object WITH a `heapStatus` field indicating success or reason for failure.
 * This function NEVER throws — all errors are caught and returned as metadata.
 *
 * @param {string} url - The target URL to scan
 * @returns {Promise<{ snapshotText: string, heapStatus: string, runtimeArtifacts: object }>}
 */
async function captureArtifacts(url) {
    let browser;
    const networkRequests = [];
    const consoleMessages = [];
    const loadedScripts = [];
    let heapStatus = 'success';

    try {
        browser = await puppeteer.launch({
            headless: 'new',
            protocolTimeout: 60000,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-background-networking',
            ],
        });

        const page = await browser.newPage();

        // Set a realistic user agent to avoid bot detection blocks
        await page.setUserAgent(
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        );

        // --- Intercept network requests ---
        await page.setRequestInterception(true);
        page.on('request', req => {
            const resourceType = req.resourceType();
            const reqUrl = req.url();
            if (resourceType === 'script') {
                loadedScripts.push(reqUrl);
            }
            if (['xhr', 'fetch'].includes(resourceType)) {
                networkRequests.push({ url: reqUrl, method: req.method() });
            }
            req.continue();
        });

        // --- Capture console output ---
        page.on('console', msg => {
            consoleMessages.push({ type: msg.type(), text: msg.text() });
        });

        // --- Navigate: try networkidle2, fall back to domcontentloaded ---
        let navSuccess = false;
        try {
            await page.goto(url, { waitUntil: 'networkidle2', timeout: 30000 });
            navSuccess = true;
        } catch (navErr1) {
            console.warn(`[BrowserWorker] networkidle2 timeout for ${url}, retrying with domcontentloaded...`);
            try {
                await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20000 });
                navSuccess = true;
            } catch (navErr2) {
                console.warn(`[BrowserWorker] domcontentloaded also failed: ${navErr2.message}. Using partial page.`);
                heapStatus = 'partial_load';
            }
        }

        // Give JS time to execute even after a partial load
        if (!navSuccess) {
            await new Promise(r => setTimeout(r, 3000));
        }

        // --- Stop the page to freeze V8 state before snapshotting ---
        try {
            await page.evaluate(() => window.stop());
        } catch (_) { /* ignore: page may be incomplete */ }

        // --- Capture localStorage keys ---
        let localStorageKeys = [];
        try {
            localStorageKeys = await Promise.race([
                page.evaluate(() => Object.keys(localStorage)),
                new Promise((_, rej) => setTimeout(() => rej(new Error('localStorage timeout')), 5000))
            ]);
        } catch (evalErr) {
            console.warn(`[BrowserWorker] localStorage capture skipped: ${evalErr.message}`);
        }

        // --- Take heap snapshot via CDP ---
        let snapshotText = '';
        try {
            const client = await page.target().createCDPSession();
            const chunks = [];
            client.on('HeapProfiler.addHeapSnapshotChunk', ({ chunk }) => chunks.push(chunk));

            await Promise.race([
                client.send('HeapProfiler.takeHeapSnapshot', { reportProgress: false }),
                new Promise((_, rej) => setTimeout(() => rej(new Error('CDP Snapshot Timeout')), 25000))
            ]);

            snapshotText = chunks.join('');
            if (!snapshotText || snapshotText.trim() === '') {
                heapStatus = 'heap_empty';
                console.warn(`[BrowserWorker] Heap snapshot was empty for ${url}.`);
            } else {
                if (heapStatus === 'success') heapStatus = 'success';
                console.log(`[BrowserWorker] Heap snapshot captured: ${snapshotText.length} bytes.`);
            }
        } catch (snapErr) {
            console.warn(`[BrowserWorker] Heap snapshot failed: ${snapErr.message}`);
            snapshotText = '';
            if (heapStatus !== 'partial_load') heapStatus = 'heap_failed';
        }

        await browser.close();

        return {
            snapshotText,
            heapStatus,
            runtimeArtifacts: {
                networkRequests,
                loadedScripts,
                consoleMessages,
                localStorageKeys,
            },
        };
    } catch (err) {
        if (browser) {
            try { await browser.close(); } catch (_) {}
        }
        // Even a critical browser failure returns a result, not a throw
        console.error(`[BrowserWorker] Critical browser failure: ${err.message}`);
        return {
            snapshotText: '',
            heapStatus: 'browser_failed',
            runtimeArtifacts: {
                networkRequests,
                loadedScripts,
                consoleMessages,
                localStorageKeys: [],
            },
        };
    }
}

/**
 * Extracts all node name strings from a parsed heap snapshot.
 * Returns empty string (gracefully) if snapshot is missing or corrupt.
 * @param {string} snapshotText - Raw JSON snapshot text
 * @returns {string} - A single large string of all node names joined by newline
 */
function extractSnapshotText(snapshotText) {
    if (!snapshotText || snapshotText.trim() === '') return '';
    let snapshot;
    try {
        snapshot = parser.parse(snapshotText);
    } catch (parseErr) {
        console.warn(`[BrowserWorker] Failed to parse heap snapshot: ${parseErr.message}`);
        return '';
    }
    const lines = [];
    for (let i = 0; i < snapshot.nodes.length; i++) {
        const name = snapshot.nodes[i].name;
        if (name && name.length > 3) {
            lines.push(name);
        }
    }
    return lines.join('\n');
}

module.exports = { captureArtifacts, extractSnapshotText };
