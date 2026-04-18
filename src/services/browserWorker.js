/**
 * browserWorker.js — Handles all Puppeteer browser automation for heap snapshot acquisition.
 */
const puppeteer = require('puppeteer');
const parser = require('heapsnapshot-parser');

/**
 * Launches a headless browser, navigates to the target URL,
 * waits for full page load + XHR/fetch completion, then captures:
 * - Heap snapshot
 * - JS file URLs loaded
 * - Network requests (XHR/Fetch)
 * - Local Storage keys
 * - Console messages
 *
 * @param {string} url - The target URL to scan
 * @returns {Promise<{ snapshotText: string, runtimeArtifacts: object }>}
 */
async function captureArtifacts(url) {
    let browser;
    const networkRequests = [];
    const consoleMessages = [];
    const loadedScripts = [];

    try {
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
            ],
        });

        const page = await browser.newPage();

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

        await page.goto(url, { waitUntil: 'networkidle2', timeout: 45000 });

        // --- Capture localStorage keys ---
        const localStorageKeys = await page.evaluate(() => Object.keys(localStorage));

        // --- Take heap snapshot via CDP ---
        const client = await page.target().createCDPSession();
        const chunks = [];
        client.on('HeapProfiler.addHeapSnapshotChunk', ({ chunk }) => chunks.push(chunk));
        await client.send('HeapProfiler.takeHeapSnapshot', { reportProgress: false });
        const snapshotText = chunks.join('');

        await browser.close();

        return {
            snapshotText,
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
        throw err;
    }
}

/**
 * Extracts all node name strings from a parsed heap snapshot.
 * @param {string} snapshotText - Raw JSON snapshot text
 * @returns {string} - A single large string of all node names joined by newline
 */
function extractSnapshotText(snapshotText) {
    const snapshot = parser.parse(snapshotText);
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
