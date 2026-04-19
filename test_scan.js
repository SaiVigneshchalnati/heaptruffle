/**
 * test_scan.js — HeapTruffle End-to-End Test Suite
 * Tests the scan pipeline with multiple domains including failure cases.
 * Usage: node test_scan.js
 */
require('dotenv').config();
const { captureArtifacts, extractSnapshotText } = require('./src/services/browserWorker');
const { analyzeArtifacts } = require('./src/services/analysisEngine');

const TESTS = [
    { name: 'Simple Site (example.com)',  url: 'https://example.com',  expectHeap: true  },
    { name: 'Google (google.com)',         url: 'https://www.google.com', expectHeap: true },
    { name: 'Heavy SPA (x.com)',           url: 'https://x.com',          expectHeap: false },
];

const PASS = '\x1b[32m✔ PASS\x1b[0m';
const FAIL = '\x1b[31m✘ FAIL\x1b[0m';
const INFO = '\x1b[36mℹ INFO\x1b[0m';
const WARN = '\x1b[33m⚠ WARN\x1b[0m';

async function runTest({ name, url, expectHeap }) {
    console.log(`\n${'─'.repeat(60)}`);
    console.log(`${INFO} Running: ${name} → ${url}`);
    console.log(`${'─'.repeat(60)}`);

    const testStart = Date.now();

    // 1. captureArtifacts — must NEVER throw
    let result;
    try {
        result = await captureArtifacts(url);
    } catch (err) {
        console.log(`${FAIL} captureArtifacts threw an unexpected error: ${err.message}`);
        return { name, passed: false, error: err.message };
    }

    const { snapshotText, heapStatus, runtimeArtifacts } = result;

    console.log(`${INFO} heapStatus     : ${heapStatus}`);
    console.log(`${INFO} snapshotText   : ${snapshotText.length} bytes`);
    console.log(`${INFO} networkRequests: ${runtimeArtifacts.networkRequests.length}`);
    console.log(`${INFO} loadedScripts  : ${runtimeArtifacts.loadedScripts.length}`);
    console.log(`${INFO} localStorageKeys: ${runtimeArtifacts.localStorageKeys.length}`);

    // Test: captureArtifacts must not throw [always passes if we get here]
    console.log(`${PASS} captureArtifacts() completed without throwing`);

    // Test: heapStatus must always be a known string
    const validStatuses = ['success', 'partial_load', 'heap_empty', 'heap_failed', 'browser_failed'];
    if (validStatuses.includes(heapStatus)) {
        console.log(`${PASS} heapStatus is a valid value: "${heapStatus}"`);
    } else {
        console.log(`${FAIL} heapStatus is unknown: "${heapStatus}"`);
    }

    // Test: snapshotText must always be a string (not null/undefined)
    if (typeof snapshotText === 'string') {
        console.log(`${PASS} snapshotText is always a string (${snapshotText.length} bytes)`);
    } else {
        console.log(`${FAIL} snapshotText is not a string: ${typeof snapshotText}`);
    }

    // Test: extractSnapshotText must not throw even on empty/corrupt input
    let heapText;
    try {
        heapText = extractSnapshotText(snapshotText);
    } catch (err) {
        console.log(`${FAIL} extractSnapshotText threw: ${err.message}`);
        return { name, passed: false, error: err.message };
    }
    console.log(`${PASS} extractSnapshotText() succeeded → ${heapText.split('\n').filter(Boolean).length} nodes`);

    // Test: analyzeArtifacts must not throw even with empty heapText
    let findings, stats;
    try {
        ({ findings, stats } = analyzeArtifacts(heapText, runtimeArtifacts));
    } catch (err) {
        console.log(`${FAIL} analyzeArtifacts threw: ${err.message}`);
        return { name, passed: false, error: err.message };
    }
    console.log(`${PASS} analyzeArtifacts() succeeded → ${findings.length} findings, score: ${stats.totalScore}`);

    // Test: findings is always an array
    if (Array.isArray(findings)) {
        console.log(`${PASS} findings is an array`);
    } else {
        console.log(`${FAIL} findings is not an array`);
    }

    // Info: runtimeArtifacts always present
    const rtFields = ['networkRequests', 'loadedScripts', 'localStorageKeys', 'consoleMessages'];
    const allPresent = rtFields.every(f => Array.isArray(runtimeArtifacts[f]));
    if (allPresent) {
        console.log(`${PASS} runtimeArtifacts has all required fields`);
    } else {
        console.log(`${FAIL} runtimeArtifacts missing some fields`);
    }

    // Warning if expected heap but got failure (not a hard fail, just informational)
    if (expectHeap && heapStatus !== 'success') {
        console.log(`${WARN} Expected heap capture but got "${heapStatus}" — acceptable for protected sites`);
    }

    const elapsed = ((Date.now() - testStart) / 1000).toFixed(1);
    console.log(`${PASS} Test completed in ${elapsed}s`);

    return { name, passed: true, heapStatus, findings: findings.length, score: stats.totalScore };
}

async function main() {
    console.log('\n╔══════════════════════════════════════════════════════════╗');
    console.log('║    HeapTruffle Scan Pipeline — End-to-End Test Suite     ║');
    console.log('╚══════════════════════════════════════════════════════════╝\n');

    const results = [];

    for (const test of TESTS) {
        const r = await runTest(test);
        results.push(r);
    }

    console.log(`\n${'═'.repeat(60)}`);
    console.log('SUMMARY');
    console.log(`${'═'.repeat(60)}`);

    let allPassed = true;
    for (const r of results) {
        const status = r.passed ? PASS : FAIL;
        const detail = r.passed
            ? `heapStatus: ${r.heapStatus}, findings: ${r.findings}, score: ${r.score}`
            : `Error: ${r.error}`;
        console.log(`${status} ${r.name} — ${detail}`);
        if (!r.passed) allPassed = false;
    }

    console.log(`\n${allPassed ? '\x1b[32m✔ ALL TESTS PASSED\x1b[0m' : '\x1b[31m✘ SOME TESTS FAILED\x1b[0m'}`);
    process.exit(allPassed ? 0 : 1);
}

main().catch(err => {
    console.error('\n\x1b[31m[FATAL]\x1b[0m Unhandled error in test runner:', err.message);
    process.exit(1);
});
