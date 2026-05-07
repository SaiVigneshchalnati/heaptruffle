/**
 * analysisEngine.js — Orchestrates artifact extraction and risk scoring over heap text.
 */
const { detectArtifacts } = require('./detectors');
const { scoreFindings, aggregateStats } = require('./riskScorer');

/**
 * Runs the full analysis pipeline on raw heap text and runtime artifacts.
 * @param {string} heapText - Concatenated node names from heap snapshot
 * @param {object} runtimeArtifacts - Data from browser worker (network, scripts, etc.)
 * @returns {{ findings: Array, stats: object }}
 */
function analyzeArtifacts(heapText, runtimeArtifacts = {}) {
    // 1. Combine all text sources for detection
    const { networkRequests = [], loadedScripts = [], localStorageKeys = [] } = runtimeArtifacts;
    const extraText = [
        ...networkRequests.map(r => r.url),
        ...loadedScripts,
        ...localStorageKeys,
    ].join('\n');

    const combinedText = heapText + '\n' + extraText;

    // 2. Run all detectors
    const rawFindings = detectArtifacts(combinedText);

    // 3. Score findings
    const scoredFindings = scoreFindings(rawFindings);

    // 4. Sort by risk score descending
    scoredFindings.sort((a, b) => b.final_score - a.final_score);

    // 5. Aggregate stats
    const stats = aggregateStats(scoredFindings);

    return { findings: scoredFindings, stats };
}

module.exports = { analyzeArtifacts };
