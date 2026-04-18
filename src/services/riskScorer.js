/**
 * riskScorer.js — Assigns a final risk score and label to each finding.
 * Factors in: base severity, context modifiers (admin route, token, duplicate evidence).
 */

const SEVERITY_ORDER = ['low', 'medium', 'high', 'critical'];

/**
 * Enriches findings with adjusted scores based on contextual risk factors.
 * @param {Array} findings - Raw findings from detectors
 * @returns {Array} - Findings with final_score and risk_label
 */
function scoreFIndings(findings) {
    return findings.map(f => {
        let score = f.score;

        // Boost: token-type artifacts get escalation
        if (['jwt_token', 'bearer_token', 'aws_access_key', 'github_token', 'google_api_key'].includes(f.artifact_type)) {
            score = Math.min(score + 10, 100);
        }

        // Boost: admin/internal endpoints are high-value
        if (f.artifact_type === 'admin_endpoint' || f.artifact_type === 'debug_route') {
            score = Math.min(score + 15, 100);
        }

        // Boost: private keys are always max
        if (f.artifact_type === 'private_key') {
            score = 100;
        }

        return {
            ...f,
            final_score: score,
            risk_label: scoreToLabel(score),
        };
    });
}

/**
 * Aggregates findings into per-severity counts for dashboard stats.
 */
function aggregateStats(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
        const label = (f.risk_label || f.severity).toLowerCase();
        if (counts[label] !== undefined) counts[label]++;
    }
    const totalScore = findings.length > 0
        ? Math.round(findings.reduce((sum, f) => sum + (f.final_score || f.score), 0) / findings.length)
        : 0;
    return { counts, totalScore };
}

function scoreToLabel(score) {
    if (score >= 85) return 'critical';
    if (score >= 65) return 'high';
    if (score >= 35) return 'medium';
    return 'low';
}

module.exports = { scoreFIndings, aggregateStats, scoreToLabel };
