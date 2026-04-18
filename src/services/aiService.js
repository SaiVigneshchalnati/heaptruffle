/**
 * aiService.js — Gemini AI integration for intelligent security report generation.
 */
const { GoogleGenerativeAI } = require('@google/generative-ai');

let genAI = null;

function getClient() {
    if (!genAI) {
        const key = process.env.GEMINI_API_KEY;
        if (!key) {
            return null;
        }
        genAI = new GoogleGenerativeAI(key);
    }
    return genAI;
}

/**
 * Generates a structured AI security report for the provided scan findings.
 * @param {string} domain - The scanned target domain
 * @param {Array} findings - Array of classified finding objects
 * @returns {Promise<string>} - Markdown-formatted security summary
 */
async function generateSecurityReport(domain, findings) {
    const client = getClient();
    if (!client) {
        return buildFallbackReport(domain, findings);
    }

    // Prepare a compact representation of findings for the prompt
    const findingSummary = findings
        .sort((a, b) => (b.final_score || b.score) - (a.final_score || a.score))
        .slice(0, 50) // Cap to top 50 for token limits
        .map(f => `[${(f.risk_label || f.severity).toUpperCase()}] ${f.artifact_type} — ${f.raw_value.substring(0, 80)}`)
        .join('\n');

    const critCount = findings.filter(f => (f.risk_label || f.severity) === 'critical').length;
    const highCount = findings.filter(f => (f.risk_label || f.severity) === 'high').length;
    const totalCount = findings.length;

    const prompt = `You are a senior web application security analyst performing client-side memory forensics.

A browser heap snapshot analysis of the website "${domain}" was conducted. The following client-side artifacts were extracted from its JavaScript heap memory:

${findingSummary}

SUMMARY STATISTICS:
- Total artifacts: ${totalCount}
- Critical: ${critCount}
- High: ${highCount}

Please produce a concise, professional security intelligence report with the following sections:

## Executive Summary
(2-3 sentences summarizing the overall risk posture)

## Key Findings
(Bullet points of the most significant issues)

## Risk Assessment
(Overall risk rating: Critical / High / Medium / Low, and justification)

## Attack Surface Analysis
(What attack vectors does this exposure create?)

## Recommended Mitigations
(Actionable security recommendations)

Keep the tone professional and suitable for a B.Tech cybersecurity thesis. Be factual, not alarmist.`;

    try {
        const model = client.getGenerativeModel({ model: 'gemini-2.0-flash' });
        const result = await model.generateContent(prompt);
        return result.response.text();
    } catch (err) {
        if (err.message.includes('429') || err.message.includes('quota')) {
            console.warn('[AI Service] Gemini quota exceeded — using fallback report.');
        } else {
            console.error('[AI Service] Gemini API error:', err.message);
        }
        return buildFallbackReport(domain, findings);
    }
}

/**
 * Builds a structured report without AI when the API key is not set.
 */
function buildFallbackReport(domain, findings) {
    const bySeverity = { critical: [], high: [], medium: [], low: [] };
    for (const f of findings) {
        const sev = (f.risk_label || f.severity).toLowerCase();
        if (bySeverity[sev]) bySeverity[sev].push(f);
    }

    const overallRisk = bySeverity.critical.length > 0 ? 'CRITICAL'
        : bySeverity.high.length > 0 ? 'HIGH'
        : bySeverity.medium.length > 0 ? 'MEDIUM' : 'LOW';

    return `## Executive Summary
Automated heap snapshot analysis of **${domain}** identified **${findings.length}** client-side artifacts across multiple risk categories. The overall risk rating is **${overallRisk}**.

## Key Findings
${bySeverity.critical.map(f => `- 🔴 **${f.artifact_type}**: \`${f.raw_value.substring(0, 60)}\``).join('\n')}
${bySeverity.high.map(f => `- 🟠 **${f.artifact_type}**: \`${f.raw_value.substring(0, 60)}\``).join('\n')}
${bySeverity.medium.map(f => `- 🟡 **${f.artifact_type}**: \`${f.raw_value.substring(0, 60)}\``).join('\n')}

## Risk Assessment
Overall Risk: **${overallRisk}**
- Critical artifacts: ${bySeverity.critical.length}
- High artifacts: ${bySeverity.high.length}
- Medium artifacts: ${bySeverity.medium.length}
- Low artifacts: ${bySeverity.low.length}

## Recommended Mitigations
- Remove sensitive credentials and tokens from client-side JavaScript bundles.
- Implement proper secret management using server-side environment variables.
- Avoid exposing internal API routes, admin paths, or debug endpoints in production.
- Enforce HTTPS and use Content Security Policy (CSP) headers.
- Audit third-party JavaScript dependencies for credential leakage.

*Note: This report was generated without AI enhancement. Set GEMINI_API_KEY for AI-powered analysis.*`;
}

module.exports = { generateSecurityReport };
