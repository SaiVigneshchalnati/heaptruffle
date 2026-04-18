/**
 * detectors.js — Multi-category artifact extraction & classification engine.
 * Each detector returns findings of shape: { raw_value, artifact_type, severity, score, category, description }
 */

// --- Severity Score Map ---
const SEVERITY_SCORES = { critical: 95, high: 75, medium: 45, low: 15 };

// --- Pattern Definitions ---
const PATTERNS = [
    // === CRITICAL ===
    {
        name: 'JWT Token',
        category: 'Authentication Token',
        severity: 'critical',
        description: 'JSON Web Token found in heap memory — may expose auth session data.',
        regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
        artifact_type: 'jwt_token',
    },
    {
        name: 'AWS Access Key',
        category: 'Cloud Credential',
        severity: 'critical',
        description: 'AWS Access Key ID detected — potential cloud infrastructure exposure.',
        regex: /AKIA[0-9A-Z]{16}/g,
        artifact_type: 'aws_access_key',
    },
    {
        name: 'AWS Secret Key',
        category: 'Cloud Credential',
        severity: 'critical',
        description: 'AWS Secret Access Key pattern detected.',
        regex: /(?:aws_secret_access_key|aws_secret|secret_key)[=:\s"']+([A-Za-z0-9/+]{40})/gi,
        artifact_type: 'aws_secret_key',
    },
    {
        name: 'Private Key Header',
        category: 'Cryptographic Key',
        severity: 'critical',
        description: 'PEM-encoded private key header detected in memory.',
        regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g,
        artifact_type: 'private_key',
    },

    // === HIGH ===
    {
        name: 'Generic API Key',
        category: 'API Credential',
        severity: 'high',
        description: 'Generic API key pattern detected — verify if it is a real credential.',
        regex: /(?:api_key|apikey|api-key|x-api-key)[=:\s"']+([A-Za-z0-9_\-]{20,64})/gi,
        artifact_type: 'api_key',
    },
    {
        name: 'Bearer Token',
        category: 'Authentication Token',
        severity: 'high',
        description: 'Bearer token string found — likely used for authenticated API requests.',
        regex: /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/g,
        artifact_type: 'bearer_token',
    },
    {
        name: 'Google API Key',
        category: 'Cloud Credential',
        severity: 'high',
        description: 'Google Cloud API key found in client memory.',
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        artifact_type: 'google_api_key',
    },
    {
        name: 'GitHub Token',
        category: 'API Credential',
        severity: 'high',
        description: 'GitHub personal access token detected.',
        regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
        artifact_type: 'github_token',
    },
    {
        name: 'Cloud Storage Bucket URL',
        category: 'Cloud Storage Reference',
        severity: 'high',
        description: 'Reference to an S3 or GCS bucket URL found — potential data exposure.',
        regex: /(?:s3\.amazonaws\.com\/[^\s"'>]+|storage\.googleapis\.com\/[^\s"'>]+)/g,
        artifact_type: 'cloud_bucket_url',
    },
    {
        name: 'Internal/Admin Endpoint',
        category: 'Internal Endpoint',
        severity: 'high',
        description: 'Path suggesting an admin or internal panel route.',
        regex: /(?:\/admin(?:\/|$)|\/internal(?:\/|$)|\/dashboard(?:\/|$)|\/superuser(?:\/|$)|\/manage(?:\/|$)|\/console(?:\/|$)|\/devtools(?:\/|$))/gi,
        artifact_type: 'admin_endpoint',
    },

    // === MEDIUM ===
    {
        name: 'GraphQL Endpoint',
        category: 'API Endpoint',
        severity: 'medium',
        description: 'GraphQL endpoint reference found — may reveal API introspection surface.',
        regex: /\/graphql(?:\/|$|\?|#)/gi,
        artifact_type: 'graphql_endpoint',
    },
    {
        name: 'WebSocket URL',
        category: 'WebSocket Connection',
        severity: 'medium',
        description: 'WebSocket (ws:// or wss://) connection string found.',
        regex: /wss?:\/\/[^\s"'>]{5,}/g,
        artifact_type: 'websocket_url',
    },
    {
        name: 'Debug/Test Route',
        category: 'Debug Artifact',
        severity: 'medium',
        description: 'Path pattern suggesting a debug, staging, or test route.',
        regex: /(?:\/debug(?:\/|$)|\/test(?:\/|$)|\/staging(?:\/|$)|\/dev(?:\/|$)|\/local(?:\/|$)|\/mock(?:\/|$))/gi,
        artifact_type: 'debug_route',
    },
    {
        name: 'Email Address',
        category: 'PII',
        severity: 'medium',
        description: 'Email address found in heap — may represent PII leakage.',
        regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
        artifact_type: 'email',
    },
    {
        name: 'IP Address Reference',
        category: 'Network Artifact',
        severity: 'medium',
        description: 'IP address found — may indicate hardcoded internal host.',
        regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
        artifact_type: 'internal_ip',
    },
    {
        name: 'Absolute HTTPS URL',
        category: 'External URL',
        severity: 'low',
        description: 'General absolute HTTPS URL found in memory.',
        regex: /https?:\/\/[a-zA-Z0-9.\-]+(?:\/[^\s"'<>]*)?/g,
        artifact_type: 'absolute_url',
    },

    // === LOW ===
    {
        name: 'Relative API Path',
        category: 'API Endpoint',
        severity: 'low',
        description: 'Relative path that may be an internal API route.',
        regex: /\/api(?:\/[a-zA-Z0-9_.\-/]+)+/g,
        artifact_type: 'relative_api_path',
    },
    {
        name: 'Environment Variable Reference',
        category: 'Configuration',
        severity: 'low',
        description: 'String pattern matching an environment variable name found in client memory.',
        regex: /process\.env\.[A-Z_]{3,}/g,
        artifact_type: 'env_var_ref',
    },
];

/**
 * Runs all detection patterns against a string.
 * Returns an array of finding objects (de-duplicated by raw_value + artifact_type).
 */
function detectArtifacts(text) {
    const seen = new Set();
    const results = [];

    for (const pattern of PATTERNS) {
        let matches;
        // Reset lastIndex for global regex
        pattern.regex.lastIndex = 0;
        while ((matches = pattern.regex.exec(text)) !== null) {
            const raw = (matches[1] || matches[0]).trim();
            if (!raw || raw.length < 4) continue;
            const key = `${pattern.artifact_type}::${raw}`;
            if (seen.has(key)) continue;
            seen.add(key);
            results.push({
                raw_value: raw,
                artifact_type: pattern.artifact_type,
                severity: pattern.severity,
                score: SEVERITY_SCORES[pattern.severity],
                category: pattern.category,
                description: pattern.description,
            });
        }
    }

    return results;
}

module.exports = { detectArtifacts, SEVERITY_SCORES };
