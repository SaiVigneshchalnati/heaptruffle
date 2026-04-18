/**
 * detectors.js — Comprehensive multi-category artifact extraction engine.
 * 28 detection patterns with confidence scores and remediation recommendations.
 */

const SEVERITY_SCORES = { critical: 95, high: 78, medium: 48, low: 18 };

// Classification categories
const CLASSIFICATION = {
    SECRET_LEAKAGE:       'Secret Leakage',
    AUTH_ARTIFACT:        'Authentication Artifact Exposure',
    ENDPOINT_EXPOSURE:    'Endpoint Exposure',
    DEBUG_ARTIFACT:       'Debug Artifact Exposure',
    CLOUD_DISCLOSURE:     'Cloud Resource Disclosure',
    INTERNAL_REFERENCE:   'Internal Reference Disclosure',
    PII_DISCLOSURE:       'PII Disclosure',
    THIRD_PARTY:          'Third-Party Asset Exposure',
};

const PATTERNS = [
    // ─── CRITICAL ─────────────────────────────────────────────
    {
        name: 'JWT Token',
        category: 'Authentication Token',
        classification: CLASSIFICATION.AUTH_ARTIFACT,
        severity: 'critical',
        confidence: 92,
        description: 'JSON Web Token found in heap — exposes active session credentials.',
        recommendation: 'Store JWTs in httpOnly cookies. Never expose tokens in JS variables or localStorage.',
        regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
        artifact_type: 'jwt_token',
    },
    {
        name: 'AWS Access Key ID',
        category: 'Cloud Credential',
        classification: CLASSIFICATION.CLOUD_DISCLOSURE,
        severity: 'critical',
        confidence: 98,
        description: 'AWS IAM Access Key ID — direct cloud infrastructure compromise risk.',
        recommendation: 'Immediately rotate this key in AWS IAM. Use IAM roles for server-side access, never embed keys client-side.',
        regex: /AKIA[0-9A-Z]{16}/g,
        artifact_type: 'aws_access_key',
    },
    {
        name: 'AWS Secret Key',
        category: 'Cloud Credential',
        classification: CLASSIFICATION.CLOUD_DISCLOSURE,
        severity: 'critical',
        confidence: 95,
        description: 'AWS Secret Access Key pattern — full programmatic AWS access.',
        recommendation: 'Rotate immediately. Use AWS Secrets Manager or environment variables on server side only.',
        regex: /(?:aws_secret_access_key|aws_secret|secret_key)[=:\s"']+([A-Za-z0-9/+]{40})/gi,
        artifact_type: 'aws_secret_key',
    },
    {
        name: 'PEM Private Key',
        category: 'Cryptographic Key',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'critical',
        confidence: 99,
        description: 'PEM-encoded private key block detected — cryptographic identity compromise.',
        recommendation: 'Revoke this private key immediately. Private keys must never leave the server boundary.',
        regex: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/g,
        artifact_type: 'private_key',
    },
    {
        name: 'Stripe Secret Key',
        category: 'Payment Credential',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'critical',
        confidence: 99,
        description: 'Stripe secret API key — full payment processing compromise.',
        recommendation: 'Rotate key immediately in Stripe dashboard. Secret keys must only be used server-side.',
        regex: /sk_live_[0-9a-zA-Z]{24,}/g,
        artifact_type: 'stripe_secret_key',
    },

    // ─── HIGH ──────────────────────────────────────────────────
    {
        name: 'Generic API Key',
        category: 'API Credential',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'high',
        confidence: 72,
        description: 'Generic API key pattern — may expose authenticated service access.',
        recommendation: 'Validate if this is a production key. Move all API keys to backend proxy pattern.',
        regex: /(?:api_key|apikey|api-key|x-api-key)[=:\s"']+([A-Za-z0-9_\-]{20,64})/gi,
        artifact_type: 'api_key',
    },
    {
        name: 'Bearer Token',
        category: 'Authentication Token',
        classification: CLASSIFICATION.AUTH_ARTIFACT,
        severity: 'high',
        confidence: 85,
        description: 'Bearer token in memory — active authorization credential.',
        recommendation: 'Use short-lived tokens. Store authorization state server-side via sessions.',
        regex: /Bearer\s+[A-Za-z0-9\-._~+\/]{20,}/g,
        artifact_type: 'bearer_token',
    },
    {
        name: 'Google API Key',
        category: 'Cloud Credential',
        classification: CLASSIFICATION.CLOUD_DISCLOSURE,
        severity: 'high',
        confidence: 95,
        description: 'Google Cloud / Firebase API key in client memory.',
        recommendation: 'Restrict key in GCP Console to specific APIs and referrer domains.',
        regex: /AIza[0-9A-Za-z\-_]{35}/g,
        artifact_type: 'google_api_key',
    },
    {
        name: 'GitHub Token',
        category: 'API Credential',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'high',
        confidence: 96,
        description: 'GitHub personal access token — repository and org access.',
        recommendation: 'Revoke on GitHub immediately. Use GitHub Apps with minimal scope for CI/CD.',
        regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
        artifact_type: 'github_token',
    },
    {
        name: 'Slack Token',
        category: 'API Credential',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'high',
        confidence: 95,
        description: 'Slack API token — workspace message and channel access.',
        recommendation: 'Revoke in Slack App settings. Never embed workspace tokens in frontend code.',
        regex: /xox[baprs]-[0-9A-Za-z\-]{10,}/g,
        artifact_type: 'slack_token',
    },
    {
        name: 'Cloud Storage Bucket URL',
        category: 'Cloud Storage Reference',
        classification: CLASSIFICATION.CLOUD_DISCLOSURE,
        severity: 'high',
        confidence: 88,
        description: 'S3 or GCS bucket URL — potential data exposure if misconfigured.',
        recommendation: 'Verify bucket ACLs are not publicly accessible. Use signed URLs for resource access.',
        regex: /(?:s3\.amazonaws\.com\/[^\s"'<>]+|storage\.googleapis\.com\/[^\s"'<>]+)/g,
        artifact_type: 'cloud_bucket_url',
    },
    {
        name: 'Admin / Internal Endpoint',
        category: 'Internal Endpoint',
        classification: CLASSIFICATION.ENDPOINT_EXPOSURE,
        severity: 'high',
        confidence: 80,
        description: 'Admin or internal control-plane route exposed in client memory.',
        recommendation: 'Move admin interfaces to separate authenticated subdomains. Never embed in SPAs.',
        regex: /(?:\/admin(?:\/|$)|\/internal(?:\/|$)|\/superuser(?:\/|$)|\/manage(?:\/|$)|\/console(?:\/|$)|\/devtools(?:\/|$)|\/backdoor(?:\/|$))/gi,
        artifact_type: 'admin_endpoint',
    },
    {
        name: 'Source Map Reference',
        category: 'Debug Artifact',
        classification: CLASSIFICATION.DEBUG_ARTIFACT,
        severity: 'high',
        confidence: 90,
        description: 'JavaScript source map (.map) file exposed — reveals original unminified source code.',
        recommendation: 'Disable source map generation in production builds or restrict access via server auth.',
        regex: /\/\/# sourceMappingURL=.+\.map/g,
        artifact_type: 'source_map',
    },

    // ─── MEDIUM ────────────────────────────────────────────────
    {
        name: 'GraphQL Endpoint',
        category: 'API Endpoint',
        classification: CLASSIFICATION.ENDPOINT_EXPOSURE,
        severity: 'medium',
        confidence: 78,
        description: 'GraphQL endpoint — may allow introspection queries to enumerate the full data schema.',
        recommendation: 'Disable GraphQL introspection in production. Implement query depth limiting and field-level auth.',
        regex: /\/graphql(?:\/|$|\?|#)/gi,
        artifact_type: 'graphql_endpoint',
    },
    {
        name: 'WebSocket URL',
        category: 'WebSocket Connection',
        classification: CLASSIFICATION.ENDPOINT_EXPOSURE,
        severity: 'medium',
        confidence: 85,
        description: 'WebSocket connection string — may leak real-time data channel configuration.',
        recommendation: 'Ensure WebSocket connections are authenticated with tokens validated server-side.',
        regex: /wss?:\/\/[^\s"'<>]{5,}/g,
        artifact_type: 'websocket_url',
    },
    {
        name: 'Debug / Staging Route',
        category: 'Debug Artifact',
        classification: CLASSIFICATION.DEBUG_ARTIFACT,
        severity: 'medium',
        confidence: 70,
        description: 'Debug, staging, or test route embedded in production client code.',
        recommendation: 'Use environment-specific route guards. Strip debug routes in production builds.',
        regex: /(?:\/debug(?:\/|$)|\/test(?:\/|$)|\/staging(?:\/|$)|\/dev(?:\/|$)|\/local(?:\/|$)|\/mock(?:\/|$)|\/sandbox(?:\/|$))/gi,
        artifact_type: 'debug_route',
    },
    {
        name: 'Email Address',
        category: 'PII',
        classification: CLASSIFICATION.PII_DISCLOSURE,
        severity: 'medium',
        confidence: 80,
        description: 'Email address in heap — potential PII leakage of user data.',
        recommendation: 'Avoid caching user PII in frontend state. Mask or tokenize PII references.',
        regex: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
        artifact_type: 'email',
    },
    {
        name: 'Private IP Address',
        category: 'Network Artifact',
        classification: CLASSIFICATION.INTERNAL_REFERENCE,
        severity: 'medium',
        confidence: 85,
        description: 'RFC-1918 private IP address — exposes internal network topology.',
        recommendation: 'Use service discovery or DNS names. Never hardcode internal IPs in frontend assets.',
        regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
        artifact_type: 'internal_ip',
    },
    {
        name: 'Firebase Config',
        category: 'Cloud Credential',
        classification: CLASSIFICATION.CLOUD_DISCLOSURE,
        severity: 'medium',
        confidence: 90,
        description: 'Firebase project configuration object detected — reveals project ID and API surface.',
        recommendation: 'Restrict Firebase rules to authenticated users. Apply per-document security rules.',
        regex: /firebaseConfig\s*=\s*\{/g,
        artifact_type: 'firebase_config',
    },
    {
        name: 'Twilio Credentials',
        category: 'API Credential',
        classification: CLASSIFICATION.SECRET_LEAKAGE,
        severity: 'medium',
        confidence: 88,
        description: 'Twilio Account SID or Auth Token pattern detected.',
        recommendation: 'Move all Twilio operations to backend. Use server-side capability tokens for client auth.',
        regex: /AC[0-9a-f]{32}/g,
        artifact_type: 'twilio_sid',
    },
    {
        name: 'Internal Staging URL',
        category: 'Internal Endpoint',
        classification: CLASSIFICATION.INTERNAL_REFERENCE,
        severity: 'medium',
        confidence: 75,
        description: 'URL containing staging, internal, or non-production hostname fragments.',
        recommendation: 'Use environment variables to manage API base URLs. Never hard-code staging references in prod.',
        regex: /https?:\/\/(?:[a-zA-Z0-9\-]+\.)?(?:staging|internal|local|dev|test|sandbox)\.[a-zA-Z0-9.\-]+/gi,
        artifact_type: 'staging_url',
    },

    // ─── LOW ───────────────────────────────────────────────────
    {
        name: 'Absolute HTTPS URL',
        category: 'External URL',
        classification: CLASSIFICATION.THIRD_PARTY,
        severity: 'low',
        confidence: 50,
        description: 'General absolute HTTPS URL — enumerate third-party dependencies.',
        recommendation: 'Audit third-party domains via CSP (Content-Security-Policy) headers.',
        regex: /https?:\/\/[a-zA-Z0-9.\-]+(?:\/[^\s"'<>]*)?/g,
        artifact_type: 'absolute_url',
    },
    {
        name: 'Relative API Path',
        category: 'API Endpoint',
        classification: CLASSIFICATION.ENDPOINT_EXPOSURE,
        severity: 'low',
        confidence: 55,
        description: 'Relative API path suggests internal routing structure.',
        recommendation: 'Ensure all API routes require authentication. Implement proper API versioning.',
        regex: /\/api(?:\/[a-zA-Z0-9_.\/\-]+)+/g,
        artifact_type: 'relative_api_path',
    },
    {
        name: 'Environment Variable Reference',
        category: 'Configuration',
        classification: CLASSIFICATION.DEBUG_ARTIFACT,
        severity: 'low',
        confidence: 70,
        description: 'process.env reference found in client bundle — may expose build configuration.',
        recommendation: 'Use .env.local for secrets. Never include server-only env vars in client bundles.',
        regex: /process\.env\.[A-Z_]{3,}/g,
        artifact_type: 'env_var_ref',
    },
    {
        name: 'Stripe Publishable Key',
        category: 'Payment Credential',
        classification: CLASSIFICATION.THIRD_PARTY,
        severity: 'low',
        confidence: 95,
        description: 'Stripe publishable key — safe for client-side use but should be verified.',
        recommendation: 'Expected in browser. Ensure corresponding secret key is NOT exposed.',
        regex: /pk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
        artifact_type: 'stripe_pub_key',
    },
    {
        name: 'NPM Package Reference',
        category: 'Supply Chain',
        classification: CLASSIFICATION.THIRD_PARTY,
        severity: 'low',
        confidence: 60,
        description: 'NPM-style package reference in memory — could indicate bundle metadata.',
        recommendation: 'Perform SCA (Software Composition Analysis) on dependencies for known CVEs.',
        regex: /"(?:@[a-zA-Z0-9\-]+\/)?[a-zA-Z0-9\-]{2,}"\s*:\s*"\^?\d+\.\d+\.\d+"/g,
        artifact_type: 'npm_package',
    },
];

function detectArtifacts(text) {
    const seen = new Set();
    const results = [];
    const foundAt = new Date().toISOString();

    for (const pattern of PATTERNS) {
        pattern.regex.lastIndex = 0;
        let match;
        while ((match = pattern.regex.exec(text)) !== null) {
            const raw = (match[1] || match[0]).trim();
            if (!raw || raw.length < 4) continue;
            const key = `${pattern.artifact_type}::${raw}`;
            if (seen.has(key)) continue;
            seen.add(key);
            results.push({
                raw_value: raw,
                artifact_type: pattern.artifact_type,
                severity: pattern.severity,
                score: SEVERITY_SCORES[pattern.severity],
                confidence: pattern.confidence,
                category: pattern.category,
                classification: pattern.classification,
                description: pattern.description,
                recommendation: pattern.recommendation,
                source_type: 'heap',
                found_at: foundAt,
            });
        }
    }

    return results;
}

module.exports = { detectArtifacts, SEVERITY_SCORES, CLASSIFICATION };
