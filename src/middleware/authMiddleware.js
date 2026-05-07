/**
 * authMiddleware.js — JWT-based auth guard & RBAC role enforcement.
 */
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('\n❌  FATAL: JWT_SECRET environment variable is not set!');
    console.error('   Add JWT_SECRET=<a-long-random-string> to your .env file.\n');
    process.exit(1);
}


/**
 * Verifies JWT from Authorization header. Attaches req.user on success.
 */
function requireAuth(req, res, next) {
    const header = req.headers['authorization'];
    const token = header && header.startsWith('Bearer ') ? header.slice(7) : null;

    if (!token) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
    }
}

/**
 * Role-based access control — allowed roles array e.g. ['admin', 'analyst']
 */
function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.user || !roles.includes(req.user.role)) {
            return res.status(403).json({ error: `Access denied. Required role: ${roles.join(' or ')}` });
        }
        next();
    };
}

module.exports = { requireAuth, requireRole, JWT_SECRET };
