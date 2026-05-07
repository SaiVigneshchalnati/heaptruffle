/**
 * authController.js — Login, register, profile management.
 */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const db = require('../db/database');
const { JWT_SECRET } = require('../middleware/authMiddleware');

/**
 * POST /api/auth/login
 */
async function login(req, res) {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required.' });
    }

    const user = db.prepare(`SELECT * FROM users WHERE username = ? OR email = ?`).get(username, username);
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });

    // Update last login
    db.prepare(`UPDATE users SET last_login = ? WHERE id = ?`).run(new Date().toISOString(), user.id);

    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
    );

    db.prepare(`INSERT INTO audit_logs (action, user_id, detail, timestamp) VALUES (?,?,?,?)`)
      .run('LOGIN', user.id, `User ${user.username} logged in`, new Date().toISOString());

    return res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
}

/**
 * POST /api/auth/register  (Admin only)
 */
async function register(req, res) {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    // Fix #11: Enforce minimum password length
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
    }

    const allowedRoles = ['admin', 'analyst', 'viewer'];
    const userRole = allowedRoles.includes(role) ? role : 'analyst';

    const existing = db.prepare(`SELECT id FROM users WHERE username = ? OR email = ?`).get(username, email);
    if (existing) return res.status(409).json({ error: 'Username or email already exists.' });

    const hash = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    db.prepare(`INSERT INTO users (id,username,email,password_hash,role,created_at) VALUES (?,?,?,?,?,?)`)
      .run(id, username, email, hash, userRole, new Date().toISOString());

    db.prepare(`INSERT INTO audit_logs (action, user_id, detail, timestamp) VALUES (?,?,?,?)`)
      .run('USER_CREATED', req.user?.id, `New user ${username} (${userRole}) created`, new Date().toISOString());

    return res.status(201).json({ message: 'User created successfully.', userId: id });
}

/**
 * GET /api/auth/me
 */
function getProfile(req, res) {
    const user = db.prepare(`SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?`).get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user });
}

/**
 * POST /api/auth/refresh  — Fix #15: Renew JWT token without re-login
 * The user must already be authenticated. Issues a fresh 24h token.
 */
function refreshToken(req, res) {
    const user = db.prepare(`SELECT id, username, email, role FROM users WHERE id = ?`).get(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role, email: user.email },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
    return res.json({ token, user: { id: user.id, username: user.username, email: user.email, role: user.role } });
}

/**
 * GET /api/auth/users  (Admin only)
 */
function getUsers(req, res) {
    const users = db.prepare(`SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC`).all();
    res.json({ users });
}

/**
 * DELETE /api/auth/users/:id  (Admin only)
 */
function deleteUser(req, res) {
    const { id } = req.params;
    if (id === req.user.id) return res.status(400).json({ error: 'Cannot delete your own account.' });

    // Fix #4: Verify user exists before deleting
    const user = db.prepare(`SELECT id, username FROM users WHERE id = ?`).get(id);
    if (!user) return res.status(404).json({ error: 'User not found.' });

    db.prepare(`DELETE FROM users WHERE id = ?`).run(id);
    db.prepare(`INSERT INTO audit_logs (action, user_id, detail, timestamp) VALUES (?,?,?,?)`)
      .run('USER_DELETED', req.user.id, `User ${user.username} deleted`, new Date().toISOString());
    res.json({ success: true });
}

module.exports = { login, register, getProfile, getUsers, deleteUser, refreshToken };

