/**
 * api.js — Unified API gateway with all routes wired.
 */
const express    = require('express');
const rateLimit  = require('express-rate-limit');
const router     = express.Router();
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

// ─── Rate Limiters ────────────────────────────────────────────
// Fix #3: Brute-force protection — 10 login attempts per 15 min per IP
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});


// ─── Controllers ──────────────────────────────────────────────
const { login, register, getProfile, getUsers, deleteUser, refreshToken } = require('../controllers/authController');
const { getTargets, addTarget, deleteTarget, toggleTarget }   = require('../controllers/targetsController');
const {
    startScan, getScans, getScanById, deleteScan,
    compareScans, getDashboardStats, downloadPDF, getAuditLogs,
} = require('../controllers/scanController');

// ─── Health ───────────────────────────────────────────────────
router.get('/health', (req, res) => res.json({
    status: 'ok', version: '3.0.0',
    timestamp: new Date().toISOString(),
    aiEnabled: !!process.env.GEMINI_API_KEY,
}));

// ─── Auth (public) ────────────────────────────────────────────
router.post('/auth/login',   loginLimiter, login);

// ─── Auth (protected) ─────────────────────────────────────────
router.post  ('/auth/register',     requireAuth, requireRole('admin'), register);
router.get   ('/auth/me',           requireAuth, getProfile);
router.post  ('/auth/refresh',      requireAuth, refreshToken);   // Fix #15: token refresh
router.get   ('/auth/users',        requireAuth, requireRole('admin'), getUsers);
router.delete('/auth/users/:id',    requireAuth, requireRole('admin'), deleteUser);

// ─── Targets ──────────────────────────────────────────────────
router.get   ('/targets',           requireAuth, getTargets);
router.post  ('/targets',           requireAuth, requireRole('admin','analyst'), addTarget);
router.delete('/targets/:id',       requireAuth, requireRole('admin'), deleteTarget);
router.patch ('/targets/:id/toggle',requireAuth, requireRole('admin'), toggleTarget);

// ─── Scans ────────────────────────────────────────────────────
router.post  ('/scan',              requireAuth, requireRole('admin','analyst'), startScan);
router.get   ('/scans',             requireAuth, getScans);
router.get   ('/scans/compare',     requireAuth, compareScans);
router.get   ('/scans/:id',         requireAuth, getScanById);
router.get   ('/scans/:id/pdf',     requireAuth, downloadPDF);
router.delete('/scans/:id',         requireAuth, requireRole('admin','analyst'), deleteScan);

// ─── Dashboard ────────────────────────────────────────────────
router.get('/dashboard',            requireAuth, getDashboardStats);

// ─── Audit ────────────────────────────────────────────────────
router.get('/audit-logs',           requireAuth, requireRole('admin'), getAuditLogs);

module.exports = router;

