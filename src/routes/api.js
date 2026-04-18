/**
 * api.js — Unified API gateway with all routes wired.
 */
const express = require('express');
const router  = express.Router();
const { requireAuth, requireRole } = require('../middleware/authMiddleware');

// ─── Controllers ──────────────────────────────────────────────
const { login, register, getProfile, getUsers, deleteUser } = require('../controllers/authController');
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
router.post('/auth/login', login);

// ─── Auth (protected) ─────────────────────────────────────────
router.post  ('/auth/register',     requireAuth, requireRole('admin'), register);
router.get   ('/auth/me',           requireAuth, getProfile);
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
