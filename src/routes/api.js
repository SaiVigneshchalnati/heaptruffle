/**
 * api.js — API route definitions (API Gateway layer).
 */
const express = require('express');
const router = express.Router();
const {
    startScan,
    getScans,
    getScanById,
    deleteScan,
    getAuditLogs,
} = require('../controllers/scanController');

// Scan Management
router.post('/scan', startScan);
router.get('/scans', getScans);
router.get('/scans/:id', getScanById);
router.delete('/scans/:id', deleteScan);

// Audit
router.get('/audit-logs', getAuditLogs);

// Health check
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        aiEnabled: !!process.env.GEMINI_API_KEY,
    });
});

module.exports = router;
