/**
 * server.js — HeapTruffle v3.0 API Gateway Entry Point
 */
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const isDev = process.env.NODE_ENV !== 'production';

// Fix #10: Security headers
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabled so CDN scripts still load

// Fix #1: Restrict CORS to configured origin only
app.use(cors({
    origin: process.env.CORS_ORIGIN || (isDev ? '*' : 'http://localhost:3000'),
    methods: ['GET', 'POST', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- API Routes ---
const apiRoutes = require('./src/routes/api');
app.use('/api', apiRoutes);

// --- SPA: login landing ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// --- SPA: main app ---
app.get('/app.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));

// --- Catch-all → login ---
app.get('/{*path}', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Fix #8: Global error handler — catches any unhandled errors in routes
app.use((err, req, res, next) => {
    console.error('[Unhandled Error]', err.message || err);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
});

// --- Start ---
app.listen(PORT, () => {
    const aiStatus = process.env.GEMINI_API_KEY ? '✅ Enabled (Gemini)' : '⚠️  Disabled (set GEMINI_API_KEY)';
    console.log(`\n🚀 HeapTruffle Platform v3.0 running at http://localhost:${PORT}`);
    console.log(`   AI Enhancement: ${aiStatus}`);
    console.log(`   Database: SQLite @ ./data/heaptruffle.db`);
    // Fix #2 + #14: Only show sensitive startup info in development
    if (isDev) {
        console.log(`   [DEV] Default Login: admin / admin@123`);
        console.log(`   [DEV] Set NODE_ENV=production to suppress this message.\n`);
    }
});

