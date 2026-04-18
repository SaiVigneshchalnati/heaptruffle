/**
 * server.js — HeapTruffle v3.0 API Gateway Entry Point
 */
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
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

// --- Start ---
app.listen(PORT, () => {
    const aiStatus = process.env.GEMINI_API_KEY ? '✅ Enabled (Gemini)' : '⚠️  Disabled (set GEMINI_API_KEY)';
    console.log(`\n🚀 HeapTruffle Platform v3.0 running at http://localhost:${PORT}`);
    console.log(`   AI Enhancement: ${aiStatus}`);
    console.log(`   Database: SQLite @ ./data/heaptruffle.db`);
    console.log(`   Default Login: admin / admin@123\n`);
});
