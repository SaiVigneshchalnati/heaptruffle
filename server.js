/**
 * server.js — API Gateway: bootstraps the HeapTruffle platform.
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');

const apiRoutes = require('./src/routes/api');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// --- Static Files (Frontend) ---
app.use(express.static(path.join(__dirname, 'public')));

// --- API Routes ---
app.use('/api', apiRoutes);

// --- Catch-all: serve frontend for any non-API route (Express v5 syntax) ---
app.get('/{*path}', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- Global Error Handler ---
app.use((err, req, res, next) => {
    console.error('[Server Error]', err);
    res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
    console.log(`\n🚀 HeapTruffle Platform running at http://localhost:${PORT}`);
    console.log(`   AI Enhancement: ${process.env.GEMINI_API_KEY ? '✅ Enabled (Gemini)' : '⚠️  Disabled (set GEMINI_API_KEY)'}`);
    console.log(`   Database: SQLite @ ./data/heaptruffle.db\n`);
});
