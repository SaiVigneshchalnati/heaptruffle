/**
 * test_ai.js — Standalone Gemini API key validation & live test
 * Run: node test_ai.js
 */
require('dotenv').config();
const { GoogleGenerativeAI } = require('@google/generative-ai');

const KEY = process.env.GEMINI_API_KEY;

async function main() {
    console.log('\n================================================');
    console.log('  HeapTruffle — Gemini AI Test');
    console.log('================================================\n');

    // 1. Check key presence
    if (!KEY || KEY.trim() === '') {
        console.error('❌  GEMINI_API_KEY is not set in .env');
        process.exit(1);
    }
    console.log(`✅  Key found: ${KEY.substring(0, 8)}...${KEY.slice(-4)}`);

    // 2. Initialize client
    const genAI = new GoogleGenerativeAI(KEY);
    const model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });

    // 3. Simple ping test
    console.log('\n🔄  Sending test prompt to Gemini API...\n');
    const t0 = Date.now();
    const result = await model.generateContent(
        'You are a cybersecurity AI. In exactly 2 sentences, describe what a browser heap snapshot forensic analysis is.'
    );
    const elapsed = Date.now() - t0;
    const text = result.response.text();

    console.log('📥  Gemini Response:\n');
    console.log(`   "${text.trim()}"\n`);
    console.log(`⏱   Response time: ${elapsed}ms`);
    console.log('\n✅  Gemini API key is VALID and WORKING!\n');

    // 4. Test security report generation (mock findings)
    const { generateSecurityReport } = require('./src/services/aiService');
    const mockFindings = [
        { raw_value: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig', artifact_type: 'jwt_token', risk_label: 'critical', final_score: 95, category: 'Authentication Token', description: 'JWT found in heap' },
        { raw_value: 'AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXX', artifact_type: 'google_api_key', risk_label: 'high', final_score: 80, category: 'Cloud Credential', description: 'Google API key' },
        { raw_value: '/admin/dashboard', artifact_type: 'admin_endpoint', risk_label: 'high', final_score: 88, category: 'Internal Endpoint', description: 'Admin route' },
    ];

    console.log('🔄  Testing full Security Report generation...\n');
    const t1 = Date.now();
    const report = await generateSecurityReport('test.example.com', mockFindings);
    const elapsed2 = Date.now() - t1;

    console.log('📋  AI Report Preview (first 600 chars):\n');
    console.log(report.substring(0, 600) + (report.length > 600 ? '\n...[truncated]' : ''));
    console.log(`\n⏱   Report generation time: ${elapsed2}ms`);
    console.log('\n🎉  ALL TESTS PASSED — AI is fully operational!\n');
}

main().catch(err => {
    console.error('\n❌  Test FAILED:', err.message);
    if (err.message.includes('API_KEY_INVALID') || err.message.includes('400')) {
        console.error('   → The API key is INVALID. Please check it in your .env file.');
    } else if (err.message.includes('PERMISSION_DENIED') || err.message.includes('403')) {
        console.error('   → The API key does not have permission for Gemini. Check Google AI Studio.');
    } else if (err.message.includes('quota') || err.message.includes('429')) {
        console.error('   → API quota exceeded. Wait a moment and try again.');
    } else {
        console.error('   → Network or API error. Check your internet connection.');
    }
    process.exit(1);
});
