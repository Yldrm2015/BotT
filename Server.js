const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

// Express app'i oluştur
const app = express();
const PORT = process.env.PORT || 3000;

// Global timestamp ve user bilgileri
const CURRENT_TIMESTAMP = '2025-03-24 12:10:55';
const CURRENT_USER = 'Yldrm2015';

// Middleware setup
app.use(bodyParser.json());

// Statik dosyaları serve et ama directory listing'i KAPAT
app.use(express.static('BotTJS', {
    index: 'index.html',
    dotfiles: 'ignore',
    directory: false // Directory listing'i devre dışı bırak
}));

// Global timestamp ve user bilgisi middleware
app.use((req, res, next) => {
    req.timestamp = CURRENT_TIMESTAMP;
    req.userLogin = CURRENT_USER;
    next();
});

// Ana sayfa - kesin olarak index.html'i serve et
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'BotTJS', 'index.html'));
});

// Bot Detection API Endpoints
app.post('/api/bot-detection/verify', (req, res) => {
    res.json({
        status: 'success',
        timestamp: CURRENT_TIMESTAMP,
        userLogin: CURRENT_USER,
        result: {
            isBot: false,
            confidence: 0.95,
            behavioral: {
                mouseMovement: true,
                scrollBehavior: true,
                keystrokes: true
            }
        }
    });
});

app.get('/api/bot-detection/status', (req, res) => {
    res.json({
        status: 'active',
        timestamp: CURRENT_TIMESTAMP,
        userLogin: CURRENT_USER
    });
});

app.post('/api/bot-detection/report', (req, res) => {
    res.json({
        status: 'success',
        timestamp: CURRENT_TIMESTAMP,
        report: {
            totalChecks: 42,
            botAttempts: 5,
            lastCheck: CURRENT_TIMESTAMP
        }
    });
});

// Security validation endpoint
app.post('/api/security/validate', (req, res) => {
    res.json({
        status: 'success',
        timestamp: CURRENT_TIMESTAMP,
        validation: {
            passed: true,
            score: 0.98
        }
    });
});

// 404 handler - her durumda index.html'e yönlendir
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'BotTJS', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: CURRENT_TIMESTAMP
    });
});

// Server'ı başlat
app.listen(PORT, () => {
    console.log(`
    Bot Detection System Started
    ==========================
    Server: http://localhost:${PORT}
    Time  : ${CURRENT_TIMESTAMP}
    User  : ${CURRENT_USER}
    Status: Active
    ==========================
    `);
});

module.exports = app;
