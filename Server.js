const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const BotDetectionSystem = require('./BotTJS/BotT');
const SecurityValidator = require('./BotTJS/SecurityValidator');

const app = express();
const PORT = process.env.PORT || 3000;

// Bot Detection System ve Security Validator instanceları
const botDetector = new BotDetectionSystem();
const securityValidator = new SecurityValidator();

// Middleware
app.use(bodyParser.json());
app.use(express.static('BotTJS'));

// Global timestamp ve user bilgisi middleware
app.use((req, res, next) => {
    req.timestamp = '2025-03-24 11:57:58';
    req.userLogin = 'Yldrm2015';
    next();
});

// Ana sayfa
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'BotTJS', 'index.html'));
});

// Bot Detection API Endpoints
app.post('/api/bot-detection/verify', async (req, res) => {
    try {
        const behavioralData = req.body;
        const result = await botDetector.analyze(behavioralData);
        res.json({
            status: 'success',
            timestamp: req.timestamp,
            userLogin: req.userLogin,
            result: result
        });
    } catch (error) {
        res.status(500).json({ error: 'Bot detection analysis failed' });
    }
});

app.post('/api/security/validate', async (req, res) => {
    try {
        const validationResult = await securityValidator.validate(req.body);
        res.json({
            status: 'success',
            timestamp: req.timestamp,
            validation: validationResult
        });
    } catch (error) {
        res.status(500).json({ error: 'Security validation failed' });
    }
});

app.get('/api/bot-detection/status', (req, res) => {
    const status = botDetector.getStatus();
    res.json({
        status: status,
        timestamp: req.timestamp,
        userLogin: req.userLogin
    });
});

app.post('/api/bot-detection/report', async (req, res) => {
    try {
        const reportData = await botDetector.generateReport(req.body);
        res.json({
            status: 'success',
            timestamp: req.timestamp,
            report: reportData
        });
    } catch (error) {
        res.status(500).json({ error: 'Report generation failed' });
    }
});

// WebSocket bağlantısı için endpoint
app.ws('/api/realtime', (ws, req) => {
    console.log('New WebSocket connection established');
    
    ws.on('message', async (msg) => {
        const data = JSON.parse(msg);
        const result = await botDetector.analyzeRealtime(data);
        ws.send(JSON.stringify(result));
    });
});

// ML model güncelleme endpoint'i
app.post('/api/ml/update', async (req, res) => {
    try {
        const updateResult = await botDetector.updateMLModels();
        res.json({
            status: 'success',
            timestamp: req.timestamp,
            update: updateResult
        });
    } catch (error) {
        res.status(500).json({ error: 'ML model update failed' });
    }
});

// Pattern veritabanı güncelleme endpoint'i
app.post('/api/patterns/update', async (req, res) => {
    try {
        const updateResult = await botDetector.updatePatternDatabase(req.body);
        res.json({
            status: 'success',
            timestamp: req.timestamp,
            update: updateResult
        });
    } catch (error) {
        res.status(500).json({ error: 'Pattern database update failed' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: req.timestamp
    });
});

// Server'ı başlat
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Bot Detection System Version: ${botDetector.version}`);
    console.log(`Current timestamp: ${botDetector.timestamp}`);
    console.log(`Current user: ${botDetector.userLogin}`);
    
    // Bot Detection System'i başlat
    botDetector.initialize()
        .then(() => {
            console.log('Bot Detection System initialized successfully');
            // ML modellerini yükle
            return botDetector.loadMLModels();
        })
        .then(() => {
            console.log('ML models loaded successfully');
            // Pattern veritabanını yükle
            return botDetector.loadPatternDatabase();
        })
        .then(() => {
            console.log('Pattern database loaded successfully');
            // Security kontrollerini başlat
            return securityValidator.initialize();
        })
        .then(() => {
            console.log('Security validator initialized successfully');
            console.log('System is ready to detect bots!');
        })
        .catch(error => {
            console.error('Initialization error:', error);
            process.exit(1);
        });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    botDetector.cleanup()
        .then(() => {
            console.log('Bot detection system cleaned up');
            process.exit(0);
        })
        .catch(err => {
            console.error('Cleanup error:', err);
            process.exit(1);
        });
});

module.exports = app;
