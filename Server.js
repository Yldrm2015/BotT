const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

// BotTJS modüllerini import et
const BotDetectionSystem = require('./BotTJS/BotT');
const SecurityValidator = require('./BotTJS/SecurityValidator');
const AlertManager = require('./BotTJS/AlertManager');
const ApiManager = require('./BotTJS/ApiManager');

const app = express();
const PORT = process.env.PORT || 3000;

// Sistem instanceları
const botDetectionSystem = new BotDetectionSystem();
const securityValidator = new SecurityValidator();
const alertManager = new AlertManager();
const apiManager = new ApiManager();

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'BotTJS')));

// Timestamp ve user bilgisi için middleware
app.use((req, res, next) => {
    req.timestamp = '2025-03-24 11:32:08';
    req.userLogin = 'Yldrm2015';
    next();
});

// Ana sayfa route'u
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'BotTJS', 'index.html'));
});

// Bot detection API endpoint'leri
app.post('/api/bot-detection/verify', async (req, res) => {
    try {
        const result = await botDetectionSystem.detect(req);
        res.json(result);
    } catch (error) {
        console.error('Bot detection error:', error);
        res.status(500).json({ error: 'Bot detection failed' });
    }
});

app.post('/api/bot-detection/report', async (req, res) => {
    try {
        const report = await botDetectionSystem.report(req.body);
        res.json(report);
    } catch (error) {
        console.error('Report generation error:', error);
        res.status(500).json({ error: 'Report generation failed' });
    }
});

app.get('/api/bot-detection/status', async (req, res) => {
    try {
        const status = botDetectionSystem.getSystemStatus();
        res.json(status);
    } catch (error) {
        console.error('Status check error:', error);
        res.status(500).json({ error: 'Status check failed' });
    }
});

// Security validation endpoints
app.post('/api/security/validate', async (req, res) => {
    try {
        const validationResult = await securityValidator.validate(req);
        res.json(validationResult);
    } catch (error) {
        console.error('Security validation error:', error);
        res.status(500).json({ error: 'Security validation failed' });
    }
});

// Alert management endpoints
app.post('/api/alerts', async (req, res) => {
    try {
        const alert = await alertManager.createAlert(req.body);
        res.json(alert);
    } catch (error) {
        console.error('Alert creation error:', error);
        res.status(500).json({ error: 'Alert creation failed' });
    }
});

app.get('/api/alerts', async (req, res) => {
    try {
        const alerts = await alertManager.getAlerts();
        res.json(alerts);
    } catch (error) {
        console.error('Alert retrieval error:', error);
        res.status(500).json({ error: 'Alert retrieval failed' });
    }
});

// API yönetimi endpoints
app.post('/api/config', async (req, res) => {
    try {
        const config = await apiManager.updateConfig(req.body);
        res.json(config);
    } catch (error) {
        console.error('Config update error:', error);
        res.status(500).json({ error: 'Config update failed' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({
        error: 'Internal server error',
        timestamp: req.timestamp,
        user: req.userLogin
    });
});

// Server'ı başlat
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Current timestamp: ${botDetectionSystem.timestamp}`);
    console.log(`Current user: ${botDetectionSystem.userLogin}`);
    
    // Sistem durumunu logla
    const status = botDetectionSystem.getSystemStatus();
    console.log('System status:', status);
    
    // Security kontrollerini başlat
    securityValidator.initializeSecurityControls()
        .then(() => console.log('Security controls initialized'))
        .catch(err => console.error('Security initialization error:', err));
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    botDetectionSystem.cleanup()
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
