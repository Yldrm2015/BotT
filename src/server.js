const express = require('express');
const path = require('path');
const app = express();

// Global değişkenler
const CURRENT_TIMESTAMP = '2025-03-24 12:30:47';
const CURRENT_USER = 'Yldrm2015';

// Önemli: SADECE BotTJS klasörünü serve et
app.use('/', express.static(path.join(__dirname, '..', 'BotTJS')));

// Her istek için index.html'i serve et
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'BotTJS', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
    Bot Detection System Started
    ==========================
    Server: http://localhost:${PORT}
    Time  : ${CURRENT_TIMESTAMP}
    User  : ${CURRENT_USER}
    ==========================
    `);
});
