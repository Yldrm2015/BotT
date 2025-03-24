const express = require('express');
const path = require('path');
const app = express();

// Önemli: SADECE BotTJS klasörünü serve et
app.use('/', express.static(path.join(__dirname, 'BotTJS')));

// Her istek için index.html'i serve et
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'BotTJS', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
