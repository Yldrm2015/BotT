// Content scanner worker
self.onmessage = function(e) {
    const { type, content, filename } = e.data;
    
    if (type === 'scan') {
        const result = scanContent(content, filename);
        self.postMessage(result);
    }
};

function scanContent(content, filename) {
    // Basit içerik taraması
    const threats = [];
    const suspiciousPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /data:/gi,
        /vbscript:/gi,
        /onload=/gi,
        /onerror=/gi
    ];

    // İçeriği kontrol et
    suspiciousPatterns.forEach(pattern => {
        if (pattern.test(content)) {
            threats.push({
                type: 'suspicious_content',
                pattern: pattern.toString(),
                filename: filename
            });
        }
    });

    return {
        filename,
        threats,
        timestamp: new Date().toISOString()
    };
}
