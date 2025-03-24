class BotDetectionSystem {
    constructor() {
        this.timestamp = '2025-03-17 09:08:07';
        this.userLogin = 'Yldrm2015';
        
        this.systemConfig = {
            mode: {
                clientSide: typeof window !== 'undefined',
                serverSide: typeof window === 'undefined',
                hybrid: true // Her iki modda da çalışabilir
            },
            general: {
                version: '3.0.0',
                environment: (typeof process !== 'undefined' && process.env && process.env.NODE_ENV) || 'production',
                debug: false,
                updateInterval: 60000 // 1 minute
            },
            detection: {
                modules: {
                    behavioral: {
                        enabled: true,
                        weight: 0.3,
                        minDataPoints: 10
                    },
                    network: {
                        enabled: true,
                        weight: 0.3,
                        timeout: 5000
                    },
                    fingerprint: {
                        enabled: true,
                        weight: 0.2,
                        updateInterval: 300000
                    },
                    validation: {
                        enabled: true,
                        weight: 0.2,
                        cacheTime: 600000
                    }
                },
                thresholds: {
                    high: 0.8,
                    medium: 0.6,
                    low: 0.4
                }
            },
            security: {
                encryption: {
                    enabled: true,
                    algorithm: 'AES-256-GCM',
                    keyRotationInterval: 86400000 // 24 hours
                },
                headers: {
                    'X-Bot-Protection': 'enabled',
                    'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY',
                    'X-XSS-Protection': '1; mode=block'
                },
                tokens: {
                    enabled: true,
                    type: 'JWT',
                    expiry: 3600 // 1 hour
                }
            },
            storage: {
                client: {
                    type: 'localStorage',
                    prefix: 'botDetection_',
                    encryption: true,
                    maxAge: 86400 // 24 hours
                },
                server: {
                    type: 'redis',
                    prefix: 'botDetection:',
                    encryption: true,
                    maxAge: 86400 // 24 hours
                }
            },
            api: {
                endpoints: {
                    verify: '/api/bot-detection/verify',
                    report: '/api/bot-detection/report',
                    status: '/api/bot-detection/status',
                    update: '/api/bot-detection/update'
                },
                methods: ['GET', 'POST'],
                rateLimit: {
                    windowMs: 900000, // 15 minutes
                    max: 100 // limit each IP to 100 requests per windowMs
                }
            }
        };

        // System State
        this.state = {
            active: true,
            mode: this.determineOperationMode(),
            initialized: false,
            components: new Map(),
            sessionId: this.generateSessionId(),
            startTime: this.timestamp,
            lastUpdate: this.timestamp,
            metrics: {
                requests: 0,
                detections: 0,
                blocks: 0,
                challenges: 0
            }
        };

        // Initialize core components
        this.initializeSystem();
    }

    reset() {
        // Timestamp güncelleme
        this.timestamp = '2025-03-21 11:29:24';
        this.userLogin = 'Yldrm2015';
    
        // Behavioral data sıfırlama
        this.behavioralData = {
            mouseMovements: [],
            scrollEvents: [],
            keystrokePatterns: [],
            pageInteractions: [],
            pageFocusTime: 0,
            copyPasteCount: 0,
            lastActivity: Date.now()
        };
    
        // Event listener'ları temizle ve yeniden başlat
        this.initializeBehavioralTracking();
    
        // Fingerprint data yenileme
        this.initializeFingerprinting();
        
        // Network data yenileme
        this.initializeNetworkControls();
        
        // Cookie storage yenileme
        this.initializeCookieStorage();
    
        console.log(`[${this.timestamp}] BotDetectionSystem reset completed by ${this.userLogin}`);
    }

   async initializeSystem() {
    try {
        // Timestamp güncelle
        this.timestamp = '2025-03-24 13:23:58';
        
        // Core bileşenleri başlat
        await this.initializeCoreComponents();
        
        // Client-side kontrolü
        if (typeof window !== 'undefined') {
            // Sadece client-side bileşenleri başlat
            await this.initializeClientComponents();
            
            // Event listener'ları başlat
            this.setupClientEventListeners();
        }

        this.state.initialized = true;
        this.log('info', 'System initialized successfully');
        return true;
    } catch (error) {
        this.log('error', 'System initialization failed', error);
        console.error('Initialization error:', error);
        return false; // throw yerine false dön
    }
}
    
  async initializeCoreComponents() {
    try {
        // Basit mock sınıflar oluştur
        class NetworkAnalysis {
            constructor() { }
            analyze() { return { score: 0.95 }; }
        }
        class SessionManager {
            constructor() { }
            manage() { return true; }
        }
        class SecurityValidator {
            constructor() { }
            validate() { return { valid: true }; }
        }
        class PatternAnalyzer {
            constructor() { }
            analyze() { return { patterns: [] }; }
        }
        class AlertManager {
            constructor() { }
            createAlert() { return true; }
        }
        class BotClassifier {
            constructor() { }
            classifyBot() { return { isBot: false }; }
        }
        class BotPolicyManager {
            constructor() { }
            evaluatePolicy() { return { action: 'allow' }; }
        }

        // Bileşenleri oluştur
        this.state.components.set('networkAnalysis', new NetworkAnalysis());
        this.state.components.set('sessionManager', new SessionManager());
        this.state.components.set('securityValidator', new SecurityValidator());
        this.state.components.set('patternAnalyzer', new PatternAnalyzer());
        this.state.components.set('alertManager', new AlertManager());
        this.state.components.set('botClassifier', new BotClassifier());
        this.state.components.set('botPolicyManager', new BotPolicyManager());
        
        return true;
    } catch (error) {
        this.log('error', 'Core components initialization failed', error);
        return false;
    }
}

    determineOperationMode() {
        const isClient = typeof window !== 'undefined';
        const isServer = typeof window === 'undefined';

        return {
            clientSide: isClient,
            serverSide: isServer,
            hybrid: this.systemConfig.mode.hybrid
        };
    }

    generateSessionId() {
        return 'session_' + Date.now() + '_' + 
               Math.random().toString(36).substr(2, 9);
    }

    log(level, message, data = {}) {
        const logEntry = {
            timestamp: this.timestamp,
            level,
            message,
            sessionId: this.state.sessionId,
            mode: this.state.mode,
            ...data
        };

        // Mode'a göre loglama
        if (this.state.mode.clientSide) {
            console[level](logEntry);
        }
        if (this.state.mode.serverSide) {
            // Server-side loglama
            this.serverLog(logEntry);
        }
    }

    setupClientEventListeners() {
    try {
        // Mouse hareketlerini izle
        document.addEventListener('mousemove', (event) => {
            if (!this.state.initialized) return;
            
            const mouseData = {
                type: 'mouse',
                x: event.clientX,
                y: event.clientY,
                timestamp: Date.now()
            };
            
            if (this.state.mode.clientSide) {
                this.processMouseMovement(mouseData);
            }
        });

        // Klavye aktivitesini izle
        document.addEventListener('keydown', (event) => {
            if (!this.state.initialized) return;
            
            const keyData = {
                type: 'keyboard',
                key: event.key,
                timestamp: Date.now()
            };
            
            if (this.state.mode.clientSide) {
                this.processKeyboardEvent(keyData);
            }
        });

        // Scroll olaylarını izle
        document.addEventListener('scroll', () => {
            if (!this.state.initialized) return;
            
            const scrollData = {
                type: 'scroll',
                position: window.scrollY,
                timestamp: Date.now()
            };
            
            if (this.state.mode.clientSide) {
                this.processScrollEvent(scrollData);
            }
        });

        console.log(`[${this.timestamp}] Client event listeners initialized`);
        return true;
    } catch (error) {
        console.error(`[${this.timestamp}] Failed to setup client event listeners:`, error);
        return false;
    }
}

// Yardımcı metodları da ekleyelim
processMouseMovement(data) {
    try {
        // Mouse hareketi işleme
        if (this.state.mode.clientSide && this.clientState?.data?.behavioral) {
            this.clientState.data.behavioral.push(data);
        }
    } catch (error) {
        console.error(`[${this.timestamp}] Mouse movement processing error:`, error);
    }
}

processKeyboardEvent(data) {
    try {
        // Klavye olayı işleme
        if (this.state.mode.clientSide && this.clientState?.data?.behavioral) {
            this.clientState.data.behavioral.push(data);
        }
    } catch (error) {
        console.error(`[${this.timestamp}] Keyboard event processing error:`, error);
    }
}

processScrollEvent(data) {
    try {
        // Scroll olayı işleme
        if (this.state.mode.clientSide && this.clientState?.data?.behavioral) {
            this.clientState.data.behavioral.push(data);
        }
    } catch (error) {
        console.error(`[${this.timestamp}] Scroll event processing error:`, error);
    }
}

    async initializeClientComponents() {
    this.timestamp = '2025-03-24 13:49:43';
    this.userLogin = 'Yldrm2015';
    
        // Client-Side Özel Başlatma
        async initializeClientComponents() {
            this.timestamp = '2025-03-17 10:07:05';
            this.userLogin = 'Yldrm2015';
    
            // Client-side event listeners
            this.clientState = {
                listeners: new Map(),
                data: {
                    behavioral: [],
                    network: [],
                    fingerprint: null
                },
                cache: new Map()
            };
    
            await this.setupClientEventListeners();
            await this.initializeClientStorage();
            await this.initializeClientAPI();
        }
    
        // Server-Side Özel Başlatma
        async initializeServerComponents() {
            this.timestamp = '2025-03-17 10:07:05';
            this.userLogin = 'Yldrm2015';
    
            // Server-side specific components
            this.serverState = {
                cache: new Map(),
                connections: new Map(),
                rateLimiter: new Map(),
                blocklist: new Set()
            };
    
            await this.setupServerMiddleware();
            await this.initializeServerStorage();
            await this.initializeServerAPI();
        }
    
        // Ana Detection Metodları
        async detect(request) {
            try {
                this.state.metrics.requests++;
                
                // Request bilgilerini hazırla
                const requestData = await this.prepareRequestData(request);
                
                // Detection bileşenlerini çalıştır
                const results = await this.runDetectionModules(requestData);
                
                // Sonuçları analiz et
                const analysis = await this.analyzeResults(results);
                
                // Politika kararını al
                const decision = await this.makeDecision(analysis);
                
                // Sonucu kaydet ve raporla
                await this.handleDetectionResult(decision);
                
                return decision;
    
            } catch (error) {
                this.log('error', 'Detection failed', error);
                return this.handleDetectionError(error);
            }
        }
    
        async prepareRequestData(request) {
            const data = {
                timestamp: this.timestamp,
                sessionId: this.state.sessionId,
                requestId: this.generateRequestId(),
                ip: this.getIPAddress(request),
                userAgent: this.getUserAgent(request),
                headers: this.getHeaders(request),
                url: this.getRequestUrl(request),
                method: request.method || 'GET'
            };
    
            // Mode'a göre ek veri ekle
            if (this.state.mode.clientSide) {
                data.behavioral = this.clientState.data.behavioral;
                data.fingerprint = this.clientState.data.fingerprint;
            }
    
            if (this.state.mode.serverSide) {
                data.connection = this.getConnectionInfo(request);
                data.geoip = await this.getGeoIPInfo(data.ip);
            }
    
            return data;
        }
    
        async runDetectionModules(requestData) {
            const modules = this.systemConfig.detection.modules;
            const results = {
                timestamp: this.timestamp,
                requestId: requestData.requestId
            };
    
            // Behavioral Analysis
            if (modules.behavioral.enabled) {
                results.behavioral = await this.runBehavioralAnalysis(requestData);
            }
    
            // Network Analysis
            if (modules.network.enabled) {
                results.network = await this.runNetworkAnalysis(requestData);
            }
    
            // Fingerprint Analysis
            if (modules.fingerprint.enabled) {
                results.fingerprint = await this.runFingerprintAnalysis(requestData);
            }
    
            // Validation
            if (modules.validation.enabled) {
                results.validation = await this.runValidation(requestData);
            }
    
            return results;
        }
    
        async analyzeResults(results) {
            const weights = this.systemConfig.detection.modules;
            let totalScore = 0;
            let totalWeight = 0;
            let confidence = 0;
            let detectedPatterns = [];
    
            // Her modülün sonuçlarını değerlendir
            for (const [module, result] of Object.entries(results)) {
                if (result && weights[module]) {
                    totalScore += result.score * weights[module].weight;
                    totalWeight += weights[module].weight;
                    confidence = Math.max(confidence, result.confidence || 0);
                    
                    if (result.patterns) {
                        detectedPatterns = [...detectedPatterns, ...result.patterns];
                    }
                }
            }
    
            // Final skoru hesapla
            const finalScore = totalWeight > 0 ? totalScore / totalWeight : 0;
    
            return {
                timestamp: this.timestamp,
                score: finalScore,
                confidence: confidence,
                patterns: detectedPatterns,
                risk: this.calculateRiskLevel(finalScore),
                modules: results
            };
        }
    
        async makeDecision(analysis) {
            // Bot sınıflandırması yap
            const classifier = this.state.components.get('botClassifier');
            const classification = await classifier.classifyBot(analysis);
    
            // Politika kararını al
            const policyManager = this.state.components.get('botPolicyManager');
            const policy = await policyManager.evaluatePolicy(classification);
    
            // Kararı uygula
            const decision = {
                timestamp: this.timestamp,
                requestId: analysis.requestId,
                sessionId: this.state.sessionId,
                score: analysis.score,
                confidence: analysis.confidence,
                risk: analysis.risk,
                classification: classification,
                action: policy.action,
                reason: policy.reason,
                duration: policy.duration
            };
    
            return decision;
        }
    
        async handleDetectionResult(decision) {
            this.state.metrics.detections++;
    
            // Karara göre metrik güncelle
            if (decision.action === 'block') {
                this.state.metrics.blocks++;
            } else if (decision.action === 'challenge') {
                this.state.metrics.challenges++;
            }
    
            // Alert oluştur
            if (decision.risk >= 'medium') {
                const alertManager = this.state.components.get('alertManager');
                await alertManager.createAlert({
                    type: 'detection',
                    severity: decision.risk,
                    details: decision
                });
            }
    
            // Sonucu kaydet
            await this.storeDetectionResult(decision);
    
            // API'ye bildir
            if (this.state.mode.clientSide) {
                await this.reportToServer(decision);
            }
        }
    
        calculateRiskLevel(score) {
            const thresholds = this.systemConfig.detection.thresholds;
            
            if (score >= thresholds.high) return 'high';
            if (score >= thresholds.medium) return 'medium';
            if (score >= thresholds.low) return 'low';
            return 'minimal';
        }

            // Client-Side Özel Metodlar
    async setupClientEventListeners() {
        this.timestamp = '2025-03-17 10:09:36';
        this.userLogin = 'Yldrm2015';

        // Mouse hareketlerini izle
        this.addClientListener('mousemove', (event) => {
            this.clientState.data.behavioral.push({
                type: 'mouse',
                x: event.clientX,
                y: event.clientY,
                timestamp: Date.now(),
                speed: this.calculateSpeed(event),
                path: this.trackMousePath(event)
            });
        });

        // Klavye aktivitesini izle
        this.addClientListener('keydown', (event) => {
            this.clientState.data.behavioral.push({
                type: 'keyboard',
                key: event.key,
                timestamp: Date.now(),
                interval: this.calculateKeyInterval(),
                pattern: this.detectKeyPattern(event)
            });
        });

        // Scroll davranışını izle
        this.addClientListener('scroll', (event) => {
            this.clientState.data.behavioral.push({
                type: 'scroll',
                position: window.scrollY,
                timestamp: Date.now(),
                speed: this.calculateScrollSpeed(),
                direction: this.getScrollDirection()
            });
        });

        // Sayfa etkileşimlerini izle
        this.addClientListener('click', (event) => {
            this.clientState.data.behavioral.push({
                type: 'interaction',
                target: event.target.tagName,
                timestamp: Date.now(),
                position: { x: event.clientX, y: event.clientY }
            });
        });

        // Tarayıcı parmak izini oluştur
        await this.generateBrowserFingerprint();
    }

    addClientListener(event, handler) {
        if (this.state.mode.clientSide) {
            const wrappedHandler = (e) => {
                try {
                    handler(e);
                    this.trimBehavioralData();
                } catch (error) {
                    this.log('error', `Event handler error: ${event}`, error);
                }
            };

            document.addEventListener(event, wrappedHandler);
            this.clientState.listeners.set(event, wrappedHandler);
        }
    }

    async generateBrowserFingerprint() {
        if (!this.state.mode.clientSide) return null;

        const components = {
            userAgent: navigator.userAgent,
            language: navigator.language,
            platform: navigator.platform,
            screenResolution: `${screen.width}x${screen.height}`,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            plugins: this.getPluginList(),
            fonts: await this.getFontList(),
            canvas: this.generateCanvasFingerprint(),
            webgl: this.generateWebGLFingerprint(),
            hardware: await this.getHardwareInfo()
        };

        this.clientState.data.fingerprint = {
            components,
            hash: await this.hashFingerprint(components),
            timestamp: this.timestamp
        };
    }

    // Server-Side Özel Metodlar
    async setupServerMiddleware() {
        if (!this.state.mode.serverSide) return;

        // Rate limiting
        this.setupRateLimiting();

        // IP filtreleme
        this.setupIPFiltering();

        // Request normalizasyon
        this.setupRequestNormalization();

        // Response güvenliği
        this.setupResponseSecurity();
    }

    setupRateLimiting() {
        const config = this.systemConfig.api.rateLimit;

        setInterval(() => {
            const now = Date.now();
            for (const [ip, data] of this.serverState.rateLimiter) {
                if (now - data.timestamp > config.windowMs) {
                    this.serverState.rateLimiter.delete(ip);
                }
            }
        }, config.windowMs);
    }

    // API Metodları
    async initializeClientAPI() {
        if (!this.state.mode.clientSide) return;

        const endpoints = this.systemConfig.api.endpoints;

        // Verification endpoint
        this.registerClientEndpoint(endpoints.verify, async () => {
            const verificationData = await this.prepareVerificationData();
            return this.sendToServer(endpoints.verify, verificationData);
        });

        // Reporting endpoint
        this.registerClientEndpoint(endpoints.report, async (data) => {
            return this.sendToServer(endpoints.report, data);
        });

        // Status endpoint
        this.registerClientEndpoint(endpoints.status, async () => {
            return this.getSystemStatus();
        });
    }

    async initializeServerAPI() {
        if (!this.state.mode.serverSide) return;

        const endpoints = this.systemConfig.api.endpoints;

        // Verification handler
        this.registerServerEndpoint(endpoints.verify, async (request) => {
            return this.handleVerificationRequest(request);
        });

        // Report handler
        this.registerServerEndpoint(endpoints.report, async (request) => {
            return this.handleReportRequest(request);
        });

        // Status handler
        this.registerServerEndpoint(endpoints.status, async (request) => {
            return this.handleStatusRequest(request);
        });
    }

    // Storage Metodları
    async initializeClientStorage() {
        if (!this.state.mode.clientSide) return;

        const config = this.systemConfig.storage.client;
        
        this.clientStorage = {
            async set(key, value) {
                const data = config.encryption ? 
                    await this.encrypt(value) : JSON.stringify(value);
                localStorage.setItem(`${config.prefix}${key}`, data);
            },

            async get(key) {
                const data = localStorage.getItem(`${config.prefix}${key}`);
                if (!data) return null;
                return config.encryption ? 
                    await this.decrypt(data) : JSON.parse(data);
            },

            async remove(key) {
                localStorage.removeItem(`${config.prefix}${key}`);
            },

            async clear() {
                const prefix = config.prefix;
                Object.keys(localStorage)
                    .filter(key => key.startsWith(prefix))
                    .forEach(key => localStorage.removeItem(key));
            }
        };
    }

    async initializeServerStorage() {
        if (!this.state.mode.serverSide) return;

        // Redis bağlantısı veya başka bir storage sistemi
        const config = this.systemConfig.storage.server;
        
        this.serverStorage = {
            async set(key, value, ttl = config.maxAge) {
                const data = config.encryption ? 
                    await this.encrypt(value) : JSON.stringify(value);
                // Redis veya benzeri storage sistemine kaydet
                await this.storage.set(`${config.prefix}${key}`, data, ttl);
            },

            async get(key) {
                const data = await this.storage.get(`${config.prefix}${key}`);
                if (!data) return null;
                return config.encryption ? 
                    await this.decrypt(data) : JSON.parse(data);
            },

            async remove(key) {
                await this.storage.del(`${config.prefix}${key}`);
            }
        };
    }

        // Yardımcı Metodlar
        timestamp = '2025-03-17 10:11:28';
        userLogin = 'Yldrm2015';
    
        generateRequestId() {
            return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }
    
        getIPAddress(request) {
            if (this.state.mode.serverSide) {
                return request.headers['x-forwarded-for'] || 
                       request.connection.remoteAddress;
            }
            return null;
        }
    
        getUserAgent(request) {
            if (this.state.mode.serverSide) {
                return request.headers['user-agent'];
            }
            return navigator.userAgent;
        }
    
        getHeaders(request) {
            if (this.state.mode.serverSide) {
                return request.headers;
            }
            return {};
        }
    
        async getGeoIPInfo(ip) {
            if (!ip || !this.state.mode.serverSide) return null;
    
            try {
                const cache = this.serverState.cache.get(`geoip:${ip}`);
                if (cache && cache.timestamp > Date.now() - 86400000) {
                    return cache.data;
                }
    
                const geoData = await this.lookupGeoIP(ip);
                this.serverState.cache.set(`geoip:${ip}`, {
                    timestamp: Date.now(),
                    data: geoData
                });
    
                return geoData;
            } catch (error) {
                this.log('error', 'GeoIP lookup failed', error);
                return null;
            }
        }
    
        // Güvenlik Metodları
        async initializeSecurityControls() {
            const security = this.systemConfig.security;
    
            if (security.encryption.enabled) {
                await this.initializeEncryption();
            }
    
            if (security.tokens.enabled) {
                await this.initializeTokenSystem();
            }
    
            this.setupSecurityHeaders();
        }
    
        async initializeEncryption() {
            const crypto = this.state.mode.serverSide ? 
                require('crypto') : window.crypto;
    
            this.encryption = {
                async encrypt(data) {
                    // AES-256-GCM şifreleme
                    const key = await this.getEncryptionKey();
                    const iv = crypto.getRandomValues(new Uint8Array(12));
                    const encoded = new TextEncoder().encode(JSON.stringify(data));
    
                    const encrypted = await crypto.subtle.encrypt(
                        { name: 'AES-GCM', iv },
                        key,
                        encoded
                    );
    
                    return {
                        data: Array.from(new Uint8Array(encrypted)),
                        iv: Array.from(iv)
                    };
                },
    
                async decrypt(encryptedData) {
                    const key = await this.getEncryptionKey();
                    const encrypted = new Uint8Array(encryptedData.data);
                    const iv = new Uint8Array(encryptedData.iv);
    
                    const decrypted = await crypto.subtle.decrypt(
                        { name: 'AES-GCM', iv },
                        key,
                        encrypted
                    );
    
                    return JSON.parse(new TextDecoder().decode(decrypted));
                }
            };
        }
    
        // Error Handling
        handleDetectionError(error) {
            this.log('error', 'Detection error occurred', error);
    
            return {
                timestamp: this.timestamp,
                success: false,
                error: {
                    code: error.code || 'DETECTION_ERROR',
                    message: error.message || 'An error occurred during detection',
                    details: this.formatError(error)
                },
                action: 'allow', // Hata durumunda varsayılan olarak izin ver
                confidence: 0
            };
        }
    
        formatError(error) {
            return {
                name: error.name,
                message: error.message,
                stack: this.systemConfig.general.debug ? error.stack : undefined,
                timestamp: this.timestamp
            };
        }
    
        // Cleanup ve Maintenance
        async cleanup() {
            // Event listener'ları temizle
            if (this.state.mode.clientSide) {
                for (const [event, handler] of this.clientState.listeners) {
                    document.removeEventListener(event, handler);
                }
                this.clientState.listeners.clear();
            }
    
            // Storage'ı temizle
            if (this.state.mode.clientSide) {
                await this.clientStorage.clear();
            }
    
            // Cache'i temizle
            if (this.state.mode.serverSide) {
                this.serverState.cache.clear();
                this.serverState.rateLimiter.clear();
            }
    
            // State'i resetle
            this.resetState();
        }
    
        resetState() {
            this.state = {
                ...this.state,
                metrics: {
                    requests: 0,
                    detections: 0,
                    blocks: 0,
                    challenges: 0
                },
                lastUpdate: this.timestamp
            };
        }
    
        // Public API
        async verify(request) {
            const result = await this.detect(request);
            return {
                timestamp: this.timestamp,
                sessionId: this.state.sessionId,
                result: result,
                status: this.getSystemStatus()
            };
        }
    
        async report(data) {
            try {
                const reportData = {
                    ...data,
                    timestamp: this.timestamp,
                    sessionId: this.state.sessionId
                };
    
                if (this.state.mode.clientSide) {
                    await this.reportToServer(reportData);
                } else {
                    await this.handleReport(reportData);
                }
    
                return { success: true, timestamp: this.timestamp };
            } catch (error) {
                return this.handleReportError(error);
            }
        }
    
        getSystemStatus() {
            return {
                timestamp: this.timestamp,
                version: this.systemConfig.general.version,
                mode: this.state.mode,
                active: this.state.active,
                metrics: this.state.metrics,
                uptime: this.calculateUptime(),
                health: this.checkSystemHealth()
            };
        }
    
        checkSystemHealth() {
            return {
                status: 'healthy',
                components: Array.from(this.state.components.keys()).reduce((acc, key) => {
                    acc[key] = this.checkComponentHealth(key);
                    return acc;
                }, {}),
                lastCheck: this.timestamp
            };
        }
    }
    
    // Export the class
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = BotDetectionSystem;
    } else if (typeof window !== 'undefined') {
        window.BotDetectionSystem = BotDetectionSystem;
    }
