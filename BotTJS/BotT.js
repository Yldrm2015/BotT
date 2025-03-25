class BotDetectionSystem {
    constructor() {
        // System start time
        this.startTime = performance.now();
        
        // System Configuration
        this.systemConfig = {
            mode: {
                clientSide: typeof window !== 'undefined',
                serverSide: typeof window === 'undefined',
                hybrid: true
            },
            general: {
                version: '3.0.0',
                environment: (typeof process !== 'undefined' && process.env && process.env.NODE_ENV) || 'production',
                debug: false,
                updateInterval: 60000
            },
            detection: {
                modules: {
                    behavioral: { enabled: true, weight: 0.3, minDataPoints: 10 },
                    network: { enabled: true, weight: 0.3, timeout: 5000 },
                    fingerprint: { enabled: true, weight: 0.2, updateInterval: 300000 },
                    validation: { enabled: true, weight: 0.2, cacheTime: 600000 }
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
                    keyRotationInterval: 86400000
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
                    expiry: 3600
                }
            },
            storage: {
                client: {
                    type: 'localStorage',
                    prefix: 'botDetection_',
                    encryption: true,
                    maxAge: 86400
                },
                server: {
                    type: 'redis',
                    prefix: 'botDetection:',
                    encryption: true,
                    maxAge: 86400
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
                    windowMs: 900000,
                    max: 100
                }
            }
        };

        // System state initialization
        this.state = {
            active: true,
            mode: this.determineOperationMode(),
            initialized: false,
            components: new Map(),
            sessionId: this.generateSessionId(),
            metrics: {
                requests: 0,
                detections: 0,
                blocks: 0,
                challenges: 0
            }
        };

        // Server state initialization
        this.serverState = {
            cache: new Map(),
            rateLimiter: new Map(),
            blocklist: new Set(),
            connections: new Map()
        };

        // Component references
        this.components = {
            patternAnalyzer: null,
            networkAnalysis: null,
            sessionManager: null,
            securityValidator: null,
            eventManager: null,
            storageManager: null
        };

        // Initialize system
        this.initializeSystem().then(() => {
            // Set component references after successful initialization
            Object.keys(this.components).forEach(key => {
                this.components[key] = this.state.components.get(key);
            });
        }).catch(error => {
            this.log('error', 'System initialization failed', error);
        });
    }

    async initializeSystem() {
        try {
            await this.initializeCoreComponents();
            
            if (typeof window !== 'undefined') {
                await this.initializeClientComponents();
            }

            this.state.initialized = true;
            this.log('info', 'System initialized successfully');
            return true;
        } catch (error) {
            this.log('error', 'System initialization failed', error);
            return false;
        }
    }

    async initializeCoreComponents() {
        try {
            if (typeof window !== 'undefined') {
                // Initialize components from BotT
                const components = {
                    patternAnalyzer: window.PatternAnalyzer,
                    networkAnalysis: window.NetworkAnalysis,
                    sessionManager: window.SessionManager,
                    securityValidator: window.SecurityValidator,
                    eventManager: window.EventManager,
                    storageManager: window.StorageManager
                };

                // Initialize each component
                for (const [name, Component] of Object.entries(components)) {
                    if (Component) {
                        this.state.components.set(name, new Component(this));
                    } else {
                        throw new Error(`Component ${name} not found`);
                    }
                }
            }
            
            return true;
        } catch (error) {
            this.log('error', 'Core components initialization failed', error);
            return false;
        }
    }

    determineOperationMode() {
        const isClient = typeof window !== 'undefined';
        const isServer = !isClient;

        return {
            clientSide: isClient,
            serverSide: isServer,
            hybrid: this.systemConfig.mode.hybrid
        };
    }

    reset() {
        this.startTime = performance.now();
        
        // Reset components
        Object.values(this.components).forEach(component => {
            if (component && typeof component.reset === 'function') {
                component.reset();
            }
        });

        // Reset metrics
        this.state.metrics = {
            requests: 0,
            detections: 0,
            blocks: 0,
            challenges: 0
        };

        this.log('info', 'System reset completed');
    }


    // Event Management Methods
    setupClientEventListeners() {
        if (!this.components.eventManager) {
            this.log('error', 'Event Manager not initialized');
            return false;
        }

        try {
            // Event Manager aracılığıyla event listener'ları kur
            this.components.eventManager.initialize({
                events: [
                    {
                        type: 'mousemove',
                        handler: (event) => {
                            if (!this.state.initialized) return;
                            this.trackEvent('mouse', {
                                x: event.clientX,
                                y: event.clientY,
                                time: performance.now()
                            });
                        }
                    },
                    {
                        type: 'keydown',
                        handler: (event) => {
                            if (!this.state.initialized) return;
                            this.trackEvent('keyboard', {
                                key: event.key,
                                time: performance.now()
                            });
                        }
                    },
                    {
                        type: 'scroll',
                        handler: () => {
                            if (!this.state.initialized) return;
                            this.trackEvent('scroll', {
                                position: window.scrollY,
                                time: performance.now()
                            });
                        }
                    },
                    {
                        type: 'submit',
                        handler: (event) => {
                            if (!this.state.initialized) return;
                            this.trackEvent('form_submit', {
                                formId: event.target.id,
                                time: performance.now()
                            });
                        }
                    },
                    {
                        type: 'click',
                        handler: (event) => {
                            if (!this.state.initialized) return;
                            this.trackEvent('click', {
                                target: event.target.tagName,
                                position: {
                                    x: event.clientX,
                                    y: event.clientY
                                },
                                time: performance.now()
                            });
                        }
                    }
                ],
                options: {
                    useCapture: true,
                    passive: true
                }
            });

            this.log('info', 'Client event listeners initialized');
            return true;
        } catch (error) {
            this.log('error', 'Failed to setup client event listeners', error);
            return false;
        }
    }

    trackEvent(eventType, details = {}) {
        if (!this.components.patternAnalyzer) {
            this.log('error', 'Pattern Analyzer not initialized');
            return;
        }

        const currentTime = performance.now();
        const event = {
            type: eventType,
            timeSinceStart: currentTime - this.startTime,
            time: currentTime,
            ...details
        };

        // Pattern Analyzer'a event'i ilet
        this.components.patternAnalyzer.analyzeEvent(event);
    }

    addClientListener(event, handler) {
        if (!this.components.eventManager) {
            this.log('error', 'Event Manager not initialized');
            return;
        }

        this.components.eventManager.addListener(event, handler);
    }

    removeClientListener(event, handler) {
        if (!this.components.eventManager) {
            this.log('error', 'Event Manager not initialized');
            return;
        }

        this.components.eventManager.removeListener(event, handler);
    }

    // Behavioral Analysis Methods
    async analyzeBehavioralData() {
        if (!this.components.patternAnalyzer) {
            this.log('error', 'Pattern Analyzer not initialized');
            return null;
        }

        try {
            const analysis = await this.components.patternAnalyzer.analyzeBehavioralPatterns();
            
            // ML entegrasyonu için ek kontrol
            if (this.components.patternAnalyzer.ML) {
                const mlAnalysis = await this.components.patternAnalyzer.ML.analyzePatterns(analysis);
                analysis.mlScore = mlAnalysis.score;
                analysis.confidence = mlAnalysis.confidence;
            }

            return analysis;
        } catch (error) {
            this.log('error', 'Behavioral analysis failed', error);
            return null;
        }
    }

    async generateBrowserFingerprint() {
        if (!this.state.mode.clientSide) return null;

        const startTime = performance.now();
        try {
            // Fingerprint bileşenlerini topla
            const components = {
                userAgent: navigator.userAgent,
                language: navigator.language,
                platform: navigator.platform,
                screenResolution: `${screen.width}x${screen.height}`,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                plugins: await this.components.patternAnalyzer.getPluginList(),
                fonts: await this.components.patternAnalyzer.getFontList(),
                canvas: await this.components.patternAnalyzer.generateCanvasFingerprint(),
                webgl: await this.components.patternAnalyzer.generateWebGLFingerprint(),
                hardware: await this.components.patternAnalyzer.getHardwareInfo(),
                generationTime: performance.now() - startTime
            };

            // Hash oluştur
            const hash = await this.components.securityValidator.hashFingerprint(components);

            return {
                components,
                hash,
                time: performance.now()
            };
        } catch (error) {
            this.log('error', 'Fingerprint generation failed', error);
            return null;
        }
    }

    optimizeBehavioralData() {
        if (!this.components.patternAnalyzer) return;

        this.components.patternAnalyzer.optimizeData({
            maxEvents: 100,
            maxPatterns: 50,
            timeWindow: 300000 // 5 minutes
        });
    }


// Ana Detection Metodları
    async detect(request) {
        try {
            const startTime = performance.now();
            this.state.metrics.requests++;

            // Request bilgilerini hazırla
            const requestData = await this.prepareRequestData(request);

            // Pattern Analizi
            const patternAnalysis = await this.components.patternAnalyzer.analyzeBehavioralPatterns();
            
            // Network Analizi
            const networkAnalysis = await this.components.networkAnalysis.analyze(request);
            
            // Session Kontrolü
            const sessionValidation = await this.components.sessionManager.validate(request);
            
            // Security Kontrolü
            const securityValidation = await this.components.securityValidator.validate(request);

            // Tüm sonuçları birleştir
            const results = {
                pattern: patternAnalysis,
                network: networkAnalysis,
                session: sessionValidation,
                security: securityValidation,
                time: performance.now(),
                requestId: requestData.requestId
            };

            // Sonuçları analiz et
            const analysis = await this.analyzeResults(results);
            
            // Karar mekanizması
            const decision = await this.makeDecision(analysis);
            
            // Metrikleri güncelle
            this.updateMetrics(decision);
            
            // İşlem süresini hesapla ve ekle
            decision.processingTime = performance.now() - startTime;
            
            return decision;

        } catch (error) {
            this.log('error', 'Detection failed', error);
            return this.handleDetectionError(error);
        }
    }

    async prepareRequestData(request) {
        const data = {
            time: performance.now(),
            sessionId: this.state.sessionId,
            requestId: this.generateRequestId(),
            ip: await this.components.networkAnalysis.getIPAddress(request),
            userAgent: this.components.networkAnalysis.getUserAgent(request),
            headers: this.components.networkAnalysis.getHeaders(request),
            url: this.components.networkAnalysis.getRequestUrl(request),
            method: request.method || 'GET'
        };

        // Client-side verilerini ekle
        if (this.state.mode.clientSide) {
            data.behavioral = await this.components.patternAnalyzer.getBehavioralData();
            data.fingerprint = await this.generateBrowserFingerprint();
        }

        // GeoIP bilgisini ekle
        if (data.ip) {
            data.geoip = await this.getGeoIPInfo(data.ip);
        }

        return data;
    }

    async analyzeResults(results) {
        const startTime = performance.now();
        const weights = this.systemConfig.detection.modules;
        
        try {
            let totalScore = 0;
            let totalWeight = 0;
            let confidence = 0;
            let detectedPatterns = [];

            // Her modülün sonuçlarını değerlendir
            for (const [module, result] of Object.entries(results)) {
                if (result && weights[module]) {
                    // Skor hesaplama
                    const moduleScore = result.score * weights[module].weight;
                    totalScore += moduleScore;
                    totalWeight += weights[module].weight;
                    
                    // Güven skorunu güncelle
                    confidence = Math.max(confidence, result.confidence || 0);
                    
                    // Tespit edilen pattern'ları ekle
                    if (result.patterns) {
                        detectedPatterns = [...detectedPatterns, ...result.patterns];
                    }

                    // Module-specific metrics
                    this.log('debug', `Module ${module} analysis`, {
                        score: result.score,
                        weight: weights[module].weight,
                        weightedScore: moduleScore,
                        patterns: result.patterns?.length || 0
                    });
                }
            }

            // Final skoru hesapla
            const finalScore = totalWeight > 0 ? totalScore / totalWeight : 0;

            // Risk seviyesini belirle
            const risk = this.calculateRiskLevel(finalScore);

            // ML doğrulaması
            let mlVerification = null;
            if (this.components.patternAnalyzer.ML) {
                mlVerification = await this.components.patternAnalyzer.ML.verifyAnalysis({
                    score: finalScore,
                    patterns: detectedPatterns,
                    confidence: confidence
                });
            }

            return {
                time: performance.now(),
                analysisTime: performance.now() - startTime,
                score: finalScore,
                confidence: mlVerification?.confidence || confidence,
                patterns: detectedPatterns,
                risk: risk,
                modules: results,
                mlVerification: mlVerification
            };

        } catch (error) {
            this.log('error', 'Analysis failed', error);
            throw error;
        }
    }

    async makeDecision(analysis) {
        try {
            // Risk değerlendirmesi
            const riskAssessment = await this.assessRisk(analysis);
            
            // Politika kontrolü
            const policy = await this.components.securityValidator.evaluatePolicy(riskAssessment);
            
            // Session durumu kontrolü
            const sessionStatus = await this.components.sessionManager.checkStatus();
            
            // Final karar
            const decision = {
                time: performance.now(),
                action: this.determineAction(riskAssessment, policy, sessionStatus),
                score: analysis.score,
                confidence: analysis.confidence,
                risk: analysis.risk,
                reason: this.generateDecisionReason(riskAssessment, policy),
                details: {
                    riskAssessment,
                    policy,
                    sessionStatus,
                    patterns: analysis.patterns
                }
            };

            // Kararı kaydet
            await this.logDecision(decision);

            return decision;

        } catch (error) {
            this.log('error', 'Decision making failed', error);
            return this.handleDecisionError(error);
        }
    }

    async assessRisk(analysis) {
        const thresholds = this.systemConfig.detection.thresholds;
        
        return {
            level: analysis.risk,
            score: analysis.score,
            confidence: analysis.confidence,
            threshold: thresholds[analysis.risk] || thresholds.medium,
            patterns: analysis.patterns.length,
            mlVerified: Boolean(analysis.mlVerification),
            time: performance.now()
        };
    }

    determineAction(riskAssessment, policy, sessionStatus) {
        // Yüksek risk durumu
        if (riskAssessment.level === 'high' && riskAssessment.confidence > 0.8) {
            return 'block';
        }
        
        // Orta risk durumu
        if (riskAssessment.level === 'medium' && riskAssessment.confidence > 0.6) {
            return 'challenge';
        }
        
        // Policy ihlali
        if (!policy.allow) {
            return policy.action || 'block';
        }
        
        // Session problemi
        if (!sessionStatus.valid) {
            return 'challenge';
        }
        
        // Varsayılan durum
        return 'allow';
    }

    generateDecisionReason(riskAssessment, policy) {
        const reasons = [];
        
        if (riskAssessment.level === 'high') {
            reasons.push(`High risk activity detected (${riskAssessment.score})`);
        }
        
        if (riskAssessment.patterns > 0) {
            reasons.push(`Suspicious patterns detected (${riskAssessment.patterns})`);
        }
        
        if (!policy.allow) {
            reasons.push(policy.reason || 'Policy violation');
        }
        
        return reasons.join('; ');
    }

    updateMetrics(decision) {
        this.state.metrics.detections++;
        
        if (decision.action === 'block') {
            this.state.metrics.blocks++;
        } else if (decision.action === 'challenge') {
            this.state.metrics.challenges++;
        }
    }

  // Storage Management Methods
    async initializeStorage() {
        try {
            if (this.state.mode.clientSide) {
                await this.initializeClientStorage();
            }
            if (this.state.mode.serverSide) {
                await this.initializeServerStorage();
            }
            return true;
        } catch (error) {
            this.log('error', 'Storage initialization failed', error);
            return false;
        }
    }

    async initializeClientStorage() {
        if (!this.components.storageManager) return;

        await this.components.storageManager.initializeClient({
            type: this.systemConfig.storage.client.type,
            prefix: this.systemConfig.storage.client.prefix,
            encryption: this.systemConfig.storage.client.encryption,
            maxAge: this.systemConfig.storage.client.maxAge
        });
    }

    async initializeServerStorage() {
        if (!this.components.storageManager) return;

        await this.components.storageManager.initializeServer({
            type: this.systemConfig.storage.server.type,
            prefix: this.systemConfig.storage.server.prefix,
            encryption: this.systemConfig.storage.server.encryption,
            maxAge: this.systemConfig.storage.server.maxAge
        });
    }

    // Server Methods
    async setupServerMiddleware() {
        if (!this.state.mode.serverSide) return;

        const startTime = performance.now();
        
        try {
            // Rate limiting
            await this.setupRateLimiting();

            // IP filtreleme
            await this.setupIPFiltering();

            // Request normalizasyon
            await this.setupRequestNormalization();

            // Response güvenliği
            await this.setupResponseSecurity();

            this.log('info', 'Server middleware setup completed', {
                setupTime: performance.now() - startTime
            });
        } catch (error) {
            this.log('error', 'Server middleware setup failed', error);
        }
    }

    setupRateLimiting() {
        const config = this.systemConfig.api.rateLimit;
        const now = performance.now();

        // Eski rate limit kayıtlarını temizle
        for (const [ip, data] of this.serverState.rateLimiter) {
            if (now - data.time > config.windowMs) {
                this.serverState.rateLimiter.delete(ip);
            }
        }

        // Rate limit kontrolü için interval başlat
        setInterval(() => this.cleanupRateLimiter(), config.windowMs);
    }

    // Logging Methods
    log(level, message, data = {}) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            time: performance.now() - this.startTime,
            level,
            message,
            sessionId: this.state.sessionId,
            mode: this.state.mode,
            ...data
        };

        if (this.state.mode.clientSide) {
            console[level](logEntry);
        }
        if (this.state.mode.serverSide) {
            this.serverLog(logEntry);
        }

        // Log storage'a kaydet
        this.storeLog(logEntry);
    }

    async storeLog(logEntry) {
        if (!this.components.storageManager) return;

        try {
            await this.components.storageManager.storeLog(logEntry);
        } catch (error) {
            console.error('Log storage failed:', error);
        }
    }

    // Helper Methods
    generateRequestId() {
        return `req_${performance.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    generateSessionId() {
        return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    async getGeoIPInfo(ip) {
        if (!ip || !this.state.mode.serverSide) return null;

        try {
            const cacheKey = `geoip:${ip}`;
            const cache = this.serverState.cache.get(cacheKey);
            const now = performance.now();

            if (cache && (now - cache.time) < 86400000) {
                return cache.data;
            }

            const geoData = await this.components.networkAnalysis.lookupGeoIP(ip);
            this.serverState.cache.set(cacheKey, {
                time: now,
                data: geoData
            });

            return geoData;
        } catch (error) {
            this.log('error', 'GeoIP lookup failed', error);
            return null;
        }
    }

    // Error Handling
    handleDetectionError(error) {
        const errorTime = performance.now();
        
        this.log('error', 'Detection error occurred', error);

        return {
            time: errorTime,
            success: false,
            error: {
                code: error.code || 'DETECTION_ERROR',
                message: error.message || 'An error occurred during detection',
                details: this.formatError(error)
            },
            action: 'allow',
            confidence: 0
        };
    }

    formatError(error) {
        return {
            name: error.name,
            message: error.message,
            stack: this.systemConfig.general.debug ? error.stack : undefined,
            time: performance.now()
        };
    }

    // System Status Methods
    getSystemStatus() {
        const currentTime = performance.now();
        
        return {
            time: currentTime,
            timestamp: new Date().toISOString(),
            version: this.systemConfig.general.version,
            mode: this.state.mode,
            active: this.state.active,
            metrics: this.state.metrics,
            uptime: currentTime - this.startTime,
            health: this.checkSystemHealth()
        };
    }

    checkSystemHealth() {
        const healthCheckTime = performance.now();
        
        const componentHealth = Array.from(this.state.components.keys()).reduce((acc, key) => {
            acc[key] = this.checkComponentHealth(key);
            return acc;
        }, {});

        return {
            status: this.determineOverallHealth(componentHealth),
            components: componentHealth,
            lastCheck: healthCheckTime,
            timestamp: new Date().toISOString()
        };
    }

    checkComponentHealth(componentName) {
        const component = this.state.components.get(componentName);
        if (!component) return { status: 'not_found' };

        try {
            return component.checkHealth ? 
                component.checkHealth() : 
                { status: 'healthy' };
        } catch (error) {
            return {
                status: 'error',
                error: this.formatError(error)
            };
        }
    }

    determineOverallHealth(componentHealth) {
        const statuses = Object.values(componentHealth).map(h => h.status);
        
        if (statuses.includes('error')) return 'unhealthy';
        if (statuses.includes('warning')) return 'degraded';
        return 'healthy';
    }

    // Cleanup Methods
    async cleanup() {
        try {
            // Event listener'ları temizle
            if (this.components.eventManager) {
                await this.components.eventManager.cleanup();
            }

            // Storage'ı temizle
            if (this.components.storageManager) {
                await this.components.storageManager.cleanup();
            }

            // Pattern analyzer'ı temizle
            if (this.components.patternAnalyzer) {
                await this.components.patternAnalyzer.cleanup();
            }

            // Cache'i temizle
            this.serverState.cache.clear();
            this.serverState.rateLimiter.clear();

            // State'i resetle
            this.resetState();

            this.log('info', 'System cleanup completed');
            return true;
        } catch (error) {
            this.log('error', 'System cleanup failed', error);
            return false;
        }
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
            lastUpdate: new Date().toISOString()
        };
    }
}

// Export the class
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BotDetectionSystem;
} else if (typeof window !== 'undefined') {
    window.BotDetectionSystem = BotDetectionSystem;
}
