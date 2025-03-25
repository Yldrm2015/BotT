class BotDetectionSystem {
    constructor() {
     this.startTime = performance.now();
        
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
            metrics: {
                requests: 0,
                detections: 0,
                blocks: 0,
                challenges: 0
            },
            serverState: {
                cache: new Map(),
        rateLimiter: new Map(),
        blocklist: new Set()
    }
        };

                // Davranış takibi için veri yapısı
        this.behavioralData = {
            events: [], // Tüm olayları ve zamanlamalarını tutacak array
            patterns: [], // Şüpheli örüntüleri tutacak array
            thresholds: {
                minTimeBetweenClicks: 200,    // ms cinsinden minimum tıklama arası süre
                minFormFillTime: 1000,        // ms cinsinden minimum form doldurma süresi
                minScrollInterval: 50,         // ms cinsinden minimum scroll arası süre
                maxEventsPerSecond: 20        // saniye başına maksimum olay sayısı
            },
            lastEventTime: this.startTime
        };

        // Initialize core components
        this.initializeSystem();
        listeners: new Map()
    }

    reset() {
        // Timestamp güncelleme
         this.startTime = performance.now();
    
        // Behavioral data sıfırlama
        this.behavioralData = {
            events: [],
            patterns: [],
            thresholds: {
                minTimeBetweenClicks: 200,
                minFormFillTime: 1000,
                minScrollInterval: 50,
                maxEventsPerSecond: 20
            },
            lastEventTime: this.startTime
        };
    
        // Event listener'ları temizle ve yeniden başlat
        this.initializeBehavioralTracking();
    
        // Fingerprint data yenileme
        this.initializeFingerprinting();
        
        // Network data yenileme
        this.initializeNetworkControls();
        
        // Cookie storage yenileme
        this.initializeCookieStorage();
    
        console.log(`Bot Detection System reset completed at ${performance.now()}`);
    }

        trackEvent(eventType, details = {}) {
        const currentTime = performance.now();
        const timeSinceLastEvent = currentTime - this.behavioralData.lastEventTime;
        
        const event = {
            type: eventType,
            timeSinceStart: currentTime - this.startTime,
            timeSinceLastEvent,
            ...details
        };

        // Olay kaydı
        this.behavioralData.events.push(event);
        
        // Son 100 olayı tut (memory optimization)
        if (this.behavioralData.events.length > 100) {
            this.behavioralData.events.shift();
        }

        // Şüpheli durum kontrolü
        this.checkForSuspiciousPatterns(event, timeSinceLastEvent);
        
        // Son olay zamanını güncelle
        this.behavioralData.lastEventTime = currentTime;
    }

    checkForSuspiciousPatterns(event, timeDiff) {
        const { thresholds } = this.behavioralData;

        // Olaylar arası süre kontrolü
        if (timeDiff < thresholds.minTimeBetweenClicks && 
            (event.type === 'click' || event.type === 'submit')) {
            this.behavioralData.patterns.push({
                type: 'rapid_action',
                timeDiff,
                event
            });
        }

        // Son 1 saniyedeki olay sayısı kontrolü
        const recentEvents = this.behavioralData.events.filter(e => 
            (performance.now() - e.timeSinceStart) < 1000
        );

        if (recentEvents.length > thresholds.maxEventsPerSecond) {
            this.behavioralData.patterns.push({
                type: 'high_frequency_actions',
                count: recentEvents.length,
                timeWindow: '1s'
            });
        }
    }

   async initializeSystem() {
    try {
        // Sistem başlangıç zamanı
        this.startTime = performance.now();
        
        // Core bileşenleri başlat
        await this.initializeCoreComponents();
        
        // Client-side kontrolü
        if (typeof window !== 'undefined') {
            await this.initializeClientComponents();
            this.setupClientEventListeners();
        }

        this.state.initialized = true;
        this.log('info', 'System initialized successfully');
        return true;
    } catch (error) {
        this.log('error', 'System initialization failed', error);
        console.error('Initialization error:', error);
        return false;
    }
}

async initializeCoreComponents() {
    try {
        class NetworkAnalysis {
            constructor() {
                this.lastAnalysisTime = performance.now();
            }
            analyze() {
                const currentTime = performance.now();
                const timeSinceLastAnalysis = currentTime - this.lastAnalysisTime;
                this.lastAnalysisTime = currentTime;
                return { 
                    score: 0.95,
                    analysisDuration: timeSinceLastAnalysis 
                };
            }
        }

        class SessionManager {
            constructor() {
                this.sessionStartTime = performance.now();
            }
            manage() {
                return {
                    success: true,
                    sessionDuration: performance.now() - this.sessionStartTime
                };
            }
        }

        class SecurityValidator {
            constructor() {
                this.validationStartTime = performance.now();
            }
            validate() {
                return { 
                    valid: true,
                    validationTime: performance.now() - this.validationStartTime 
                };
            }
        }

        class PatternAnalyzer {
            analyze(events) {
                const patterns = [];
                if (events && events.length >= 2) {
                    // Son iki olayı analiz et
                    const lastTwo = events.slice(-2);
                    const timeDiff = lastTwo[1].time - lastTwo[0].time;
                    
                    if (timeDiff < 50) { // 50ms'den hızlı olaylar
                        patterns.push({
                            type: 'rapid_sequence',
                            timeDiff,
                            events: lastTwo
                        });
                    }
                }
                return { patterns };
            }
        }

        // Diğer bileşenleri oluştur
        this.state.components.set('networkAnalysis', new NetworkAnalysis());
        this.state.components.set('sessionManager', new SessionManager());
        this.state.components.set('securityValidator', new SecurityValidator());
        this.state.components.set('patternAnalyzer', new PatternAnalyzer());
        
        return true;
    } catch (error) {
        this.log('error', 'Core components initialization failed', error);
        return false;
    }
}

log(level, message, data = {}) {
    const logEntry = {
        time: performance.now() - this.startTime, // Başlangıçtan itibaren geçen süre
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
}

setupClientEventListeners() {
    try {
        // Mouse hareketlerini izle
        document.addEventListener('mousemove', (event) => {
            if (!this.state.initialized) return;
            
            this.trackEvent('mouse', {
                x: event.clientX,
                y: event.clientY,
                time: performance.now()
            });
        });

        // Klavye aktivitesini izle
        document.addEventListener('keydown', (event) => {
            if (!this.state.initialized) return;
            
            this.trackEvent('keyboard', {
                key: event.key,
                time: performance.now()
            });
        });

        // Scroll olaylarını izle
        document.addEventListener('scroll', () => {
            if (!this.state.initialized) return;
            
            this.trackEvent('scroll', {
                position: window.scrollY,
                time: performance.now()
            });
        });

        // Form olaylarını izle
        document.addEventListener('submit', (event) => {
            if (!this.state.initialized) return;
            
            this.trackEvent('form_submit', {
                formId: event.target.id,
                time: performance.now()
            });
        });

        console.log('Client event listeners initialized');
        return true;
    } catch (error) {
        console.error('Failed to setup client event listeners:', error);
        return false;
    }
}

trackEvent(eventType, details) {
    if (!this.behavioralData) {
        this.behavioralData = {
            events: [],
            patterns: [],
            lastEventTime: performance.now()
        };
    }

    const currentTime = performance.now();
    const timeSinceLastEvent = currentTime - this.behavioralData.lastEventTime;

    const event = {
        type: eventType,
        timeSinceStart: currentTime - this.startTime,
        timeSinceLastEvent,
        ...details
    };

    // Olay kaydı
    this.behavioralData.events.push(event);
    
    // Son 100 olayı tut
    if (this.behavioralData.events.length > 100) {
        this.behavioralData.events.shift();
    }

    // Şüpheli durum analizi
    const patternAnalyzer = this.state.components.get('patternAnalyzer');
    if (patternAnalyzer) {
        const analysis = patternAnalyzer.analyze(this.behavioralData.events);
        if (analysis.patterns.length > 0) {
            this.behavioralData.patterns.push(...analysis.patterns);
        }
    }

    // Son olay zamanını güncelle
    this.behavioralData.lastEventTime = currentTime;
}

// Ana Detection Metodları
async detect(request) {
    try {
        const startTime = performance.now();
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
        
        // İşlem süresini hesapla
        const processingTime = performance.now() - startTime;
        decision.processingTime = processingTime;
        
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
        ip: this.getIPAddress(request),
        userAgent: this.getUserAgent(request),
        headers: this.getHeaders(request),
        url: this.getRequestUrl(request),
        method: request.method || 'GET'
    };

    // Mode'a göre ek veri ekle
    if (this.state.mode.clientSide && this.behavioralData) {
        data.behavioral = {
            events: this.behavioralData.events,
            patterns: this.behavioralData.patterns,
            lastEventTime: this.behavioralData.lastEventTime
        };
    }

    return data;
}

async runDetectionModules(requestData) {
    const modules = this.systemConfig.detection.modules;
    const results = {
        time: performance.now(),
        requestId: requestData.requestId
    };

    // Modülleri paralel çalıştır
    const modulePromises = [];

    if (modules.behavioral.enabled) {
        modulePromises.push(this.runBehavioralAnalysis(requestData));
    }
    if (modules.network.enabled) {
        modulePromises.push(this.runNetworkAnalysis(requestData));
    }
    if (modules.fingerprint.enabled) {
        modulePromises.push(this.runFingerprintAnalysis(requestData));
    }
    if (modules.validation.enabled) {
        modulePromises.push(this.runValidation(requestData));
    }

    const moduleResults = await Promise.all(modulePromises);
    
    // Sonuçları birleştir
    moduleResults.forEach((result, index) => {
        const moduleName = Object.keys(modules)[index];
        results[moduleName] = result;
    });

    return results;
}

async analyzeResults(results) {
    const startTime = performance.now();
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
        time: performance.now(),
        analysisTime: performance.now() - startTime,
        score: finalScore,
        confidence: confidence,
        patterns: detectedPatterns,
        risk: this.calculateRiskLevel(finalScore),
        modules: results
    };
}

addClientListener(event, handler) {
    if (this.state.mode.clientSide) {
        const wrappedHandler = (e) => {
            try {
                const eventTime = performance.now();
                const eventData = {
                    type: event,
                    time: eventTime,
                    timeSinceStart: eventTime - this.startTime
                };

                // Event tipine göre özel veri ekle
                switch(event) {
                    case 'mousemove':
                        eventData.x = e.clientX;
                        eventData.y = e.clientY;
                        eventData.speed = this.calculateSpeed(e);
                        break;
                    case 'keydown':
                        eventData.key = e.key;
                        eventData.interval = this.calculateKeyInterval(eventTime);
                        break;
                    case 'scroll':
                        eventData.position = window.scrollY;
                        eventData.speed = this.calculateScrollSpeed(eventTime);
                        break;
                    case 'click':
                        eventData.target = e.target.tagName;
                        eventData.position = { x: e.clientX, y: e.clientY };
                        break;
                }

                // Event'i işle
                this.trackEvent(event, eventData);
                handler(e);

                // Bellek optimizasyonu
                this.optimizeBehavioralData();
            } catch (error) {
                this.log('error', `Event handler error: ${event}`, error);
            }
        };

        document.addEventListener(event, wrappedHandler);
        if (!this.behavioralData.listeners) {
            this.behavioralData.listeners = new Map();
        }
        this.behavioralData.listeners.set(event, wrappedHandler);
    }
}

optimizeBehavioralData() {
    if (this.behavioralData.events.length > 100) {
        // En eski olayları sil
        this.behavioralData.events = this.behavioralData.events.slice(-100);
    }
    
    if (this.behavioralData.patterns.length > 50) {
        // En eski örüntüleri sil
        this.behavioralData.patterns = this.behavioralData.patterns.slice(-50);
    }
}
    
  async generateBrowserFingerprint() {
    if (!this.state.mode.clientSide) return null;

    const startTime = performance.now();
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
        hardware: await this.getHardwareInfo(),
        generationTime: performance.now() - startTime
    };

    this.behavioralData.fingerprint = {
        components,
        hash: await this.hashFingerprint(components),
        time: performance.now()
    };
}

// Server-Side Özel Metodlar
async setupServerMiddleware() {
    if (!this.state.mode.serverSide) return;

    const startTime = performance.now();
    
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
}

setupRateLimiting() {
    const config = this.systemConfig.api.rateLimit;

    setInterval(() => {
        const now = performance.now();
        for (const [ip, data] of this.serverState.rateLimiter) {
            if (now - data.time > config.windowMs) {
                this.serverState.rateLimiter.delete(ip);
            }
        }
    }, config.windowMs);
}

// Storage Metodları
async initializeClientStorage() {
    if (!this.state.mode.clientSide) return;

    const config = this.systemConfig.storage.client;
    
    this.clientStorage = {
        async set(key, value, ttl = config.maxAge) {
            const storageData = {
                value,
                time: performance.now(),
                expiry: performance.now() + ttl
            };

            const data = config.encryption ? 
                await this.encrypt(storageData) : JSON.stringify(storageData);
            localStorage.setItem(`${config.prefix}${key}`, data);
        },

        async get(key) {
            const data = localStorage.getItem(`${config.prefix}${key}`);
            if (!data) return null;

            const storageData = config.encryption ? 
                await this.decrypt(data) : JSON.parse(data);

            if (performance.now() > storageData.expiry) {
                this.remove(key);
                return null;
            }

            return storageData.value;
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

    const config = this.systemConfig.storage.server;
    
    this.serverStorage = {
        async set(key, value, ttl = config.maxAge) {
            const storageData = {
                value,
                time: performance.now(),
                expiry: performance.now() + ttl
            };

            const data = config.encryption ? 
                await this.encrypt(storageData) : JSON.stringify(storageData);
            await this.storage.set(`${config.prefix}${key}`, data);
        },

        async get(key) {
            const data = await this.storage.get(`${config.prefix}${key}`);
            if (!data) return null;

            const storageData = config.encryption ? 
                await this.decrypt(data) : JSON.parse(data);

            if (performance.now() > storageData.expiry) {
                await this.remove(key);
                return null;
            }

            return storageData.value;
        },

        async remove(key) {
            await this.storage.del(`${config.prefix}${key}`);
        }
    };
}

// Yardımcı Metodlar
generateRequestId() {
    return `req_${performance.now()}_${Math.random().toString(36).substr(2, 9)}`;
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

        const geoData = await this.lookupGeoIP(ip);
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

getSystemStatus() {
    const currentTime = performance.now();
    
    return {
        time: currentTime,
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
    
    return {
        status: 'healthy',
        components: Array.from(this.state.components.keys()).reduce((acc, key) => {
            acc[key] = this.checkComponentHealth(key);
            return acc;
        }, {}),
        lastCheck: healthCheckTime
    };
}
