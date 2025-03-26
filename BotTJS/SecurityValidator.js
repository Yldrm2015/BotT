(function(window) {
    'use strict';

    if (!window.SecurityValidator) {
        window.SecurityValidator = {};
    }

    class SecurityValidator {
     
        constructor() {
            this.timestamp = this.getCurrentTimestamp();
            // Temel güvenlik konfigürasyonu
            this.validationConfig = {
                headers: {
                    required: [
                        'Content-Security-Policy',
                        'X-Content-Type-Options',
                        'X-Frame-Options',
                        'X-XSS-Protection',
                        'Strict-Transport-Security'
                    ],
                    recommended: [
                        'Referrer-Policy',
                        'Feature-Policy',
                        'Cross-Origin-Resource-Policy',
                        'Cross-Origin-Embedder-Policy',
                        'Cross-Origin-Opener-Policy'
                    ],
                    values: {
                        'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                        'X-Content-Type-Options': ['nosniff'],
                        'X-XSS-Protection': ['1', '1; mode=block'],
                        'Referrer-Policy': ['strict-origin-when-cross-origin']
                    }
                },
                csp: {
                    directives: {
                        'default-src': ["'self'"],
                        'script-src': ["'self'", "'strict-dynamic'"],
                        'style-src': ["'self'", "'unsafe-inline'"],
                        'img-src': ["'self'", 'data:', 'https:'],
                        'font-src': ["'self'", 'https:', 'data:'],
                        'connect-src': ["'self'"],
                        'frame-ancestors': ["'none'"],
                        'form-action': ["'self'"]
                    },
                    reportUri: '/security/csp-report'
                },

                botDetection: {
                    patterns: {
                        userAgent: [
                            /bot|crawler|spider|crawling/i,
                            /HeadlessChrome/i,
                            /Phantom|Selenium|WebDriver/i
                        ],
                        behavior: {
                            maxRequestsPerMinute: 60,
                            minTimeBeforeClicks: 200,
                            suspiciousPatterns: true
                        },
                        fingerprint: {
                            required: ['canvas', 'webgl', 'audio'],
                            checkWebdriver: true
                        }
                    },
                    action: {
                        block: true,
                        logAttempts: true,
                        captchaThreshold: 3
                    }
                },

                protectedPaths: {
                    highSecurity: {
                        patterns: ['^/admin.*', '^/payment.*'],
                        action: 'block'
                    },
                    mediumSecurity: {
                        patterns: ['^/profile.*', '^/orders.*'],
                        action: 'monitor'
                    },
                    monitoring: {
                        patterns: ['^/products.*', '^/search.*'],
                        action: 'log'
                    }
                },

                rateLimiting: {
                    global: {
                        maxRequests: 1000,
                        windowMs: 900000, // 15 dakika
                        blockDuration: 600000 // 10 dakika
                    },
                    endpoints: {
                        '/api/*': {
                            maxRequests: 100,
                            windowMs: 60000  // 1 dakika
                        },
                        '/login': {
                            maxRequests: 5,
                            windowMs: 300000, // 5 dakika
                            blockDuration: 900000 // 15 dakika
                        },
                        '/register': {
                            maxRequests: 3,
                            windowMs: 3600000, // 1 saat
                            blockDuration: 7200000 // 2 saat
                        }
                    },
                    store: {
                        requests: new Map(),
                        blocked: new Map()
                    }
                },

                auditLogging: {
                    enabled: true,
                    storage: {
                        maxSize: 1000, // maksimum log sayısı
                        rotationInterval: 86400000, // 24 saat
                    },
                    levels: {
                        high: ['security_violation', 'bot_detection', 'rate_limit_exceeded'],
                        medium: ['rate_limit_warning', 'suspicious_activity'],
                        low: ['path_access', 'validation_warning']
                    },
                    retention: {
                        high: 2592000000,   // 30 gün
                        medium: 1209600000, // 14 gün
                        low: 604800000     // 7 gün
                    }
                },

                inputValidation: {
                    rules: {
                        string: {
                            maxLength: 1000,
                            sanitize: true,
                            allowHtml: false
                        },
                        email: {
                            pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                            maxLength: 254
                        },
                        username: {
                            pattern: /^[a-zA-Z0-9_-]{3,20}$/,
                            sanitize: true
                        },
                        password: {
                            minLength: 8,
                            requireSpecial: true,
                            requireNumbers: true,
                            requireUppercase: true
                        },
                        url: {
                            pattern: /^https?:\/\/.+/,
                            maxLength: 2048,
                            allowedProtocols: ['http', 'https']
                        }
                    },
                    sanitization: {
                        enableXSSProtection: true,
                        enableSQLInjectionProtection: true,
                        stripTags: true,
                        escapeHTML: true
                    },
                    errorHandling: {
                        throwOnFailure: false,
                        logFailures: true
                    }
                },

                https: {
                    required: true,
                    upgradeInsecure: true,
                    hsts: {
                        maxAge: 31536000,
                        includeSubDomains: true,
                        preload: true
                    }
                }
            };

            // Validation durumu
            this.validationState = {
                initialized: false,
                secureContext: window.isSecureContext,
                lastCheck: this.timestamp,
                headers: new Map(),
                violations: [],
                warnings: []
            };

            // Performance metrikleri
            this.metrics = {
                checks: 0,
                violations: 0,
                lastViolation: null,
                responseTime: []
            };

            this.tokenValidator = new TokenAuthValidator(this);
            this.contentValidator = new ContentSecurityValidator(this);
            this.realtimeValidator = new RealTimeSecurityValidator(this);

            this.initializeValidators();
            this.initialize();
        }

        handleValidationError(type, error, source = 'main') {
            const currentTime = this.getCurrentTimestamp();
            const currentUser = this.getCurrentUser();
            
            // Konsola log
            console.error(`[${currentTime}] Validation error (${type}) from ${source}:`, error);
            
            // Violation kaydı
            const violation = {
                type,
                source,
                error: error.message,
                timestamp: currentTime,
                user: currentUser,
                details: {
                    stack: error.stack,
                    code: error.code
                }
            };
    
            // State güncelleme
            this.validationState.violations.push(violation);
    
            // Metrics güncelleme
            this.metrics.violations++;
            
            // Audit log
            this.auditLog({
                type: 'validation_error',
                error_type: type,
                source: source,
                details: violation
            });
    
            return violation;
        }

        initializeValidators() {
            // Validators'ları güvenli bir şekilde oluştur
            if (window.SecurityValidator && window.SecurityValidator.TokenAuthValidator) {
                this.tokenValidator = new window.SecurityValidator.TokenAuthValidator(this);
            } else {
                console.warn('[${this.timestamp}] TokenAuthValidator not available');
            }
        
            if (window.SecurityValidator && window.SecurityValidator.ContentSecurityValidator) {
                this.contentValidator = new window.SecurityValidator.ContentSecurityValidator(this);
            } else {
                console.warn('[${this.timestamp}] ContentSecurityValidator not available');
            }
        
            if (window.SecurityValidator && window.SecurityValidator.RealTimeSecurityValidator) {
                this.realtimeValidator = new window.SecurityValidator.RealTimeSecurityValidator(this);
            } else {
                console.warn('[${this.timestamp}] RealTimeSecurityValidator not available');
            }
        }

        getCurrentTimestamp() {
            const now = new Date();
            return now.toISOString().slice(0, 19).replace('T', ' ');
        }

        updateTimestamp() {
            this.timestamp = this.getCurrentTimestamp();
            return this.timestamp;
        }

        // Kullanıcı bilgisi için yardımcı metod
        getCurrentUser() {
            // Örnek kullanıcı yönetimi:
            // 1. Önce session'dan kontrol et
            const sessionUser = sessionStorage.getItem('currentUser');
            if (sessionUser) return sessionUser;

            // 2. localStorage'dan kontrol et
            const localUser = localStorage.getItem('currentUser');
            if (localUser) return localUser;

            // 3. Cookie'den kontrol et
            const cookieUser = this.getCookie('currentUser');
            if (cookieUser) return cookieUser;

            // 4. Hiçbiri yoksa anonim kullanıcı
            return 'anonymous';
        }

        // Cookie yardımcı metodu
        getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
            return null;
        }

        handleValidationError(type, error, source = 'main') {
            const currentTime = this.getCurrentTimestamp();
            const currentUser = this.getCurrentUser();
            
            // Konsola log
            console.error(`[${currentTime}] Validation error (${type}) from ${source}:`, error);
            
            // Violation kaydı
            const violation = {
                type,
                source,
                error: error.message,
                timestamp: currentTime,
                user: currentUser,
                details: {
                    stack: error.stack,
                    code: error.code
                }
            };
    
            // State güncelleme
            this.validationState.violations.push(violation);
    
            // Metrics güncelleme
            this.metrics.violations++;
            
            // Audit log
            this.auditLog({
                type: 'validation_error',
                error_type: type,
                source: source,
                details: violation
            });
    
            return violation;
        }

        // SecurityValidator.js içine eklenecek
        reset() {
            this.timestamp = this.getCurrentTimestamp();
            // Violations listesini temizle
            this.violations = [];
            
            // State'i sıfırla
            this.state = {
                initialized: true,
                lastCheck: this.timestamp,
                checkCount: 0
            };

            console.log(`[${this.timestamp}] SecurityValidator reset completed by ${this.userLogin}`);
        }

        validateRequest(requestData) {
            try {
                const { url, method } = requestData;
                
                // Path validation
                if (!this.validatePath(new URL(url, window.location.origin).pathname)) {
                    return false;
                }
    
                // Rate limit check
                if (!this.checkRateLimit(url)) {
                    return false;
                }
    
                // Bot detection
                if (this.detectBot()) {
                    return false;
                }
    
                return true;
            } catch (error) {
                this.handleValidationError('request_validation', error);
                return false;
            }
        }

        async initialize() {
            try {
                // Başlangıç kontrolü
                if (this.validationState.initialized) {
                    console.log(`[${this.timestamp}] SecurityValidator already initialized`);
                    return;
                }
        
                // Ana güvenlik kontrollerini başlat
                if (!window.isSecureContext) {
                    throw new Error('Secure context required');
                }
        
                if (this.validationConfig.https.required && 
                    window.location.protocol !== 'https:') {
                    this.upgradeToHttps();
                    return;
                }
        
                try {
                    // Core bileşenleri başlat
                    await this.initializeHeaderValidation();
                    await this.initializeCSPMonitoring();
                    await this.setupEventListeners();
        
                    // Alt validator'ları başlat
                    await Promise.all([
                        this.tokenValidator.initializeAuth(),
                        this.contentValidator.initializeContent(),
                        this.realtimeValidator.initialize()
                    ]).catch(error => {
                        console.warn(`[${this.timestamp}] Sub-validator initialization warning:`, error);
                    });
        
                    this.validationState.initialized = true;
                    console.log(`[${this.timestamp}] SecurityValidator initialized successfully`);
                } catch (initError) {
                    console.warn(`[${this.timestamp}] Component initialization warning:`, initError);
                }
        
            } catch (error) {
                console.error(`[${this.timestamp}] Initialization failed:`, error);
                this.handleInitializationError(error);
                this.validationState.initialized = true;
                this.validationState.initializationWarnings = true;
            }
        }

        upgradeToHttps() {
            const httpsUrl = `https://${window.location.host}${window.location.pathname}${window.location.search}`;
            window.location.replace(httpsUrl);
        }

        async initializeHeaderValidation() {
            // Response header analizi için observer
            const observer = new PerformanceObserver((list) => {
                list.getEntries().forEach(entry => {
                    if (entry.entryType === 'resource') {
                        this.validateResourceHeaders(entry);
                    }
                });
            });

            observer.observe({ entryTypes: ['resource'] });

            // İlk sayfa yüklenme header kontrolü
            await this.validateCurrentPageHeaders();
        }

        validateResourceHeaders(resource) {
            try {
                // Resource response headers'ı olmayabilir, bu normal
                if (!resource || !resource.name) return true;
        
                // Development ortamında header kontrollerini yumuşat
                if (window.location.hostname === 'localhost' || 
                    window.location.hostname === '127.0.0.1') {
                    return true;
                }
        
                const headers = resource.headers || {};
                const missing = this.validationConfig.headers.required
                    .filter(header => !headers[header.toLowerCase()]);
        
                if (missing.length > 0) {
                    // Development ortamında sadece uyarı ver
                    console.warn(`[${this.timestamp}] Missing security headers:`, missing.join(', '));
                    return true;
                }
        
                return true;
            } catch (error) {
                this.handleValidationError('resource_headers', error);
                return false;
            }
        }
        

        async validateCurrentPageHeaders() {
            const startTime = performance.now();

            try {
                const response = await fetch(window.location.href, {
                    method: 'HEAD',
                    cache: 'no-store'
                });

                const headers = Array.from(response.headers.entries());
                const validation = this.validateHeaders(headers);

                this.updateValidationState('page', validation);
                this.updateMetrics('headers', performance.now() - startTime);

            } catch (error) {
                this.handleValidationError('headers', error);
            }
        }

        validateHeaders(headers) {
            const missing = this.findMissingHeaders(headers);
            const invalid = this.findInvalidHeaderValues(headers);
            const warnings = this.checkRecommendedHeaders(headers);
        
            const result = {
                valid: missing.length === 0 && invalid.length === 0,
                missing,
                invalid,
                warnings,
                timestamp: this.timestamp
            };
        
            // Critical headers eksik ise
            if (missing.length > 0) {
                this.handleMissingHeaders(missing);
            }
        
            // Header değerleri invalid ise
            if (invalid.length > 0) {
                this.handleInvalidHeaders(invalid);
            }
        
            return result;
        }
        
        // handleMissingHeaders fonksiyonunu sınıfın üye fonksiyonu olarak tanımla
        handleMissingHeaders(missing) {
            console.error(`[${this.timestamp}] Missing required headers:`, missing);
            const violation = {
                type: 'missing_headers',
                headers: missing,
                timestamp: this.timestamp
            };
            this.validationState.violations.push(violation);
        }

        findMissingHeaders(headers) {
            const headerKeys = headers.map(([key]) => key.toLowerCase());
            return this.validationConfig.headers.required.filter(required => 
                !headerKeys.includes(required.toLowerCase())
            );
        }

        findInvalidHeaderValues(headers) {
            return headers.filter(([key, value]) => {
                const validValues = this.validationConfig.headers.values[key];
                return validValues && !validValues.includes(value);
            });
        }

        checkRecommendedHeaders(headers) {
            const headerKeys = headers.map(([key]) => key.toLowerCase());
            return this.validationConfig.headers.recommended.filter(recommended =>
                !headerKeys.includes(recommended.toLowerCase())
            );
        }

        initializeCSPMonitoring() {
            // CSP violation listener
            document.addEventListener('securitypolicyviolation', (e) => {
                this.handleCSPViolation({
                    directive: e.violatedDirective,
                    source: e.blockedURI,
                    timestamp: this.timestamp,
                    sample: e.sample || ''
                });
            });

            // CSP header oluştur ve uygula
            this.applyCSP();
        }

        applyCSP() {
            const csp = this.buildCSPHeader();
            
            // Meta tag ile CSP uygula ama frame-ancestors ve report-uri hariç
            const metaCsp = csp
                .split(';')
                .filter(directive => !directive.includes('frame-ancestors') && !directive.includes('report-uri'))
                .join(';');
            
            const meta = document.createElement('meta');
            meta.httpEquiv = 'Content-Security-Policy';
            meta.content = metaCsp;
            document.head.appendChild(meta);
        }

        buildCSPHeader() {
            return Object.entries(this.validationConfig.csp.directives)
                .map(([directive, sources]) => 
                    `${directive} ${sources.join(' ')}`
                )
                .concat(`report-uri ${this.validationConfig.csp.reportUri}`)
                .join('; ');
        }

        setupXHRInterceptor() {
            const originalOpen = XMLHttpRequest.prototype.open;
            const originalSend = XMLHttpRequest.prototype.send;
            const self = this;
        
            XMLHttpRequest.prototype.open = function(method, url, ...args) {
                this._securityData = {
                    method,
                    url,
                    timestamp: this.timestamp
                };
                return originalOpen.apply(this, [method, url, ...args]);
            };
        
            XMLHttpRequest.prototype.send = function(data) {
                if (self.validateRequest(this._securityData)) {
                    return originalSend.apply(this, [data]);
                }
                throw new Error('Request blocked by security policy');
            };
        }

        setupEventListeners() {
            // Dinamik content ekleme monitörü
            const observer = new MutationObserver((mutations) => {
                mutations.forEach(mutation => {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1) { // ELEMENT_NODE
                            this.validateElement(node);
                        }
                    });
                });
            });

            observer.observe(document.documentElement, {
                childList: true,
                subtree: true
            });

            // Path güvenlik kontrolü için URL değişikliği dinleyicileri
            window.addEventListener('popstate', () => {
                this.validatePath(window.location.pathname);
            });

            window.addEventListener('hashchange', () => {
                this.validatePath(window.location.pathname);
            });

            // Link tıklamalarını yakala
            document.addEventListener('click', (e) => {
                if (e.target.tagName === 'A' && e.target.href) {
                    const url = new URL(e.target.href);
                    if (!this.validatePath(url.pathname)) {
                        e.preventDefault();
                        console.error(`[${this.timestamp}] Blocked navigation to restricted path: ${url.pathname}`);
                    }
                }
            }, true);

            // Form submission kontrolü
            document.addEventListener('submit', (e) => {
                this.validateFormSubmission(e);
            }, true);

            // AJAX request interceptor
            this.setupXHRInterceptor();
            this.setupFetchInterceptor();
        }

        setupFetchInterceptor() {
            const originalFetch = window.fetch;
            const self = this;
        
            window.fetch = async (input, init) => {
                const url = input instanceof Request ? input.url : input;
        
                try {
                    // Request validation
                    if (!self.validateRequest({ url, method: init?.method || 'GET' })) {
                        throw new Error('Request blocked by security policy');
                    }
        
                    const response = await originalFetch(input, init);
                    
                    // Response validation
                    await self.validateResourceHeaders(response);
        
                    return response;
                } catch (error) {
                    self.handleValidationError('fetch', error);
                    throw error;
                }
            };
        }

        validateElement(element) {
            // Inline script kontrolü
            if (element.tagName === 'SCRIPT') {
                this.validateScript(element);
            }

            // Inline style kontrolü
            if (element.hasAttribute('style')) {
                this.validateInlineStyle(element);
            }

            // URL attribute kontrolü
            this.validateElementUrls(element);
        }

        validateScript(script) {
            if (script.hasAttribute('src')) {
                const src = script.getAttribute('src');
                if (!this.isValidScriptSource(src)) {
                    this.handleInvalidScript(script, src);
                }
            } else {
                // Inline script kontrolü
                this.validateInlineScript(script);
            }
        }

        validatePath(path) {
            const securityLevel = this.checkPathSecurity(path);
            return this.applySecurityRules(path, securityLevel);
        }
        
        checkPathSecurity(path) {
            for (const [level, config] of Object.entries(this.validationConfig.protectedPaths)) {
                if (config.patterns.some(pattern => new RegExp(pattern).test(path))) {
                    return level;
                }
            }
            return 'public';
        }

        applySecurityRules(path, securityLevel) {
            const config = this.validationConfig.protectedPaths[securityLevel];
            
            if (!config) return true;
            
            switch (config.action) {
                case 'block':
                    this.handleSecurityViolation('high', path);
                    return false;
                    
                case 'monitor':
                    this.logSecurityEvent('medium', path);
                    return true;
                    
                case 'log':
                    this.logSecurityEvent('low', path);
                    return true;
                    
                default:
                    return true;
            }
        }
        
        handleSecurityViolation(level, path) {
            const violation = {
                type: 'path_security',
                level: level,
                path: path,
                timestamp: '2025-03-19 07:27:23',
                user: 'Yldrm2015'
            };
            
            this.validationState.violations.push(violation);
            console.error(`Security violation: ${level} security path accessed: ${path}`);
        }
        
        logSecurityEvent(level, path) {
            const event = {
                type: 'path_access',
                level: level,
                path: path,
                timestamp: '2025-03-19 07:27:23',
                user: 'Yldrm2015'
            };
            
            this.validationState.warnings.push(event);
            console.error(`Security violation: ${level} security path accessed: ${path}`);
    
            // Audit log ekleme
            this.auditLog({
                type: 'security_violation',
                level: level,
                path: path
            });
        }

        detectBot() {
            const checks = {
                userAgent: this.checkUserAgent(),
                behavior: this.checkBehaviorPatterns(),
                fingerprint: this.checkBrowserFingerprint()
            };
        
            const isSuspicious = Object.values(checks).some(result => result === true);
        
            if (isSuspicious) {
                this.handleBotDetection(checks);
                return true;
            }
            return false;
        }

        checkRateLimit(path) {
            const timestamp = '2025-03-19 08:23:53';
            const currentTime = new Date(timestamp).getTime();
            const clientIP = this.getClientIP();
        
            // Önce global limit kontrolü
            if (this.isRateLimited(clientIP, 'global', currentTime)) {
                return false;
            }
        
            // Endpoint özel limitleri kontrol et
            for (const [pattern, limits] of Object.entries(this.validationConfig.rateLimiting.endpoints)) {
                if (new RegExp(pattern).test(path)) {
                    if (this.isRateLimited(clientIP, pattern, currentTime, limits)) {
                        return false;
                    }
                }
            }
        
            return true;
        }
        
        isRateLimited(clientIP, endpoint, currentTime, limits = null) {
            const store = this.validationConfig.rateLimiting.store;
            const config = limits || this.validationConfig.rateLimiting.global;
            const key = `${clientIP}:${endpoint}`;
        
            // Blok kontrolü
            if (store.blocked.has(key)) {
                const blockExpire = store.blocked.get(key);
                if (currentTime < blockExpire) {
                    this.logRateLimitViolation(clientIP, endpoint, 'blocked');
                    return true;
                }
                store.blocked.delete(key);
            }
        
            // İstek geçmişini kontrol et
            if (!store.requests.has(key)) {
                store.requests.set(key, []);
            }
        
            const requests = store.requests.get(key);
            const windowStart = currentTime - config.windowMs;
        
            // Eski istekleri temizle
            while (requests.length > 0 && requests[0] < windowStart) {
                requests.shift();
            }
        
            // Yeni isteği ekle ve limit kontrolü yap
            requests.push(currentTime);
            
            if (requests.length > config.maxRequests) {
                // Limiti aştı, blokla
                store.blocked.set(key, currentTime + config.blockDuration);
                this.logRateLimitViolation(clientIP, endpoint, 'exceeded');
                return true;
            }
        
            return false;
        }
        
        logRateLimitViolation(clientIP, endpoint, type) {
            const violation = {
                type: 'rate_limit',
                timestamp: '2025-03-19 08:23:53',
                user: 'Yldrm2015',
                clientIP: clientIP,
                endpoint: endpoint,
                violationType: type
            };
            
            this.validationState.violations.push(violation);
            console.error(`Rate limit ${type} for ${clientIP} on ${endpoint}`);

             // Audit log ekleme
            this.auditLog({
                type: 'rate_limit',
                clientIP: clientIP,
                endpoint: endpoint,
                violationType: type
            });
        }
        
        getClientIP() {
            // Gerçek uygulamada IP adresi alınacak
            return '127.0.0.1';
        }
        
        generateLogId() {
            return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

        getLogLevel(eventType) {
            for (const [level, events] of Object.entries(this.validationConfig.auditLogging.levels)) {
                if (events.includes(eventType)) {
                    return level;
                }
            }
            return 'low';
        }
        
        storeLogEntry(logEntry) {
            if (!this.validationState.auditLogs) {
                this.validationState.auditLogs = [];
            }
        
            this.validationState.auditLogs.push(logEntry);
        
            // Maksimum log sayısı kontrolü
            if (this.validationState.auditLogs.length > this.validationConfig.auditLogging.storage.maxSize) {
                this.validationState.auditLogs.shift(); // En eski logu sil
            }
        }

        auditLog(event) {
            const timestamp = '2025-03-19 09:44:48';
            const logEntry = {
                id: this.generateLogId(),
                timestamp: timestamp,
                user: 'Yldrm2015',
                type: event.type,
                level: this.getLogLevel(event.type),
                details: {
                    ...event,
                    clientIP: this.getClientIP(),
                    userAgent: navigator.userAgent
                },
                metadata: {
                    path: window.location.pathname,
                    referrer: document.referrer
                }
            };
        
            this.storeLogEntry(logEntry);
            this.checkLogRotation();
            
            if (this.isHighSeverity(event.type)) {
                console.error(`High severity audit event: ${event.type}`, logEntry);
            }
        }

        validateInput(input, type, options = {}) {
            const timestamp = '2025-03-19 10:30:54';
            const rules = { ...this.validationConfig.inputValidation.rules[type], ...options };
            const validationResult = {
                isValid: true,
                sanitizedValue: input,
                errors: []
            };
        
            try {
                // Null/undefined kontrolü
                if (input === null || input === undefined) {
                    throw new Error('Input cannot be null or undefined');
                }
        
                // String dönüşümü
                let value = String(input);
        
                // Uzunluk kontrolleri
                if (rules.maxLength && value.length > rules.maxLength) {
                    validationResult.errors.push(`Input exceeds maximum length of ${rules.maxLength}`);
                }
                if (rules.minLength && value.length < rules.minLength) {
                    validationResult.errors.push(`Input is shorter than minimum length of ${rules.minLength}`);
                }
        
                // Pattern kontrolü
                if (rules.pattern && !rules.pattern.test(value)) {
                    validationResult.errors.push(`Input format is invalid for type: ${type}`);
                }
        
                // Özel kurallar kontrolü
                if (type === 'password') {
                    if (rules.requireSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(value)) {
                        validationResult.errors.push('Password must contain special characters');
                    }
                    if (rules.requireNumbers && !/\d/.test(value)) {
                        validationResult.errors.push('Password must contain numbers');
                    }
                    if (rules.requireUppercase && !/[A-Z]/.test(value)) {
                        validationResult.errors.push('Password must contain uppercase letters');
                    }
                }
        
                // Sanitizasyon
                if (rules.sanitize) {
                    validationResult.sanitizedValue = this.sanitizeInput(value);
                }
        
                validationResult.isValid = validationResult.errors.length === 0;
        
                // Log validation attempt
                this.auditLog({
                    type: 'input_validation',
                    inputType: type,
                    isValid: validationResult.isValid,
                    errors: validationResult.errors
                });
        
            } catch (error) {
                validationResult.isValid = false;
                validationResult.errors.push(error.message);
            }
        
            return validationResult;
        }
        
        sanitizeInput(value) {
            const config = this.validationConfig.inputValidation.sanitization;
            let sanitized = value;
        
            if (config.stripTags) {
                sanitized = sanitized.replace(/<[^>]*>/g, '');
            }
        
            if (config.escapeHTML) {
                sanitized = this.escapeHTML(sanitized);
            }
        
            if (config.enableXSSProtection) {
                sanitized = this.preventXSS(sanitized);
            }
        
            if (config.enableSQLInjectionProtection) {
                sanitized = this.preventSQLInjection(sanitized);
            }
        
            return sanitized;
        }
        
        escapeHTML(str) {
            return str
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }
        
        preventXSS(input) {
            // XSS özel karakterleri temizle
            return input
                .replace(/javascript:/gi, '')
                .replace(/on\w+=/gi, '')
                .replace(/data:/gi, '');
        }
        
        preventSQLInjection(input) {
            // SQL Injection karakterlerini temizle
            return input
                .replace(/'/g, "''")
                .replace(/--/g, '')
                .replace(/;/g, '');
        }
        
        checkLogRotation() {
            const currentTime = new Date('2025-03-19 09:44:48').getTime();
            
            if (!this.validationState.lastRotation) {
                this.validationState.lastRotation = currentTime;
                return;
            }
        
            if (currentTime - this.validationState.lastRotation >= this.validationConfig.auditLogging.storage.rotationInterval) {
                this.rotateAuditLogs();
                this.validationState.lastRotation = currentTime;
            }
        }
        
        rotateAuditLogs() {
            const currentTime = new Date('2025-03-19 09:44:48').getTime();
            
            // Retention süresi dolmuş logları temizle
            this.validationState.auditLogs = this.validationState.auditLogs.filter(log => {
                const logTime = new Date(log.timestamp).getTime();
                const retention = this.validationConfig.auditLogging.retention[log.level];
                return currentTime - logTime < retention;
            });
        
            // Arşivleme işlemi burada yapılabilir
            console.log(`Log rotation completed at ${currentTime}`);
        }
        
        isHighSeverity(eventType) {
            return this.validationConfig.auditLogging.levels.high.includes(eventType);
        }
        
        checkUserAgent() {
            const userAgent = navigator.userAgent;
            return this.validationConfig.botDetection.patterns.userAgent.some(pattern => 
                pattern.test(userAgent)
            );
        }
        
        checkBehaviorPatterns() {
            const config = this.validationConfig.botDetection.patterns.behavior;
            
            // Son bir dakika içindeki istek sayısını kontrol et
            if (this.requestCount > config.maxRequestsPerMinute) {
                return true;
            }
        
            // Mouse hareketleri ve tıklama zamanlarını kontrol et
            if (this.lastClickTime && 
                Date.now() - this.lastClickTime < config.minTimeBeforeClicks) {
                return true;
            }
        
            return false;
        }
        
        checkBrowserFingerprint() {
            const required = this.validationConfig.botDetection.patterns.fingerprint.required;
            
            // Canvas fingerprint kontrolü
            if (required.includes('canvas') && !this.hasValidCanvas()) {
                return true;
            }
        
            // WebGL fingerprint kontrolü
            if (required.includes('webgl') && !this.hasValidWebGL()) {
                return true;
            }
        
            // WebDriver kontrolü
            if (this.validationConfig.botDetection.patterns.fingerprint.checkWebdriver && 
                navigator.webdriver) {
                return true;
            }
        
            return false;
        }

        hasValidCanvas() {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                
                // Test çizimi
                ctx.textBaseline = "alphabetic";
                ctx.fillStyle = "#FF0000";
                ctx.fillRect(125, 1, 62, 20);  // Burada virgüller arasında boşluk ekledim
                
                return canvas.toDataURL().length > 0;  // Noktalı virgül eklendi
            } catch (error) {
                return false;
            }
        }
        
        hasValidWebGL() {
            try {
                const canvas = document.createElement('canvas');
                return !!(canvas.getContext('webgl') || canvas.getContext('experimental-webgl'));  // Noktalı virgül eklendi
            } catch (error) {
                return false;
            }
        }
        
        handleBotDetection(checks) {
            const botEvent = {
                type: 'bot_detection',
                timestamp: '2025-03-19 07:45:33',
                user: 'Yldrm2015',
                checks: checks,
                userAgent: navigator.userAgent
            };
        
            this.validationState.violations.push(botEvent);
        
            if (this.validationConfig.botDetection.action.block) {
                this.blockRequest();
            }

             // Audit log ekleme
            this.auditLog({
                type: 'bot_detection',
                checks: checks
            });
        }
        
        // Utility methods
        updateValidationState(type, result) {
            this.validationState.headers.set(type, result);
            this.validationState.lastCheck = this.timestamp;
        }

        updateMetrics(type, duration) {
            this.metrics.checks++;
            this.metrics.responseTime.push({
                type,
                duration,
                timestamp: this.timestamp
            });

            // Sadece son 100 ölçümü tut
            if (this.metrics.responseTime.length > 100) {
                this.metrics.responseTime.shift();
            }
        }

        // Error handlers
        handleInitializationError(error) {
            console.error(`[${this.timestamp}] Security initialization failed:`, error);
            this.validationState.error = {
                type: 'initialization',
                message: error.message,
                timestamp: this.timestamp
            };
        }

        handleValidationError(type, error) {
            console.error(`[${this.timestamp}] Validation error (${type}):`, error);
            this.validationState.violations.push({
                type,
                error: error.message,
                timestamp: this.timestamp
            });
        }

        handleCSPViolation(violation) {
            this.metrics.violations++;
            this.metrics.lastViolation = violation;
            this.validationState.violations.push(violation);
        }

        // Public API
        getValidationState() {
            return {
                ...this.validationState,
                metrics: this.metrics,
                timestamp: this.timestamp
            };
        }

        getMetrics() {
            return {
                ...this.metrics,
                timestamp: this.timestamp
            };
        }

        calculateBotScore(results) {
            let score = 0;
            const weights = {
                userAgent: 0.3,
                behavior: 0.4,
                fingerprint: 0.3
            };
        
            if (results.userAgent) score += weights.userAgent;
            if (results.behavior) score += weights.behavior;
            if (results.fingerprint) score += weights.fingerprint;
        
            return score;
        }

        // API Configuration and Methods
        apiConfig = {
            endpoint: 'http://localhost:3000/api', // Backend API endpoint
            headers: {
                'Content-Type': 'application/json'
            }
        };

        // Backend API Methods
        async sendToBackend(validationResults) {
            try {
                const response = await fetch(`${this.apiConfig.endpoint}/validate`, {
                    method: 'POST',
                    headers: this.apiConfig.headers,
                    body: JSON.stringify({
                        timestamp: this.timestamp,
                        user: this.userLogin,
                        results: validationResults,
                        metrics: this.metrics,
                        violations: this.validationState.violations
                    })
                });

                if (!response.ok) {
                    throw new Error(`API Error: ${response.status}`);
                }

                const data = await response.json();
                this.handleApiResponse(data);
                return data;

            } catch (error) {
                this.handleApiError(error);
                return null;
            }
        }

        handleApiResponse(data) {
            const logEntry = {
                type: 'api_response',
                timestamp: this.timestamp,
                data: data
            };
            
            this.auditLog(logEntry);
            
            // Update validation state with server response
            if (data.blockedIPs) {
                this.updateBlockedIPs(data.blockedIPs);
            }
            
            if (data.securityUpdates) {
                this.applySecurityUpdates(data.securityUpdates);
            }
        }

        handleApiError(error) {
            const logEntry = {
                type: 'api_error',
                timestamp: this.timestamp,
                error: error.message
            };
            
            this.auditLog(logEntry);
            console.error('API Error:', error);
        }

        updateBlockedIPs(blockedIPs) {
            // Update local blocklist with server data
            this.validationConfig.protection.ipBlacklist = new Set([
                ...this.validationConfig.protection.ipBlacklist,
                ...blockedIPs
            ]);
        }

        applySecurityUpdates(updates) {
            // Apply security configuration updates from server
            if (updates.rateLimit) {
                Object.assign(this.validationConfig.rateLimiting, updates.rateLimit);
            }
            
            if (updates.protection) {
                Object.assign(this.validationConfig.protection, updates.protection);
            }
            
            // Log configuration update
            this.auditLog({
                type: 'config_update',
                timestamp: this.timestamp,
                updates: updates
            });
        }

        // API Health Check
        async checkApiHealth() {
            try {
                const response = await fetch(`${this.apiConfig.endpoint}/health`);
                return response.ok;
            } catch (error) {
                this.handleApiError(error);
                return false;
            }
        }

            }

            // Global scope'a ekle
            window.SecurityValidator = SecurityValidator;

        })(window);

    (function(window) {
    'use strict';

    if (!window.SecurityValidator) {
        window.SecurityValidator = {};
    }

    class TokenAuthValidator {
    
        constructor(validator) {
            this.timestamp = this.getCurrentTimestamp();
            this.validator = validator;
            
            this.authConfig = {
                tokens: {
                    jwt: {
                        algorithms: ['RS256', 'ES256'],
                        maxAge: 3600,
                        requiredClaims: ['sub', 'iat', 'exp', 'jti'],
                        issuer: 'https://auth.example.com',
                        audience: 'https://api.example.com'
                    },
                    session: {
                        length: 32,
                        entropy: 256,
                        maxAge: 86400
                    }
                },
                access: {
                    roles: ['user', 'admin', 'moderator'],
                    permissions: ['read', 'write', 'delete'],
                    rbac: {
                        enabled: true,
                        matrix: {
                            user: ['read'],
                            moderator: ['read', 'write'],
                            admin: ['read', 'write', 'delete']
                        }
                    }
                },
                storage: {
                    type: 'sessionStorage',
                    prefix: 'auth_',
                    encrypt: true
                }
            };

            // Cache ve state yönetimi
            this.tokenCache = new Map();
            this.validationState = {
                initialized: false,
                lastCheck: this.timestamp,
                tokens: new Map(),
                sessions: new Map(),
                violations: []
            };

            // Crypto utils
            this.crypto = window.crypto.subtle;
            
            this.initialize();
        }

        handleValidationError(type, error) {
            // Ana validator'ın hata yönetimini kullan
            return this.validator.handleValidationError(type, error, 'token_auth');
        }

        async initializeAuth() {
            try {
                // Storage başlat
                await this.initializeStorage();
    
                // Token izleme başlat
                this.startTokenMonitoring();
    
                // Oturum izleme başlat
                this.startSessionMonitoring();
    
                // API sağlık kontrolü
                const apiStatus = await this.checkApiHealth();
                if (!apiStatus) {
                    console.warn(`[${this.timestamp}] API connection failed`);
                }
    
                this.validationState.initialized = true;
                console.log(`[${this.timestamp}] TokenAuthValidator initialized successfully`);
            } catch (error) {
                console.error(`[${this.timestamp}] Token/Auth initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        async initializeStorage() {
            const storage = this.authConfig.storage.type === 'localStorage' ? 
                          localStorage : sessionStorage;

            // Storage encryption key oluştur
            if (this.authConfig.storage.encrypt) {
                const key = await this.generateStorageKey();
                await this.setEncryptionKey(key);
            }

            // Mevcut tokenleri validate et
            for (let i = 0; i < storage.length; i++) {
                const key = storage.key(i);
                if (key.startsWith(this.authConfig.storage.prefix)) {
                    const token = await this.getStoredToken(key);
                    await this.validateStoredToken(token);
                }
            }
        }

        async generateStorageKey() {
            const key = await this.crypto.generateKey(
                {
                    name: 'AES-GCM',
                    length: 256
                },
                true,
                ['encrypt', 'decrypt']
            );

            return key;
        }

        startTokenMonitoring() {
            // Token expiration monitor
            setInterval(() => {
                this.checkTokenExpirations();
            }, 60000); // Her dakika kontrol

            // Token refresh monitor
            setInterval(() => {
                this.checkTokenRefreshes();
            }, 300000); // Her 5 dakika kontrol
        }

        startSessionMonitoring() {
            // Active session monitor
            setInterval(() => {
                this.checkActiveSessions();
            }, 30000); // Her 30 saniye kontrol

            // Session cleanup
            setInterval(() => {
                this.cleanupExpiredSessions();
            }, 3600000); // Her saat kontrol
        }

        async validateToken(token, type = 'jwt') {
            const startTime = performance.now();

            try {
                // Cache check
                const cached = this.tokenCache.get(token);
                if (cached && cached.expiresAt > Date.now()) {
                    return cached.validation;
                }

                let validation;
                if (type === 'jwt') {
                    validation = await this.validateJWT(token);
                } else {
                    validation = await this.validateSessionToken(token);
                }

                // Cache result
                this.cacheValidation(token, validation);

                // Metrics update
                this.updateMetrics('token_validation', performance.now() - startTime);

                return validation;

            } catch (error) {
                this.handleValidationError('token', error);
                return {
                    valid: false,
                    error: error.message,
                    timestamp: this.timestamp
                };
            }
        }

        async validateJWT(token) {
            // JWT parts
            const parts = token.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }

            const [headerB64, payloadB64, signature] = parts;

            // Header validation
            const header = this.decodeBase64JSON(headerB64);
            this.validateJWTHeader(header);

            // Payload validation
            const payload = this.decodeBase64JSON(payloadB64);
            this.validateJWTPayload(payload);

            // Signature validation
            await this.validateJWTSignature(token);

            return {
                valid: true,
                token: {
                    header,
                    payload,
                    signature
                },
                timestamp: this.timestamp
            };
        }

        validateJWTHeader(header) {
            // Algorithm check
            if (!header.alg || !this.authConfig.tokens.jwt.algorithms.includes(header.alg)) {
                throw new Error('Invalid or unsupported algorithm');
            }

            // Token type check
            if (header.typ !== 'JWT') {
                throw new Error('Invalid token type');
            }
        }

        validateJWTPayload(payload) {
            const now = Math.floor(Date.now() / 1000);

            // Required claims
            this.authConfig.tokens.jwt.requiredClaims.forEach(claim => {
                if (!(claim in payload)) {
                    throw new Error(`Missing required claim: ${claim}`);
                }
            });

            // Expiration
            if (payload.exp && payload.exp < now) {
                throw new Error('Token expired');
            }

            // Not before
            if (payload.nbf && payload.nbf > now) {
                throw new Error('Token not yet valid');
            }

            // Issuer
            if (payload.iss !== this.authConfig.tokens.jwt.issuer) {
                throw new Error('Invalid token issuer');
            }

            // Audience
            if (payload.aud !== this.authConfig.tokens.jwt.audience) {
                throw new Error('Invalid token audience');
            }

            // Maximum age check
            if (payload.iat && (now - payload.iat > this.authConfig.tokens.jwt.maxAge)) {
                throw new Error('Token too old');
            }
        }

        async validateJWTSignature(token) {
            try {
                const key = await this.getPublicKey();
                const isValid = await this.verifySignature(token, key);

                if (!isValid) {
                    throw new Error('Invalid token signature');
                }
            } catch (error) {
                throw new Error(`Signature validation failed: ${error.message}`);
            }
        }

        async validatePermissions(token, required) {
            const validation = await this.validateToken(token);
            if (!validation.valid) {
                return false;
            }

            const payload = validation.token.payload;
            const role = payload.role;

            if (!this.authConfig.access.roles.includes(role)) {
                return false;
            }

            const allowedPermissions = this.authConfig.access.rbac.matrix[role];
            return required.every(permission => allowedPermissions.includes(permission));
        }

        // Utility methods
        decodeBase64JSON(base64Url) {
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonStr = atob(base64);
            return JSON.parse(jsonStr);
        }

        async encryptData(data) {
            const key = await this.getEncryptionKey();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const encoded = encoder.encode(JSON.stringify(data));

            const encrypted = await this.crypto.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                encoded
            );

            return {
                encrypted: Array.from(new Uint8Array(encrypted)),
                iv: Array.from(iv)
            };
        }

        updateMetrics(type, duration) {
            this.validator.updateMetrics(type, duration);
        }

        // Error handlers
        handleValidationError(type, error) {
            this.validationState.violations.push({
                type,
                error: error.message,
                timestamp: this.timestamp
            });
        }

        // Public API
        getValidationState() {
            return {
                ...this.validationState,
                timestamp: this.timestamp
            };
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.TokenAuthValidator = TokenAuthValidator;

})(window);

(function(window) {
    'use strict';

    class ContentSecurityValidator {
      

        constructor(validator) {
            this.timestamp = this.getCurrentTimestamp();
            this.validator = validator;

            this.contentConfig = {
                sanitization: {
                    html: {
                        allowedTags: [
                            'a', 'b', 'br', 'code', 'div', 'em', 'i', 'li', 
                            'ol', 'p', 'pre', 'span', 'strong', 'ul'
                        ],
                        allowedAttributes: {
                            'a': ['href', 'title', 'target'],
                            'code': ['class'],
                            'div': ['class', 'id'],
                            'span': ['class']
                        },
                        allowedSchemes: ['http', 'https', 'mailto'],
                        maxLength: 50000
                    },
                    javascript: {
                        evalEnabled: false,
                        inlineScripts: false,
                        allowedAPIs: [
                            'fetch',
                            'localStorage',
                            'sessionStorage'
                        ],
                        blockedProperties: [
                            'eval',
                            'Function',
                            '__proto__',
                            'constructor'
                        ]
                    },
                    sql: {
                        enabled: true,
                        patterns: [
                            /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
                            /(\b(OR|AND)\b\s+\d+\s*[=<>])/i,
                            /('.*?'|\d+)\s*(=|<|>|LIKE)\s*('.*?'|\d+)/i
                        ]
                    }
                },
                validation: {
                    inputs: {
                        text: {
                            maxLength: 1000,
                            pattern: /^[\w\s.,!?-]+$/,
                            sanitize: true
                        },
                        email: {
                            pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                            maxLength: 254
                        },
                        url: {
                            pattern: /^https?:\/\/[\w\-.]+(:\d+)?([\/\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/,
                            maxLength: 2048
                        },
                        number: {
                            min: Number.MIN_SAFE_INTEGER,
                            max: Number.MAX_SAFE_INTEGER,
                            decimals: 2
                        }
                    },
                    files: {
                        maxSize: 10 * 1024 * 1024, // 10MB
                        allowedTypes: [
                            'image/jpeg',
                            'image/png',
                            'image/gif',
                            'application/pdf',
                            'text/plain'
                        ],
                        scanContent: true
                    }
                }
            };

            this.validationState = {
                initialized: false,
                lastCheck: this.timestamp,
                violations: [],
                sanitizedElements: new WeakMap(),
                activeScans: new Set()
            };

            // Content scanning için Web Worker
            this.scannerWorker = null;
            
            this.initialize();
        }

        handleValidationError(type, error) {
            // Ana validator'ın hata yönetimini kullan
            return this.validator.handleValidationError(type, error, 'content_security');
        }

        async initializeContent() {
            try {
                // Content scanner worker başlat
                if (window.Worker) {
                    this.initializeScanner();
                }
    
                // DOM mutation observer başlat
                this.initializeDOMObserver();
    
                // Input event listeners
                this.setupInputValidation();
    
                // File upload handlers
                this.setupFileValidation();
    
                this.validationState.initialized = true;
                console.log(`[${this.timestamp}] ContentSecurityValidator initialized`);
            } catch (error) {
                console.error(`[${this.timestamp}] Content security initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        initializeScanner() {
            try {
                this.scannerWorker = new Worker('contentScanner.worker.js');
                
                this.scannerWorker.onmessage = (e) => {
                    this.handleScannerResult(e.data);
                };

                this.scannerWorker.onerror = (e) => {
                    console.error('Scanner worker error:', e);
                };

            } catch (error) {
                console.error('Scanner worker initialization failed:', error);
            }
        }

        initializeDOMObserver() {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach(mutation => {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(node => {
                            if (node.nodeType === 1) { // ELEMENT_NODE
                                this.validateElement(node);
                            }
                        });
                    } else if (mutation.type === 'attributes') {
                        this.validateElementAttribute(mutation.target, mutation.attributeName);
                    }
                });
            });

            observer.observe(document.documentElement, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ['src', 'href', 'style']
            });
        }

        setupInputValidation() {
            document.addEventListener('input', (e) => {
                if (e.target.tagName === 'INPUT' || 
                    e.target.tagName === 'TEXTAREA') {
                    this.validateInput(e.target);
                }
            }, true);

            document.addEventListener('change', (e) => {
                if (e.target.type === 'file') {
                    this.validateFileUpload(e.target.files);
                }
            }, true);
        }

        async validateElement(element) {
            const startTime = performance.now();

            try {
                // HTML içerik kontrolü
                if (element.innerHTML) {
                    const sanitizedHTML = await this.sanitizeHTML(element.innerHTML);
                    if (sanitizedHTML !== element.innerHTML) {
                        this.handleSanitization(element, 'html');
                        element.innerHTML = sanitizedHTML;
                    }
                }

                // Script kontrolü
                if (element.tagName === 'SCRIPT') {
                    await this.validateScript(element);
                }

                // Style kontrolü
                if (element.hasAttribute('style')) {
                    const sanitizedStyle = this.sanitizeStyle(element.getAttribute('style'));
                    if (sanitizedStyle !== element.getAttribute('style')) {
                        this.handleSanitization(element, 'style');
                        element.setAttribute('style', sanitizedStyle);
                    }
                }

                // URL attribute kontrolü
                ['src', 'href', 'action'].forEach(attr => {
                    if (element.hasAttribute(attr)) {
                        this.validateURL(element.getAttribute(attr));
                    }
                });

                this.updateMetrics('element_validation', performance.now() - startTime);

            } catch (error) {
                this.handleValidationError('element', error);
            }
        }

        async validateInput(input) {
            const type = input.type || 'text';
            const value = input.value;
            const config = this.contentConfig.validation.inputs[type];

            if (!config) return;

            try {
                // Length check
                if (value.length > config.maxLength) {
                    throw new Error(`Input exceeds maximum length of ${config.maxLength}`);
                }

                // Pattern check
                if (config.pattern && !config.pattern.test(value)) {
                    throw new Error('Input format is invalid');
                }

                // Type specific validation
                switch (type) {
                    case 'email':
                        this.validateEmail(value);
                        break;
                    case 'url':
                        this.validateURL(value);
                        break;
                    case 'number':
                        this.validateNumber(value);
                        break;
                }

                // SQL injection check
                if (this.contentConfig.sanitization.sql.enabled) {
                    this.checkSQLInjection(value);
                }

                // Content scan if needed
                if (config.sanitize) {
                    input.value = await this.sanitizeContent(value);
                }

            } catch (error) {
                this.handleInputError(input, error);
            }
        }

        async validateFileUpload(files) {
            const config = this.contentConfig.validation.files;

            for (let file of files) {
                try {
                    // Size check
                    if (file.size > config.maxSize) {
                        throw new Error(`File size exceeds maximum of ${config.maxSize} bytes`);
                    }

                    // Type check
                    if (!config.allowedTypes.includes(file.type)) {
                        throw new Error(`File type ${file.type} is not allowed`);
                    }

                    // Content scan
                    if (config.scanContent) {
                        await this.scanFileContent(file);
                    }

                } catch (error) {
                    this.handleFileError(file, error);
                }
            }
        }

        async scanFileContent(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                
                reader.onload = (e) => {
                    const content = e.target.result;
                    this.scannerWorker.postMessage({
                        type: 'scan',
                        content: content,
                        filename: file.name
                    });

                    this.validationState.activeScans.add(file.name);
                };

                reader.onerror = () => reject(new Error('File read failed'));
                reader.readAsArrayBuffer(file);
            });
        }

        async sanitizeContent(content) {
            // HTML sanitization
            content = await this.sanitizeHTML(content);

            // JavaScript sanitization
            content = this.sanitizeJavaScript(content);

            // SQL injection prevention
            content = this.sanitizeSQL(content);

            return content;
        }

        handleScannerResult(result) {
            const { filename, threats } = result;
            this.validationState.activeScans.delete(filename);

            if (threats.length > 0) {
                this.handleThreatDetection(filename, threats);
            }
        }

        // Error handlers
        handleValidationError(type, error) {
            this.validationState.violations.push({
                type,
                error: error.message,
                timestamp: this.timestamp
            });
        }

        handleInputError(input, error) {
            input.setCustomValidity(error.message);
            input.reportValidity();
        }

        handleFileError(file, error) {
            this.validationState.violations.push({
                type: 'file',
                filename: file.name,
                error: error.message,
                timestamp: this.timestamp
            });
        }

        // Public API
        getValidationState() {
            return {
                ...this.validationState,
                timestamp: this.timestamp
            };
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.ContentSecurityValidator = ContentSecurityValidator;

})(window);

(function(window) {
    'use strict';

    class RealTimeSecurityValidator {
      
        constructor(validator) {
            this.timestamp = this.getCurrentTimestamp();
            this.validator = validator;
            
            this.realtimeConfig = {
                rateLimit: {
                    global: {
                        windowMs: 60000,
                        maxRequests: 100,
                        blockDuration: 300000
                    },
                    endpoints: {
                        '/api/auth': {
                            windowMs: 300000,
                            maxRequests: 5
                        },
                        '/api/upload': {
                            windowMs: 3600000,
                            maxRequests: 10,
                            maxSize: 50 * 1024 * 1024 // 50MB
                        }
                    },
                    ip: {
                        windowMs: 60000,
                        maxRequests: 30
                    }
                },
                monitoring: {
                    enabled: true,
                    interval: 1000,
                    metrics: ['cpu', 'memory', 'network'],
                    thresholds: {
                        cpu: 80,
                        memory: 90,
                        requests: 1000
                    }
                },
                protection: {
                    autoBlock: true,
                    blockThreshold: 5,
                    suspiciousPatterns: [
                        /eval\(.+\)/,
                        /(union|select|insert|update|delete)\s+.*?(?:from|into|where)/i,
                        /document\.cookie/i,
                        /\<script\>|\<\/script\>/i
                    ],
                    ipBlacklist: new Set(),
                    userBlacklist: new Set()
                },
                realtime: {
                    websocket: {
                        enabled: true,
                        reconnectInterval: 5000,
                        maxRetries: 3
                    },
                    sync: {
                        interval: 10000,
                        batchSize: 50
                    }
                }
            };

            this.state = {
                initialized: false,
                wsConnected: false,
                lastSync: this.timestamp,
                requestCounts: new Map(),
                blockList: new Set(),
                warnings: [],
                incidents: []
            };

            // Performance metrics
            this.metrics = {
                requests: [],
                blocked: [],
                warnings: [],
                performance: []
            };

            this.initialize();
        }

        handleValidationError(type, error) {
            // Ana validator'ın hata yönetimini kullan
            return this.validator.handleValidationError(type, error, 'realtime_security');
        }

        initializeRateLimiter() {
            // Global rate limiter
            this.globalLimiter = new RateLimiter(
                this.realtimeConfig.rateLimit.global
            );

            // Endpoint specific limiters
            this.endpointLimiters = new Map();
            Object.entries(this.realtimeConfig.rateLimit.endpoints).forEach(([endpoint, config]) => {
                this.endpointLimiters.set(endpoint, new RateLimiter(config));
            });

            // IP based limiter
            this.ipLimiter = new RateLimiter(
                this.realtimeConfig.rateLimit.ip
            );

            // Request interceptor
            this.setupRequestInterceptor();
        }

        setupRequestInterceptor() {
            const originalFetch = window.fetch;
            window.fetch = async (input, init) => {
                const url = input instanceof Request ? input.url : input;
                
                try {
                    // Rate limit kontrolü
                    await this.checkRateLimit(url);

                    // Request validation
                    await this.validateRequest(url, init);

                    const response = await originalFetch(input, init);
                    
                    // Response validation
                    await this.validateResponse(response);

                    return response;

                } catch (error) {
                    this.handleRequestError(url, error);
                    throw error;
                }
            };
        }

        async checkRateLimit(url) {
            // Global limit check
            if (!await this.globalLimiter.checkLimit()) {
                throw new Error('Global rate limit exceeded');
            }

            // Endpoint specific check
            const endpoint = this.getEndpoint(url);
            const endpointLimiter = this.endpointLimiters.get(endpoint);
            if (endpointLimiter && !await endpointLimiter.checkLimit()) {
                throw new Error(`Rate limit exceeded for ${endpoint}`);
            }

            // IP based check
            const clientIP = await this.getClientIP();
            if (!await this.ipLimiter.checkLimit(clientIP)) {
                throw new Error('IP-based rate limit exceeded');
            }
        }

        async initializeMonitoring() {
            if (!this.realtimeConfig.monitoring.enabled) return;

            // Performance monitoring
            if (window.performance) {
                this.startPerformanceMonitoring();
            }

            // Resource monitoring
            if (window.navigator.hardwareConcurrency) {
                this.startResourceMonitoring();
            }

            // Network monitoring
            this.startNetworkMonitoring();
        }

        startPerformanceMonitoring() {
            const observer = new PerformanceObserver((list) => {
                list.getEntries().forEach(entry => {
                    this.processPerformanceEntry(entry);
                });
            });

            observer.observe({
                entryTypes: ['resource', 'navigation', 'longtask']
            });
        }

        startResourceMonitoring() {
            setInterval(() => {
                this.checkResourceUsage();
            }, this.realtimeConfig.monitoring.interval);
        }

        async checkResourceUsage() {
            try {
                const usage = await this.getResourceUsage();
                this.analyzeResourceMetrics(usage);
            } catch (error) {
                console.error('Resource monitoring error:', error);
            }
        }

        async getResourceUsage() {
            return {
                cpu: await this.getCPUUsage(),
                memory: await this.getMemoryUsage(),
                network: await this.getNetworkMetrics()
            };
        }

        async initializeWebSocket() {
            try {
                this.ws = new WebSocket('wss://security-sync.example.com');
                
                this.ws.onopen = () => {
                    this.state.wsConnected = true;
                    this.startRealtimeSync();
                };

                this.ws.onmessage = (event) => {
                    this.handleWebSocketMessage(event.data);
                };

                this.ws.onclose = () => {
                    this.state.wsConnected = false;
                    this.handleWebSocketClose();
                };

                this.ws.onerror = (error) => {
                    this.handleWebSocketError(error);
                };

            } catch (error) {
                console.error('WebSocket initialization failed:', error);
            }
        }

        startRealtimeSync() {
            setInterval(() => {
                this.syncSecurityState();
            }, this.realtimeConfig.realtime.sync.interval);
        }

        async syncSecurityState() {
            if (!this.state.wsConnected) return;

            const state = {
                timestamp: this.timestamp,
                metrics: this.getMetricsSummary(),
                incidents: this.getRecentIncidents(),
                blockList: Array.from(this.state.blockList)
            };

            this.ws.send(JSON.stringify(state));
        }

        initializeProtection() {
            // Suspicious pattern detection
            this.setupPatternDetection();

            // Auto-blocking system
            if (this.realtimeConfig.protection.autoBlock) {
                this.setupAutoBlocking();
            }

            // Real-time threat monitoring
            this.startThreatMonitoring();
        }

        setupPatternDetection() {
            const patterns = this.realtimeConfig.protection.suspiciousPatterns;
            
            // URL monitoring
            window.addEventListener('hashchange', () => {
                this.checkUrlPatterns(window.location.href);
            });

            // Input monitoring
            document.addEventListener('input', (e) => {
                if (e.target.tagName === 'INPUT' || 
                    e.target.tagName === 'TEXTAREA') {
                    this.checkInputPatterns(e.target.value);
                }
            }, true);
        }

        setupAutoBlocking() {
            setInterval(() => {
                this.analyzeBlockingCriteria();
            }, 60000); // Her dakika kontrol
        }

        analyzeBlockingCriteria() {
            for (const [ip, count] of this.state.requestCounts) {
                if (count >= this.realtimeConfig.protection.blockThreshold) {
                    this.blockIP(ip);
                }
            }
        }

        blockIP(ip) {
            this.state.blockList.add(ip);
            this.notifyBlockage(ip);
            
            // Sync with server
            if (this.state.wsConnected) {
                this.ws.send(JSON.stringify({
                    type: 'block',
                    ip: ip,
                    timestamp: this.timestamp
                }));
            }
        }

        // Utility methods
        getMetricsSummary() {
            return {
                requests: this.summarizeMetrics(this.metrics.requests),
                blocked: this.summarizeMetrics(this.metrics.blocked),
                warnings: this.metrics.warnings.length,
                performance: this.calculatePerformanceScore()
            };
        }

        summarizeMetrics(metrics) {
            return {
                count: metrics.length,
                recent: metrics.slice(-10)
            };
        }

        // Error handlers
        handleRequestError(url, error) {
            console.error(`Request error for ${url}:`, error);
            this.state.incidents.push({
                type: 'request_error',
                url: url,
                error: error.message,
                timestamp: this.timestamp
            });
        }

        // Public API
        getState() {
            return {
                ...this.state,
                metrics: this.getMetricsSummary(),
                timestamp: this.timestamp
            };
        }

        calculateBotScore(results) {
            let score = 0;
            const weights = {
                userAgent: 0.3,
                behavior: 0.4,
                fingerprint: 0.3
            };
        
            if (results.userAgent) score += weights.userAgent;
            if (results.behavior) score += weights.behavior;
            if (results.fingerprint) score += weights.fingerprint;
        
            return score;
        }
    }

    // Rate Limiter utility class
    class RateLimiter {
        constructor(config) {
            this.config = config;
            this.requests = new Map();
        }

        async checkLimit(key = 'global') {
            const now = Date.now();
            const windowStart = now - this.config.windowMs;
            
            // Clean old requests
            this.cleanup(windowStart);

            // Get request count
            const requests = this.requests.get(key) || [];
            if (requests.length >= this.config.maxRequests) {
                return false;
            }

            // Add new request
            requests.push(now);
            this.requests.set(key, requests);

            return true;
        }

        cleanup(windowStart) {
            for (const [key, requests] of this.requests) {
                const valid = requests.filter(time => time > windowStart);
                if (valid.length === 0) {
                    this.requests.delete(key);
                } else {
                    this.requests.set(key, valid);
                }
            }
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.RealTimeSecurityValidator = RealTimeSecurityValidator;

})(window);
