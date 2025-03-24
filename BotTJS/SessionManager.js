(function(window) {
    'use strict';

    class AdvancedSecurityValidator {
        timestamp = '2025-03-17 11:53:15';
        userLogin = 'Yldrm2015';

        constructor(validator) {
            this.validator = validator;

            this.advancedConfig = {
                protection: {
                    ml: {
                        enabled: true,
                        models: {
                            anomalyDetection: true,
                            threatPrediction: true,
                            behaviorAnalysis: true
                        },
                        threshold: 0.85,
                        trainingInterval: 86400000 // 24 hours
                    },
                    patterns: {
                        enabled: true,
                        rules: {
                            xss: [
                                /<script\b[^>]*>(.*?)<\/script>/gi,
                                /javascript:[^\s]*/gi,
                                /on\w+\s*=\s*"[^"]*"/gi
                            ],
                            sqlInjection: [
                                /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
                                /('|\s+)(\b(OR|AND)\b)(\s+|\d+|'|\"|=|<|>)/i,
                                /'\s*or\s*'1'\s*=\s*'1/i
                            ],
                            pathTraversal: [
                                /\.\.[\/\\]/g,
                                /\.\.%2f/gi,
                                /%252e%252e%252f/gi
                            ],
                            commandInjection: [
                                /\b(exec|eval|system|call|pass|include)\b/i,
                                /\${\s*[^\s}]+\s*}/g,
                                /`[^`]*`/g
                            ]
                        },
                        customRules: new Map()
                    },
                    encryption: {
                        algorithms: {
                            symmetric: 'AES-256-GCM',
                            asymmetric: 'RSA-OAEP',
                            hash: 'SHA-512'
                        },
                        keyRotation: {
                            enabled: true,
                            interval: 43200000 // 12 hours
                        },
                        storage: {
                            type: 'secureStorage',
                            prefix: 'security_key_'
                        }
                    },
                    mitigation: {
                        enabled: true,
                        actions: {
                            block: true,
                            redirect: '/security-error',
                            report: true,
                            notify: true
                        },
                        thresholds: {
                            low: 0.3,
                            medium: 0.6,
                            high: 0.8,
                            critical: 0.95
                        }
                    }
                },
                analysis: {
                    behavioral: {
                        enabled: true,
                        features: [
                            'mouseMovement',
                            'keyboardDynamics',
                            'touchGestures',
                            'deviceOrientation'
                        ],
                        profileLength: 1000,
                        updateInterval: 60000
                    },
                    context: {
                        enabled: true,
                        factors: [
                            'timePattern',
                            'locationPattern',
                            'deviceProfile',
                            'networkProfile'
                        ]
                    },
                    performance: {
                        enabled: true,
                        metrics: [
                            'responseTime',
                            'cpuUsage',
                            'memoryUsage',
                            'networkLatency'
                        ],
                        thresholds: {
                            responseTime: 2000,
                            cpuUsage: 80,
                            memoryUsage: 85,
                            networkLatency: 1000
                        }
                    }
                },
                realtime: {
                    monitoring: {
                        enabled: true,
                        interval: 1000,
                        metrics: [
                            'requests',
                            'errors',
                            'latency',
                            'bandwidth'
                        ]
                    },
                    protection: {
                        enabled: true,
                        features: {
                            ddosProtection: true,
                            bruteForceProtection: true,
                            scanningProtection: true
                        },
                        thresholds: {
                            requestsPerSecond: 100,
                            errorRate: 0.1,
                            bandwidthLimit: '10mb'
                        }
                    },
                    response: {
                        enabled: true,
                        autoScale: true,
                        loadBalancing: true,
                        failover: true
                    }
                }
            };

            this.state = {
                initialized: false,
                mlModels: new Map(),
                behavioralProfiles: new Map(),
                performanceMetrics: [],
                activeThreats: new Set(),
                mitigationActions: new Map()
            };

            this.initialize();
        }

        async initialize() {
            try {
                // ML modelleri yükle
                if (this.advancedConfig.protection.ml.enabled) {
                    await this.initializeMLModels();
                }

                // Pattern detection başlat
                if (this.advancedConfig.protection.patterns.enabled) {
                    this.initializePatternDetection();
                }

                // Behavioral analysis başlat
                if (this.advancedConfig.analysis.behavioral.enabled) {
                    this.initializeBehavioralAnalysis();
                }

                // Performance monitoring başlat
                if (this.advancedConfig.analysis.performance.enabled) {
                    this.initializePerformanceMonitoring();
                }

                // Real-time protection başlat
                if (this.advancedConfig.realtime.protection.enabled) {
                    this.initializeRealtimeProtection();
                }

                this.state.initialized = true;
                console.log(`[${this.timestamp}] AdvancedSecurityValidator initialized`);

            } catch (error) {
                console.error(`[${this.timestamp}] Advanced security initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        async initializeMLModels() {
            // Anomaly detection model
            if (this.advancedConfig.protection.ml.models.anomalyDetection) {
                const anomalyModel = await this.loadModel('anomaly');
                this.state.mlModels.set('anomaly', anomalyModel);
            }

            // Threat prediction model
            if (this.advancedConfig.protection.ml.models.threatPrediction) {
                const threatModel = await this.loadModel('threat');
                this.state.mlModels.set('threat', threatModel);
            }

            // Behavior analysis model
            if (this.advancedConfig.protection.ml.models.behaviorAnalysis) {
                const behaviorModel = await this.loadModel('behavior');
                this.state.mlModels.set('behavior', behaviorModel);
            }

            // Model training scheduler
            this.startModelTraining();
        }

        async loadModel(type) {
            // Model loading implementation
            // Production'da gerçek ML model loading kullanılmalı
            return {
                type,
                version: '1.0.0',
                predict: async (data) => {
                    return this.simulateModelPrediction(data);
                },
                train: async (data) => {
                    return this.simulateModelTraining(data);
                }
            };
        }

        simulateModelPrediction(data) {
            // Simulated ML prediction
            const score = Math.random();
            return {
                score,
                confidence: Math.random(),
                features: Object.keys(data)
            };
        }

        initializePatternDetection() {
            // DOM mutation observer
            const observer = new MutationObserver((mutations) => {
                mutations.forEach(mutation => {
                    if (mutation.type === 'childList') {
                        mutation.addedNodes.forEach(node => {
                            if (node.nodeType === 1) { // ELEMENT_NODE
                                this.scanElement(node);
                            }
                        });
                    }
                });
            });

            observer.observe(document.documentElement, {
                childList: true,
                subtree: true
            });

            // Network request interceptor
            this.setupNetworkInterceptor();
        }

        async scanElement(element) {
            const patterns = this.advancedConfig.protection.patterns.rules;
            const threats = [];

            // HTML content scan
            if (element.innerHTML) {
                Object.entries(patterns).forEach(([type, rules]) => {
                    rules.forEach(pattern => {
                        if (pattern.test(element.innerHTML)) {
                            threats.push({
                                type,
                                pattern: pattern.toString(),
                                element: element.tagName,
                                content: element.innerHTML.substring(0, 100)
                            });
                        }
                    });
                });
            }

            // Attribute scan
            Array.from(element.attributes).forEach(attr => {
                Object.entries(patterns).forEach(([type, rules]) => {
                    rules.forEach(pattern => {
                        if (pattern.test(attr.value)) {
                            threats.push({
                                type,
                                pattern: pattern.toString(),
                                attribute: attr.name,
                                value: attr.value
                            });
                        }
                    });
                });
            });

            if (threats.length > 0) {
                await this.handleThreats(threats);
            }
        }

        setupNetworkInterceptor() {
            const originalFetch = window.fetch;
            window.fetch = async (input, init) => {
                try {
                    // Request analysis
                    await this.analyzeRequest(input, init);

                    const response = await originalFetch(input, init);

                    // Response analysis
                    await this.analyzeResponse(response);

                    return response;

                } catch (error) {
                    this.handleRequestError(error, input);
                    throw error;
                }
            };
        }

        async analyzeRequest(input, init) {
            const url = input instanceof Request ? input.url : input;
            const method = init?.method || 'GET';
            const body = init?.body;

            // URL pattern check
            await this.checkUrlPatterns(url);

            // Method validation
            this.validateMethod(method);

            // Body content analysis
            if (body) {
                await this.analyzeRequestBody(body);
            }

            // Real-time threat assessment
            const threatScore = await this.assessThreatLevel({
                url,
                method,
                body,
                timestamp: this.timestamp
            });

            if (threatScore > this.advancedConfig.protection.ml.threshold) {
                throw new Error('High threat level detected');
            }
        }

        async checkUrlPatterns(url) {
            const patterns = this.advancedConfig.protection.patterns.rules;
            const threats = [];

            Object.entries(patterns).forEach(([type, rules]) => {
                rules.forEach(pattern => {
                    if (pattern.test(url)) {
                        threats.push({
                            type,
                            pattern: pattern.toString(),
                            url
                        });
                    }
                });
            });

            if (threats.length > 0) {
                await this.handleThreats(threats);
            }
        }

        async assessThreatLevel(data) {
            // ML model prediction
            const model = this.state.mlModels.get('threat');
            if (!model) return 0;

            const prediction = await model.predict(data);
            return prediction.score;
        }

        async handleThreats(threats) {
            // Add to active threats
            threats.forEach(threat => {
                this.state.activeThreats.add({
                    ...threat,
                    timestamp: this.timestamp,
                    id: `threat_${this.generateRandomString(8)}`
                });
            });

            // Determine severity
            const severity = this.calculateThreatSeverity(threats);

            // Apply mitigation
            if (this.advancedConfig.mitigation.enabled) {
                await this.applyMitigation(threats, severity);
            }

            // Notify
            this.notifyThreats(threats, severity);
        }

        calculateThreatSeverity(threats) {
            const scores = threats.map(threat => {
                switch (threat.type) {
                    case 'xss':
                    case 'sqlInjection':
                        return 0.9;
                    case 'commandInjection':
                        return 0.8;
                    case 'pathTraversal':
                        return 0.7;
                    default:
                        return 0.5;
                }
            });

            const maxScore = Math.max(...scores);
            const thresholds = this.advancedConfig.mitigation.thresholds;

            if (maxScore >= thresholds.critical) return 'critical';
            if (maxScore >= thresholds.high) return 'high';
            if (maxScore >= thresholds.medium) return 'medium';
            return 'low';
        }

        async applyMitigation(threats, severity) {
            const actions = this.advancedConfig.mitigation.actions;

            switch (severity) {
                case 'critical':
                    if (actions.block) {
                        this.blockExecution();
                    }
                    break;
                case 'high':
                    if (actions.redirect) {
                        this.redirectToSafePage();
                    }
                    break;
                case 'medium':
                    if (actions.report) {
                        await this.reportThreats(threats);
                    }
                    break;
                case 'low':
                    if (actions.notify) {
                        this.notifyThreats(threats, severity);
                    }
                    break;
            }
        }

        blockExecution() {
            // Execution blocking implementation
            throw new Error('Security violation: Execution blocked');
        }

        redirectToSafePage() {
            window.location.href = this.advancedConfig.mitigation.actions.redirect;
        }

        async reportThreats(threats) {
            // Report to security endpoint
            if (this.validator.logger) {
                threats.forEach(threat => {
                    this.validator.logger.log('error', 'security', 
                        'Security threat detected', threat);
                });
            }
        }

        notifyThreats(threats, severity) {
            if (window.SecurityLogger) {
                threats.forEach(threat => {
                    window.SecurityLogger.log(severity, 'security',
                        `Security threat detected: ${threat.type}`, threat);
                });
            }
        }

        // Public API
        getThreatStatus() {
            return {
                activeThreats: Array.from(this.state.activeThreats),
                mitigationActions: Array.from(this.state.mitigationActions),
                timestamp: this.timestamp
            };
        }

        getSecurityMetrics() {
            return {
                mlModels: Array.from(this.state.mlModels.keys()),
                behavioralProfiles: this.state.behavioralProfiles.size,
                performanceMetrics: this.state.performanceMetrics.slice(-100),
                timestamp: this.timestamp,
                status: {
                    initialized: this.state.initialized,
                    activeMitigations: this.state.mitigationActions.size,
                    activeThreats: this.state.activeThreats.size
                }
            };
        }

        async updateSecurityConfiguration(newConfig) {
            try {
                // Deep merge with existing config
                this.advancedConfig = this.mergeConfigs(this.advancedConfig, newConfig);

                // Reinitialize affected components
                if (newConfig.protection?.ml) {
                    await this.initializeMLModels();
                }

                if (newConfig.protection?.patterns) {
                    this.initializePatternDetection();
                }

                if (newConfig.analysis?.behavioral) {
                    this.initializeBehavioralAnalysis();
                }

                if (newConfig.realtime?.protection) {
                    this.initializeRealtimeProtection();
                }

                return {
                    success: true,
                    timestamp: this.timestamp,
                    message: 'Security configuration updated successfully'
                };

            } catch (error) {
                return {
                    success: false,
                    timestamp: this.timestamp,
                    error: error.message
                };
            }
        }

        mergeConfigs(target, source) {
            const merged = { ...target };

            for (const [key, value] of Object.entries(source)) {
                if (value && typeof value === 'object' && !Array.isArray(value)) {
                    merged[key] = this.mergeConfigs(merged[key] || {}, value);
                } else {
                    merged[key] = value;
                }
            }

            return merged;
        }

        registerCustomRule(name, pattern, category = 'custom') {
            if (!this.advancedConfig.protection.patterns.customRules) {
                this.advancedConfig.protection.patterns.customRules = new Map();
            }

            this.advancedConfig.protection.patterns.customRules.set(name, {
                pattern,
                category,
                enabled: true,
                timestamp: this.timestamp
            });
        }

        removeCustomRule(name) {
            if (this.advancedConfig.protection.patterns.customRules) {
                this.advancedConfig.protection.patterns.customRules.delete(name);
            }
        }

        async testSecurityRule(rule, testData) {
            try {
                const result = {
                    timestamp: this.timestamp,
                    rule: rule,
                    matches: [],
                    performance: {
                        startTime: performance.now()
                    }
                };

                // Pattern testing
                if (rule.pattern) {
                    const pattern = new RegExp(rule.pattern);
                    const matches = testData.match(pattern);
                    if (matches) {
                        result.matches = matches;
                    }
                }

                // ML model testing if applicable
                if (this.state.mlModels.has(rule.model)) {
                    const model = this.state.mlModels.get(rule.model);
                    const prediction = await model.predict(testData);
                    result.mlPrediction = prediction;
                }

                result.performance.duration = performance.now() - result.performance.startTime;
                return result;

            } catch (error) {
                return {
                    timestamp: this.timestamp,
                    error: error.message,
                    rule: rule
                };
            }
        }

        generateSecurityReport() {
            return {
                timestamp: this.timestamp,
                userLogin: this.userLogin,
                status: {
                    initialized: this.state.initialized,
                    mlModelsActive: this.state.mlModels.size,
                    activeThreats: Array.from(this.state.activeThreats),
                    mitigationActions: Array.from(this.state.mitigationActions)
                },
                metrics: {
                    performance: this.state.performanceMetrics.slice(-100),
                    behavioral: {
                        profiles: this.state.behavioralProfiles.size,
                        anomalies: this.getRecentAnomalies()
                    }
                },
                configuration: {
                    protection: {
                        ml: this.advancedConfig.protection.ml.enabled,
                        patterns: this.advancedConfig.protection.patterns.enabled,
                        encryption: this.advancedConfig.protection.encryption.enabled
                    },
                    analysis: {
                        behavioral: this.advancedConfig.analysis.behavioral.enabled,
                        context: this.advancedConfig.analysis.context.enabled,
                        performance: this.advancedConfig.analysis.performance.enabled
                    },
                    realtime: {
                        monitoring: this.advancedConfig.realtime.monitoring.enabled,
                        protection: this.advancedConfig.realtime.protection.enabled,
                        response: this.advancedConfig.realtime.response.enabled
                    }
                }
            };
        }

        getRecentAnomalies() {
            return Array.from(this.state.activeThreats)
                .filter(threat => threat.type === 'anomaly')
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
                .slice(0, 10);
        }

        async exportSecurityState() {
            try {
                const state = {
                    timestamp: this.timestamp,
                    userLogin: this.userLogin,
                    configuration: this.advancedConfig,
                    state: {
                        initialized: this.state.initialized,
                        mlModels: Array.from(this.state.mlModels.entries()),
                        behavioralProfiles: Array.from(this.state.behavioralProfiles.entries()),
                        performanceMetrics: this.state.performanceMetrics,
                        activeThreats: Array.from(this.state.activeThreats),
                        mitigationActions: Array.from(this.state.mitigationActions)
                    }
                };

                // State'i encrypt et
                const encrypted = await this.encryptState(state);

                return {
                    data: encrypted,
                    timestamp: this.timestamp,
                    signature: await this.signData(encrypted)
                };

            } catch (error) {
                return {
                    error: error.message,
                    timestamp: this.timestamp
                };
            }
        }

        async encryptState(state) {
            const key = await this.getEncryptionKey();
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                new TextEncoder().encode(JSON.stringify(state))
            );

            return {
                data: Array.from(new Uint8Array(encrypted)),
                iv: Array.from(iv)
            };
        }

        async signData(data) {
            const encoder = new TextEncoder();
            const encoded = encoder.encode(JSON.stringify(data));
            const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.AdvancedSecurityValidator = AdvancedSecurityValidator;

})(window);

(function(window) {
    'use strict';

    class TokenAuthValidator {
        timestamp = '2025-03-17 12:04:24';
        userLogin = 'Yldrm2015';

        constructor(validator) {
            this.validator = validator;

            this.authConfig = {
                tokens: {
                    jwt: {
                        algorithms: ['RS256', 'ES256', 'PS256'],
                        maxAge: 3600,
                        required: {
                            claims: ['sub', 'iat', 'exp', 'jti', 'iss', 'aud'],
                            headers: ['alg', 'typ', 'kid']
                        },
                        issuer: 'https://auth.example.com',
                        audience: 'https://api.example.com',
                        keyManagement: {
                            rotation: true,
                            interval: 86400, // 24 hours
                            backupKeys: 2
                        }
                    },
                    session: {
                        type: 'encrypted',
                        length: 64,
                        entropy: 256,
                        maxAge: 86400,
                        renewThreshold: 3600,
                        persistent: false
                    },
                    refresh: {
                        enabled: true,
                        type: 'rotating',
                        length: 128,
                        maxAge: 2592000, // 30 days
                        singleUse: true
                    }
                },
                authentication: {
                    methods: {
                        password: {
                            enabled: true,
                            minLength: 12,
                            complexity: {
                                uppercase: true,
                                lowercase: true,
                                numbers: true,
                                special: true
                            },
                            hashAlgorithm: 'argon2id',
                            hashParams: {
                                iterations: 3,
                                memory: 65536,
                                parallelism: 4
                            }
                        },
                        mfa: {
                            enabled: true,
                            preferred: 'totp',
                            methods: ['totp', 'backup-codes', 'webauthn'],
                            graceLogin: false
                        },
                        biometric: {
                            enabled: true,
                            methods: ['fingerprint', 'face'],
                            strengthVerification: true
                        }
                    },
                    session: {
                        management: {
                            maxConcurrent: 3,
                            forceLogoutOthers: true,
                            deviceTracking: true
                        },
                        protection: {
                            fingerprintValidation: true,
                            geoValidation: true,
                            deviceValidation: true
                        }
                    }
                },
                authorization: {
                    rbac: {
                        enabled: true,
                        roles: ['user', 'admin', 'moderator', 'system'],
                        inheritance: {
                            'admin': ['moderator'],
                            'moderator': ['user']
                        }
                    },
                    permissions: {
                        schema: {
                            'resource': ['create', 'read', 'update', 'delete'],
                            'user': ['view', 'edit', 'delete'],
                            'system': ['configure', 'monitor', 'manage']
                        },
                        defaultRole: 'user'
                    },
                    policies: {
                        enabled: true,
                        enforceOrder: true,
                        defaultPolicy: 'deny'
                    }
                },
                security: {
                    encryption: {
                        tokens: {
                            algorithm: 'AES-256-GCM',
                            keyDerivation: 'PBKDF2',
                            keyLength: 256
                        },
                        storage: {
                            algorithm: 'AES-256-GCM',
                            keyStorage: 'secure'
                        }
                    },
                    signing: {
                        algorithm: 'Ed25519',
                        keyRotation: true,
                        timestamps: true
                    }
                }
            };

            this.state = {
                initialized: false,
                keys: new Map(),
                sessions: new Map(),
                tokens: {
                    active: new Set(),
                    revoked: new Set(),
                    blacklisted: new Set()
                },
                mfa: {
                    pending: new Map(),
                    verified: new Set()
                }
            };

            this.initialize();
        }

        async initialize() {
            try {
                // Key management başlat
                await this.initializeKeyManagement();

                // Token validation başlat
                await this.initializeTokenValidation();

                // Session management başlat
                this.initializeSessionManagement();

                // MFA system başlat
                if (this.authConfig.authentication.methods.mfa.enabled) {
                    await this.initializeMFASystem();
                }

                this.state.initialized = true;
                console.log(`[${this.timestamp}] TokenAuthValidator initialized`);

            } catch (error) {
                console.error(`[${this.timestamp}] Token/Auth initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        async initializeKeyManagement() {
            // JWT signing keys
            const keyPair = await this.generateKeyPair();
            this.state.keys.set('current', keyPair);

            // Rotation schedule
            if (this.authConfig.tokens.jwt.keyManagement.rotation) {
                this.startKeyRotation();
            }

            // Encryption keys
            await this.initializeEncryptionKeys();
        }

        async generateKeyPair() {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: 'ECDSA',
                    namedCurve: 'P-256'
                },
                true,
                ['sign', 'verify']
            );

            return {
                publicKey: keyPair.publicKey,
                privateKey: keyPair.privateKey,
                created: this.timestamp,
                algorithm: 'ES256'
            };
        }

        async initializeEncryptionKeys() {
            const tokenKey = await this.generateEncryptionKey();
            this.state.keys.set('token_encryption', tokenKey);

            const storageKey = await this.generateEncryptionKey();
            this.state.keys.set('storage_encryption', storageKey);
        }

        async generateEncryptionKey() {
            return await window.crypto.subtle.generateKey(
                {
                    name: 'AES-GCM',
                    length: this.authConfig.security.encryption.tokens.keyLength
                },
                true,
                ['encrypt', 'decrypt']
            );
        }

        async validateToken(token, type = 'jwt') {
            try {
                // Token format check
                if (!this.isValidTokenFormat(token, type)) {
                    throw new Error('Invalid token format');
                }

                // Token type specific validation
                switch(type) {
                    case 'jwt':
                        return await this.validateJWT(token);
                    case 'session':
                        return await this.validateSessionToken(token);
                    case 'refresh':
                        return await this.validateRefreshToken(token);
                    default:
                        throw new Error('Unsupported token type');
                }

            } catch (error) {
                this.handleValidationError(error);
                return {
                    valid: false,
                    error: error.message
                };
            }
        }

        async validateJWT(token) {
            // Parse token parts
            const [headerB64, payloadB64, signature] = token.split('.');
            
            // Decode header and payload
            const header = this.decodeBase64JSON(headerB64);
            const payload = this.decodeBase64JSON(payloadB64);

            // Header validation
            this.validateJWTHeader(header);

            // Payload validation
            this.validateJWTPayload(payload);

            // Signature validation
            await this.validateJWTSignature(token, header.alg);

            // Token blacklist check
            if (this.state.tokens.blacklisted.has(payload.jti)) {
                throw new Error('Token has been blacklisted');
            }

            return {
                valid: true,
                token: {
                    header,
                    payload,
                    signature
                }
            };
        }

        validateJWTHeader(header) {
            // Required fields
            this.authConfig.tokens.jwt.required.headers.forEach(field => {
                if (!header[field]) {
                    throw new Error(`Missing required header field: ${field}`);
                }
            });

            // Algorithm check
            if (!this.authConfig.tokens.jwt.algorithms.includes(header.alg)) {
                throw new Error('Unsupported algorithm');
            }

            // Type check
            if (header.typ !== 'JWT') {
                throw new Error('Invalid token type');
            }

            // Key ID check
            if (!this.state.keys.has(header.kid)) {
                throw new Error('Unknown key identifier');
            }
        }

        validateJWTPayload(payload) {
            const now = Math.floor(Date.now() / 1000);

            // Required claims
            this.authConfig.tokens.jwt.required.claims.forEach(claim => {
                if (!payload[claim]) {
                    throw new Error(`Missing required claim: ${claim}`);
                }
            });

            // Timestamp validation
            if (payload.exp && payload.exp < now) {
                throw new Error('Token has expired');
            }

            if (payload.nbf && payload.nbf > now) {
                throw new Error('Token not yet valid');
            }

            // Issuer validation
            if (payload.iss !== this.authConfig.tokens.jwt.issuer) {
                throw new Error('Invalid token issuer');
            }

            // Audience validation
            if (payload.aud !== this.authConfig.tokens.jwt.audience) {
                throw new Error('Invalid token audience');
            }

            // Maximum age check
            if (now - payload.iat > this.authConfig.tokens.jwt.maxAge) {
                throw new Error('Token has exceeded maximum age');
            }
        }

        async validateJWTSignature(token, algorithm) {
            try {
                const signatureBase64 = token.split('.')[2];
                const signature = this.base64URLtoArrayBuffer(signatureBase64);
                const data = new TextEncoder().encode(token.split('.').slice(0, 2).join('.'));

                const key = this.state.keys.get('current').publicKey;
                const isValid = await window.crypto.subtle.verify(
                    {
                        name: 'ECDSA',
                        hash: {name: 'SHA-256'}
                    },
                    key,
                    signature,
                    data
                );

                if (!isValid) {
                    throw new Error('Invalid signature');
                }

            } catch (error) {
                throw new Error(`Signature validation failed: ${error.message}`);
            }
        }

        async validateSession(sessionId) {
            const session = this.state.sessions.get(sessionId);
            if (!session) {
                return {
                    valid: false,
                    error: 'Session not found'
                };
            }

            try {
                // Session expiration check
                if (this.isSessionExpired(session)) {
                    this.terminateSession(sessionId);
                    throw new Error('Session expired');
                }

                // Fingerprint validation
                if (this.authConfig.authentication.session.protection.fingerprintValidation) {
                    await this.validateSessionFingerprint(session);
                }

                // Device validation
                if (this.authConfig.authentication.session.protection.deviceValidation) {
                    await this.validateSessionDevice(session);
                }

                // Geo validation
                if (this.authConfig.authentication.session.protection.geoValidation) {
                    await this.validateSessionLocation(session);
                }

                return {
                    valid: true,
                    session: {
                        id: sessionId,
                        user: session.user,
                        created: session.created,
                        lastActivity: session.lastActivity
                    }
                };

            } catch (error) {
                return {
                    valid: false,
                    error: error.message
                };
            }
        }

        async validateMFA(token, method) {
            if (!this.authConfig.authentication.methods.mfa.enabled) {
                return {
                    valid: false,
                    error: 'MFA is not enabled'
                };
            }

            try {
                switch (method) {
                    case 'totp':
                        return await this.validateTOTP(token);
                    case 'backup-codes':
                        return await this.validateBackupCode(token);
                    case 'webauthn':
                        return await this.validateWebAuthn(token);
                    default:
                        throw new Error('Unsupported MFA method');
                }
            } catch (error) {
                return {
                    valid: false,
                    error: error.message
                };
            }
        }

        // Utility methods
        decodeBase64JSON(base64Url) {
            const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
            const jsonStr = atob(base64);
            return JSON.parse(jsonStr);
        }

        base64URLtoArrayBuffer(base64URL) {
            const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(base64);
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            return buffer;
        }

        // Error handlers
        handleValidationError(error) {
            console.error(`[${this.timestamp}] Token validation error:`, error);
            
            if (this.validator.logger) {
                this.validator.logger.log('error', 'auth', 
                    'Token validation failed', {
                        error: error.message,
                        timestamp: this.timestamp
                    });
            }
        }

        // Public API
        getAuthStatus() {
            return {
                initialized: this.state.initialized,
                activeSessions: this.state.sessions.size,
                activeTokens: this.state.tokens.active.size,
                mfaStatus: {
                    enabled: this.authConfig.authentication.methods.mfa.enabled,
                    pendingValidations: this.state.mfa.pending.size
                },
                timestamp: this.timestamp
            };
        }

        async revokeToken(token, reason = 'user_request') {
            try {
                const validation = await this.validateToken(token);
                if (!validation.valid) {
                    throw new Error('Invalid token');
                }

                const jti = validation.token.payload.jti;
                this.state.tokens.active.delete(jti);
                this.state.tokens.revoked.add(jti);

                return {
                    success: true,
                    timestamp: this.timestamp,
                    reason
                };

            } catch (error) {
                return {
                    success: false,
                    error: error.message,
                    timestamp: this.timestamp
                };
            }
        }

        async refreshSession(sessionId) {
            try {
                const validation = await this.validateSession(sessionId);
                if (!validation.valid) {
                    throw new Error('Invalid session');
                }

                const session = this.state.sessions.get(sessionId);
                const newToken = await this.generateSessionToken(session.user);

                return {
                    success: true,
                    token: newToken,
                    timestamp: this.timestamp
                };

            } catch (error) {
                return {
                    success: false,
                    error: error.message,
                    timestamp: this.timestamp
                };
            }
        }

        async generateSessionToken(user) {
            const token = {
                id: this.generateRandomString(32),
                user: user,
                created: this.timestamp,
                expires: this.calculateExpiration('session'),
                fingerprint: await this.generateFingerprint()
            };

            const encrypted = await this.encryptToken(token);
            this.state.tokens.active.add(token.id);

            return encrypted;
        }

        calculateExpiration(type) {
            const now = new Date(this.timestamp);
            let expiration;

            switch(type) {
                case 'jwt':
                    expiration = now.getTime() + (this.authConfig.tokens.jwt.maxAge * 1000);
                    break;
                case 'session':
                    expiration = now.getTime() + (this.authConfig.tokens.session.maxAge * 1000);
                    break;
                case 'refresh':
                    expiration = now.getTime() + (this.authConfig.tokens.refresh.maxAge * 1000);
                    break;
                default:
                    expiration = now.getTime() + 3600000; // 1 hour default
            }

            return new Date(expiration).toISOString();
        }

        async generateFingerprint() {
            const components = [
                navigator.userAgent,
                navigator.language,
                navigator.platform,
                Intl.DateTimeFormat().resolvedOptions().timeZone,
                screen.colorDepth,
                screen.pixelDepth,
                screen.width + 'x' + screen.height
            ];

            const fingerprint = components.join('|');
            const encoder = new TextEncoder();
            const data = encoder.encode(fingerprint);
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            
            return Array.from(new Uint8Array(hashBuffer))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');
        }

        async encryptToken(token) {
            const key = this.state.keys.get('token_encryption');
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const encoder = new TextEncoder();
            const data = encoder.encode(JSON.stringify(token));

            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                data
            );

            return {
                data: Array.from(new Uint8Array(encrypted)),
                iv: Array.from(iv),
                id: token.id
            };
        }

        async decryptToken(encryptedToken) {
            try {
                const key = this.state.keys.get('token_encryption');
                const decrypted = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: new Uint8Array(encryptedToken.iv)
                    },
                    key,
                    new Uint8Array(encryptedToken.data)
                );

                return JSON.parse(new TextDecoder().decode(decrypted));
            } catch (error) {
                throw new Error('Token decryption failed');
            }
        }

        generateRandomString(length) {
            const array = new Uint8Array(length);
            crypto.getRandomValues(array);
            return Array.from(array, byte => 
                byte.toString(16).padStart(2, '0')
            ).join('');
        }

        startKeyRotation() {
            const interval = this.authConfig.tokens.jwt.keyManagement.interval * 1000;
            
            setInterval(async () => {
                try {
                    // Generate new key pair
                    const newKeyPair = await this.generateKeyPair();
                    
                    // Backup current key
                    const currentKey = this.state.keys.get('current');
                    const backupId = `backup_${this.timestamp}`;
                    this.state.keys.set(backupId, currentKey);

                    // Set new key as current
                    this.state.keys.set('current', newKeyPair);

                    // Clean old backup keys
                    this.cleanupBackupKeys();

                    console.log(`[${this.timestamp}] Key rotation completed`);
                } catch (error) {
                    console.error(`[${this.timestamp}] Key rotation failed:`, error);
                }
            }, interval);
        }

        cleanupBackupKeys() {
            const maxBackups = this.authConfig.tokens.jwt.keyManagement.backupKeys;
            const keys = Array.from(this.state.keys.entries())
                .filter(([id]) => id.startsWith('backup_'))
                .sort((a, b) => b[1].created.localeCompare(a[1].created));

            // Remove excess backup keys
            while (keys.length > maxBackups) {
                const [oldestId] = keys.pop();
                this.state.keys.delete(oldestId);
            }
        }

        // Monitoring and reporting methods
        getTokenMetrics() {
            return {
                active: this.state.tokens.active.size,
                revoked: this.state.tokens.revoked.size,
                blacklisted: this.state.tokens.blacklisted.size,
                timestamp: this.timestamp
            };
        }

        getKeyMetrics() {
            return {
                current: !!this.state.keys.get('current'),
                backups: Array.from(this.state.keys.keys())
                    .filter(id => id.startsWith('backup_')).length,
                lastRotation: this.state.keys.get('current')?.created,
                timestamp: this.timestamp
            };
        }

        getMFAStatus() {
            return {
                enabled: this.authConfig.authentication.methods.mfa.enabled,
                preferredMethod: this.authConfig.authentication.methods.mfa.preferred,
                pendingValidations: this.state.mfa.pending.size,
                verifiedSessions: this.state.mfa.verified.size,
                timestamp: this.timestamp
            };
        }

        exportSecurityConfig() {
            return {
                tokens: {
                    ...this.authConfig.tokens,
                    jwt: {
                        ...this.authConfig.tokens.jwt,
                        keyManagement: {
                            ...this.authConfig.tokens.jwt.keyManagement,
                            currentKeyAge: this.calculateKeyAge()
                        }
                    }
                },
                authentication: this.authConfig.authentication,
                authorization: this.authConfig.authorization,
                security: {
                    ...this.authConfig.security,
                    currentState: {
                        keysInitialized: this.state.keys.size > 0,
                        sessionsActive: this.state.sessions.size,
                        mfaEnabled: this.authConfig.authentication.methods.mfa.enabled
                    }
                },
                timestamp: this.timestamp
            };
        }

        calculateKeyAge() {
            const currentKey = this.state.keys.get('current');
            if (!currentKey) return null;

            const created = new Date(currentKey.created);
            const now = new Date(this.timestamp);
            return Math.floor((now - created) / 1000); // Age in seconds
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.TokenAuthValidator = TokenAuthValidator;

})(window);

(function(window) {
    'use strict';

    class ContentSecurityValidator {
        timestamp = '2025-03-17 12:17:26';
        userLogin = 'Yldrm2015';

        constructor(validator) {
            this.validator = validator;

            this.contentConfig = {
                validation: {
                    input: {
                        text: {
                            maxLength: 1000,
                            minLength: 1,
                            allowedPatterns: [
                                /^[\w\s.,!?-]+$/,
                                /^[a-zA-Z0-9\s]+$/
                            ],
                            sanitize: true,
                            trim: true
                        },
                        email: {
                            pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                            maxLength: 254,
                            normalizeCase: true,
                            validateMX: true
                        },
                        url: {
                            pattern: /^https?:\/\/[\w\-.]+(:\d+)?([\/\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/,
                            maxLength: 2048,
                            allowedProtocols: ['http', 'https'],
                            validateDomain: true
                        },
                        file: {
                            maxSize: 10 * 1024 * 1024, // 10MB
                            allowedTypes: [
                                'image/jpeg',
                                'image/png',
                                'image/gif',
                                'application/pdf',
                                'text/plain'
                            ],
                            scanContent: true,
                            validateSignature: true
                        }
                    },
                    html: {
                        allowedTags: [
                            'a', 'b', 'br', 'code', 'div', 'em', 
                            'i', 'li', 'ol', 'p', 'pre', 'span', 
                            'strong', 'ul', 'img'
                        ],
                        allowedAttributes: {
                            'a': ['href', 'title', 'target'],
                            'img': ['src', 'alt', 'width', 'height'],
                            'div': ['class', 'id'],
                            'span': ['class']
                        },
                        requireHttps: true,
                        maxLength: 50000
                    }
                },
                protection: {
                    xss: {
                        enabled: true,
                        mode: 'aggressive',
                        sanitize: true,
                        validateEvents: true,
                        blockEval: true
                    },
                    injection: {
                        sql: {
                            enabled: true,
                            patterns: [
                                /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
                                /('|\s+)(\b(OR|AND)\b)(\s+|\d+|'|\"|=|<|>)/i,
                                /'\s*or\s*'1'\s*=\s*'1/i
                            ],
                            escapeCharacters: true
                        },
                        nosql: {
                            enabled: true,
                            patterns: [
                                /\$where:/i,
                                /\$regex:/i,
                                /\$exists:/i
                            ]
                        },
                        command: {
                            enabled: true,
                            patterns: [
                                /[;&|`]|\$\(/,
                                /\bexec\b|\beval\b|\bsystem\b/i
                            ]
                        }
                    },
                    upload: {
                        scan: {
                            enabled: true,
                            virusCheck: true,
                            malwareDetection: true,
                            executeableCheck: true
                        },
                        storage: {
                            validatePath: true,
                            sanitizeName: true,
                            randomizeNames: true
                        }
                    }
                },
                encoding: {
                    input: 'UTF-8',
                    output: 'UTF-8',
                    normalize: true,
                    stripBOM: true,
                    convertEncoding: true
                },
                monitoring: {
                    enabled: true,
                    logLevel: 'warn',
                    metrics: {
                        collect: true,
                        interval: 60000
                    }
                }
            };

            this.state = {
                initialized: false,
                validationCache: new Map(),
                sanitizerCache: new Map(),
                scannerWorker: null,
                metrics: {
                    validated: 0,
                    blocked: 0,
                    sanitized: 0,
                    scanned: 0
                }
            };

            this.initialize();
        }

        async initialize() {
            try {
                // HTML sanitizer başlat
                await this.initializeSanitizer();

                // Content scanner worker başlat
                if (this.contentConfig.protection.upload.scan.enabled) {
                    this.initializeScanner();
                }

                // Input validation handlers
                this.setupInputValidation();

                // XSS protection
                if (this.contentConfig.protection.xss.enabled) {
                    this.initializeXSSProtection();
                }

                this.state.initialized = true;
                console.log(`[${this.timestamp}] ContentSecurityValidator initialized`);

            } catch (error) {
                console.error(`[${this.timestamp}] Content security initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        handleInitializationError(error) {
            this.state.initialized = false;
            this.logError('initialization', error);
            throw new Error(`Content security initialization failed: ${error.message}`);
        }

        logError(type, error) {
            const errorData = {
                type,
                message: error.message,
                stack: error.stack,
                timestamp: this.timestamp
            };

            if (this.validator?.logger) {
                this.validator.logger.log('error', 'content-security', 
                    `Content security error: ${type}`, errorData);
            }
        }

        async initializeSanitizer() {
            this.state.sanitizer = {
                allowedTags: new Set(this.contentConfig.validation.html.allowedTags),
                allowedAttributes: this.contentConfig.validation.html.allowedAttributes,
                
                sanitize: (html) => {
                    const doc = new DOMParser().parseFromString(html, 'text/html');
                    this.sanitizeNode(doc.body);
                    return doc.body.innerHTML;
                }
            };
        }

        sanitizeNode(node) {
            const allowedTags = this.state.sanitizer.allowedTags;
            const allowedAttributes = this.state.sanitizer.allowedAttributes;

            Array.from(node.children).forEach(child => {
                const tagName = child.tagName.toLowerCase();
                
                if (!allowedTags.has(tagName)) {
                    node.removeChild(child);
                    return;
                }

                // Clean attributes
                Array.from(child.attributes).forEach(attr => {
                    const tagAttrs = allowedAttributes[tagName];
                    if (!tagAttrs || !tagAttrs.includes(attr.name)) {
                        child.removeAttribute(attr.name);
                    }
                });

                // URL attributes check
                if (child.hasAttribute('href') || child.hasAttribute('src')) {
                    this.sanitizeUrlAttributes(child);
                }

                // Recursive check for nested elements
                this.sanitizeNode(child);
            });
        }

        sanitizeUrlAttributes(element) {
            ['href', 'src'].forEach(attr => {
                if (element.hasAttribute(attr)) {
                    const url = element.getAttribute(attr);
                    try {
                        const parsed = new URL(url);
                        if (this.contentConfig.validation.html.requireHttps) {
                            if (parsed.protocol !== 'https:') {
                                element.removeAttribute(attr);
                            }
                        }
                    } catch {
                        element.removeAttribute(attr);
                    }
                }
            });
        }

        setupInputValidation() {
            const validationHandlers = {
                text: this.validateText.bind(this),
                email: this.validateEmail.bind(this),
                url: this.validateUrl.bind(this),
                file: this.validateFile.bind(this)
            };

            document.addEventListener('input', (e) => {
                const type = e.target.dataset.validationType || 'text';
                const handler = validationHandlers[type];

                if (handler) {
                    const result = handler(e.target.value);
                    this.handleValidationResult(e.target, result);
                }
            }, true);
        }

        validateText(value) {
            const config = this.contentConfig.validation.input.text;

            if (!value) {
                return this.createValidationResult(false, 'Empty value');
            }

            if (config.trim) {
                value = value.trim();
            }

            if (value.length > config.maxLength) {
                return this.createValidationResult(false, 'Exceeds maximum length');
            }

            if (value.length < config.minLength) {
                return this.createValidationResult(false, 'Below minimum length');
            }

            const validPattern = config.allowedPatterns.some(
                pattern => pattern.test(value)
            );

            if (!validPattern) {
                return this.createValidationResult(false, 'Invalid characters');
            }

            if (config.sanitize) {
                value = this.sanitizeText(value);
            }

            return this.createValidationResult(true, null, value);
        }

        validateEmail(email) {
            const config = this.contentConfig.validation.input.email;

            if (!email) {
                return this.createValidationResult(false, 'Empty email');
            }

            if (email.length > config.maxLength) {
                return this.createValidationResult(false, 'Email too long');
            }

            if (!config.pattern.test(email)) {
                return this.createValidationResult(false, 'Invalid email format');
            }

            if (config.normalizeCase) {
                email = email.toLowerCase();
            }

            return this.createValidationResult(true, null, email);
        }

        validateUrl(url) {
            const config = this.contentConfig.validation.input.url;

            if (!url) {
                return this.createValidationResult(false, 'Empty URL');
            }

            try {
                const parsed = new URL(url);
                
                if (!config.pattern.test(url)) {
                    return this.createValidationResult(false, 'Invalid URL format');
                }

                if (url.length > config.maxLength) {
                    return this.createValidationResult(false, 'URL too long');
                }

                if (!config.allowedProtocols.includes(parsed.protocol.slice(0, -1))) {
                    return this.createValidationResult(false, 'Invalid protocol');
                }

                return this.createValidationResult(true, null, url);
            } catch {
                return this.createValidationResult(false, 'Invalid URL');
            }
        }

        async validateFile(file) {
            const config = this.contentConfig.validation.input.file;

            if (!file) {
                return this.createValidationResult(false, 'No file provided');
            }

            if (file.size > config.maxSize) {
                return this.createValidationResult(false, 'File too large');
            }

            if (!config.allowedTypes.includes(file.type)) {
                return this.createValidationResult(false, 'Invalid file type');
            }

            if (config.validateSignature) {
                const signatureValid = await this.validateFileSignature(file);
                if (!signatureValid) {
                    return this.createValidationResult(false, 'Invalid file signature');
                }
            }

            if (config.scanContent) {
                const scanResult = await this.scanFile(file);
                if (!scanResult.valid) {
                    return this.createValidationResult(false, scanResult.error);
                }
            }

            return this.createValidationResult(true);
        }

        async validateFileSignature(file) {
            try {
                const signature = await this.readFileSignature(file);
                return this.verifyFileSignature(signature, file.type);
            } catch (error) {
                this.logError('file-signature', error);
                return false;
            }
        }

        async readFileSignature(file) {
            return new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const arr = new Uint8Array(e.target.result);
                    const signature = Array.from(arr.slice(0, 4))
                        .map(byte => byte.toString(16).padStart(2, '0'))
                        .join('');
                    resolve(signature);
                };
                reader.onerror = () => reject(new Error('Failed to read file'));
                reader.readAsArrayBuffer(file.slice(0, 4));
            });
        }

        verifyFileSignature(signature, fileType) {
            const signatures = {
                'image/jpeg': ['ffd8ff'],
                'image/png': ['89504e47'],
                'image/gif': ['47494638'],
                'application/pdf': ['25504446']
            };

            return signatures[fileType]?.some(validSig => 
                signature.startsWith(validSig)
            ) ?? false;
        }

        async scanFile(file) {
            if (!this.state.scannerWorker) {
                return { valid: false, error: 'Scanner not available' };
            }

            return new Promise((resolve) => {
                const reader = new FileReader();
                
                reader.onload = (e) => {
                    this.state.scannerWorker.postMessage({
                        type: 'scan',
                        content: e.target.result,
                        filename: file.name,
                        fileType: file.type
                    });

                    this.state.scannerWorker.onmessage = (event) => {
                        const result = event.data;
                        this.state.metrics.scanned++;
                        
                        if (result.threats.length > 0) {
                            resolve({
                                valid: false,
                                error: 'Security threats detected',
                                threats: result.threats
                            });
                        } else {
                            resolve({ valid: true });
                        }
                    };
                };

                reader.onerror = () => {
                    resolve({ valid: false, error: 'File read failed' });
                };

                reader.readAsArrayBuffer(file);
            });
        }

        createValidationResult(valid, error = null, sanitized = null) {
            return {
                valid,
                error,
                sanitized,
                timestamp: this.timestamp
            };
        }

        sanitizeText(text) {
            if (!text) return '';

            // Basic XSS prevention
            text = text
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#x27;')
                .replace(/`/g, '&#x60;');

            // Extra sanitization
            if (this.contentConfig.protection.xss.mode === 'aggressive') {
                text = text
                    .replace(/javascript:/gi, '')
                    .replace(/data:/gi, '')
                    .replace(/vbscript:/gi, '');
            }

            return text;
        }

                // Public API
                getValidationMetrics() {
                    return {
                        ...this.state.metrics,
                        timestamp: this.timestamp,
                        user: this.userLogin
                    };
                }
        
                getSanitizationStatus() {
                    return {
                        initialized: this.state.initialized,
                        sanitizerActive: !!this.state.sanitizer,
                        scannerActive: !!this.state.scannerWorker,
                        metrics: this.state.metrics,
                        timestamp: this.timestamp,
                        user: this.userLogin
                    };
                }
        
                updateContentConfig(newConfig) {
                    try {
                        // Deep merge configuration
                        this.contentConfig = this.mergeConfigs(this.contentConfig, newConfig);
        
                        // Reinitialize components if needed
                        if (newConfig.validation?.html) {
                            this.initializeSanitizer();
                        }
        
                        if (newConfig.protection?.upload?.scan) {
                            this.initializeScanner();
                        }
        
                        return {
                            success: true,
                            timestamp: this.timestamp,
                            message: 'Content security configuration updated successfully'
                        };
        
                    } catch (error) {
                        this.logError('config-update', error);
                        return {
                            success: false,
                            error: error.message,
                            timestamp: this.timestamp
                        };
                    }
                }
        
                mergeConfigs(target, source) {
                    const merged = { ...target };
        
                    for (const [key, value] of Object.entries(source)) {
                        if (value && typeof value === 'object' && !Array.isArray(value)) {
                            merged[key] = this.mergeConfigs(merged[key] || {}, value);
                        } else {
                            merged[key] = value;
                        }
                    }
        
                    return merged;
                }
        
                getSecurityReport() {
                    return {
                        timestamp: this.timestamp,
                        user: this.userLogin,
                        status: {
                            initialized: this.state.initialized,
                            components: {
                                sanitizer: !!this.state.sanitizer,
                                scanner: !!this.state.scannerWorker
                            }
                        },
                        metrics: this.state.metrics,
                        configuration: {
                            validation: {
                                html: {
                                    tagsCount: this.contentConfig.validation.html.allowedTags.length,
                                    attributesCount: Object.keys(this.contentConfig.validation.html.allowedAttributes).length
                                },
                                input: {
                                    types: Object.keys(this.contentConfig.validation.input)
                                }
                            },
                            protection: {
                                xss: this.contentConfig.protection.xss.enabled,
                                injection: {
                                    sql: this.contentConfig.protection.injection.sql.enabled,
                                    nosql: this.contentConfig.protection.injection.nosql.enabled,
                                    command: this.contentConfig.protection.injection.command.enabled
                                },
                                upload: this.contentConfig.protection.upload.scan.enabled
                            }
                        }
                    };
                }
        
                exportSecurityState() {
                    return {
                        timestamp: this.timestamp,
                        user: this.userLogin,
                        metrics: this.state.metrics,
                        cache: {
                            validation: Array.from(this.state.validationCache.keys()),
                            sanitizer: Array.from(this.state.sanitizerCache.keys())
                        },
                        configuration: this.contentConfig
                    };
                }
        
                resetMetrics() {
                    this.state.metrics = {
                        validated: 0,
                        blocked: 0,
                        sanitized: 0,
                        scanned: 0
                    };
        
                    return {
                        success: true,
                        timestamp: this.timestamp,
                        message: 'Metrics reset successfully'
                    };
                }
        
                dispose() {
                    // Clean up resources
                    if (this.state.scannerWorker) {
                        this.state.scannerWorker.terminate();
                    }
        
                    // Clear caches
                    this.state.validationCache.clear();
                    this.state.sanitizerCache.clear();
        
                    // Reset state
                    this.state = {
                        initialized: false,
                        validationCache: new Map(),
                        sanitizerCache: new Map(),
                        scannerWorker: null,
                        metrics: {
                            validated: 0,
                            blocked: 0,
                            sanitized: 0,
                            scanned: 0
                        }
                    };
        
                    return {
                        success: true,
                        timestamp: this.timestamp,
                        message: 'Content security validator disposed successfully'
                    };
                }
            }
        
            // Ana SecurityValidator sınıfına entegre et
            window.SecurityValidator.ContentSecurityValidator = ContentSecurityValidator;
        
        })(window);

        (function(window) {
            'use strict';
        
            class AdvancedSecurityValidator {
                timestamp = '2025-03-17 12:25:25';
                userLogin = 'Yldrm2015';
        
                constructor(validator) {
                    this.validator = validator;
        
                    this.advancedConfig = {
                        protection: {
                            ml: {
                                enabled: true,
                                models: {
                                    anomalyDetection: true,
                                    threatPrediction: true,
                                    behaviorAnalysis: true
                                },
                                threshold: 0.85,
                                trainingInterval: 86400000 // 24 hours
                            },
                            patterns: {
                                enabled: true,
                                rules: {
                                    xss: [
                                        /<script\b[^>]*>(.*?)<\/script>/gi,
                                        /javascript:[^\s]*/gi,
                                        /on\w+\s*=\s*"[^"]*"/gi
                                    ],
                                    sqlInjection: [
                                        /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b)/i,
                                        /('|\s+)(\b(OR|AND)\b)(\s+|\d+|'|\"|=|<|>)/i,
                                        /'\s*or\s*'1'\s*=\s*'1/i
                                    ],
                                    pathTraversal: [
                                        /\.\.[\/\\]/g,
                                        /\.\.%2f/gi,
                                        /%252e%252e%252f/gi
                                    ],
                                    commandInjection: [
                                        /\b(exec|eval|system|call|pass|include)\b/i,
                                        /\${\s*[^\s}]+\s*}/g,
                                        /`[^`]*`/g
                                    ]
                                },
                                customRules: new Map()
                            },
                            encryption: {
                                algorithms: {
                                    symmetric: 'AES-256-GCM',
                                    asymmetric: 'RSA-OAEP',
                                    hash: 'SHA-512'
                                },
                                keyRotation: {
                                    enabled: true,
                                    interval: 43200000 // 12 hours
                                },
                                storage: {
                                    type: 'secureStorage',
                                    prefix: 'security_key_'
                                }
                            },
                            mitigation: {
                                enabled: true,
                                actions: {
                                    block: true,
                                    redirect: '/security-error',
                                    report: true,
                                    notify: true
                                },
                                thresholds: {
                                    low: 0.3,
                                    medium: 0.6,
                                    high: 0.8,
                                    critical: 0.95
                                }
                            }
                        },
                        analysis: {
                            behavioral: {
                                enabled: true,
                                features: [
                                    'mouseMovement',
                                    'keyboardDynamics',
                                    'touchGestures',
                                    'deviceOrientation'
                                ],
                                profileLength: 1000,
                                updateInterval: 60000
                            },
                            context: {
                                enabled: true,
                                factors: [
                                    'timePattern',
                                    'locationPattern',
                                    'deviceProfile',
                                    'networkProfile'
                                ]
                            },
                            performance: {
                                enabled: true,
                                metrics: [
                                    'responseTime',
                                    'cpuUsage',
                                    'memoryUsage',
                                    'networkLatency'
                                ],
                                thresholds: {
                                    responseTime: 2000,
                                    cpuUsage: 80,
                                    memoryUsage: 85,
                                    networkLatency: 1000
                                }
                            }
                        },
                        realtime: {
                            monitoring: {
                                enabled: true,
                                interval: 1000,
                                metrics: [
                                    'requests',
                                    'errors',
                                    'latency',
                                    'bandwidth'
                                ]
                            },
                            protection: {
                                enabled: true,
                                features: {
                                    ddosProtection: true,
                                    bruteForceProtection: true,
                                    scanningProtection: true
                                },
                                thresholds: {
                                    requestsPerSecond: 100,
                                    errorRate: 0.1,
                                    bandwidthLimit: '10mb'
                                }
                            },
                            response: {
                                enabled: true,
                                autoScale: true,
                                loadBalancing: true,
                                failover: true
                            }
                        }
                    };
        
                    this.state = {
                        initialized: false,
                        mlModels: new Map(),
                        behavioralProfiles: new Map(),
                        performanceMetrics: [],
                        activeThreats: new Set(),
                        mitigationActions: new Map(),
                        realtimeStats: {
                            requests: 0,
                            errors: 0,
                            latency: [],
                            bandwidth: 0
                        }
                    };
        
                    this.initialize();
                }
        
                async initialize() {
                    try {
                        // ML models başlat
                        if (this.advancedConfig.protection.ml.enabled) {
                            await this.initializeMLModels();
                        }
        
                        // Behavioral analysis başlat
                        if (this.advancedConfig.analysis.behavioral.enabled) {
                            this.initializeBehavioralAnalysis();
                        }
        
                        // Performance monitoring başlat
                        if (this.advancedConfig.analysis.performance.enabled) {
                            this.initializePerformanceMonitoring();
                        }
        
                        // Realtime protection başlat
                        if (this.advancedConfig.realtime.protection.enabled) {
                            this.initializeRealtimeProtection();
                        }
        
                        this.state.initialized = true;
                        console.log(`[${this.timestamp}] AdvancedSecurityValidator initialized`);
        
                    } catch (error) {
                        console.error(`[${this.timestamp}] Advanced security initialization failed:`, error);
                        this.handleInitializationError(error);
                    }
                }
        
                async initializeMLModels() {
                    // Anomaly detection model
                    if (this.advancedConfig.protection.ml.models.anomalyDetection) {
                        const anomalyModel = await this.loadModel('anomaly');
                        this.state.mlModels.set('anomaly', anomalyModel);
                    }
        
                    // Threat prediction model
                    if (this.advancedConfig.protection.ml.models.threatPrediction) {
                        const threatModel = await this.loadModel('threat');
                        this.state.mlModels.set('threat', threatModel);
                    }
        
                    // Behavior analysis model
                    if (this.advancedConfig.protection.ml.models.behaviorAnalysis) {
                        const behaviorModel = await this.loadModel('behavior');
                        this.state.mlModels.set('behavior', behaviorModel);
                    }
                }
        
                async loadModel(type) {
                    // Model loading simulation
                    // Production'da gerçek ML model entegrasyonu yapılmalı
                    return {
                        type,
                        version: '1.0.0',
                        predict: async (data) => {
                            return this.simulateModelPrediction(data);
                        },
                        train: async (data) => {
                            return this.simulateModelTraining(data);
                        }
                    };
                }
        
                initializeBehavioralAnalysis() {
                    if (this.advancedConfig.analysis.behavioral.enabled) {
                        // Mouse movement tracking
                        document.addEventListener('mousemove', (e) => {
                            this.analyzeBehavior('mouse', {
                                x: e.clientX,
                                y: e.clientY,
                                timestamp: Date.now()
                            });
                        });
        
                        // Keyboard dynamics
                        document.addEventListener('keypress', (e) => {
                            this.analyzeBehavior('keyboard', {
                                key: e.key,
                                timeStamp: e.timeStamp
                            });
                        });
        
                        // Touch gestures
                        document.addEventListener('touchstart', (e) => {
                            this.analyzeBehavior('touch', {
                                touches: e.touches.length,
                                timestamp: Date.now()
                            });
                        });
        
                        // Device orientation
                        if (window.DeviceOrientationEvent) {
                            window.addEventListener('deviceorientation', (e) => {
                                this.analyzeBehavior('orientation', {
                                    alpha: e.alpha,
                                    beta: e.beta,
                                    gamma: e.gamma
                                });
                            });
                        }
                    }
                }
        
                analyzeBehavior(type, data) {
                    if (!this.state.behavioralProfiles.has(type)) {
                        this.state.behavioralProfiles.set(type, []);
                    }
        
                    const profile = this.state.behavioralProfiles.get(type);
                    profile.push({
                        ...data,
                        timestamp: this.timestamp
                    });
        
                    // Profile length kontrol
                    if (profile.length > this.advancedConfig.analysis.behavioral.profileLength) {
                        profile.shift();
                    }
        
                    // Anomaly detection
                    if (this.state.mlModels.has('behavior')) {
                        this.detectBehavioralAnomalies(type, profile);
                    }
                }
        
                async detectBehavioralAnomalies(type, profile) {
                    const model = this.state.mlModels.get('behavior');
                    const prediction = await model.predict({
                        type,
                        profile: profile.slice(-10),
                        timestamp: this.timestamp
                    });
        
                    if (prediction.score > this.advancedConfig.protection.ml.threshold) {
                        this.handleThreat({
                            type: 'behavioral_anomaly',
                            source: type,
                            score: prediction.score,
                            timestamp: this.timestamp
                        });
                    }
                }
        
                initializePerformanceMonitoring() {
                    if (this.advancedConfig.analysis.performance.enabled) {
                        setInterval(() => {
                            this.collectPerformanceMetrics();
                        }, this.advancedConfig.analysis.performance.updateInterval);
                    }
                }
        
                collectPerformanceMetrics() {
                    const metrics = {
                        timestamp: this.timestamp,
                        responseTime: this.measureResponseTime(),
                        cpuUsage: this.measureCPUUsage(),
                        memoryUsage: this.measureMemoryUsage(),
                        networkLatency: this.measureNetworkLatency()
                    };
        
                    this.state.performanceMetrics.push(metrics);
        
                    // Check thresholds
                    this.checkPerformanceThresholds(metrics);
                }
        
                checkPerformanceThresholds(metrics) {
                    const thresholds = this.advancedConfig.analysis.performance.thresholds;
        
                    for (const [metric, value] of Object.entries(metrics)) {
                        if (metric !== 'timestamp' && value > thresholds[metric]) {
                            this.handleThreat({
                                type: 'performance_threshold',
                                metric,
                                value,
                                threshold: thresholds[metric],
                                timestamp: this.timestamp
                            });
                        }
                    }
                }
        
                initializeRealtimeProtection() {
                    if (this.advancedConfig.realtime.protection.enabled) {
                        // DDoS protection
                        this.setupDDoSProtection();
        
                        // Brute force protection
                        this.setupBruteForceProtection();
        
                        // Scanning protection
                        this.setupScanningProtection();
        
                        // Stats collection
                        this.startRealtimeStats();
                    }
                }
        
                setupDDoSProtection() {
                    const threshold = this.advancedConfig.realtime.protection.thresholds.requestsPerSecond;
                    let requestCount = 0;
        
                    setInterval(() => {
                        if (requestCount > threshold) {
                            this.handleThreat({
                                type: 'ddos_attack',
                                requests: requestCount,
                                threshold,
                                timestamp: this.timestamp
                            });
                        }
                        requestCount = 0;
                    }, 1000);
        
                    // Request counting
                    const originalFetch = window.fetch;
                    window.fetch = async (...args) => {
                        requestCount++;
                        return originalFetch(...args);
                    };
                }
        
                setupBruteForceProtection() {
                    const attempts = new Map();
        
                    document.addEventListener('submit', (e) => {
                        if (e.target.querySelector('input[type="password"]')) {
                            const formId = e.target.id || 'default';
                            
                            if (!attempts.has(formId)) {
                                attempts.set(formId, {
                                    count: 0,
                                    firstAttempt: Date.now()
                                });
                            }
        
                            const attempt = attempts.get(formId);
                            attempt.count++;
        
                            if (this.detectBruteForceAttempt(attempt)) {
                                e.preventDefault();
                                this.handleThreat({
                                    type: 'brute_force',
                                    formId,
                                    attempts: attempt.count,
                                    timestamp: this.timestamp
                                });
                            }
                        }
                    });
                }
        
                detectBruteForceAttempt(attempt) {
                    const timeWindow = 300000; // 5 minutes
                    const maxAttempts = 5;
        
                    if (Date.now() - attempt.firstAttempt > timeWindow) {
                        attempt.count = 1;
                        attempt.firstAttempt = Date.now();
                        return false;
                    }
        
                    return attempt.count > maxAttempts;
                }
        
                setupScanningProtection() {
                    let requestPatterns = new Map();
        
                    // Request pattern analysis
                    const analyzeRequest = (url) => {
                        const path = new URL(url, window.location.origin).pathname;
                        
                        if (!requestPatterns.has(path)) {
                            requestPatterns.set(path, {
                                count: 0,
                                firstRequest: Date.now()
                            });
                        }
        
                        const pattern = requestPatterns.get(path);
                        pattern.count++;
        
                        if (this.detectScanningPattern(pattern)) {
                            this.handleThreat({
                                type: 'scanning_attempt',
                                path,
                                count: pattern.count,
                                timestamp: this.timestamp
                            });
                        }
                    };
        
                    // Intercept requests
                    const originalFetch = window.fetch;
                    window.fetch = async (url, options) => {
                        analyzeRequest(url);
                        return originalFetch(url, options);
                    };
                }
        
                detectScanningPattern(pattern) {
                    const timeWindow = 60000; // 1 minute
                    const maxRequests = 30;
        
                    if (Date.now() - pattern.firstRequest > timeWindow) {
                        pattern.count = 1;
                        pattern.firstRequest = Date.now();
                        return false;
                    }
        
                    return pattern.count > maxRequests;
                }
        
                startRealtimeStats() {
                    setInterval(() => {
                        this.updateRealtimeStats();
                    }, this.advancedConfig.realtime.monitoring.interval);
                }
        
                updateRealtimeStats() {
                    const stats = this.state.realtimeStats;
                    
                    // Calculate averages
                    const avgLatency = stats.latency.length > 0 
                        ? stats.latency.reduce((a, b) => a + b) / stats.latency.length 
                        : 0;
        
                    // Update metrics
                    if (this.validator.logger) {
                        this.validator.logger.log('info', 'security', 
                            'Realtime security stats', {
                                requests: stats.requests,
                                errors: stats.errors,
                                latency: avgLatency,
                                bandwidth: stats.bandwidth,
                                timestamp: this.timestamp
                            });
                    }
        
                    // Reset counters
                    stats.requests = 0;
                    stats.errors = 0;
                    stats.latency = [];
                    stats.bandwidth = 0;
        }

        handleThreat(threat) {
            // Add to active threats
            this.state.activeThreats.add({
                ...threat,
                id: `threat_${Date.now()}`
            });

            // Determine severity
            const severity = this.calculateThreatSeverity(threat);

            // Apply mitigation if enabled
            if (this.advancedConfig.protection.mitigation.enabled) {
                this.applyMitigation(threat, severity);
            }

            // Log threat
            if (this.validator.logger) {
                this.validator.logger.log('error', 'security',
                    'Security threat detected', {
                        threat,
                        severity,
                        timestamp: this.timestamp
                    });
            }
        }

        calculateThreatSeverity(threat) {
            const thresholds = this.advancedConfig.protection.mitigation.thresholds;

            let score;
            switch (threat.type) {
                case 'ddos_attack':
                    score = threat.requests / this.advancedConfig.realtime.protection.thresholds.requestsPerSecond;
                    break;
                case 'brute_force':
                    score = threat.attempts / 10; // Normalize to 0-1
                    break;
                case 'scanning_attempt':
                    score = threat.count / 50; // Normalize to 0-1
                    break;
                case 'behavioral_anomaly':
                    score = threat.score;
                    break;
                case 'performance_threshold':
                    score = threat.value / threat.threshold;
                    break;
                default:
                    score = 0.5; // Default middle severity
            }

            if (score >= thresholds.critical) return 'critical';
            if (score >= thresholds.high) return 'high';
            if (score >= thresholds.medium) return 'medium';
            return 'low';
        }

        applyMitigation(threat, severity) {
            const actions = this.advancedConfig.protection.mitigation.actions;
            const mitigation = {
                timestamp: this.timestamp,
                threat,
                severity,
                actions: []
            };

            switch (severity) {
                case 'critical':
                    if (actions.block) {
                        this.blockAccess();
                        mitigation.actions.push('block');
                    }
                    break;
                case 'high':
                    if (actions.redirect) {
                        this.redirectToSafePage();
                        mitigation.actions.push('redirect');
                    }
                    break;
                case 'medium':
                    if (actions.report) {
                        this.reportThreat(threat);
                        mitigation.actions.push('report');
                    }
                    break;
                case 'low':
                    if (actions.notify) {
                        this.notifyThreat(threat);
                        mitigation.actions.push('notify');
                    }
                    break;
            }

            this.state.mitigationActions.set(threat.id, mitigation);
        }

        blockAccess() {
            // Implementation for blocking access
            window.location.href = '/security-blocked';
        }

        redirectToSafePage() {
            window.location.href = this.advancedConfig.protection.mitigation.actions.redirect;
        }

        reportThreat(threat) {
            // Send to security monitoring system
            if (this.validator.logger) {
                this.validator.logger.log('warn', 'security',
                    'Security threat reported', {
                        threat,
                        timestamp: this.timestamp
                    });
            }
        }

        notifyThreat(threat) {
            // Trigger notification event
            const event = new CustomEvent('securityThreat', {
                detail: {
                    threat,
                    timestamp: this.timestamp
                }
            });
            window.dispatchEvent(event);
        }

        // Public API
        getSecurityStatus() {
            return {
                initialized: this.state.initialized,
                activeThreats: Array.from(this.state.activeThreats),
                mitigationActions: Array.from(this.state.mitigationActions.values()),
                mlModels: Array.from(this.state.mlModels.keys()),
                behavioralProfiles: this.state.behavioralProfiles.size,
                performanceMetrics: this.state.performanceMetrics.slice(-10),
                realtimeStats: { ...this.state.realtimeStats },
                timestamp: this.timestamp,
                user: this.userLogin
            };
        }

        updateConfig(newConfig) {
            try {
                this.advancedConfig = {
                    ...this.advancedConfig,
                    ...newConfig
                };

                return {
                    success: true,
                    message: 'Security configuration updated successfully',
                    timestamp: this.timestamp
                };
            } catch (error) {
                return {
                    success: false,
                    error: error.message,
                    timestamp: this.timestamp
                };
            }
        }

        dispose() {
            // Cleanup resources
            this.state.mlModels.clear();
            this.state.behavioralProfiles.clear();
            this.state.performanceMetrics = [];
            this.state.activeThreats.clear();
            this.state.mitigationActions.clear();

            this.state.initialized = false;

            return {
                success: true,
                message: 'Advanced security validator disposed successfully',
                timestamp: this.timestamp
            };
        }
    }

    // Ana SecurityValidator sınıfına entegre et
    window.SecurityValidator.AdvancedSecurityValidator = AdvancedSecurityValidator;

})(window);

