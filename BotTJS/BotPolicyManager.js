class BotPolicyManager {
    constructor() {
        this.timestamp = '2025-03-17 10:16:29';
        this.userLogin = 'Yldrm2015';
        
        // Operation mode detection
        this.mode = {
            clientSide: typeof window !== 'undefined',
            serverSide: typeof window === 'undefined',
            hybrid: true
        };

        // Session management
        this.sessionId = this.generateSessionId();
        
        this.policyConfig = {
            general: {
                version: '3.0.0',
                enabled: true,
                environment: process.env.NODE_ENV || 'production',
                updateInterval: 3600000, // 1 hour
                maxPolicies: 1000,
                syncInterval: 300000 // 5 minutes (client-server sync)
            },
            enforcement: {
                modes: {
                    monitor: {
                        actions: ['log', 'alert'],
                        threshold: 0.3,
                        clientSideEnforceable: true
                    },
                    challenge: {
                        actions: ['captcha', 'delay', 'ratelimit'],
                        threshold: 0.6,
                        clientSideEnforceable: true
                    },
                    block: {
                        actions: ['block', 'ban', 'report'],
                        threshold: 0.9,
                        clientSideEnforceable: false // Block kararları sadece server-side
                    }
                },
                rateLimit: {
                    enabled: true,
                    window: 60000, // 1 minute
                    maxRequests: {
                        default: {
                            client: 30,  // Client-side limit
                            server: 100  // Server-side limit
                        },
                        authenticated: {
                            client: 60,
                            server: 200
                        },
                        premium: {
                            client: 120,
                            server: 500
                        }
                    },
                    penaltyDuration: {
                        first: 300000,    // 5 minutes
                        second: 1800000,  // 30 minutes
                        third: 86400000   // 24 hours
                    },
                    syncThreshold: 0.8 // %80 limite ulaşınca server ile senkronize et
                }
            },
            rules: {
                botCategories: {
                    good: {
                        searchEngines: {
                            allowedPaths: ['*'],
                            rateLimit: 200,
                            requireValidation: false,
                            clientSideAllowed: true
                        },
                        monitoring: {
                            allowedPaths: ['/status', '/health'],
                            rateLimit: 60,
                            requireValidation: true,
                            clientSideAllowed: true
                        },
                        partners: {
                            allowedPaths: ['/api/v1/*'],
                            rateLimit: 300,
                            requireApiKey: true,
                            clientSideAllowed: false
                        }
                    },
                    suspicious: {
                        actions: ['challenge', 'monitor'],
                        thresholds: {
                            requests: 50,
                            failures: 5,
                            timeWindow: 300000 // 5 minutes
                        },
                        clientSideEnforcement: {
                            enabled: true,
                            maxAttempts: 3
                        }
                    },
                    malicious: {
                        actions: ['block', 'report'],
                        banDuration: 86400000, // 24 hours
                        notifyAdmin: true,
                        clientSideEnforcement: {
                            enabled: false // Malicious botlar sadece server-side ele alınır
                        }
                    }
                },
                customRules: [],
                ipRanges: {
                    whitelist: [],
                    blacklist: [],
                    rateLimit: {}
                }
            },
            storage: {
                client: {
                    type: 'localStorage',
                    prefix: 'botPolicy_',
                    encryption: true,
                    maxAge: 86400, // 24 hours
                    syncInterval: 300000 // 5 minutes
                },
                server: {
                    type: 'redis',
                    prefix: 'botPolicy:',
                    encryption: true,
                    maxAge: 86400 // 24 hours
                }
            },
            api: {
                endpoints: {
                    sync: '/api/bot-policy/sync',
                    enforce: '/api/bot-policy/enforce',
                    report: '/api/bot-policy/report',
                    status: '/api/bot-policy/status'
                },
                methods: ['GET', 'POST'],
                headers: {
                    'X-Bot-Policy-Version': '3.0.0',
                    'X-Bot-Policy-Mode': '{mode}',
                    'X-Session-ID': '{sessionId}'
                }
            },
            notifications: {
                enabled: true,
                channels: {
                    client: {
                        console: {
                            enabled: true,
                            minSeverity: 'low'
                        },
                        customEvent: {
                            enabled: true,
                            eventName: 'botPolicyNotification'
                        }
                    },
                    server: {
                        email: {
                            enabled: true,
                            recipients: ['admin@example.com'],
                            minSeverity: 'high'
                        },
                        webhook: {
                            enabled: true,
                            url: 'https://api.example.com/security/webhooks',
                            minSeverity: 'medium'
                        },
                        slack: {
                            enabled: true,
                            webhook: 'https://hooks.slack.com/services/xxx/yyy/zzz',
                            channel: '#security-alerts',
                            minSeverity: 'high'
                        }
                    }
                }
            }
        };

        // System state
        this.state = {
            policies: new Map(),
            violations: new Map(),
            activeBlocks: new Map(),
            rateLimits: new Map(),
            cache: new Map(),
            sync: {
                lastSync: this.timestamp,
                nextSync: this.timestamp,
                status: 'initialized'
            },
            stats: {
                enforced: 0,
                blocked: 0,
                challenged: 0,
                whitelisted: 0,
                synced: 0,
                errors: 0,
                lastUpdate: this.timestamp
            }
        };

        // Initialize the manager
        this.initialize();
    }

    generateSessionId() {
        return `bpm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    }

    async initialize() {
        try {
            // Core initialization
            await this.initializeCore();
            
            // Mode-specific initialization
            if (this.mode.clientSide) {
                await this.initializeClientMode();
            }
            if (this.mode.serverSide) {
                await this.initializeServerMode();
            }

            // Start periodic tasks
            this.startPeriodicTasks();
            
            this.log('info', 'BotPolicyManager initialized successfully');
        } catch (error) {
            this.log('error', 'BotPolicyManager initialization failed', error);
            throw error;
        }
    }

    log(level, message, data = {}) {
        const logEntry = {
            timestamp: this.timestamp,
            level,
            message,
            sessionId: this.sessionId,
            mode: this.mode,
            ...data
        };

        if (this.mode.clientSide) {
            console[level](logEntry);
        }
        if (this.mode.serverSide) {
            // Server-side logging implementation
            this.serverLog(logEntry);
        }
    }

      // Core Initialization Methods
      async initializeCore() {
        this.timestamp = '2025-03-17 10:19:45';
        this.userLogin = 'Yldrm2015';

        await this.initializeStorage();
        await this.loadPolicies();
        await this.setupEnforcement();
    }

    async initializeStorage() {
        if (this.mode.clientSide) {
            this.storage = {
                async get(key) {
                    try {
                        const data = localStorage.getItem(`${this.policyConfig.storage.client.prefix}${key}`);
                        return data ? JSON.parse(data) : null;
                    } catch (error) {
                        this.log('error', 'Client storage get failed', error);
                        return null;
                    }
                },

                async set(key, value) {
                    try {
                        localStorage.setItem(
                            `${this.policyConfig.storage.client.prefix}${key}`,
                            JSON.stringify(value)
                        );
                        return true;
                    } catch (error) {
                        this.log('error', 'Client storage set failed', error);
                        return false;
                    }
                },

                async remove(key) {
                    try {
                        localStorage.removeItem(`${this.policyConfig.storage.client.prefix}${key}`);
                        return true;
                    } catch (error) {
                        this.log('error', 'Client storage remove failed', error);
                        return false;
                    }
                }
            };
        } else {
            // Server-side storage implementation
            this.storage = {
                async get(key) {
                    // Redis implementation
                    try {
                        const data = await redis.get(`${this.policyConfig.storage.server.prefix}${key}`);
                        return data ? JSON.parse(data) : null;
                    } catch (error) {
                        this.log('error', 'Server storage get failed', error);
                        return null;
                    }
                },

                async set(key, value, ttl = this.policyConfig.storage.server.maxAge) {
                    try {
                        await redis.setex(
                            `${this.policyConfig.storage.server.prefix}${key}`,
                            ttl,
                            JSON.stringify(value)
                        );
                        return true;
                    } catch (error) {
                        this.log('error', 'Server storage set failed', error);
                        return false;
                    }
                },

                async remove(key) {
                    try {
                        await redis.del(`${this.policyConfig.storage.server.prefix}${key}`);
                        return true;
                    } catch (error) {
                        this.log('error', 'Server storage remove failed', error);
                        return false;
                    }
                }
            };
        }
    }

    async loadPolicies() {
        try {
            // Load cached policies
            const cachedPolicies = await this.storage.get('policies');
            if (cachedPolicies) {
                this.state.policies = new Map(Object.entries(cachedPolicies));
            }

            if (this.mode.clientSide) {
                // Client-side policy sync
                await this.syncPoliciesWithServer();
            } else {
                // Server-side policy load
                await this.loadServerPolicies();
            }

            // Load custom rules
            await this.loadCustomRules();

            // Initialize policy cache
            await this.initializePolicyCache();

            this.log('info', 'Policies loaded successfully');
        } catch (error) {
            this.log('error', 'Failed to load policies', error);
            throw error;
        }
    }

    async setupEnforcement() {
        // Initialize enforcement components
        this.enforcement = {
            rateLimit: new Map(),
            blocks: new Map(),
            challenges: new Map()
        };

        // Setup mode-specific enforcement
        if (this.mode.clientSide) {
            await this.setupClientEnforcement();
        } else {
            await this.setupServerEnforcement();
        }
    }

    // Core Policy Enforcement Methods
    async enforcePolicy(request, botClassification) {
        this.timestamp = '2025-03-17 10:19:45';
        
        const policyDecision = {
            timestamp: this.timestamp,
            requestId: request.id || this.generateRequestId(),
            sessionId: this.sessionId,
            userLogin: this.userLogin,
            action: 'allow',
            appliedRules: []
        };

        try {
            // Client-side kontrol
            if (this.mode.clientSide && !this.canEnforceClientSide(request)) {
                return await this.delegateToServer(request, botClassification);
            }

            // Rate limit kontrolü
            const rateLimitCheck = await this.checkRateLimit(request);
            if (rateLimitCheck.limited) {
                return this.finalizePolicyDecision({
                    ...policyDecision,
                    action: 'rateLimit',
                    details: rateLimitCheck
                });
            }

            // Bot kategori kontrolü
            const categoryPolicy = await this.getBotCategoryPolicy(botClassification);
            if (this.mode.clientSide && !categoryPolicy.clientSideAllowed) {
                return await this.delegateToServer(request, botClassification);
            }

            // Enforcement action belirleme
            const enforcementAction = this.determineEnforcementAction(
                categoryPolicy,
                botClassification.score
            );

            // Custom rule değerlendirmesi
            const customRuleCheck = await this.evaluateCustomRules(request, botClassification);

            // Final karar
            const finalDecision = await this.makeFinalDecision(
                enforcementAction,
                customRuleCheck,
                request
            );

            // Sync with server if needed
            if (this.mode.clientSide && this.shouldSyncWithServer(finalDecision)) {
                await this.syncDecisionWithServer(finalDecision);
            }

            return this.finalizePolicyDecision({
                ...policyDecision,
                ...finalDecision
            });

        } catch (error) {
            this.log('error', 'Policy enforcement error', error);
            return this.handleEnforcementError(error, policyDecision);
        }
    }

    async checkRateLimit(request) {
        const config = this.policyConfig.enforcement.rateLimit;
        if (!config.enabled) return { limited: false };

        const key = this.getRateLimitKey(request);
        const limits = this.mode.clientSide ? 
            config.maxRequests[request.type || 'default'].client :
            config.maxRequests[request.type || 'default'].server;

        const current = await this.getRateLimitState(key);

        if (Date.now() >= current.reset) {
            current.count = 0;
            current.reset = Date.now() + config.window;
        }

        const limited = current.count >= limits;

        if (!limited) {
            current.count++;
            await this.updateRateLimitState(key, current);

            // Client-side sync check
            if (this.mode.clientSide && 
                (current.count / limits) >= config.syncThreshold) {
                await this.syncRateLimitWithServer(key, current);
            }
        }

        return {
            limited,
            current: current.count,
            limit: limits,
            reset: current.reset,
            remaining: Math.max(0, limits - current.count)
        };
    }

        // Client-Side Specific Methods
        async initializeClientMode() {
            this.timestamp = '2025-03-17 10:23:11';
            this.userLogin = 'Yldrm2015';
    
            // Client state initialization
            this.clientState = {
                syncQueue: new Map(),
                pendingDecisions: new Map(),
                localCache: new Map(),
                eventHandlers: new Map()
            };
    
            // Setup client-side event listeners
            await this.setupClientEventListeners();
            
            // Initial sync with server
            await this.performInitialSync();
            
            // Start client-side periodic tasks
            this.startClientPeriodicTasks();
        }
    
        async setupClientEventListeners() {
            // Policy update event listener
            window.addEventListener('policyUpdate', async (event) => {
                try {
                    await this.handlePolicyUpdate(event.detail);
                } catch (error) {
                    this.log('error', 'Policy update handler failed', error);
                }
            });
    
            // Sync status event listener
            window.addEventListener('syncStatus', async (event) => {
                try {
                    await this.handleSyncStatus(event.detail);
                } catch (error) {
                    this.log('error', 'Sync status handler failed', error);
                }
            });
        }
    
        async performInitialSync() {
            try {
                const response = await fetch(this.policyConfig.api.endpoints.sync, {
                    method: 'GET',
                    headers: {
                        'X-Session-ID': this.sessionId,
                        'X-Bot-Policy-Version': this.policyConfig.general.version,
                        'X-Bot-Policy-Mode': 'client'
                    }
                });
    
                if (response.ok) {
                    const syncData = await response.json();
                    await this.processSyncData(syncData);
                    this.state.sync.lastSync = this.timestamp;
                    this.state.sync.status = 'synced';
                } else {
                    throw new Error('Initial sync failed');
                }
            } catch (error) {
                this.log('error', 'Initial sync failed', error);
                this.state.sync.status = 'failed';
            }
        }
    
        async syncDecisionWithServer(decision) {
            const syncKey = `${decision.requestId}_${this.timestamp}`;
            this.clientState.syncQueue.set(syncKey, decision);
    
            try {
                const response = await fetch(this.policyConfig.api.endpoints.enforce, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Session-ID': this.sessionId,
                        'X-Bot-Policy-Version': this.policyConfig.general.version
                    },
                    body: JSON.stringify({
                        decision,
                        timestamp: this.timestamp,
                        sessionId: this.sessionId
                    })
                });
    
                if (response.ok) {
                    const serverDecision = await response.json();
                    this.clientState.syncQueue.delete(syncKey);
                    return this.reconcileDecisions(decision, serverDecision);
                } else {
                    throw new Error('Decision sync failed');
                }
            } catch (error) {
                this.log('error', 'Decision sync failed', error);
                return decision; // Fall back to client decision
            }
        }
    
        // Server-Side Specific Methods
        async initializeServerMode() {
            this.timestamp = '2025-03-17 10:23:11';
            this.userLogin = 'Yldrm2015';
    
            // Server state initialization
            this.serverState = {
                activeSessions: new Map(),
                policyCache: new Map(),
                rateLimiters: new Map(),
                syncStatus: new Map()
            };
    
            // Initialize server-side components
            await this.initializeServerComponents();
            
            // Load server-side policies
            await this.loadServerPolicies();
            
            // Start server-side periodic tasks
            this.startServerPeriodicTasks();
        }
    
        async initializeServerComponents() {
            // Initialize rate limiter
            this.rateLimiter = {
                async check(key, limit, window) {
                    const current = this.serverState.rateLimiters.get(key) || {
                        count: 0,
                        reset: Date.now() + window
                    };
    
                    if (Date.now() >= current.reset) {
                        current.count = 0;
                        current.reset = Date.now() + window;
                    }
    
                    const limited = current.count >= limit;
                    if (!limited) {
                        current.count++;
                        this.serverState.rateLimiters.set(key, current);
                    }
    
                    return {
                        limited,
                        current: current.count,
                        limit,
                        reset: current.reset,
                        remaining: Math.max(0, limit - current.count)
                    };
                }
            };
    
            // Initialize policy validator
            this.policyValidator = {
                async validate(policy) {
                    // Policy validation logic
                    const validationResult = {
                        valid: true,
                        errors: []
                    };
    
                    // Check required fields
                    if (!policy.action) {
                        validationResult.valid = false;
                        validationResult.errors.push('Missing required field: action');
                    }
    
                    // Check policy format
                    if (policy.rules && !Array.isArray(policy.rules)) {
                        validationResult.valid = false;
                        validationResult.errors.push('Invalid rules format');
                    }
    
                    return validationResult;
                }
            };
    
            // Initialize sync manager
            this.syncManager = {
                sessions: new Map(),
    
                async trackSession(sessionId, clientData) {
                    this.sessions.set(sessionId, {
                        lastSync: this.timestamp,
                        clientVersion: clientData.version,
                        syncCount: 0,
                        status: 'active'
                    });
                },
    
                async updateSession(sessionId, status) {
                    const session = this.sessions.get(sessionId);
                    if (session) {
                        session.lastSync = this.timestamp;
                        session.syncCount++;
                        session.status = status;
                        this.sessions.set(sessionId, session);
                    }
                }
            };
        }
    
        async handleClientSync(request) {
            const sessionId = request.headers['x-session-id'];
            const clientVersion = request.headers['x-bot-policy-version'];
    
            try {
                // Track sync request
                await this.syncManager.trackSession(sessionId, {
                    version: clientVersion,
                    timestamp: this.timestamp
                });
    
                // Get policies for client
                const clientPolicies = await this.getClientPolicies(sessionId);
    
                // Update sync status
                await this.syncManager.updateSession(sessionId, 'synced');
    
                return {
                    status: 'success',
                    timestamp: this.timestamp,
                    policies: clientPolicies,
                    syncToken: this.generateSyncToken(sessionId)
                };
            } catch (error) {
                this.log('error', 'Client sync handler failed', error);
                throw error;
            }
        }
    
        async getClientPolicies(sessionId) {
            // Filter policies for client-side use
            const allPolicies = Array.from(this.state.policies.values());
            return allPolicies.filter(policy => 
                policy.clientSideEnforcement?.enabled || 
                policy.clientSideAllowed
            );
        }
    
        generateSyncToken(sessionId) {
            return `sync_${sessionId}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        }

            // Utility Methods
    timestamp = '2025-03-17 10:25:03';
    userLogin = 'Yldrm2015';

    // Periodic Tasks
    startPeriodicTasks() {
        if (this.mode.clientSide) {
            // Client-side periodic tasks
            setInterval(() => this.syncWithServer(), 
                this.policyConfig.general.syncInterval);
            
            setInterval(() => this.cleanupClientCache(), 
                this.policyConfig.storage.client.maxAge * 1000);
        } else {
            // Server-side periodic tasks
            setInterval(() => this.cleanupServerCache(), 
                this.policyConfig.storage.server.maxAge * 1000);
            
            setInterval(() => this.checkActiveSessions(), 
                this.policyConfig.general.updateInterval);
        }

        // Common periodic tasks
        setInterval(() => this.updateStats(), 60000); // Her dakika
    }

    async cleanupClientCache() {
        try {
            const now = Date.now();
            
            // Clear expired items from local cache
            for (const [key, value] of this.clientState.localCache) {
                if (value.expiry && value.expiry < now) {
                    this.clientState.localCache.delete(key);
                }
            }

            // Clear old sync queue items
            for (const [key, value] of this.clientState.syncQueue) {
                if (now - value.timestamp > 3600000) { // 1 saat
                    this.clientState.syncQueue.delete(key);
                }
            }

            this.log('info', 'Client cache cleanup completed');
        } catch (error) {
            this.log('error', 'Client cache cleanup failed', error);
        }
    }

    async cleanupServerCache() {
        try {
            const now = Date.now();
            
            // Clear expired sessions
            for (const [sessionId, session] of this.serverState.activeSessions) {
                if (now - session.lastActivity > 86400000) { // 24 saat
                    this.serverState.activeSessions.delete(sessionId);
                }
            }

            // Clear expired rate limiters
            for (const [key, limiter] of this.serverState.rateLimiters) {
                if (now > limiter.reset) {
                    this.serverState.rateLimiters.delete(key);
                }
            }

            this.log('info', 'Server cache cleanup completed');
        } catch (error) {
            this.log('error', 'Server cache cleanup failed', error);
        }
    }

    // Helper Methods
    formatTimestamp(date = new Date()) {
        return date.toISOString().replace('T', ' ').slice(0, 19);
    }

    generateRequestId() {
        return `req_${this.timestamp.replace(/[^0-9]/g, '')}_${Math.random().toString(36).substr(2, 9)}`;
    }

    calculateHash(data) {
        if (this.mode.clientSide) {
            // Client-side hashing
            const str = JSON.stringify(data);
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const char = str.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return hash.toString(36);
        } else {
            // Server-side hashing
            const crypto = require('crypto');
            return crypto
                .createHash('sha256')
                .update(JSON.stringify(data))
                .digest('hex');
        }
    }

    // Error Handling Methods
    handleError(error, context = {}) {
        const errorInfo = {
            timestamp: this.timestamp,
            error: {
                name: error.name,
                message: error.message,
                stack: this.policyConfig.general.debug ? error.stack : undefined
            },
            context: {
                mode: this.mode,
                sessionId: this.sessionId,
                ...context
            }
        };

        // Log error
        this.log('error', error.message, errorInfo);

        // Notify if needed
        if (this.shouldNotifyError(error)) {
            this.notifyError(errorInfo);
        }

        return errorInfo;
    }

    shouldNotifyError(error) {
        // Check if error needs notification
        return error.severity === 'high' || 
               error.critical || 
               error.security;
    }

    async notifyError(errorInfo) {
        if (this.mode.clientSide) {
            // Client-side notification
            if (this.policyConfig.notifications.channels.client.console.enabled) {
                console.error('Bot Policy Error:', errorInfo);
            }
            if (this.policyConfig.notifications.channels.client.customEvent.enabled) {
                window.dispatchEvent(new CustomEvent(
                    'botPolicyError',
                    { detail: errorInfo }
                ));
            }
        } else {
            // Server-side notification
            for (const [channel, config] of Object.entries(
                this.policyConfig.notifications.channels.server
            )) {
                if (config.enabled) {
                    await this.sendNotification(channel, errorInfo);
                }
            }
        }
    }

    // Stats and Metrics
    updateStats() {
        const currentStats = {
            timestamp: this.timestamp,
            mode: this.mode,
            session: {
                id: this.sessionId,
                duration: Date.now() - new Date(this.state.sync.lastSync).getTime()
            },
            enforcement: {
                total: this.state.stats.enforced,
                blocked: this.state.stats.blocked,
                challenged: this.state.stats.challenged,
                whitelisted: this.state.stats.whitelisted
            },
            sync: {
                status: this.state.sync.status,
                lastSync: this.state.sync.lastSync,
                syncCount: this.state.stats.synced
            },
            performance: {
                averageResponseTime: this.calculateAverageResponseTime(),
                cacheHitRate: this.calculateCacheHitRate(),
                errorRate: this.calculateErrorRate()
            }
        };

        // Update stats in storage
        this.storage.set('stats', currentStats);

        // Report stats if needed
        if (this.mode.clientSide && this.shouldReportStats()) {
            this.reportStatsToServer(currentStats);
        }

        return currentStats;
    }

    calculateAverageResponseTime() {
        // Implementation of response time calculation
        return 0; // Placeholder
    }

    calculateCacheHitRate() {
        // Implementation of cache hit rate calculation
        return 0; // Placeholder
    }

    calculateErrorRate() {
        // Implementation of error rate calculation
        return 0; // Placeholder
    }

    // Public API Methods
    getStatus() {
        return {
            timestamp: this.timestamp,
            version: this.policyConfig.general.version,
            mode: this.mode,
            session: {
                id: this.sessionId,
                status: this.state.sync.status
            },
            stats: this.state.stats,
            health: {
                status: 'healthy',
                lastCheck: this.timestamp,
                details: this.getHealthDetails()
            }
        };
    }

    getHealthDetails() {
        return {
            storage: this.checkStorageHealth(),
            sync: this.checkSyncHealth(),
            enforcement: this.checkEnforcementHealth()
        };
    }
}

// Export the class
if (typeof module !== 'undefined' && module.exports) {
    module.exports = BotPolicyManager;
} else if (typeof window !== 'undefined') {
    window.BotPolicyManager = BotPolicyManager;
}


