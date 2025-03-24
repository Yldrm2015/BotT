(function(window) {
    'use strict';

    class AlertManager {
        static instance = null;
        timestamp = '2025-03-17 10:53:45';
        userLogin = 'Yldrm2015';

        static getInstance() {
            if (!AlertManager.instance) {
                AlertManager.instance = new AlertManager();
            }
            return AlertManager.instance;
        }

        constructor() {
            if (AlertManager.instance) {
                return AlertManager.instance;
            }

            // Browser uyumluluk kontrolü
            this.checkBrowserCompatibility();

            // Temel konfigürasyon
            this.alertConfig = {
                general: {
                    enabled: true,
                    environment: 'production',
                    maxAlerts: 1000,
                    retentionPeriod: 604800000, // 7 days
                    batchProcessing: true,
                    webWorker: true
                },
                severity: {
                    levels: ['critical', 'high', 'medium', 'low', 'info'],
                    thresholds: {
                        critical: 90,
                        high: 70,
                        medium: 50,
                        low: 30,
                        info: 0
                    },
                    autoEscalation: {
                        enabled: true,
                        threshold: 3,
                        timeWindow: 3600000 // 1 hour
                    }
                },
                notification: {
                    channels: {
                        console: {
                            enabled: true,
                            minSeverity: 'low'
                        },
                        browser: {
                            enabled: true,
                            minSeverity: 'medium',
                            requirePermission: true,
                            icon: '/path/to/icon.png'
                        },
                        webhook: {
                            enabled: true,
                            endpoint: '/api/alerts',
                            minSeverity: 'high',
                            retryAttempts: 3,
                            retryDelay: 5000,
                            timeout: 5000
                        }
                    },
                    templates: {
                        console: '[{severity}] {message}',
                        browser: '{title}: {message}',
                        webhook: {
                            format: 'json',
                            includeMetadata: true
                        }
                    }
                },
                storage: {
                    type: 'localStorage',
                    prefix: 'alertManager_',
                    encryption: true,
                    compression: true,
                    maxAge: 604800000, // 7 days
                    syncInterval: 300000 // 5 minutes
                },
                aggregation: {
                    enabled: true,
                    timeWindow: 300000, // 5 minutes
                    similarityThreshold: 0.8,
                    maxGroupSize: 10,
                    webWorker: true
                },
                performance: {
                    maxQueueSize: 1000,
                    processInterval: 1000, // 1 second
                    batchSize: 50,
                    maxWorkers: 4
                }
            };

            // State yönetimi
            this.state = {
                alerts: [],
                alertGroups: new Map(),
                queue: [],
                processing: false,
                online: navigator.onLine,
                notificationPermission: Notification.permission,
                workers: new Map(),
                stats: {
                    total: 0,
                    bySeverity: {
                        critical: 0,
                        high: 0,
                        medium: 0,
                        low: 0,
                        info: 0
                    },
                    lastAlert: null,
                    startTime: this.timestamp
                }
            };

            // Web worker ve event sistemini başlat
            this.initializeSystem();

            AlertManager.instance = this;
        }

        checkBrowserCompatibility() {
            this.supports = {
                localStorage: (() => {
                    try {
                        localStorage.setItem('test', 'test');
                        localStorage.removeItem('test');
                        return true;
                    } catch (e) {
                        return false;
                    }
                })(),
                notifications: 'Notification' in window,
                webWorkers: 'Worker' in window,
                compression: 'CompressionStream' in window,
                crypto: 'crypto' in window && 'subtle' in window.crypto,
                indexedDB: 'indexedDB' in window,
                serviceWorker: 'serviceWorker' in navigator,
                webSocket: 'WebSocket' in window
            };

            // Feature detection sonuçlarını logla
            console.log('[AlertManager] Browser compatibility:', this.supports);
        }

        initializeSystem() {
            // Event listener'ları kur
            this.setupEventListeners();

            // Web worker'ları başlat
            if (this.supports.webWorkers && this.alertConfig.general.webWorker) {
                this.initializeWorkers();
            }

            // Notification izinlerini kontrol et
            if (this.supports.notifications) {
                this.checkNotificationPermission();
            }

            // Storage'dan state'i yükle
            this.loadState();

            // Periodic tasks'ları başlat
            this.startPeriodicTasks();

            console.log(`[${this.timestamp}] AlertManager initialized successfully`);
        }

        setupEventListeners() {
            // Window events
            window.addEventListener('online', () => this.handleOnline());
            window.addEventListener('offline', () => this.handleOffline());
            window.addEventListener('beforeunload', () => this.handleBeforeUnload());

            // Custom events
            window.addEventListener('alertmanager', (e) => this.handleCustomEvent(e));
        }

        // Event handlers
        handleOnline() {
            this.state.online = true;
            this.processQueue();
        }

        handleOffline() {
            this.state.online = false;
        }

        handleBeforeUnload() {
            this.saveState();
        }

        handleCustomEvent(event) {
            const { type, data } = event.detail;
            switch(type) {
                case 'createAlert':
                    this.createAlert(data);
                    break;
                case 'clearAlerts':
                    this.clearAlerts();
                    break;
                // Diğer custom event handler'lar
            }
        }
    }

    // Global scope'a ekle
    window.AlertManager = AlertManager;

})(window);

(function(window) {
    'use strict';

    // Part 2: Web Workers ve Event Yönetimi
    class AlertManagerWorkers {
        timestamp = '2025-03-17 11:04:56';
        userLogin = 'Yldrm2015';

        constructor(manager) {
            this.manager = manager;
            this.workers = new Map();
            this.taskQueue = [];
            this.isProcessing = false;
        }

        initializeWorkers() {
            if (!this.manager.supports.webWorkers) return;

            const workerTypes = {
                aggregation: 'alertAggregationWorker.js',
                processing: 'alertProcessingWorker.js',
                analysis: 'alertAnalysisWorker.js',
                storage: 'alertStorageWorker.js'
            };

            for (const [type, script] of Object.entries(workerTypes)) {
                try {
                    const worker = new Worker(script);
                    worker.onmessage = (e) => this.handleWorkerMessage(type, e);
                    worker.onerror = (e) => this.handleWorkerError(type, e);
                    this.workers.set(type, worker);
                } catch (error) {
                    console.error(`Failed to initialize ${type} worker:`, error);
                }
            }
        }

        handleWorkerMessage(type, event) {
            const { action, data } = event.data;

            switch (action) {
                case 'alertProcessed':
                    this.manager.handleProcessedAlert(data);
                    break;
                case 'aggregationComplete':
                    this.manager.handleAggregationResult(data);
                    break;
                case 'analysisComplete':
                    this.manager.handleAnalysisResult(data);
                    break;
                case 'storageSync':
                    this.manager.handleStorageSync(data);
                    break;
                case 'error':
                    this.handleWorkerError(type, data);
                    break;
            }

            this.processNextTask();
        }

        handleWorkerError(type, error) {
            console.error(`Worker error (${type}):`, error);
            this.manager.createSystemAlert({
                title: 'Worker Error',
                message: `Error in ${type} worker: ${error.message}`,
                severity: 'high',
                category: 'system'
            });

            // Worker'ı yeniden başlat
            this.restartWorker(type);
        }

        restartWorker(type) {
            const worker = this.workers.get(type);
            if (worker) {
                worker.terminate();
                this.initializeWorker(type);
            }
        }

        queueTask(type, task) {
            this.taskQueue.push({ type, task });
            if (!this.isProcessing) {
                this.processNextTask();
            }
        }

        async processNextTask() {
            if (this.taskQueue.length === 0) {
                this.isProcessing = false;
                return;
            }

            this.isProcessing = true;
            const { type, task } = this.taskQueue.shift();
            const worker = this.workers.get(type);

            if (worker) {
                worker.postMessage(task);
            } else {
                console.warn(`Worker ${type} not available, processing in main thread`);
                await this.processInMainThread(type, task);
                this.processNextTask();
            }
        }

        async processInMainThread(type, task) {
            try {
                let result;
                switch (type) {
                    case 'aggregation':
                        result = await this.manager.performAggregation(task.data);
                        break;
                    case 'processing':
                        result = await this.manager.processAlertSync(task.data);
                        break;
                    case 'analysis':
                        result = await this.manager.analyzeAlertSync(task.data);
                        break;
                    case 'storage':
                        result = await this.manager.handleStorageSync(task.data);
                        break;
                }
                this.handleWorkerMessage(type, { data: { action: `${type}Complete`, data: result } });
            } catch (error) {
                this.handleWorkerError(type, error);
            }
        }

        terminateWorkers() {
            for (const [type, worker] of this.workers) {
                try {
                    worker.terminate();
                    console.log(`Worker ${type} terminated`);
                } catch (error) {
                    console.error(`Error terminating ${type} worker:`, error);
                }
            }
            this.workers.clear();
        }
    }

    class AlertManagerEvents {
        timestamp = '2025-03-17 11:04:56';
        userLogin = 'Yldrm2015';

        constructor(manager) {
            this.manager = manager;
            this.eventQueue = [];
            this.isProcessing = false;
            this.setupEventSystem();
        }

        setupEventSystem() {
            // Custom event listener
            window.addEventListener('alertmanager', (e) => this.handleCustomEvent(e));

            // Browser events
            window.addEventListener('online', () => this.handleOnlineStatus(true));
            window.addEventListener('offline', () => this.handleOnlineStatus(false));
            window.addEventListener('visibilitychange', () => this.handleVisibilityChange());
            window.addEventListener('beforeunload', (e) => this.handleBeforeUnload(e));

            // Performance monitoring
            if ('PerformanceObserver' in window) {
                this.setupPerformanceMonitoring();
            }
        }

        handleCustomEvent(event) {
            const { type, data } = event.detail;
            this.queueEvent({ type, data });
        }

        queueEvent(event) {
            this.eventQueue.push({
                ...event,
                timestamp: this.timestamp,
                queuedAt: Date.now()
            });

            if (!this.isProcessing) {
                this.processEventQueue();
            }
        }

        async processEventQueue() {
            if (this.eventQueue.length === 0) {
                this.isProcessing = false;
                return;
            }

            this.isProcessing = true;
            const event = this.eventQueue.shift();

            try {
                await this.processEvent(event);
            } catch (error) {
                console.error('Event processing error:', error);
                this.handleEventError(event, error);
            }

            // Process next event
            this.processEventQueue();
        }

        async processEvent(event) {
            const { type, data } = event;

            switch (type) {
                case 'createAlert':
                    await this.manager.createAlert(data);
                    break;
                case 'updateAlert':
                    await this.manager.updateAlert(data);
                    break;
                case 'deleteAlert':
                    await this.manager.deleteAlert(data);
                    break;
                case 'clearAlerts':
                    await this.manager.clearAlerts();
                    break;
                default:
                    console.warn('Unknown event type:', type);
            }
        }

        handleOnlineStatus(isOnline) {
            this.manager.state.online = isOnline;
            this.dispatchStatusEvent({
                type: isOnline ? 'online' : 'offline',
                timestamp: this.timestamp
            });

            if (isOnline) {
                this.manager.processPendingAlerts();
            }
        }

        handleVisibilityChange() {
            if (document.visibilityState === 'visible') {
                this.manager.refreshAlerts();
            }
        }

        handleBeforeUnload(event) {
            if (this.manager.hasPendingChanges()) {
                event.preventDefault();
                event.returnValue = '';
                return '';
            }
        }

        dispatchStatusEvent(status) {
            const event = new CustomEvent('alertmanagerStatus', {
                detail: status,
                bubbles: true,
                cancelable: true
            });
            window.dispatchEvent(event);
        }

        setupPerformanceMonitoring() {
            const observer = new PerformanceObserver((list) => {
                for (const entry of list.getEntries()) {
                    if (entry.duration > 100) { // 100ms threshold
                        console.warn('Long task detected:', entry);
                        this.handlePerformanceIssue(entry);
                    }
                }
            });

            observer.observe({ entryTypes: ['longtask', 'measure'] });
        }

        handlePerformanceIssue(entry) {
            this.manager.createSystemAlert({
                title: 'Performance Issue Detected',
                message: `Long task detected: ${entry.name} (${Math.round(entry.duration)}ms)`,
                severity: 'medium',
                category: 'performance'
            });
        }
    }

    // Ana AlertManager sınıfına entegre et
    window.AlertManager.Workers = AlertManagerWorkers;
    window.AlertManager.Events = AlertManagerEvents;

})(window);

(function(window) {
    'use strict';

    // Part 3: Storage ve State Management
    class AlertManagerStorage {
        timestamp = '2025-03-17 11:06:22';
        userLogin = 'Yldrm2015';

        constructor(manager) {
            this.manager = manager;
            this.prefix = this.manager.alertConfig.storage.prefix;
            this.initializeStorage();
        }

        async initializeStorage() {
            this.storageType = this.determineStorageType();
            await this.setupStorage();
            this.startStorageSync();
        }

        determineStorageType() {
            const config = this.manager.alertConfig.storage;

            if (config.type === 'indexedDB' && this.manager.supports.indexedDB) {
                return 'indexedDB';
            } else if (config.type === 'localStorage' && this.manager.supports.localStorage) {
                return 'localStorage';
            } else {
                console.warn('Falling back to memory storage');
                return 'memory';
            }
        }

        async setupStorage() {
            switch (this.storageType) {
                case 'indexedDB':
                    await this.setupIndexedDB();
                    break;
                case 'localStorage':
                    this.setupLocalStorage();
                    break;
                case 'memory':
                    this.setupMemoryStorage();
                    break;
            }
        }

        async setupIndexedDB() {
            return new Promise((resolve, reject) => {
                const request = indexedDB.open('AlertManagerDB', 1);

                request.onerror = () => reject(request.error);
                request.onsuccess = () => {
                    this.db = request.result;
                    resolve();
                };

                request.onupgradeneeded = (event) => {
                    const db = event.target.result;
                    
                    // Alerts store
                    if (!db.objectStoreNames.contains('alerts')) {
                        const alertStore = db.createObjectStore('alerts', { keyPath: 'id' });
                        alertStore.createIndex('timestamp', 'timestamp');
                        alertStore.createIndex('severity', 'severity');
                    }

                    // Groups store
                    if (!db.objectStoreNames.contains('alertGroups')) {
                        const groupStore = db.createObjectStore('alertGroups', { keyPath: 'id' });
                        groupStore.createIndex('lastUpdate', 'lastUpdate');
                    }
                };
            });
        }

        setupLocalStorage() {
            this.storage = {
                getItem: (key) => {
                    const value = localStorage.getItem(this.prefix + key);
                    return value ? this.decrypt(value) : null;
                },
                setItem: (key, value) => {
                    const encrypted = this.encrypt(value);
                    localStorage.setItem(this.prefix + key, encrypted);
                },
                removeItem: (key) => {
                    localStorage.removeItem(this.prefix + key);
                },
                clear: () => {
                    Object.keys(localStorage)
                        .filter(key => key.startsWith(this.prefix))
                        .forEach(key => localStorage.removeItem(key));
                }
            };
        }

        setupMemoryStorage() {
            const memoryStore = new Map();
            this.storage = {
                getItem: (key) => memoryStore.get(key),
                setItem: (key, value) => memoryStore.set(key, value),
                removeItem: (key) => memoryStore.delete(key),
                clear: () => memoryStore.clear()
            };
        }

        async saveAlert(alert) {
            const processed = await this.processForStorage(alert);

            switch (this.storageType) {
                case 'indexedDB':
                    await this.saveToIndexedDB('alerts', processed);
                    break;
                case 'localStorage':
                    this.storage.setItem(`alert:${alert.id}`, JSON.stringify(processed));
                    break;
                case 'memory':
                    this.storage.setItem(`alert:${alert.id}`, processed);
                    break;
            }
        }

        async processForStorage(data) {
            let processed = { ...data };

            if (this.manager.alertConfig.storage.compression) {
                processed = await this.compress(processed);
            }

            return processed;
        }

        async compress(data) {
            if (!this.manager.supports.compression) return data;

            try {
                const jsonString = JSON.stringify(data);
                const encoder = new TextEncoder();
                const encoded = encoder.encode(jsonString);
                
                const cs = new CompressionStream('gzip');
                const writer = cs.writable.getWriter();
                writer.write(encoded);
                writer.close();
                
                return new Response(cs.readable).arrayBuffer();
            } catch (error) {
                console.error('Compression failed:', error);
                return data;
            }
        }

        encrypt(data) {
            if (!this.manager.alertConfig.storage.encryption) return data;

            try {
                // Basic encryption for demo (In production use Web Crypto API)
                const text = JSON.stringify(data);
                return btoa(text);
            } catch (error) {
                console.error('Encryption failed:', error);
                return data;
            }
        }

        decrypt(data) {
            if (!this.manager.alertConfig.storage.encryption) return data;

            try {
                // Basic decryption for demo
                const text = atob(data);
                return JSON.parse(text);
            } catch (error) {
                console.error('Decryption failed:', error);
                return data;
            }
        }

        async saveToIndexedDB(storeName, data) {
            return new Promise((resolve, reject) => {
                const transaction = this.db.transaction([storeName], 'readwrite');
                const store = transaction.objectStore(storeName);
                const request = store.put(data);

                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });
        }

        async getFromIndexedDB(storeName, key) {
            return new Promise((resolve, reject) => {
                const transaction = this.db.transaction([storeName], 'readonly');
                const store = transaction.objectStore(storeName);
                const request = store.get(key);

                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(request.error);
            });
        }

        startStorageSync() {
            const syncInterval = this.manager.alertConfig.storage.syncInterval;
            
            setInterval(() => {
                this.syncStorage().catch(error => {
                    console.error('Storage sync failed:', error);
                });
            }, syncInterval);
        }

        async syncStorage() {
            const lastSync = await this.getLastSyncTimestamp();
            const updates = await this.getUpdatesSince(lastSync);

            if (updates.length > 0) {
                await this.applyUpdates(updates);
                await this.updateLastSyncTimestamp();
            }
        }

        async getLastSyncTimestamp() {
            return this.storage.getItem('lastSync') || 0;
        }

        async updateLastSyncTimestamp() {
            this.storage.setItem('lastSync', Date.now());
        }

        async cleanup() {
            const maxAge = this.manager.alertConfig.storage.maxAge;
            const cutoff = Date.now() - maxAge;

            switch (this.storageType) {
                case 'indexedDB':
                    await this.cleanupIndexedDB(cutoff);
                    break;
                case 'localStorage':
                    this.cleanupLocalStorage(cutoff);
                    break;
                case 'memory':
                    this.cleanupMemoryStorage(cutoff);
                    break;
            }
        }

        destroy() {
            if (this.db) {
                this.db.close();
            }
            this.storage?.clear();
        }
    }

    // Ana AlertManager sınıfına entegre et
    window.AlertManager.Storage = AlertManagerStorage;

})(window);

(function(window) {
    'use strict';

    // Part 4: Notification ve Browser API Entegrasyonları
    class AlertManagerNotifications {
        timestamp = '2025-03-17 11:07:32';
        userLogin = 'Yldrm2015';

        constructor(manager) {
            this.manager = manager;
            this.notificationQueue = [];
            this.isProcessing = false;
            this.setupNotifications();
        }

        async setupNotifications() {
            if (!this.manager.supports.notifications) {
                console.warn('Browser notifications not supported');
                return;
            }

            await this.requestNotificationPermission();
            this.setupServiceWorker();
        }

        async requestNotificationPermission() {
            try {
                const permission = await Notification.requestPermission();
                this.manager.state.notificationPermission = permission;
                
                if (permission === 'granted') {
                    console.log('Notification permission granted');
                } else {
                    console.warn('Notification permission not granted:', permission);
                }
            } catch (error) {
                console.error('Error requesting notification permission:', error);
            }
        }

        async setupServiceWorker() {
            if (!this.manager.supports.serviceWorker) return;

            try {
                const registration = await navigator.serviceWorker.register(
                    '/alertManagerServiceWorker.js'
                );
                
                registration.addEventListener('push', (event) => {
                    const data = event.data?.json() ?? {};
                    this.handlePushNotification(data);
                });
            } catch (error) {
                console.error('Service Worker registration failed:', error);
            }
        }

        async notify(alert) {
            if (!this.canNotify(alert)) return;

            this.notificationQueue.push(alert);
            if (!this.isProcessing) {
                this.processNotificationQueue();
            }
        }

        async processNotificationQueue() {
            if (this.notificationQueue.length === 0) {
                this.isProcessing = false;
                return;
            }

            this.isProcessing = true;
            const alert = this.notificationQueue.shift();

            try {
                await this.showNotification(alert);
            } catch (error) {
                console.error('Notification failed:', error);
                this.handleNotificationError(alert, error);
            }

            // Rate limiting
            await this.delay(1000);
            this.processNotificationQueue();
        }

        canNotify(alert) {
            if (!this.manager.supports.notifications) return false;
            if (this.manager.state.notificationPermission !== 'granted') return false;
            if (!document.hidden) return false; // Only notify if page is hidden

            const config = this.manager.alertConfig.notification.channels.browser;
            return this.manager.isSeverityAboveThreshold(
                alert.severity, 
                config.minSeverity
            );
        }

        async showNotification(alert) {
            const config = this.manager.alertConfig.notification.channels.browser;
            const options = this.createNotificationOptions(alert);

            try {
                if (this.manager.supports.serviceWorker) {
                    const registration = await navigator.serviceWorker.ready;
                    await registration.showNotification(alert.title, options);
                } else {
                    new Notification(alert.title, options);
                }

                this.logNotification(alert);
            } catch (error) {
                throw new Error(`Notification failed: ${error.message}`);
            }
        }

        createNotificationOptions(alert) {
            const config = this.manager.alertConfig.notification.channels.browser;
            
            return {
                body: alert.message,
                icon: this.getAlertIcon(alert.severity),
                badge: this.getAlertBadge(alert.severity),
                tag: alert.id,
                renotify: true,
                requireInteraction: alert.severity === 'critical',
                silent: alert.severity === 'info',
                timestamp: Date.now(),
                data: {
                    alertId: alert.id,
                    url: window.location.href,
                    timestamp: this.timestamp
                },
                actions: this.getNotificationActions(alert)
            };
        }

        getNotificationActions(alert) {
            const actions = [];

            if (alert.severity === 'critical' || alert.severity === 'high') {
                actions.push({
                    action: 'view',
                    title: 'View Details',
                    icon: '/icons/view.png'
                });
            }

            if (alert.actionable) {
                actions.push({
                    action: 'resolve',
                    title: 'Resolve',
                    icon: '/icons/resolve.png'
                });
            }

            return actions;
        }

        getAlertIcon(severity) {
            const icons = {
                critical: '/icons/critical.png',
                high: '/icons/high.png',
                medium: '/icons/medium.png',
                low: '/icons/low.png',
                info: '/icons/info.png'
            };
            return icons[severity] || icons.info;
        }

        getAlertBadge(severity) {
            const badges = {
                critical: '/badges/critical.png',
                high: '/badges/high.png',
                medium: '/badges/medium.png',
                low: '/badges/low.png',
                info: '/badges/info.png'
            };
            return badges[severity] || badges.info;
        }

        handlePushNotification(data) {
            const alert = {
                id: data.alertId || this.manager.generateAlertId(),
                title: data.title,
                message: data.message,
                severity: data.severity || 'info',
                timestamp: this.timestamp,
                source: 'push',
                data: data
            };

            this.manager.processAlert(alert);
        }

        handleNotificationClick(event) {
            event.notification.close();
            const alertId = event.notification.data.alertId;

            if (event.action === 'view') {
                this.viewAlertDetails(alertId);
            } else if (event.action === 'resolve') {
                this.resolveAlert(alertId);
            }
        }

        async viewAlertDetails(alertId) {
            const alert = await this.manager.getAlert(alertId);
            if (alert) {
                this.manager.emit('viewAlertDetails', alert);
            }
        }

        async resolveAlert(alertId) {
            try {
                await this.manager.updateAlert(alertId, { status: 'resolved' });
                this.manager.emit('alertResolved', alertId);
            } catch (error) {
                console.error('Failed to resolve alert:', error);
            }
        }

        logNotification(alert) {
            this.manager.log('notification', {
                alertId: alert.id,
                timestamp: this.timestamp,
                type: 'browser',
                severity: alert.severity
            });
        }

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        }
    }

    // Final cleanup ve entegrasyon
    window.AlertManager.Notifications = AlertManagerNotifications;

    // AlertManager sistemini başlat
    document.addEventListener('DOMContentLoaded', () => {
        const manager = AlertManager.getInstance();
        console.log('[AlertManager] System initialized at:', manager.timestamp);
    });

})(window);