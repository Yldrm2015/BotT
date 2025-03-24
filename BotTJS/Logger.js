class Logger {
    constructor() {
        this.timestamp = '2025-03-13 11:41:45';
        this.userLogin = 'Yldrm2015';

        this.logConfig = {
            general: {
                enabled: true,
                level: 'info', // debug, info, warn, error
                maxEntries: 1000,
                rotationInterval: 86400000, // 24 hours
                environment: 'production'
            },
            storage: {
                type: 'localStorage',
                prefix: 'botDetection_logs_',
                encryption: true,
                maxAge: 604800000, // 7 days
                compressionEnabled: true
            },
            console: {
                enabled: true,
                colorized: true,
                showTimestamp: true,
                showLevel: true,
                filter: {
                    minLevel: 'info',
                    excludePatterns: []
                }
            },
            remote: {
                enabled: true,
                endpoint: '/api/logs',
                batchSize: 50,
                sendInterval: 60000, // 1 minute
                retryAttempts: 3,
                retryDelay: 5000,
                headers: {
                    'Content-Type': 'application/json',
                    'X-Client-Version': '2.0.0'
                }
            },
            formats: {
                timestamp: 'YYYY-MM-DD HH:mm:ss',
                messageTemplate: '[{timestamp}] [{level}] [{userLogin}]: {message}'
            }
        };

        this.logBuffer = {
            debug: [],
            info: [],
            warn: [],
            error: []
        };

        this.stats = {
            totalLogs: 0,
            errorCount: 0,
            lastLog: null,
            startTime: this.timestamp
        };

        this.initializeLogger();
    }

    initializeLogger() {
        this.setupStorageSystem();
        this.startPeriodicTasks();
        this.loadExistingLogs();
    }

    log(level, message, data = {}) {
        if (!this.isLevelEnabled(level)) return;

        const logEntry = {
            timestamp: this.timestamp,
            level: level,
            message: message,
            userLogin: this.userLogin,
            data: data,
            sessionId: this.getSessionId(),
            metadata: this.collectMetadata()
        };

        this.processLogEntry(logEntry);
        this.updateStats(logEntry);

        if (this.logConfig.console.enabled) {
            this.writeToConsole(logEntry);
        }

        if (this.logConfig.remote.enabled) {
            this.addToBuffer(logEntry);
        }

        return logEntry;
    }

    debug(message, data = {}) {
        return this.log('debug', message, data);
    }

    info(message, data = {}) {
        return this.log('info', message, data);
    }

    warn(message, data = {}) {
        return this.log('warn', message, data);
    }

    error(message, data = {}) {
        return this.log('error', message, data);
    }

    processLogEntry(entry) {
        if (this.logConfig.storage.encryption) {
            entry = this.encryptLogEntry(entry);
        }

        if (this.logConfig.storage.compressionEnabled) {
            entry = this.compressLogEntry(entry);
        }

        this.saveToPersistentStorage(entry);
    }

    encryptLogEntry(entry) {
        try {
            const encrypted = {
                ...entry,
                data: this.encrypt(JSON.stringify(entry.data)),
                metadata: this.encrypt(JSON.stringify(entry.metadata))
            };
            return encrypted;
        } catch (error) {
            this.handleEncryptionError(error);
            return entry;
        }
    }

    compressLogEntry(entry) {
        try {
            return {
                ...entry,
                data: this.compress(entry.data),
                metadata: this.compress(entry.metadata)
            };
        } catch (error) {
            this.handleCompressionError(error);
            return entry;
        }
    }

    writeToConsole(entry) {
        if (!this.shouldShowInConsole(entry.level)) return;

        const formattedMessage = this.formatConsoleMessage(entry);
        const consoleMethod = this.getConsoleMethod(entry.level);

        if (this.logConfig.console.colorized) {
            this.writeColorized(consoleMethod, formattedMessage, entry.level);
        } else {
            console[consoleMethod](formattedMessage);
        }
    }

    formatConsoleMessage(entry) {
        return this.logConfig.formats.messageTemplate
            .replace('{timestamp}', entry.timestamp)
            .replace('{level}', entry.level.toUpperCase())
            .replace('{userLogin}', entry.userLogin)
            .replace('{message}', entry.message);
    }

    writeColorized(method, message, level) {
        const colors = {
            debug: '\x1b[34m', // blue
            info: '\x1b[32m',  // green
            warn: '\x1b[33m',  // yellow
            error: '\x1b[31m'  // red
        };

        console[method](
            `${colors[level]}%s\x1b[0m`,
            message
        );
    }

    addToBuffer(entry) {
        this.logBuffer[entry.level].push(entry);

        if (this.shouldSendBufferNow()) {
            this.sendBufferToRemote();
        }
    }

    async sendBufferToRemote() {
        if (!this.hasBufferedLogs()) return;

        const logs = this.prepareLogsForRemote();
        
        try {
            await this.sendLogs(logs);
            this.clearBuffer();
        } catch (error) {
            this.handleRemoteError(error);
        }
    }

    async sendLogs(logs) {
        const response = await fetch(this.logConfig.remote.endpoint, {
            method: 'POST',
            headers: this.logConfig.remote.headers,
            body: JSON.stringify({
                logs,
                metadata: {
                    timestamp: this.timestamp,
                    userLogin: this.userLogin,
                    batchId: this.generateBatchId()
                }
            })
        });

        if (!response.ok) {
            throw new Error(`Remote logging failed: ${response.statusText}`);
        }

        return response.json();
    }

    saveToPersistentStorage(entry) {
        try {
            const key = `${this.logConfig.storage.prefix}${entry.timestamp}`;
            localStorage.setItem(key, JSON.stringify(entry));
            this.cleanOldLogs();
        } catch (error) {
            this.handleStorageError(error);
        }
    }

    cleanOldLogs() {
        const maxAge = this.logConfig.storage.maxAge;
        const prefix = this.logConfig.storage.prefix;
        
        Object.keys(localStorage)
            .filter(key => key.startsWith(prefix))
            .forEach(key => {
                try {
                    const entry = JSON.parse(localStorage.getItem(key));
                    const age = Date.now() - new Date(entry.timestamp).getTime();
                    
                    if (age > maxAge) {
                        localStorage.removeItem(key);
                    }
                } catch (error) {
                    localStorage.removeItem(key);
                }
            });
    }

    getLogStats() {
        return {
            ...this.stats,
            bufferSize: this.getBufferSize(),
            lastUpdate: this.timestamp
        };
    }

    getLogs(filter = {}) {
        const logs = this.loadLogsFromStorage();
        return this.filterLogs(logs, filter);
    }

    filterLogs(logs, { level, startTime, endTime, search }) {
        return logs.filter(log => {
            if (level && log.level !== level) return false;
            if (startTime && new Date(log.timestamp) < new Date(startTime)) return false;
            if (endTime && new Date(log.timestamp) > new Date(endTime)) return false;
            if (search && !this.searchInLog(log, search)) return false;
            return true;
        });
    }

    searchInLog(log, search) {
        const searchString = search.toLowerCase();
        return (
            log.message.toLowerCase().includes(searchString) ||
            JSON.stringify(log.data).toLowerCase().includes(searchString)
        );
    }

    clearLogs() {
        this.logBuffer = {
            debug: [],
            info: [],
            warn: [],
            error: []
        };
        this.clearPersistentStorage();
        this.resetStats();
    }

    // Utility Methods
    isLevelEnabled(level) {
        const levels = ['debug', 'info', 'warn', 'error'];
        const configLevel = this.logConfig.general.level;
        return levels.indexOf(level) >= levels.indexOf(configLevel);
    }

    getSessionId() {
        // Implementation depends on your session management
        return 'session-' + Date.now();
    }

    collectMetadata() {
        return {
            userAgent: navigator.userAgent,
            url: window.location.href,
            timestamp: this.timestamp
        };
    }

    handleEncryptionError(error) {
        console.error('Log encryption failed:', error);
    }

    handleCompressionError(error) {
        console.error('Log compression failed:', error);
    }

    handleRemoteError(error) {
        console.error('Remote logging failed:', error);
    }

    handleStorageError(error) {
        console.error('Storage operation failed:', error);
    }
}