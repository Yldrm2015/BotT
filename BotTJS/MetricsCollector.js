class MetricsCollector {
    constructor() {
        this.timestamp = '2025-03-14 08:09:52';
        this.userLogin = 'Yldrm2015';

        this.metricsConfig = {
            general: {
                enabled: true,
                environment: 'production',
                sampleInterval: 5000, // 5 seconds
                maxDataPoints: 1000,
                autoCleanup: true
            },
            categories: {
                performance: {
                    enabled: true,
                    metrics: ['cpu', 'memory', 'loadTime', 'fps'],
                    sampleRate: 1000
                },
                network: {
                    enabled: true,
                    metrics: ['latency', 'bandwidth', 'requests', 'errors'],
                    sampleRate: 5000
                },
                behavior: {
                    enabled: true,
                    metrics: ['mouseMovements', 'keystrokes', 'scrolling', 'clicks'],
                    sampleRate: 2000
                },
                security: {
                    enabled: true,
                    metrics: ['failedAttempts', 'suspiciousActivities', 'anomalyScore'],
                    sampleRate: 10000
                }
            },
            storage: {
                type: 'localStorage',
                prefix: 'botDetection_metrics_',
                encryption: true,
                compression: true,
                maxAge: 604800000, // 7 days
                cleanupInterval: 86400000 // 24 hours
            },
            aggregation: {
                enabled: true,
                intervals: {
                    '1m': 60000,
                    '5m': 300000,
                    '15m': 900000,
                    '1h': 3600000
                },
                functions: ['avg', 'min', 'max', 'sum', 'count']
            },
            alerts: {
                enabled: true,
                thresholds: {
                    cpu: { warning: 80, critical: 90 },
                    memory: { warning: 85, critical: 95 },
                    latency: { warning: 1000, critical: 2000 },
                    errorRate: { warning: 0.05, critical: 0.1 }
                }
            },
            export: {
                formats: ['json', 'csv'],
                compression: true,
                includeMetadata: true
            }
        };

        this.metrics = {
            performance: new Map(),
            network: new Map(),
            behavior: new Map(),
            security: new Map()
        };

        this.aggregatedData = {
            '1m': new Map(),
            '5m': new Map(),
            '15m': new Map(),
            '1h': new Map()
        };

        this.stats = {
            totalSamples: 0,
            startTime: this.timestamp,
            lastUpdate: null,
            byCategory: {
                performance: 0,
                network: 0,
                behavior: 0,
                security: 0
            }
        };

        this.initializeCollector();
    }

    initializeCollector() {
        this.startCollection();
        this.setupAggregation();
        this.loadStoredMetrics();
        this.startCleanupTask();
    }

    startCollection() {
        Object.keys(this.metricsConfig.categories).forEach(category => {
            if (this.metricsConfig.categories[category].enabled) {
                this.startCategoryCollection(category);
            }
        });
    }

    startCategoryCollection(category) {
        const config = this.metricsConfig.categories[category];
        setInterval(() => {
            this.collectMetrics(category);
        }, config.sampleRate);
    }

    async collectMetrics(category) {
        try {
            const metrics = await this.gatherCategoryMetrics(category);
            this.processMetrics(category, metrics);
        } catch (error) {
            this.handleCollectionError(category, error);
        }
    }

    async gatherCategoryMetrics(category) {
        switch (category) {
            case 'performance':
                return this.collectPerformanceMetrics();
            case 'network':
                return this.collectNetworkMetrics();
            case 'behavior':
                return this.collectBehaviorMetrics();
            case 'security':
                return this.collectSecurityMetrics();
            default:
                throw new Error(`Unknown category: ${category}`);
        }
    }

    async collectPerformanceMetrics() {
        const metrics = {
            timestamp: this.timestamp,
            cpu: await this.measureCPUUsage(),
            memory: this.measureMemoryUsage(),
            loadTime: this.measureLoadTime(),
            fps: this.measureFPS()
        };

        this.checkPerformanceThresholds(metrics);
        return metrics;
    }

    async collectNetworkMetrics() {
        const metrics = {
            timestamp: this.timestamp,
            latency: await this.measureLatency(),
            bandwidth: await this.measureBandwidth(),
            requests: this.getActiveRequests(),
            errors: this.getNetworkErrors()
        };

        this.checkNetworkThresholds(metrics);
        return metrics;
    }

    collectBehaviorMetrics() {
        return {
            timestamp: this.timestamp,
            mouseMovements: this.getMouseMetrics(),
            keystrokes: this.getKeystrokeMetrics(),
            scrolling: this.getScrollMetrics(),
            clicks: this.getClickMetrics()
        };
    }

    collectSecurityMetrics() {
        return {
            timestamp: this.timestamp,
            failedAttempts: this.getFailedAttempts(),
            suspiciousActivities: this.getSuspiciousActivities(),
            anomalyScore: this.calculateAnomalyScore()
        };
    }

    processMetrics(category, metrics) {
        this.storeMetrics(category, metrics);
        this.updateAggregations(category, metrics);
        this.updateStats(category);
        this.checkThresholds(category, metrics);
    }

    storeMetrics(category, metrics) {
        const key = `${this.timestamp}_${category}`;
        this.metrics[category].set(key, metrics);

        if (this.metrics[category].size > this.metricsConfig.general.maxDataPoints) {
            const oldestKey = Array.from(this.metrics[category].keys())[0];
            this.metrics[category].delete(oldestKey);
        }

        this.saveToStorage(category, key, metrics);
    }

    updateAggregations(category, metrics) {
        Object.keys(this.aggregatedData).forEach(interval => {
            this.updateIntervalAggregation(interval, category, metrics);
        });
    }

    updateIntervalAggregation(interval, category, metrics) {
        const intervalMs = this.metricsConfig.aggregation.intervals[interval];
        const key = Math.floor(Date.now() / intervalMs) * intervalMs;

        if (!this.aggregatedData[interval].has(key)) {
            this.aggregatedData[interval].set(key, this.initializeAggregation());
        }

        const aggregation = this.aggregatedData[interval].get(key);
        this.updateAggregationValues(aggregation, category, metrics);
    }

    updateAggregationValues(aggregation, category, metrics) {
        Object.entries(metrics).forEach(([metric, value]) => {
            if (typeof value === 'number') {
                if (!aggregation[category][metric]) {
                    aggregation[category][metric] = {
                        count: 0,
                        sum: 0,
                        min: value,
                        max: value
                    };
                }

                const agg = aggregation[category][metric];
                agg.count++;
                agg.sum += value;
                agg.min = Math.min(agg.min, value);
                agg.max = Math.max(agg.max, value);
            }
        });
    }

    checkThresholds(category, metrics) {
        const thresholds = this.metricsConfig.alerts.thresholds;
        
        Object.entries(metrics).forEach(([metric, value]) => {
            if (thresholds[metric]) {
                if (value >= thresholds[metric].critical) {
                    this.triggerAlert('critical', category, metric, value);
                } else if (value >= thresholds[metric].warning) {
                    this.triggerAlert('warning', category, metric, value);
                }
            }
        });
    }

    triggerAlert(level, category, metric, value) {
        const alert = {
            timestamp: this.timestamp,
            level,
            category,
            metric,
            value,
            threshold: this.metricsConfig.alerts.thresholds[metric][level]
        };

        // Assuming AlertManager is available
        if (window.alertManager) {
            window.alertManager.createAlert({
                title: `${level.toUpperCase()} - ${metric}`,
                message: `${metric} value (${value}) exceeded ${level} threshold (${alert.threshold})`,
                severity: level === 'critical' ? 'critical' : 'high',
                source: 'MetricsCollector',
                data: alert
            });
        }
    }

    getMetrics(options = {}) {
        const { category, startTime, endTime, metrics = [] } = options;
        let result = new Map();

        if (category) {
            result = this.filterMetricsByTime(
                this.metrics[category],
                startTime,
                endTime
            );
        } else {
            Object.keys(this.metrics).forEach(cat => {
                result.set(cat, this.filterMetricsByTime(
                    this.metrics[cat],
                    startTime,
                    endTime
                ));
            });
        }

        if (metrics.length > 0) {
            result = this.filterMetricsByNames(result, metrics);
        }

        return result;
    }

    getAggregatedMetrics(interval, options = {}) {
        if (!this.metricsConfig.aggregation.intervals[interval]) {
            throw new Error(`Invalid interval: ${interval}`);
        }

        const { category, startTime, endTime, metrics = [] } = options;
        let result = new Map();

        const filteredData = this.filterAggregatedDataByTime(
            this.aggregatedData[interval],
            startTime,
            endTime
        );

        if (category) {
            result = this.extractCategoryAggregation(filteredData, category, metrics);
        } else {
            result = filteredData;
        }

        return result;
    }

    async exportMetrics(format = 'json', options = {}) {
        const metrics = this.getMetrics(options);

        switch (format) {
            case 'json':
                return this.exportToJSON(metrics, options);
            case 'csv':
                return this.exportToCSV(metrics, options);
            default:
                throw new Error(`Unsupported format: ${format}`);
        }
    }

    exportToJSON(metrics, options) {
        const data = {
            timestamp: this.timestamp,
            userLogin: this.userLogin,
            metrics: Array.from(metrics.entries()),
            stats: this.stats
        };

        if (options.includeConfig) {
            data.config = this.metricsConfig;
        }

        return this.metricsConfig.export.compression ?
            this.compressData(JSON.stringify(data)) :
            JSON.stringify(data);
    }

    exportToCSV(metrics, options) {
        const rows = [['Timestamp', 'Category', 'Metric', 'Value']];
        
        metrics.forEach((categoryMetrics, category) => {
            categoryMetrics.forEach((metricData, timestamp) => {
                Object.entries(metricData).forEach(([metric, value]) => {
                    if (typeof value === 'number') {
                        rows.push([timestamp, category, metric, value]);
                    }
                });
            });
        });

        return rows.map(row => row.join(',')).join('\n');
    }

    // Utility Methods
    async measureCPUUsage() {
        // Implementation would depend on available browser APIs
        return Math.random() * 100; // Placeholder
    }

    measureMemoryUsage() {
        if (performance.memory) {
            return (performance.memory.usedJSHeapSize / 
                    performance.memory.jsHeapSizeLimit) * 100;
        }
        return null;
    }

    measureLoadTime() {
        if (window.performance) {
            return performance.now();
        }
        return null;
    }

    measureFPS() {
        // Implementation would use requestAnimationFrame
        return 60; // Placeholder
    }

    async measureLatency() {
        const start = performance.now();
        try {
            await fetch('/ping');
            return performance.now() - start;
        } catch {
            return null;
        }
    }

    async measureBandwidth() {
        // Implementation would measure network bandwidth
        return 1000000; // Placeholder
    }

    getActiveRequests() {
        // Implementation would track active XMLHttpRequests/fetch calls
        return 0;
    }

    getNetworkErrors() {
        // Implementation would track failed network requests
        return 0;
    }

    clearMetrics() {
        this.metrics = {
            performance: new Map(),
            network: new Map(),
            behavior: new Map(),
            security: new Map()
        };
        this.clearAggregatedData();
        this.resetStats();
    }

    resetStats() {
        this.stats = {
            totalSamples: 0,
            startTime: this.timestamp,
            lastUpdate: null,
            byCategory: {
                performance: 0,
                network: 0,
                behavior: 0,
                security: 0
            }
        };
    }
}