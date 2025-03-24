class DataAggregator {
    constructor() {
        this.timestamp = '2025-03-14 08:19:28';
        this.userLogin = 'Yldrm2015';

        this.aggregatorConfig = {
            general: {
                enabled: true,
                environment: 'production',
                updateInterval: 5000, // 5 seconds
                maxDataAge: 604800000, // 7 days
                autoCleanup: true
            },
            sources: {
                behavioral: {
                    enabled: true,
                    weight: 0.3,
                    metrics: ['mousePatterns', 'keyboardPatterns', 'interactionSpeed']
                },
                network: {
                    enabled: true,
                    weight: 0.25,
                    metrics: ['requestPatterns', 'responseTime', 'errorRate']
                },
                security: {
                    enabled: true,
                    weight: 0.25,
                    metrics: ['validationScore', 'threatLevel', 'anomalyScore']
                },
                performance: {
                    enabled: true,
                    weight: 0.2,
                    metrics: ['loadTime', 'resourceUsage', 'errorCount']
                }
            },
            analysis: {
                methods: ['weighted', 'average', 'threshold'],
                timeWindows: {
                    short: 300000,    // 5 minutes
                    medium: 3600000,  // 1 hour
                    long: 86400000    // 24 hours
                },
                thresholds: {
                    suspicious: 0.7,
                    dangerous: 0.9
                }
            },
            storage: {
                type: 'localStorage',
                prefix: 'botDetection_aggregated_',
                encryption: true,
                compression: true,
                maxEntries: 10000
            },
            export: {
                formats: ['json', 'csv'],
                scheduled: {
                    enabled: true,
                    interval: 3600000, // 1 hour
                    format: 'json'
                }
            }
        };

        this.aggregatedData = {
            current: new Map(),
            historical: new Map(),
            analyzed: new Map()
        };

        this.stats = {
            totalDataPoints: 0,
            lastUpdate: null,
            bySource: {
                behavioral: 0,
                network: 0,
                security: 0,
                performance: 0
            },
            analysisResults: {
                suspicious: 0,
                dangerous: 0,
                safe: 0
            }
        };

        this.initializeAggregator();
    }

    initializeAggregator() {
        this.startDataCollection();
        this.setupAnalysisSchedule();
        this.loadStoredData();
        if (this.aggregatorConfig.export.scheduled.enabled) {
            this.setupExportSchedule();
        }
    }

    async aggregateData() {
        try {
            const data = await this.collectDataFromSources();
            this.processData(data);
            this.analyzeAggregatedData();
            this.updateStats();
            this.cleanupOldData();
            
            return this.getCurrentAggregation();
        } catch (error) {
            this.handleAggregationError(error);
            throw error;
        }
    }

    async collectDataFromSources() {
        const collectedData = {};

        for (const [source, config] of Object.entries(this.aggregatorConfig.sources)) {
            if (!config.enabled) continue;

            try {
                const sourceData = await this.collectSourceData(source);
                collectedData[source] = this.preprocessSourceData(source, sourceData);
            } catch (error) {
                this.handleSourceError(source, error);
            }
        }

        return collectedData;
    }

    async collectSourceData(source) {
        switch (source) {
            case 'behavioral':
                return this.getBehavioralData();
            case 'network':
                return this.getNetworkData();
            case 'security':
                return this.getSecurityData();
            case 'performance':
                return this.getPerformanceData();
            default:
                throw new Error(`Unknown data source: ${source}`);
        }
    }

    preprocessSourceData(source, data) {
        const config = this.aggregatorConfig.sources[source];
        
        return {
            timestamp: this.timestamp,
            weight: config.weight,
            metrics: this.normalizeMetrics(data, config.metrics),
            raw: data
        };
    }

    normalizeMetrics(data, metricNames) {
        const normalized = {};

        metricNames.forEach(metric => {
            if (data[metric] !== undefined) {
                normalized[metric] = this.normalizeValue(data[metric]);
            }
        });

        return normalized;
    }

    normalizeValue(value) {
        if (typeof value !== 'number') return value;
        return Math.max(0, Math.min(1, value));
    }

    processData(data) {
        const key = this.timestamp;
        this.aggregatedData.current.set(key, data);

        // Store historical data
        this.aggregatedData.historical.set(key, {
            timestamp: this.timestamp,
            data: this.calculateAggregates(data)
        });

        // Maintain size limits
        if (this.aggregatedData.historical.size > this.aggregatorConfig.storage.maxEntries) {
            const oldestKey = Array.from(this.aggregatedData.historical.keys())[0];
            this.aggregatedData.historical.delete(oldestKey);
        }

        this.saveToStorage(key, data);
    }

    calculateAggregates(data) {
        const aggregates = {};

        for (const [source, sourceData] of Object.entries(data)) {
            const metrics = sourceData.metrics;
            const weight = sourceData.weight;

            for (const [metric, value] of Object.entries(metrics)) {
                if (!aggregates[metric]) {
                    aggregates[metric] = {
                        weightedSum: 0,
                        totalWeight: 0,
                        count: 0,
                        min: value,
                        max: value
                    };
                }

                const agg = aggregates[metric];
                agg.weightedSum += value * weight;
                agg.totalWeight += weight;
                agg.count++;
                agg.min = Math.min(agg.min, value);
                agg.max = Math.max(agg.max, value);
            }
        }

        return this.finalizeAggregates(aggregates);
    }

    finalizeAggregates(aggregates) {
        const finalized = {};

        for (const [metric, data] of Object.entries(aggregates)) {
            finalized[metric] = {
                weighted: data.weightedSum / data.totalWeight,
                average: data.weightedSum / data.count,
                min: data.min,
                max: data.max
            };
        }

        return finalized;
    }

    analyzeAggregatedData() {
        const analyzed = new Map();

        for (const [timestamp, data] of this.aggregatedData.current) {
            const analysis = {
                timestamp,
                score: this.calculateThreatScore(data),
                indicators: this.identifyThreatIndicators(data),
                recommendation: this.generateRecommendation(data)
            };

            analyzed.set(timestamp, analysis);
            this.updateAnalysisStats(analysis);
        }

        this.aggregatedData.analyzed = analyzed;
    }

    calculateThreatScore(data) {
        let totalScore = 0;
        let totalWeight = 0;

        for (const [source, sourceData] of Object.entries(data)) {
            const sourceScore = this.calculateSourceScore(sourceData);
            totalScore += sourceScore * sourceData.weight;
            totalWeight += sourceData.weight;
        }

        return totalWeight > 0 ? totalScore / totalWeight : 0;
    }

    calculateSourceScore(sourceData) {
        const metrics = sourceData.metrics;
        return Object.values(metrics).reduce((sum, value) => sum + value, 0) / 
               Object.keys(metrics).length;
    }

    identifyThreatIndicators(data) {
        const indicators = [];

        for (const [source, sourceData] of Object.entries(data)) {
            for (const [metric, value] of Object.entries(sourceData.metrics)) {
                if (value > this.aggregatorConfig.analysis.thresholds.suspicious) {
                    indicators.push({
                        source,
                        metric,
                        value,
                        severity: value > this.aggregatorConfig.analysis.thresholds.dangerous ? 
                                 'dangerous' : 'suspicious'
                    });
                }
            }
        }

        return indicators;
    }

    generateRecommendation(data) {
        const threatScore = this.calculateThreatScore(data);
        
        if (threatScore > this.aggregatorConfig.analysis.thresholds.dangerous) {
            return {
                action: 'block',
                confidence: 'high',
                reason: 'Multiple high-risk indicators detected'
            };
        } else if (threatScore > this.aggregatorConfig.analysis.thresholds.suspicious) {
            return {
                action: 'monitor',
                confidence: 'medium',
                reason: 'Suspicious activity patterns detected'
            };
        }

        return {
            action: 'allow',
            confidence: 'high',
            reason: 'No significant threats detected'
        };
    }

    getAggregatedData(options = {}) {
        const {
            timeWindow = 'medium',
            source = null,
            metrics = null
        } = options;

        const windowMs = this.aggregatorConfig.analysis.timeWindows[timeWindow];
        const cutoff = Date.now() - windowMs;

        return this.filterAggregatedData(cutoff, source, metrics);
    }

    getAnalysis(options = {}) {
        const {
            timeWindow = 'short',
            includeThreatIndicators = true,
            includeRecommendations = true
        } = options;

        const analysis = {
            timestamp: this.timestamp,
            overview: this.getAnalysisOverview(timeWindow),
            stats: this.getAnalysisStats()
        };

        if (includeThreatIndicators) {
            analysis.threatIndicators = this.getRecentThreatIndicators(timeWindow);
        }

        if (includeRecommendations) {
            analysis.recommendations = this.getRecentRecommendations(timeWindow);
        }

        return analysis;
    }

    async exportData(format = 'json', options = {}) {
        const data = this.prepareDataForExport(options);

        switch (format) {
            case 'json':
                return this.exportToJSON(data);
            case 'csv':
                return this.exportToCSV(data);
            default:
                throw new Error(`Unsupported export format: ${format}`);
        }
    }

    // Utility Methods
    saveToStorage(key, data) {
        try {
            let storageData = data;

            if (this.aggregatorConfig.storage.encryption) {
                storageData = this.encryptData(data);
            }

            if (this.aggregatorConfig.storage.compression) {
                storageData = this.compressData(storageData);
            }

            localStorage.setItem(
                `${this.aggregatorConfig.storage.prefix}${key}`,
                JSON.stringify(storageData)
            );
        } catch (error) {
            this.handleStorageError(error);
        }
    }

    updateStats() {
        this.stats.totalDataPoints++;
        this.stats.lastUpdate = this.timestamp;

        for (const source of Object.keys(this.aggregatorConfig.sources)) {
            if (this.aggregatedData.current.has(source)) {
                this.stats.bySource[source]++;
            }
        }
    }

    cleanupOldData() {
        const maxAge = this.aggregatorConfig.general.maxDataAge;
        const cutoff = Date.now() - maxAge;

        for (const map of [this.aggregatedData.current, this.aggregatedData.historical, this.aggregatedData.analyzed]) {
            for (const [key, value] of map) {
                if (new Date(value.timestamp).getTime() < cutoff) {
                    map.delete(key);
                }
            }
        }
    }

    handleAggregationError(error) {
        console.error('Aggregation error:', error);
        
        if (window.logger) {
            window.logger.error('Data aggregation failed:', error);
        }

        if (window.alertManager) {
            window.alertManager.createAlert({
                title: 'Data Aggregation Error',
                message: error.message,
                severity: 'high',
                source: 'DataAggregator'
            });
        }
    }
}