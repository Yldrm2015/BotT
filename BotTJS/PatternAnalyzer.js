(function(window) {
    'use strict';

    class PatternAnalyzer {
        static instance = null;
        timestamp = '2025-03-17 11:12:45';
        userLogin = 'Yldrm2015';

        // Singleton pattern
        static getInstance() {
            if (!PatternAnalyzer.instance) {
                PatternAnalyzer.instance = new PatternAnalyzer();
            }
            return PatternAnalyzer.instance;
        }

        constructor() {
            if (PatternAnalyzer.instance) {
                return PatternAnalyzer.instance;
            }

            // Browser capability check
            this.capabilities = this.checkCapabilities();

            this.analyzerConfig = {
                analysis: {
                    enabled: true,
                    interval: 5000,
                    batchSize: 100,
                    minSampleSize: 20,
                    confidenceThreshold: 0.75,
                    useWebWorker: true,
                    useMachineLearning: true,
                    useGPU: true // WebGL için
                },
                patterns: {
                    behavioral: {
                        mouse: {
                            linearMovement: 0.8,
                            gridAlignment: 0.7,
                            speedConsistency: 0.85,
                            clickAccuracy: 0.9,
                            // Yeni özellikler
                            acceleration: 0.75,
                            direction: 0.8,
                            hoverPatterns: 0.7,
                            multiClickPatterns: 0.85
                        },
                        keyboard: {
                            typingSpeed: 0.8,
                            rhythmConsistency: 0.75,
                            burstPattern: 0.85,
                            specialKeyUsage: 0.7,
                            // Yeni özellikler
                            keyPressDepth: 0.8,
                            keyReleaseTime: 0.75,
                            languagePatterns: 0.7,
                            errorCorrection: 0.8
                        },
                        scroll: {
                            smoothness: 0.8,
                            consistency: 0.75,
                            periodicity: 0.7,
                            // Yeni özellikler
                            momentum: 0.8,
                            direction: 0.75,
                            stopPoints: 0.7,
                            readingPatterns: 0.85
                        },
                        touch: { // Yeni kategori
                            pressure: 0.8,
                            area: 0.75,
                            multiTouch: 0.85,
                            gestureComplexity: 0.8
                        }
                    },
                    network: {
                        requestTiming: 0.85,
                        parallelRequests: 0.8,
                        errorPatterns: 0.9,
                        // Yeni özellikler
                        cacheBehavior: 0.8,
                        headerPatterns: 0.85,
                        payloadConsistency: 0.75,
                        apiUsagePatterns: 0.8
                    },
                    timing: {
                        interactionDelay: 0.8,
                        responseTime: 0.85,
                        sessionDuration: 0.75,
                        // Yeni özellikler
                        microTiming: 0.8,
                        burstPatterns: 0.85,
                        idlePatterns: 0.75,
                        focusPatterns: 0.8
                    }
                },
                thresholds: {
                    botProbability: 0.8,
                    humanProbability: 0.2,
                    uncertaintyRange: 0.3,
                    // Yeni thresholds
                    anomalyThreshold: 0.9,
                    learningRate: 0.1,
                    adaptiveThreshold: true
                },
                weights: {
                    behavioral: 0.5,
                    network: 0.3,
                    timing: 0.2,
                    // Dinamik ağırlık ayarı
                    dynamic: true,
                    learningRate: 0.01
                },
                ml: {
                    enabled: true,
                    modelType: 'tensorflow',
                    modelPath: '/models/pattern-analyzer',
                    batchSize: 32,
                    epochs: 10,
                    validationSplit: 0.2
                }
            };

            this.state = {
                isAnalyzing: false,
                workerActive: false,
                modelLoaded: false,
                lastUpdate: this.timestamp,
                sampleCount: 0,
                accuracy: 0,
                gpuAvailable: false
            };

            // Performance monitoring
            this.metrics = {
                startTime: performance.now(),
                analysisTime: 0,
                sampleCount: 0,
                accuracy: new MovingAverage(100),
                confidence: new MovingAverage(100)
            };

            this.initialize();
            PatternAnalyzer.instance = this;
        }

        checkCapabilities() {
            return {
                webWorker: typeof Worker !== 'undefined',
                webGL: this.checkWebGL(),
                deviceOrientation: typeof window.DeviceOrientationEvent !== 'undefined',
                touch: 'ontouchstart' in window,
                gyroscope: typeof window.Gyroscope !== 'undefined',
                bluetooth: typeof navigator.bluetooth !== 'undefined',
                performance: typeof performance !== 'undefined',
                sharedArrayBuffer: typeof SharedArrayBuffer !== 'undefined',
                webAssembly: typeof WebAssembly !== 'undefined'
            };
        }

        checkWebGL() {
            try {
                const canvas = document.createElement('canvas');
                return !!(window.WebGLRenderingContext && 
                    (canvas.getContext('webgl') || 
                     canvas.getContext('experimental-webgl')));
            } catch (e) {
                return false;
            }
        }

        async initialize() {
            try {
                // Web Worker başlatma
                if (this.capabilities.webWorker && this.analyzerConfig.analysis.useWebWorker) {
                    await this.initializeWorker();
                }

                // GPU kontrol ve başlatma
                if (this.capabilities.webGL && this.analyzerConfig.analysis.useGPU) {
                    await this.initializeGPU();
                }

                // ML model yükleme
                if (this.analyzerConfig.ml.enabled) {
                    await this.loadMLModel();
                }

                // Event listener'ları kur
                this.setupEventListeners();

                // Analizi başlat
                this.startAnalysis();

                console.log(`[${this.timestamp}] PatternAnalyzer initialized successfully`);
            } catch (error) {
                console.error(`[${this.timestamp}] PatternAnalyzer initialization failed:`, error);
                this.handleInitializationError(error);
            }
        }

        setupEventListeners() {
            // Performance monitoring
            if (typeof PerformanceObserver !== 'undefined') {
                const perfObserver = new PerformanceObserver(this.handlePerformanceEntry.bind(this));
                perfObserver.observe({ entryTypes: ['measure', 'longtask'] });
            }

            // Device orientation
            if (this.capabilities.deviceOrientation) {
                window.addEventListener('deviceorientation', 
                    this.handleDeviceOrientation.bind(this));
            }

            // Touch events
            if (this.capabilities.touch) {
                window.addEventListener('touchstart', 
                    this.handleTouch.bind(this), { passive: true });
            }

            // Visibility change
            document.addEventListener('visibilitychange', 
                this.handleVisibilityChange.bind(this));
        }

        // Event handlers
        handlePerformanceEntry(entries) {
            entries.getEntries().forEach(entry => {
                if (entry.entryType === 'measure') {
                    this.metrics.analysisTime += entry.duration;
                }
            });
        }

        handleDeviceOrientation(event) {
            if (this.state.isAnalyzing) {
                this.updatePatternData('behavioral', 'orientation', {
                    alpha: event.alpha,
                    beta: event.beta,
                    gamma: event.gamma,
                    timestamp: performance.now()
                });
            }
        }

        handleTouch(event) {
            if (this.state.isAnalyzing) {
                this.updatePatternData('behavioral', 'touch', {
                    touches: Array.from(event.touches).map(touch => ({
                        x: touch.clientX,
                        y: touch.clientY,
                        force: touch.force,
                        radiusX: touch.radiusX,
                        radiusY: touch.radiusY
                    })),
                    timestamp: performance.now()
                });
            }
        }

        handleVisibilityChange() {
            if (document.hidden) {
                this.pauseAnalysis();
            } else {
                this.resumeAnalysis();
            }
        }
    }

    // Utility class for moving averages
    class MovingAverage {
        constructor(size) {
            this.size = size;
            this.values = [];
        }

        add(value) {
            this.values.push(value);
            if (this.values.length > this.size) {
                this.values.shift();
            }
            return this.calculate();
        }

        calculate() {
            return this.values.reduce((a, b) => a + b, 0) / this.values.length;
        }
    }

    // Global scope'a ekle
    window.PatternAnalyzer = PatternAnalyzer;

})(window);

(function(window) {
    'use strict';

    class PatternAnalyzer {
        // Gelişmiş Analiz Algoritmaları
        async analyzeBehavioralPatterns() {
            performance.mark('behavioral-start');

            const patterns = {
                mouse: await this.analyzeMousePatterns(),
                keyboard: await this.analyzeKeyboardPatterns(),
                scroll: await this.analyzeScrollPatterns(),
                touch: await this.analyzeTouchPatterns(),
                multimodal: await this.analyzeMultimodalPatterns()
            };

            performance.mark('behavioral-end');
            performance.measure('behavioral-analysis', 'behavioral-start', 'behavioral-end');

            return this.combinePatternResults(patterns);
        }

        async analyzeMousePatterns() {
            const patterns = this.patternData.behavioral.get('mouse');
            if (!this.hasEnoughData(patterns)) {
                return this.createDefaultScore();
            }

            const features = {
                movement: this.analyzeMouseMovement(patterns),
                clicks: this.analyzeMouseClicks(patterns),
                hover: this.analyzeHoverBehavior(patterns),
                trajectory: this.analyzeTrajectory(patterns)
            };

            return this.calculateFeatureScore(features, 'mouse');
        }

        analyzeMouseMovement(patterns) {
            return {
                linearity: this.calculateLinearity(patterns),
                acceleration: this.calculateAcceleration(patterns),
                jitter: this.calculateJitter(patterns),
                angleDistribution: this.calculateAngleDistribution(patterns)
            };
        }

        calculateLinearity(patterns) {
            const points = patterns.map(p => [p.x, p.y]);
            const segments = this.createSegments(points);
            
            return segments.map(segment => {
                const regression = this.linearRegression(segment);
                return {
                    r2: regression.r2,
                    slope: regression.slope,
                    length: this.segmentLength(segment)
                };
            });
        }

        calculateAcceleration(patterns) {
            const velocities = this.calculateVelocities(patterns);
            const accelerations = this.calculateDerivative(velocities);
            
            return {
                mean: this.calculateMean(accelerations),
                variance: this.calculateVariance(accelerations),
                peaks: this.findPeaks(accelerations),
                distribution: this.calculateDistribution(accelerations)
            };
        }

        calculateJitter(patterns) {
            const smoothPath = this.smoothPath(patterns);
            const deviations = patterns.map((p, i) => {
                if (!smoothPath[i]) return 0;
                return this.euclideanDistance(p, smoothPath[i]);
            });

            return {
                mean: this.calculateMean(deviations),
                variance: this.calculateVariance(deviations),
                maxDeviation: Math.max(...deviations)
            };
        }

        analyzeMouseClicks(patterns) {
            const clickPatterns = patterns.filter(p => p.type === 'click');
            
            return {
                timing: this.analyzeClickTiming(clickPatterns),
                accuracy: this.analyzeClickAccuracy(clickPatterns),
                doubleClicks: this.analyzeDoubleClicks(clickPatterns),
                distribution: this.analyzeClickDistribution(clickPatterns)
            };
        }

        analyzeClickTiming(clicks) {
            const intervals = this.calculateIntervals(clicks);
            
            return {
                mean: this.calculateMean(intervals),
                variance: this.calculateVariance(intervals),
                rhythm: this.analyzeRhythm(intervals),
                consistency: this.calculateConsistency(intervals)
            };
        }

        analyzeHoverBehavior(patterns) {
            const hoverEvents = this.extractHoverEvents(patterns);
            
            return {
                duration: this.analyzeHoverDuration(hoverEvents),
                movement: this.analyzeHoverMovement(hoverEvents),
                frequency: this.analyzeHoverFrequency(hoverEvents),
                intentionality: this.analyzeHoverIntentionality(hoverEvents)
            };
        }

        analyzeTrajectory(patterns) {
            const trajectory = this.constructTrajectory(patterns);
            
            return {
                complexity: this.calculateTrajectoryComplexity(trajectory),
                smoothness: this.calculateTrajectorySmoothness(trajectory),
                efficiency: this.calculateTrajectoryEfficiency(trajectory),
                naturalness: this.calculateTrajectoryNaturalness(trajectory)
            };
        }

        async analyzeKeyboardPatterns() {
            const patterns = this.patternData.behavioral.get('keyboard');
            if (!this.hasEnoughData(patterns)) {
                return this.createDefaultScore();
            }

            const features = {
                typing: this.analyzeTypingPatterns(patterns),
                rhythm: this.analyzeKeyboardRhythm(patterns),
                errors: this.analyzeTypingErrors(patterns),
                complexity: this.analyzeInputComplexity(patterns)
            };

            return this.calculateFeatureScore(features, 'keyboard');
        }

        analyzeTypingPatterns(patterns) {
            return {
                speed: this.calculateTypingSpeed(patterns),
                consistency: this.calculateTypingConsistency(patterns),
                bursts: this.analyzeTypingBursts(patterns),
                pauses: this.analyzeTypingPauses(patterns)
            };
        }

        calculateTypingSpeed(patterns) {
            const intervals = this.getKeyIntervals(patterns);
            
            return {
                wpm: this.calculateWPM(intervals),
                variability: this.calculateSpeedVariability(intervals),
                trend: this.calculateSpeedTrend(intervals)
            };
        }

        async analyzeScrollPatterns() {
            const patterns = this.patternData.behavioral.get('scroll');
            if (!this.hasEnoughData(patterns)) {
                return this.createDefaultScore();
            }

            const features = {
                movement: this.analyzeScrollMovement(patterns),
                rhythm: this.analyzeScrollRhythm(patterns),
                reading: this.analyzeReadingPattern(patterns),
                momentum: this.analyzeScrollMomentum(patterns)
            };

            return this.calculateFeatureScore(features, 'scroll');
        }

        analyzeScrollMovement(patterns) {
            return {
                smoothness: this.calculateScrollSmoothness(patterns),
                direction: this.analyzeScrollDirection(patterns),
                speed: this.analyzeScrollSpeed(patterns),
                acceleration: this.analyzeScrollAcceleration(patterns)
            };
        }

        async analyzeTouchPatterns() {
            const patterns = this.patternData.behavioral.get('touch');
            if (!this.hasEnoughData(patterns)) {
                return this.createDefaultScore();
            }

            const features = {
                gestures: this.analyzeTouchGestures(patterns),
                pressure: this.analyzeTouchPressure(patterns),
                multitouch: this.analyzeMultitouch(patterns),
                precision: this.analyzeTouchPrecision(patterns)
            };

            return this.calculateFeatureScore(features, 'touch');
        }

        // Utility Methods
        hasEnoughData(patterns) {
            return patterns && patterns.length >= this.analyzerConfig.analysis.minSampleSize;
        }

        createDefaultScore() {
            return {
                score: 0.5,
                confidence: 0,
                features: {}
            };
        }

        calculateFeatureScore(features, type) {
            const weights = this.analyzerConfig.patterns.behavioral[type];
            let totalScore = 0;
            let totalWeight = 0;

            for (const [feature, value] of Object.entries(features)) {
                if (weights[feature]) {
                    totalScore += value.score * weights[feature];
                    totalWeight += weights[feature];
                }
            }

            return {
                score: totalWeight > 0 ? totalScore / totalWeight : 0.5,
                confidence: this.calculateConfidence(features),
                features
            };
        }

        combinePatternResults(patterns) {
            const weights = this.analyzerConfig.weights;
            let totalScore = 0;
            let totalWeight = 0;

            for (const [type, result] of Object.entries(patterns)) {
                if (weights[type]) {
                    totalScore += result.score * weights[type];
                    totalWeight += weights[type];
                }
            }

            return {
                score: totalWeight > 0 ? totalScore / totalWeight : 0.5,
                confidence: this.calculateOverallConfidence(patterns),
                patterns
            };
        }
    }

    // Ana sınıfa ekle
    Object.assign(window.PatternAnalyzer.prototype, PatternAnalyzer.prototype);

})(window);

(function(window) {
    'use strict';

    // Part 3: Machine Learning Integration
    class PatternAnalyzerML {
        timestamp = '2025-03-17 11:13:33';
        userLogin = 'Yldrm2015';

        constructor(analyzer) {
            this.analyzer = analyzer;
            this.models = new Map();
            this.state = {
                modelLoaded: false,
                training: false,
                lastTraining: null,
                samples: 0,
                accuracy: 0
            };
        }

        async initializeML() {
            if (!this.analyzer.analyzerConfig.ml.enabled) return;

            try {
                await this.loadTensorFlow();
                await this.loadModels();
                await this.warmupModels();
                
                this.setupAutoTraining();
                this.state.modelLoaded = true;

                console.log(`[${this.timestamp}] ML system initialized`);
            } catch (error) {
                console.error(`[${this.timestamp}] ML initialization failed:`, error);
                this.handleMLError(error);
            }
        }

        async loadTensorFlow() {
            if (typeof tf === 'undefined') {
                await import('https://cdn.jsdelivr.net/npm/@tensorflow/tfjs');
            }

            // GPU acceleration if available
            if (this.analyzer.capabilities.webGL) {
                await tf.setBackend('webgl');
                console.log('Using WebGL backend for TensorFlow.js');
            }
        }

        async loadModels() {
            const modelTypes = ['behavioral', 'network', 'timing'];
            
            for (const type of modelTypes) {
                try {
                    const model = await this.loadModel(type);
                    this.models.set(type, model);
                } catch (error) {
                    console.error(`Failed to load ${type} model:`, error);
                    await this.createModel(type);
                }
            }
        }

        async loadModel(type) {
            const modelPath = `${this.analyzer.analyzerConfig.ml.modelPath}/${type}`;
            try {
                const model = await tf.loadLayersModel(modelPath);
                await this.validateModel(model, type);
                return model;
            } catch (error) {
                throw new Error(`Model loading failed: ${error.message}`);
            }
        }

        async createModel(type) {
            const model = tf.sequential();
            
            // Model architecture based on type
            switch(type) {
                case 'behavioral':
                    this.createBehavioralModel(model);
                    break;
                case 'network':
                    this.createNetworkModel(model);
                    break;
                case 'timing':
                    this.createTimingModel(model);
                    break;
            }

            await this.compileModel(model);
            this.models.set(type, model);
            return model;
        }

        createBehavioralModel(model) {
            model.add(tf.layers.dense({
                inputShape: [50],
                units: 128,
                activation: 'relu'
            }));
            
            model.add(tf.layers.dropout(0.3));
            
            model.add(tf.layers.dense({
                units: 64,
                activation: 'relu'
            }));
            
            model.add(tf.layers.dense({
                units: 32,
                activation: 'relu'
            }));
            
            model.add(tf.layers.dense({
                units: 1,
                activation: 'sigmoid'
            }));
        }

        async compileModel(model) {
            model.compile({
                optimizer: tf.train.adam(0.001),
                loss: 'binaryCrossentropy',
                metrics: ['accuracy']
            });
        }

        async warmupModels() {
            for (const [type, model] of this.models) {
                try {
                    const dummyData = this.createDummyData(type);
                    await model.predict(dummyData).dispose();
                } catch (error) {
                    console.error(`Warmup failed for ${type} model:`, error);
                }
            }
        }

        createDummyData(type) {
            const shape = this.getInputShape(type);
            return tf.zeros([1, ...shape]);
        }

        async predictPattern(type, features) {
            const model = this.models.get(type);
            if (!model) return this.createDefaultPrediction();

            try {
                const tensor = this.preprocessFeatures(features);
                const prediction = await model.predict(tensor);
                const result = await this.postprocessPrediction(prediction);
                tensor.dispose();
                prediction.dispose();
                return result;
            } catch (error) {
                console.error(`Prediction failed for ${type}:`, error);
                return this.createDefaultPrediction();
            }
        }

        preprocessFeatures(features) {
            return tf.tidy(() => {
                const normalized = this.normalizeFeatures(features);
                const reshaped = this.reshapeFeatures(normalized);
                return tf.tensor2d(reshaped, [1, reshaped.length]);
            });
        }

        normalizeFeatures(features) {
            return Object.values(features).map(value => {
                if (typeof value === 'number') {
                    return (value - this.featureStats.min) / 
                           (this.featureStats.max - this.featureStats.min);
                }
                return 0;
            });
        }

        async trainModel(type, data) {
            const model = this.models.get(type);
            if (!model || this.state.training) return;

            this.state.training = true;
            const startTime = performance.now();

            try {
                const { xs, ys } = this.prepareTrainingData(data);
                
                const history = await model.fit(xs, ys, {
                    epochs: this.analyzer.analyzerConfig.ml.epochs,
                    batchSize: this.analyzer.analyzerConfig.ml.batchSize,
                    validationSplit: this.analyzer.analyzerConfig.ml.validationSplit,
                    callbacks: {
                        onEpochEnd: (epoch, logs) => {
                            this.updateTrainingProgress(epoch, logs);
                        }
                    }
                });

                this.updateModelMetrics(type, history);
                await this.saveModel(type, model);

            } catch (error) {
                console.error(`Training failed for ${type}:`, error);
                this.handleTrainingError(error);
            } finally {
                this.state.training = false;
                this.state.lastTraining = this.timestamp;
                const duration = performance.now() - startTime;
                console.log(`Training completed in ${duration}ms`);
            }
        }

        prepareTrainingData(data) {
            return tf.tidy(() => {
                const shuffled = this.shuffleData(data);
                const features = shuffled.map(item => item.features);
                const labels = shuffled.map(item => item.label);

                return {
                    xs: tf.tensor2d(features),
                    ys: tf.tensor2d(labels)
                };
            });
        }

        shuffleData(data) {
            return data.slice().sort(() => Math.random() - 0.5);
        }

        updateTrainingProgress(epoch, logs) {
            const progress = {
                epoch,
                accuracy: logs.acc,
                loss: logs.loss,
                valAccuracy: logs.val_acc,
                valLoss: logs.val_loss,
                timestamp: this.timestamp
            };

            this.analyzer.emit('trainingProgress', progress);
        }

        async saveModel(type, model) {
            try {
                const modelPath = `${this.analyzer.analyzerConfig.ml.modelPath}/${type}`;
                await model.save(`localstorage://${modelPath}`);
            } catch (error) {
                console.error(`Model saving failed for ${type}:`, error);
            }
        }

        createDefaultPrediction() {
            return {
                score: 0.5,
                confidence: 0,
                timestamp: this.timestamp
            };
        }

        destroy() {
            for (const model of this.models.values()) {
                try {
                    model.dispose();
                } catch (error) {
                    console.error('Model disposal error:', error);
                }
            }
            this.models.clear();
        }
    }

    // Ana sınıfa entegre et
    window.PatternAnalyzer.ML = PatternAnalyzerML;

})(window);

(function(window) {
    'use strict';

    // Part 4: Performance Optimizations & Web Workers
    class PatternAnalyzerWorker {
        timestamp = '2025-03-17 11:15:01';
        userLogin = 'Yldrm2015';

        constructor(analyzer) {
            this.analyzer = analyzer;
            this.workers = new Map();
            this.taskQueue = [];
            this.processing = false;
            this.metrics = new WorkerMetrics();
        }

        async initializeWorkers() {
            if (!this.analyzer.capabilities.webWorker) return;

            const workerTypes = {
                behavioral: 'behavioralAnalysis.worker.js',
                network: 'networkAnalysis.worker.js',
                timing: 'timingAnalysis.worker.js',
                ml: 'mlProcessing.worker.js'
            };

            for (const [type, script] of Object.entries(workerTypes)) {
                try {
                    await this.createWorker(type, script);
                } catch (error) {
                    console.error(`Worker initialization failed for ${type}:`, error);
                }
            }
        }

        async createWorker(type, script) {
            return new Promise((resolve, reject) => {
                try {
                    const worker = new Worker(script);
                    
                    worker.onmessage = (e) => this.handleWorkerMessage(type, e);
                    worker.onerror = (e) => this.handleWorkerError(type, e);
                    
                    // Worker initialization
                    worker.postMessage({
                        type: 'init',
                        config: this.analyzer.analyzerConfig,
                        timestamp: this.timestamp
                    });

                    this.workers.set(type, {
                        worker,
                        status: 'idle',
                        tasks: 0,
                        lastActive: this.timestamp
                    });

                    resolve(worker);
                } catch (error) {
                    reject(error);
                }
            });
        }

        handleWorkerMessage(type, event) {
            const { action, data, taskId } = event.data;
            
            this.metrics.recordTask(type, event.timeStamp);

            switch (action) {
                case 'analysisComplete':
                    this.handleAnalysisResult(type, data, taskId);
                    break;
                case 'progress':
                    this.updateProgress(type, data);
                    break;
                case 'error':
                    this.handleWorkerError(type, data);
                    break;
            }

            this.processNextTask(type);
        }

        handleAnalysisResult(type, result, taskId) {
            const task = this.findTask(taskId);
            if (task) {
                task.resolve(result);
                this.removeTask(taskId);
            }

            const workerInfo = this.workers.get(type);
            if (workerInfo) {
                workerInfo.status = 'idle';
                workerInfo.tasks--;
                workerInfo.lastActive = this.timestamp;
            }
        }

        handleWorkerError(type, error) {
            console.error(`Worker error (${type}):`, error);
            
            const workerInfo = this.workers.get(type);
            if (workerInfo) {
                workerInfo.status = 'error';
                this.restartWorker(type);
            }
        }

        async queueTask(type, data) {
            return new Promise((resolve, reject) => {
                const task = {
                    id: this.generateTaskId(),
                    type,
                    data,
                    resolve,
                    reject,
                    timestamp: this.timestamp,
                    retries: 0
                };

                this.taskQueue.push(task);
                this.processNextTask(type);
            });
        }

        async processNextTask(type) {
            if (this.processing) return;
            
            const workerInfo = this.workers.get(type);
            if (!workerInfo || workerInfo.status !== 'idle') return;

            const task = this.taskQueue.find(t => t.type === type);
            if (!task) return;

            this.processing = true;
            
            try {
                workerInfo.status = 'busy';
                workerInfo.tasks++;

                const worker = workerInfo.worker;
                worker.postMessage({
                    taskId: task.id,
                    type: task.type,
                    data: task.data,
                    timestamp: this.timestamp
                });

                this.metrics.startTask(task.id, type);

            } catch (error) {
                this.handleTaskError(task, error);
            } finally {
                this.processing = false;
            }
        }

        async restartWorker(type) {
            const workerInfo = this.workers.get(type);
            if (!workerInfo) return;

            try {
                workerInfo.worker.terminate();
                await this.createWorker(type, workerInfo.worker.script);
                this.retryFailedTasks(type);
            } catch (error) {
                console.error(`Worker restart failed for ${type}:`, error);
            }
        }

        retryFailedTasks(type) {
            const failedTasks = this.taskQueue.filter(
                task => task.type === type && task.retries < 3
            );

            for (const task of failedTasks) {
                task.retries++;
                this.processNextTask(type);
            }
        }

        optimizeWorkerPool() {
            // Worker pool optimization based on metrics
            const stats = this.metrics.getStats();
            
            for (const [type, workerInfo] of this.workers) {
                const typeStats = stats.byType[type];
                
                if (typeStats.avgProcessingTime > 100 && workerInfo.tasks > 5) {
                    this.scaleWorker(type, 'up');
                } else if (typeStats.avgProcessingTime < 50 && workerInfo.tasks < 2) {
                    this.scaleWorker(type, 'down');
                }
            }
        }

        async scaleWorker(type, direction) {
            const workerInfo = this.workers.get(type);
            if (!workerInfo) return;

            if (direction === 'up' && this.canScaleUp(type)) {
                await this.createWorker(`${type}_${Date.now()}`, workerInfo.worker.script);
            } else if (direction === 'down' && this.canScaleDown(type)) {
                this.removeExtraWorker(type);
            }
        }

        terminateWorkers() {
            for (const [type, workerInfo] of this.workers) {
                try {
                    workerInfo.worker.terminate();
                    console.log(`Worker ${type} terminated`);
                } catch (error) {
                    console.error(`Error terminating worker ${type}:`, error);
                }
            }
            this.workers.clear();
        }
    }

    class WorkerMetrics {
        constructor() {
            this.tasks = new Map();
            this.stats = {
                total: 0,
                completed: 0,
                failed: 0,
                avgProcessingTime: 0,
                byType: {}
            };
        }

        startTask(taskId, type) {
            this.tasks.set(taskId, {
                type,
                startTime: performance.now(),
                status: 'processing'
            });
        }

        recordTask(type, endTime) {
            const typeStats = this.stats.byType[type] || {
                total: 0,
                completed: 0,
                failed: 0,
                avgProcessingTime: 0,
                processingTimes: []
            };

            typeStats.total++;
            typeStats.completed++;
            
            const processingTime = endTime - performance.now();
            typeStats.processingTimes.push(processingTime);
            
            if (typeStats.processingTimes.length > 100) {
                typeStats.processingTimes.shift();
            }

            typeStats.avgProcessingTime = 
                typeStats.processingTimes.reduce((a, b) => a + b, 0) / 
                typeStats.processingTimes.length;

            this.stats.byType[type] = typeStats;
        }

        getStats() {
            return {
                ...this.stats,
                timestamp: new Date().toISOString(),
                activeThreads: this.tasks.size
            };
        }
    }

    // Ana sınıfa entegre et
    window.PatternAnalyzer.Worker = PatternAnalyzerWorker;

    // Service Worker registration
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/patternAnalyzer.sw.js')
                .then(registration => {
                    console.log('PatternAnalyzer ServiceWorker registered:', registration);
                })
                .catch(error => {
                    console.error('ServiceWorker registration failed:', error);
                });
        });
    }

})(window);