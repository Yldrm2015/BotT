class BehavioralAnalysis {
    constructor(config) {
        this.config = config;
        this.timestamp = '2025-03-13 11:27:03';
        this.userLogin = 'Yldrm2015';

        this.analysisConfig = {
            mouseThresholds: {
                naturalMovementScore: 0.7,
                minimumSampleSize: 50,
                maxSpeed: 1000,
                minSpeed: 5,
                maxAcceleration: 150,
                suspiciousPatternThreshold: 0.8
            },
            keyboardThresholds: {
                naturalTypingScore: 0.6,
                minimumKeystrokes: 20,
                maxTypingSpeed: 200,
                minTypingSpeed: 10,
                patternMatchThreshold: 0.75
            },
            scrollThresholds: {
                naturalScrollScore: 0.65,
                minimumScrollEvents: 10,
                maxScrollSpeed: 2000,
                minScrollSpeed: 50,
                smoothScrollThreshold: 0.7
            },
            interactionThresholds: {
                minInteractionGap: 100,
                maxSuspiciousRepetitions: 5,
                naturalInteractionScore: 0.6
            }
        };

        this.analysisResults = {
            timestamp: this.timestamp,
            userLogin: this.userLogin,
            mousePatterns: [],
            keyboardPatterns: [],
            scrollPatterns: [],
            interactionPatterns: [],
            overallScore: 0,
            lastUpdate: this.timestamp,
            status: 'initialized',
            confidence: 0
        };

        this.patternHistory = {
            mouseMovements: [],
            keystrokes: [],
            scrollEvents: [],
            interactions: [],
            maxHistoryLength: 1000
        };

        this.initializeAnalysis();
    }

    initializeAnalysis() {
        this.lastMousePosition = null;
        this.lastScrollPosition = null;
        this.lastKeystrokeTime = null;
        this.currentPatternSequence = [];
        this.suspiciousPatternCount = 0;
    }

    // Mouse Movement Analysis Methods
    analyzeMouseMovement(event) {
        const movement = {
            timestamp: Date.now(),
            x: event.clientX,
            y: event.clientY,
            speed: this.calculateSpeed(event),
            direction: this.calculateDirection(event),
            acceleration: this.calculateAcceleration(event)
        };

        this.patternHistory.mouseMovements.push(movement);
        this.trimHistory('mouseMovements');
        
        const analysis = {
            naturalness: this.calculateMouseNaturalness(),
            isBot: this.detectBotBehavior(movement),
            confidence: this.calculateConfidence('mouse'),
            patterns: this.detectMousePatterns()
        };

        this.updateMouseAnalysis(analysis);
        return analysis;
    }

    calculateSpeed(event) {
        if (!this.lastMousePosition) {
            this.lastMousePosition = { x: event.clientX, y: event.clientY, timestamp: Date.now() };
            return 0;
        }

        const dx = event.clientX - this.lastMousePosition.x;
        const dy = event.clientY - this.lastMousePosition.y;
        const dt = Date.now() - this.lastMousePosition.timestamp;
        const distance = Math.sqrt(dx * dx + dy * dy);
        
        this.lastMousePosition = { x: event.clientX, y: event.clientY, timestamp: Date.now() };
        return dt > 0 ? distance / dt : 0;
    }

    calculateDirection(event) {
        if (!this.lastMousePosition) return 0;
        
        return Math.atan2(
            event.clientY - this.lastMousePosition.y,
            event.clientX - this.lastMousePosition.x
        ) * (180 / Math.PI);
    }

    calculateAcceleration(event) {
        const currentSpeed = this.calculateSpeed(event);
        if (!this.lastSpeed) {
            this.lastSpeed = { speed: currentSpeed, timestamp: Date.now() };
            return 0;
        }

        const dt = Date.now() - this.lastSpeed.timestamp;
        const acceleration = dt > 0 ? (currentSpeed - this.lastSpeed.speed) / dt : 0;
        
        this.lastSpeed = { speed: currentSpeed, timestamp: Date.now() };
        return acceleration;
    }

    // Keyboard Analysis Methods
    analyzeKeystrokes(event) {
        const keystroke = {
            timestamp: Date.now(),
            key: event.key,
            interval: this.calculateKeystrokeInterval(),
            pattern: this.detectKeystrokePattern(event)
        };

        this.patternHistory.keystrokes.push(keystroke);
        this.trimHistory('keystrokes');

        const analysis = {
            naturalness: this.calculateTypingNaturalness(),
            isBot: this.detectAutomatedTyping(keystroke),
            confidence: this.calculateConfidence('keyboard'),
            patterns: this.analyzeKeyboardPatterns()
        };

        this.updateKeyboardAnalysis(analysis);
        return analysis;
    }

    calculateKeystrokeInterval() {
        if (!this.lastKeystrokeTime) {
            this.lastKeystrokeTime = Date.now();
            return 0;
        }

        const interval = Date.now() - this.lastKeystrokeTime;
        this.lastKeystrokeTime = Date.now();
        return interval;
    }

    detectKeystrokePattern(event) {
        this.currentPatternSequence.push({
            key: event.key,
            timestamp: Date.now()
        });

        if (this.currentPatternSequence.length > 10) {
            this.currentPatternSequence.shift();
        }

        return this.analyzeKeySequence();
    }

    // Scroll Analysis Methods
    analyzeScrollBehavior(event) {
        const scroll = {
            timestamp: Date.now(),
            position: window.scrollY,
            delta: this.calculateScrollDelta(),
            speed: this.calculateScrollSpeed(),
            direction: this.getScrollDirection()
        };

        this.patternHistory.scrollEvents.push(scroll);
        this.trimHistory('scrollEvents');

        const analysis = {
            naturalness: this.calculateScrollNaturalness(),
            isBot: this.detectAutomatedScrolling(scroll),
            confidence: this.calculateConfidence('scroll'),
            patterns: this.detectScrollPatterns()
        };

        this.updateScrollAnalysis(analysis);
        return analysis;
    }

    calculateScrollDelta() {
        if (!this.lastScrollPosition) {
            this.lastScrollPosition = window.scrollY;
            return 0;
        }

        const delta = window.scrollY - this.lastScrollPosition;
        this.lastScrollPosition = window.scrollY;
        return delta;
    }

    getScrollDirection() {
        const delta = this.calculateScrollDelta();
        return delta > 0 ? 'down' : delta < 0 ? 'up' : 'none';
    }

    // Pattern Detection Methods
    detectMousePatterns() {
        const patterns = {
            linear: this.detectLinearMovement(),
            circular: this.detectCircularMovement(),
            grid: this.detectGridPattern(),
            repetitive: this.detectRepetitiveMovement()
        };

        return this.evaluatePatterns(patterns);
    }

    detectLinearMovement() {
        const movements = this.patternHistory.mouseMovements.slice(-20);
        if (movements.length < 3) return false;

        let linearCount = 0;
        for (let i = 2; i < movements.length; i++) {
            const direction1 = Math.atan2(
                movements[i].y - movements[i-1].y,
                movements[i].x - movements[i-1].x
            );
            const direction2 = Math.atan2(
                movements[i-1].y - movements[i-2].y,
                movements[i-1].x - movements[i-2].x
            );

            if (Math.abs(direction1 - direction2) < 0.1) {
                linearCount++;
            }
        }

        return linearCount / (movements.length - 2) > 0.8;
    }

    detectCircularMovement() {
        // Implement circular movement detection logic
        return false;
    }

    detectGridPattern() {
        // Implement grid pattern detection logic
        return false;
    }

    detectRepetitiveMovement() {
        // Implement repetitive movement detection logic
        return false;
    }

    detectBotBehavior(movement) {
        // Implement bot behavior detection logic based on movement patterns
        return false;
    }

    calculateMouseNaturalness() {
        // Implement naturalness calculation for mouse movements
        return 0;
    }

    calculateTypingNaturalness() {
        // Implement naturalness calculation for typing patterns
        return 0;
    }

    analyzeKeySequence() {
        // Implement key sequence analysis logic
        return 'pattern';
    }

    detectAutomatedTyping(keystroke) {
        // Implement automated typing detection logic based on keystroke patterns
        return false;
    }

    calculateScrollNaturalness() {
        // Implement naturalness calculation for scroll behaviors
        return 0;
    }

    detectAutomatedScrolling(scroll) {
        // Implement automated scrolling detection logic based on scroll patterns
        return false;
    }

    detectScrollPatterns() {
        // Implement scroll pattern detection logic
        return {};
    }

    analyzeKeyboardPatterns() {
        // Implement keyboard pattern analysis logic
        return {};
    }

    evaluatePatterns(patterns) {
        // Implement pattern evaluation logic
        return patterns;
    }

    // Utility Methods
    trimHistory(type) {
        if (this.patternHistory[type].length > this.patternHistory.maxHistoryLength) {
            this.patternHistory[type] = this.patternHistory[type].slice(
                -this.patternHistory.maxHistoryLength
            );
        }
    }

    calculateConfidence(type) {
        const patterns = this.patternHistory[`${type}s`];
        const minSamples = this.analysisConfig[`${type}Thresholds`].minimumSampleSize;
        return Math.min(patterns.length / (minSamples * 2), 1);
    }

    // Analysis Update Methods
    updateMouseAnalysis(analysis) {
        this.analysisResults.mousePatterns.push(analysis);
        if (this.analysisResults.mousePatterns.length > 100) {
            this.analysisResults.mousePatterns.shift();
        }
        this.updateOverallScore();
    }

    updateKeyboardAnalysis(analysis) {
        this.analysisResults.keyboardPatterns.push(analysis);
        if (this.analysisResults.keyboardPatterns.length > 100) {
            this.analysisResults.keyboardPatterns.shift();
        }
        this.updateOverallScore();
    }

    updateScrollAnalysis(analysis) {
        this.analysisResults.scrollPatterns.push(analysis);
        if (this.analysisResults.scrollPatterns.length > 100) {
            this.analysisResults.scrollPatterns.shift();
        }
        this.updateOverallScore();
    }

    updateOverallScore() {
        const mouseScore = this.calculateAverageScore('mousePatterns');
        const keyboardScore = this.calculateAverageScore('keyboardPatterns');
        const scrollScore = this.calculateAverageScore('scrollPatterns');

        this.analysisResults.overallScore = (
            mouseScore * 0.4 +
            keyboardScore * 0.3 +
            scrollScore * 0.3
        );

        this.analysisResults.lastUpdate = Date.now();
        this.checkThresholds();
    }

    // Scoring and Evaluation Methods
    calculateAverageScore(patternType) {
        const patterns = this.analysisResults[patternType];
        if (patterns.length === 0) return 0;

        return patterns.reduce((sum, p) => sum + p.naturalness, 0) / patterns.length;
    }

    checkThresholds() {
        if (this.analysisResults.overallScore < 0.4) {
            this.analysisResults.status = 'high_risk';
        } else if (this.analysisResults.overallScore < 0.6) {
            this.analysisResults.status = 'medium_risk';
        } else {
            this.analysisResults.status = 'low_risk';
        }
    }

    // Public API Methods
    getAnalysisResults() {
        return {
            ...this.analysisResults,
            timestamp: Date.now(),
            metadata: {
                sampleCounts: {
                    mouse: this.patternHistory.mouseMovements.length,
                    keyboard: this.patternHistory.keystrokes.length,
                    scroll: this.patternHistory.scrollEvents.length
                },
                thresholds: this.analysisConfig
            }
        };
    }

    reset() {
        this.initializeAnalysis();
        this.patternHistory = {
            mouseMovements: [],
            keystrokes: [],
            scrollEvents: [],
            interactions: [],
            maxHistoryLength: 1000
        };
        this.analysisResults.status = 'reset';
        this.analysisResults.overallScore = 0;
    }
}