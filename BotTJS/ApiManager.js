// ApiManager.js
class ApiManager {
    constructor() {
        this.timestamp = '2025-03-20 09:35:55';
        this.userLogin = 'Yldrm2015';

        this.apiConfig = {
            baseUrl: 'http://localhost:3000',
            endpoints: {
                validate: '/api/validate',
                health: '/api/health',
                events: '/api/events',
                metrics: '/api/metrics'
            },
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.userLogin}`
            },
            retry: {
                maxAttempts: 3,
                delay: 1000
            },
            timeout: 5000
        };

        this.initialize();
    }

    async initialize() {
        try {
            const isHealthy = await this.checkHealth();
            if (!isHealthy) {
                throw new Error('API service is not healthy');
            }
            console.log(`[${this.timestamp}] ApiManager initialized successfully`);
        } catch (error) {
            console.error(`[${this.timestamp}] ApiManager initialization failed:`, error);
        }
    }

    async checkHealth() {
        try {
            const response = await this.fetchWithTimeout(
                `${this.apiConfig.baseUrl}${this.apiConfig.endpoints.health}`
            );
            return response.ok;
        } catch (error) {
            console.error(`[${this.timestamp}] Health check failed:`, error);
            return false;
        }
    }

    async sendData(data, retryCount = 0) {
        try {
            const response = await this.fetchWithTimeout(
                `${this.apiConfig.baseUrl}${this.apiConfig.endpoints.validate}`,
                {
                    method: 'POST',
                    headers: this.apiConfig.headers,
                    body: JSON.stringify({
                        timestamp: this.timestamp,
                        userLogin: this.userLogin,
                        data: data
                    })
                }
            );

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            if (retryCount < this.apiConfig.retry.maxAttempts) {
                await this.delay(this.apiConfig.retry.delay);
                return this.sendData(data, retryCount + 1);
            }
            this.handleError(error);
            return null;
        }
    }

    async sendEvent(event) {
        try {
            const response = await this.fetchWithTimeout(
                `${this.apiConfig.baseUrl}${this.apiConfig.endpoints.events}`,
                {
                    method: 'POST',
                    headers: this.apiConfig.headers,
                    body: JSON.stringify({
                        timestamp: this.timestamp,
                        userLogin: this.userLogin,
                        event: event
                    })
                }
            );

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            this.handleError(error);
            return null;
        }
    }

    async getMetrics() {
        try {
            const response = await this.fetchWithTimeout(
                `${this.apiConfig.baseUrl}${this.apiConfig.endpoints.metrics}`,
                {
                    headers: this.apiConfig.headers
                }
            );

            if (!response.ok) {
                throw new Error(`API Error: ${response.status}`);
            }

            return await response.json();
        } catch (error) {
            this.handleError(error);
            return null;
        }
    }

    async fetchWithTimeout(url, options = {}) {
        const controller = new AbortController();
        const timeout = setTimeout(() => {
            controller.abort();
        }, this.apiConfig.timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal
            });
            clearTimeout(timeout);
            return response;
        } catch (error) {
            clearTimeout(timeout);
            throw error;
        }
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    handleError(error) {
        console.error(`[${this.timestamp}] API Error:`, error);
        // Implement error handling logic
    }

    // Test metodu
    async test() {
        console.log(`[${this.timestamp}] Running API tests...`);
        
        // Health check
        const health = await this.checkHealth();
        console.log(`Health check: ${health ? 'OK' : 'Failed'}`);

        // Send test data
        const testData = {
            type: 'test',
            value: 'test_value'
        };
        const sendResult = await this.sendData(testData);
        console.log('Send data test:', sendResult);

        // Get metrics
        const metrics = await this.getMetrics();
        console.log('Metrics test:', metrics);

        return {
            health,
            sendResult,
            metrics
        };
    }
}

// Global scope'a ekle
window.ApiManager = ApiManager;