class ConfigManager {
    constructor(timeManager) {
        this.timeManager = timeManager;
        this.config = this.initializeConfig();
    }

    initializeConfig() {
        return {
            networkControls: {
                blockKnownProxies: true,
                checkWebRTC: true,
                tcpFingerprintingStrict: true,
                checkConnectionSpeed: true
            },
            timeAndUserConfig: {
                currentDateTime: this.timeManager.getCurrentDateTime(),
                userLogin: this.timeManager.getUserLogin(),
                lastChecked: null,
                status: 'Not yet checked'
            },
            behavioralThresholds: {
                mouseMovementNaturalness: 0.6,
                scrollSpeedVariance: 0.4,
                keystrokeNaturalness: 0.7,
                interactionTimingVariance: 0.5,
                pageFocusRatio: 0.4,
                copyPasteCount: 5
            }
        };
    }
}