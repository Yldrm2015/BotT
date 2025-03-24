class TimeManager {
    constructor(initialDateTime = null) {
        this._currentDateTime = initialDateTime || '2025-03-13 11:44:41';
        this._userLogin = 'Yldrm2015';
        this._offset = 0;
        this._timeZone = 'UTC';
        this._lastSync = this._currentDateTime;
        this._syncInterval = 300000; // 5 minutes
    }

    getCurrentDateTime() {
        if (this._offset) {
            const date = new Date(new Date().getTime() + this._offset);
            return date.toISOString().replace('T', ' ').slice(0, 19);
        }
        return this._currentDateTime;
    }

    getUserLogin() {
        return this._userLogin;
    }

    setDateTime(dateTime) {
        this._currentDateTime = dateTime;
        this._offset = new Date(dateTime).getTime() - new Date().getTime();
        this._lastSync = dateTime;
    }

    updateOffset(serverTime) {
        const localTime = new Date().getTime();
        const serverTimeMs = new Date(serverTime).getTime();
        this._offset = serverTimeMs - localTime;
    }

    formatDate(date = new Date(), format = 'YYYY-MM-DD HH:mm:ss') {
        if (this._offset) {
            date = new Date(date.getTime() + this._offset);
        }
        
        const year = date.getUTCFullYear();
        const month = String(date.getUTCMonth() + 1).padStart(2, '0');
        const day = String(date.getUTCDate()).padStart(2, '0');
        const hours = String(date.getUTCHours()).padStart(2, '0');
        const minutes = String(date.getUTCMinutes()).padStart(2, '0');
        const seconds = String(date.getUTCSeconds()).padStart(2, '0');

        return format
            .replace('YYYY', year)
            .replace('MM', month)
            .replace('DD', day)
            .replace('HH', hours)
            .replace('mm', minutes)
            .replace('ss', seconds);
    }

    getTimestamp() {
        return new Date(this._currentDateTime).getTime();
    }

    calculateTimeDifference(startTime, endTime) {
        const start = new Date(startTime).getTime();
        const end = new Date(endTime).getTime();
        return end - start;
    }

    isExpired(timestamp, duration) {
        const expirationTime = new Date(timestamp).getTime() + duration;
        const currentTime = this.getTimestamp();
        return currentTime > expirationTime;
    }

    getTimeZone() {
        return this._timeZone;
    }

    setTimeZone(timeZone) {
        this._timeZone = timeZone;
    }

    getLastSync() {
        return this._lastSync;
    }

    needsSync() {
        const timeSinceLastSync = this.calculateTimeDifference(
            this._lastSync,
            this._currentDateTime
        );
        return timeSinceLastSync >= this._syncInterval;
    }

    getMetadata() {
        return {
            currentDateTime: this._currentDateTime,
            userLogin: this._userLogin,
            timeZone: this._timeZone,
            lastSync: this._lastSync,
            offset: this._offset
        };
    }
}