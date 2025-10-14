/**
 * Chrome storage utilities for SQLi Scanner
 */

export class StorageUtils {

    static KEYS = {
        SCAN_SETTINGS: 'scan_settings',
        FINDINGS: 'findings',
        RECENT_REQUESTS: 'recent_requests',
        SCAN_HISTORY: 'scan_history',
        TARGETS: 'targets',
        PAYLOADS: 'custom_payloads',
        PREFERENCES: 'user_preferences',
        SESSION_DATA: 'session_data'
    };

    /**
     * Store scan settings
     */
    static async storeScanSettings(settings) {
        try {
            await chrome.storage.local.set({
                [this.KEYS.SCAN_SETTINGS]: {
                    ...settings,
                    timestamp: Date.now()
                }
            });
            return true;
        } catch (error) {
            console.error('Failed to store scan settings:', error);
            return false;
        }
    }

    /**
     * Load scan settings
     */
    static async loadScanSettings() {
        try {
            const result = await chrome.storage.local.get([this.KEYS.SCAN_SETTINGS]);
            return result[this.KEYS.SCAN_SETTINGS] || this.getDefaultScanSettings();
        } catch (error) {
            console.error('Failed to load scan settings:', error);
            return this.getDefaultScanSettings();
        }
    }

    /**
     * Store findings with deduplication
     */
    static async storeFindings(findings) {
        try {
            const existingFindings = await this.loadFindings();
            const allFindings = [...existingFindings];

            // Deduplicate findings
            for (const finding of findings) {
                const isDuplicate = existingFindings.some(existing =>
                    existing.parameter === finding.parameter &&
                    existing.location === finding.location &&
                    existing.technique === finding.technique
                );

                if (!isDuplicate) {
                    allFindings.push({
                        ...finding,
                        id: finding.id || Date.now().toString() + Math.random().toString(36).substr(2, 9),
                        timestamp: finding.timestamp || Date.now()
                    });
                }
            }

            await chrome.storage.local.set({
                [this.KEYS.FINDINGS]: allFindings
            });

            return allFindings.length;
        } catch (error) {
            console.error('Failed to store findings:', error);
            return 0;
        }
    }

    /**
     * Load findings with filtering options
     */
    static async loadFindings(options = {}) {
        try {
            const result = await chrome.storage.local.get([this.KEYS.FINDINGS]);
            let findings = result[this.KEYS.FINDINGS] || [];

            // Apply filters
            if (options.confidence) {
                findings = findings.filter(f => f.confidence === options.confidence);
            }

            if (options.technique) {
                findings = findings.filter(f => f.technique === options.technique);
            }

            if (options.dateRange) {
                const { start, end } = options.dateRange;
                findings = findings.filter(f => 
                    f.timestamp >= start && f.timestamp <= end
                );
            }

            if (options.domain) {
                findings = findings.filter(f => 
                    f.location && f.location.includes(options.domain)
                );
            }

            // Sort by timestamp (newest first)
            findings.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));

            return findings;
        } catch (error) {
            console.error('Failed to load findings:', error);
            return [];
        }
    }

    /**
     * Clear findings
     */
    static async clearFindings() {
        try {
            await chrome.storage.local.remove([this.KEYS.FINDINGS]);
            return true;
        } catch (error) {
            console.error('Failed to clear findings:', error);
            return false;
        }
    }

    /**
     * Store recent network requests
     */
    static async storeRecentRequests(requests) {
        try {
            // Keep only last 100 requests
            const limitedRequests = requests.slice(-100);

            await chrome.storage.local.set({
                [this.KEYS.RECENT_REQUESTS]: limitedRequests
            });

            return true;
        } catch (error) {
            console.error('Failed to store recent requests:', error);
            return false;
        }
    }

    /**
     * Load recent network requests
     */
    static async loadRecentRequests() {
        try {
            const result = await chrome.storage.local.get([this.KEYS.RECENT_REQUESTS]);
            return result[this.KEYS.RECENT_REQUESTS] || [];
        } catch (error) {
            console.error('Failed to load recent requests:', error);
            return [];
        }
    }

    /**
     * Store scan history
     */
    static async storeScanHistory(scanData) {
        try {
            const existingHistory = await this.loadScanHistory();

            const newEntry = {
                id: Date.now().toString(),
                timestamp: Date.now(),
                target: scanData.target,
                findings: scanData.findings?.length || 0,
                duration: scanData.duration || 0,
                techniques: scanData.techniques || [],
                settings: scanData.settings || {}
            };

            existingHistory.unshift(newEntry);

            // Keep only last 50 scans
            const limitedHistory = existingHistory.slice(0, 50);

            await chrome.storage.local.set({
                [this.KEYS.SCAN_HISTORY]: limitedHistory
            });

            return newEntry.id;
        } catch (error) {
            console.error('Failed to store scan history:', error);
            return null;
        }
    }

    /**
     * Load scan history
     */
    static async loadScanHistory() {
        try {
            const result = await chrome.storage.local.get([this.KEYS.SCAN_HISTORY]);
            return result[this.KEYS.SCAN_HISTORY] || [];
        } catch (error) {
            console.error('Failed to load scan history:', error);
            return [];
        }
    }

    /**
     * Store user preferences
     */
    static async storePreferences(preferences) {
        try {
            const existing = await this.loadPreferences();
            const updated = { ...existing, ...preferences };

            await chrome.storage.local.set({
                [this.KEYS.PREFERENCES]: updated
            });

            return true;
        } catch (error) {
            console.error('Failed to store preferences:', error);
            return false;
        }
    }

    /**
     * Load user preferences
     */
    static async loadPreferences() {
        try {
            const result = await chrome.storage.local.get([this.KEYS.PREFERENCES]);
            return result[this.KEYS.PREFERENCES] || this.getDefaultPreferences();
        } catch (error) {
            console.error('Failed to load preferences:', error);
            return this.getDefaultPreferences();
        }
    }

    /**
     * Store custom payloads
     */
    static async storeCustomPayloads(payloads) {
        try {
            await chrome.storage.local.set({
                [this.KEYS.PAYLOADS]: payloads
            });
            return true;
        } catch (error) {
            console.error('Failed to store custom payloads:', error);
            return false;
        }
    }

    /**
     * Load custom payloads
     */
    static async loadCustomPayloads() {
        try {
            const result = await chrome.storage.local.get([this.KEYS.PAYLOADS]);
            return result[this.KEYS.PAYLOADS] || [];
        } catch (error) {
            console.error('Failed to load custom payloads:', error);
            return [];
        }
    }

    /**
     * Get storage usage statistics
     */
    static async getStorageStats() {
        try {
            const usage = await chrome.storage.local.getBytesInUse();
            const quota = chrome.storage.local.QUOTA_BYTES || 5242880; // 5MB default

            return {
                used: usage,
                quota: quota,
                available: quota - usage,
                percentageUsed: Math.round((usage / quota) * 100)
            };
        } catch (error) {
            console.error('Failed to get storage stats:', error);
            return {
                used: 0,
                quota: 5242880,
                available: 5242880,
                percentageUsed: 0
            };
        }
    }

    /**
     * Clear all extension data
     */
    static async clearAllData() {
        try {
            await chrome.storage.local.clear();
            return true;
        } catch (error) {
            console.error('Failed to clear all data:', error);
            return false;
        }
    }

    /**
     * Export all data for backup
     */
    static async exportData() {
        try {
            const allData = await chrome.storage.local.get();
            return {
                exportDate: new Date().toISOString(),
                version: '1.0.0',
                data: allData
            };
        } catch (error) {
            console.error('Failed to export data:', error);
            return null;
        }
    }

    /**
     * Import data from backup
     */
    static async importData(exportedData) {
        try {
            if (!exportedData.data) {
                throw new Error('Invalid backup format');
            }

            // Clear existing data first
            await chrome.storage.local.clear();

            // Import new data
            await chrome.storage.local.set(exportedData.data);

            return true;
        } catch (error) {
            console.error('Failed to import data:', error);
            return false;
        }
    }

    /**
     * Default scan settings
     */
    static getDefaultScanSettings() {
        return {
            mode: 'safe',
            techniques: {
                'error-based': true,
                'boolean-blind': true,
                'time-blind': false,
                'union-based': true,
                'waf-bypass': false
            },
            advanced: {
                retryCount: 3,
                timingThreshold: 2000,
                concurrentRequests: 1,
                requestDelay: 100
            },
            scope: {
                currentOriginOnly: false,
                includeCookies: true,
                includeHeaders: false
            }
        };
    }

    /**
     * Default user preferences
     */
    static getDefaultPreferences() {
        return {
            theme: 'light',
            autoSave: true,
            showNotifications: true,
            logLevel: 'info',
            exportFormat: 'json',
            autoHighlight: true,
            confirmDestructive: true
        };
    }

    /**
     * Session storage utilities (for temporary data)
     */
    static async storeSessionData(key, data) {
        try {
            const sessionData = await this.loadSessionData();
            sessionData[key] = {
                data,
                timestamp: Date.now()
            };

            await chrome.storage.session.set({
                [this.KEYS.SESSION_DATA]: sessionData
            });

            return true;
        } catch (error) {
            console.error('Failed to store session data:', error);
            return false;
        }
    }

    static async loadSessionData(key = null) {
        try {
            const result = await chrome.storage.session.get([this.KEYS.SESSION_DATA]);
            const sessionData = result[this.KEYS.SESSION_DATA] || {};

            if (key) {
                return sessionData[key]?.data || null;
            }

            return sessionData;
        } catch (error) {
            console.error('Failed to load session data:', error);
            return key ? null : {};
        }
    }
}