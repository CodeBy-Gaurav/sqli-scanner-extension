/**
 * Chrome permissions management utilities
 */

export class PermissionsUtils {

    static PERMISSIONS = {
        STORAGE: 'storage',
        ACTIVE_TAB: 'activeTab',
        SCRIPTING: 'scripting',
        DOWNLOADS: 'downloads',
        WEB_REQUEST: 'webRequest',
        TABS: 'tabs'
    };

    static HOST_PERMISSIONS = {
        ALL_URLS: '<all_urls>',
        HTTP: 'http://*/*',
        HTTPS: 'https://*/*'
    };

    /**
     * Check if all required permissions are granted
     */
    static async checkRequiredPermissions() {
        const requiredPermissions = [
            this.PERMISSIONS.STORAGE,
            this.PERMISSIONS.ACTIVE_TAB,
            this.PERMISSIONS.SCRIPTING,
            this.PERMISSIONS.DOWNLOADS
        ];

        try {
            const hasPermissions = await chrome.permissions.contains({
                permissions: requiredPermissions
            });

            const hasHostPermissions = await chrome.permissions.contains({
                origins: [this.HOST_PERMISSIONS.ALL_URLS]
            });

            return {
                hasAllRequired: hasPermissions && hasHostPermissions,
                hasPermissions,
                hasHostPermissions,
                missing: {
                    permissions: hasPermissions ? [] : requiredPermissions,
                    origins: hasHostPermissions ? [] : [this.HOST_PERMISSIONS.ALL_URLS]
                }
            };
        } catch (error) {
            console.error('Failed to check permissions:', error);
            return {
                hasAllRequired: false,
                error: error.message
            };
        }
    }

    /**
     * Request additional permissions
     */
    static async requestPermissions(permissions = [], origins = []) {
        try {
            const granted = await chrome.permissions.request({
                permissions,
                origins
            });

            if (granted) {
                console.log('Permissions granted:', { permissions, origins });
            } else {
                console.warn('Permissions denied:', { permissions, origins });
            }

            return granted;
        } catch (error) {
            console.error('Failed to request permissions:', error);
            return false;
        }
    }

    /**
     * Remove permissions (for privacy)
     */
    static async removePermissions(permissions = [], origins = []) {
        try {
            const removed = await chrome.permissions.remove({
                permissions,
                origins
            });

            if (removed) {
                console.log('Permissions removed:', { permissions, origins });
            }

            return removed;
        } catch (error) {
            console.error('Failed to remove permissions:', error);
            return false;
        }
    }

    /**
     * Get current permissions
     */
    static async getCurrentPermissions() {
        try {
            const permissions = await chrome.permissions.getAll();
            return permissions;
        } catch (error) {
            console.error('Failed to get current permissions:', error);
            return { permissions: [], origins: [] };
        }
    }

    /**
     * Check if can access specific URL
     */
    static async canAccessUrl(url) {
        try {
            const urlObj = new URL(url);
            const origin = `${urlObj.protocol}//${urlObj.host}/*`;

            const hasPermission = await chrome.permissions.contains({
                origins: [origin]
            });

            return hasPermission;
        } catch (error) {
            console.error('Failed to check URL access:', error);
            return false;
        }
    }

    /**
     * Request permission for specific domain
     */
    static async requestDomainPermission(domain) {
        const origins = [
            `http://${domain}/*`,
            `https://${domain}/*`
        ];

        return await this.requestPermissions([], origins);
    }

    /**
     * Check scripting permission for tab
     */
    static async canScriptTab(tabId) {
        try {
            // Try to inject a simple script to test
            await chrome.scripting.executeScript({
                target: { tabId },
                func: () => true
            });
            return true;
        } catch (error) {
            console.warn('Cannot script tab:', error.message);
            return false;
        }
    }

    /**
     * Request host permission with user-friendly dialog
     */
    static async requestHostPermissionWithDialog(url) {
        try {
            const urlObj = new URL(url);
            const domain = urlObj.hostname;

            // Show user-friendly explanation
            const userConsent = confirm(
                `SQLi Scanner needs permission to access ${domain} for security testing.\n\n` +
                'This permission allows the extension to:\n' +
                '• Discover forms and inputs on the page\n' +
                '• Send test requests to check for vulnerabilities\n' +
                '• Analyze responses for SQL injection patterns\n\n' +
                'Grant permission?'
            );

            if (!userConsent) {
                return false;
            }

            const origins = [`${urlObj.protocol}//${urlObj.host}/*`];
            return await this.requestPermissions([], origins);
        } catch (error) {
            console.error('Failed to request host permission:', error);
            return false;
        }
    }

    /**
     * Setup permission change listener
     */
    static setupPermissionListener(callback) {
        if (chrome.permissions.onAdded) {
            chrome.permissions.onAdded.addListener((permissions) => {
                console.log('Permissions added:', permissions);
                callback({ type: 'added', permissions });
            });
        }

        if (chrome.permissions.onRemoved) {
            chrome.permissions.onRemoved.addListener((permissions) => {
                console.log('Permissions removed:', permissions);
                callback({ type: 'removed', permissions });
            });
        }
    }

    /**
     * Check if extension has minimum viable permissions
     */
    static async hasMinimumPermissions() {
        const minimum = [
            this.PERMISSIONS.STORAGE,
            this.PERMISSIONS.ACTIVE_TAB
        ];

        try {
            return await chrome.permissions.contains({
                permissions: minimum
            });
        } catch (error) {
            console.error('Failed to check minimum permissions:', error);
            return false;
        }
    }

    /**
     * Get permission status for UI display
     */
    static async getPermissionStatus() {
        try {
            const current = await this.getCurrentPermissions();
            const required = await this.checkRequiredPermissions();

            return {
                current,
                required: required.hasAllRequired,
                missing: required.missing,
                optional: {
                    webRequest: current.permissions.includes(this.PERMISSIONS.WEB_REQUEST),
                    tabs: current.permissions.includes(this.PERMISSIONS.TABS)
                },
                hostAccess: {
                    allUrls: current.origins.includes(this.HOST_PERMISSIONS.ALL_URLS),
                    http: current.origins.some(origin => origin.startsWith('http://')),
                    https: current.origins.some(origin => origin.startsWith('https://'))
                }
            };
        } catch (error) {
            console.error('Failed to get permission status:', error);
            return {
                current: { permissions: [], origins: [] },
                required: false,
                error: error.message
            };
        }
    }

    /**
     * Validate manifest permissions
     */
    static validateManifestPermissions() {
        const manifest = chrome.runtime.getManifest();

        const analysis = {
            valid: true,
            warnings: [],
            recommendations: []
        };

        // Check required permissions
        const required = ['storage', 'activeTab', 'scripting', 'downloads'];
        const declared = manifest.permissions || [];

        for (const permission of required) {
            if (!declared.includes(permission)) {
                analysis.valid = false;
                analysis.warnings.push(`Missing required permission: ${permission}`);
            }
        }

        // Check host permissions
        const hostPermissions = manifest.host_permissions || [];
        if (!hostPermissions.includes('<all_urls>')) {
            analysis.recommendations.push('Consider adding <all_urls> for broader scanning capabilities');
        }

        // Check optional permissions that enhance functionality
        const beneficial = ['webRequest', 'tabs'];
        for (const permission of beneficial) {
            if (!declared.includes(permission)) {
                analysis.recommendations.push(`Consider adding optional permission: ${permission}`);
            }
        }

        return analysis;
    }

    /**
     * Request permissions based on scan configuration
     */
    static async requestPermissionsForScan(config) {
        const needed = {
            permissions: [],
            origins: []
        };

        // Always need basic permissions
        needed.permissions.push(
            this.PERMISSIONS.STORAGE,
            this.PERMISSIONS.ACTIVE_TAB,
            this.PERMISSIONS.SCRIPTING
        );

        // Need downloads for report export
        if (config.enableExports !== false) {
            needed.permissions.push(this.PERMISSIONS.DOWNLOADS);
        }

        // Need web request for advanced network monitoring
        if (config.techniques?.includes('advanced-timing') || config.networkMonitoring) {
            needed.permissions.push(this.PERMISSIONS.WEB_REQUEST);
        }

        // Need broader host permissions for comprehensive scanning
        if (!config.scope?.currentOriginOnly) {
            needed.origins.push(this.HOST_PERMISSIONS.ALL_URLS);
        }

        // Check what we already have
        const current = await this.getCurrentPermissions();
        const missingPermissions = needed.permissions.filter(p => 
            !current.permissions.includes(p)
        );
        const missingOrigins = needed.origins.filter(o => 
            !current.origins.includes(o)
        );

        // Request missing permissions
        if (missingPermissions.length || missingOrigins.length) {
            return await this.requestPermissions(missingPermissions, missingOrigins);
        }

        return true; // Already have all needed permissions
    }
}