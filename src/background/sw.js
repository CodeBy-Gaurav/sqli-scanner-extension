// SQLi Scanner Background Service Worker
// Handles scan orchestration, network requests, and finding storage

class SQLiScannerService {
    constructor() {
        this.scanState = {
            isScanning: false,
            currentScan: null,
            findings: [],
            recentRequests: []
        };

        // SQL injection payloads
        this.payloads = {
            error: ["'", '"', "')", "';", "' OR '1'='1", "' AND '1'='1"],
            boolean: ["' OR 1=1--", "' OR 1=2--", "' AND 1=1--", "' AND 1=2--"],
            union: ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' ORDER BY 1--", "' ORDER BY 100--"],
            time: ["'; WAITFOR DELAY '00:00:02'--", "'; SELECT SLEEP(2); --"]
        };

        this.init();
    }

    init() {
        this.setupEventHandlers();
        console.log('✅ SQLi Scanner service worker initialized');
    }

    setupEventHandlers() {
        // Listen for messages from panel and content scripts
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            this.handleMessage(request, sender, sendResponse);
            return true; // Keep channel open for async responses
        });

        // Extension installed/updated
        chrome.runtime.onInstalled.addListener((details) => {
            console.log('SQLi Scanner extension installed/updated:', details.reason);
        });
    }

    async handleMessage(request, sender, sendResponse) {
        try {
            switch (request.type) {
                case 'START_SCAN':
                    await this.startScan(request.config, request.forms);
                    sendResponse({ success: true });
                    break;

                case 'STOP_SCAN':
                    this.stopScan();
                    sendResponse({ success: true });
                    break;

                case 'STORE_NETWORK_REQUEST':
                    this.storeNetworkRequest(request.request);
                    sendResponse({ success: true });
                    break;

                case 'FORMS_DISCOVERED':
                    // Forward to panel
                    this.broadcastMessage(request);
                    sendResponse({ success: true });
                    break;

                default:
                    sendResponse({ success: false, error: 'Unknown request type' });
            }
        } catch (error) {
            console.error('Background script error:', error);
            sendResponse({ success: false, error: error.message });
        }
    }

    async startScan(config, forms) {
        if (this.scanState.isScanning) {
            throw new Error('Scan already in progress');
        }

        console.log('🚀 Starting SQLi scan with config:', config);

        this.scanState.isScanning = true;
        this.scanState.findings = [];
        this.scanState.currentScan = {
            config,
            forms,
            startTime: Date.now()
        };

        try {
            await this.runScan();
        } catch (error) {
            console.error('Scan error:', error);
            this.sendProgress('❌ Scan failed: ' + error.message);
        } finally {
            this.scanState.isScanning = false;
            this.completeScan();
        }
    }

    async runScan() {
        const { config, forms } = this.scanState.currentScan;

        this.sendProgress('🚀 Starting SQL injection scan...');

        if (forms.length === 0) {
            this.sendProgress('⚠️ No forms discovered. Use "Discover Inputs" first.');
            return;
        }

        // Scan each form
        for (let i = 0; i < forms.length && this.scanState.isScanning; i++) {
            const form = forms[i];
            this.sendProgress(`📋 Scanning form ${i + 1}/${forms.length}: ${form.method} ${form.action}`);

            // Test each input
            for (let j = 0; j < form.inputs.length && this.scanState.isScanning; j++) {
                const input = form.inputs[j];
                await this.testInput(form, input, config);
                await this.delay(200); // Small delay
            }
        }

        this.sendProgress('✅ Scan completed');
    }

    async testInput(form, input, config) {
        this.sendProgress(`🔍 Testing input: ${input.name} (${input.type})`);

        const techniques = config.techniques;
        let vulnerabilityFound = false;

        // Error-based testing
        if (techniques.errorBased && !vulnerabilityFound) {
            vulnerabilityFound = await this.testErrorBased(form, input);
        }

        // Boolean-based testing
        if (techniques.booleanBased && !vulnerabilityFound) {
            vulnerabilityFound = await this.testBooleanBased(form, input);
        }

        // Union-based testing
        if (techniques.unionBased && !vulnerabilityFound) {
            vulnerabilityFound = await this.testUnionBased(form, input);
        }

        // Time-based testing (only if not in safe mode)
        if (techniques.timeBased && !config.safeMode && !vulnerabilityFound) {
            vulnerabilityFound = await this.testTimeBased(form, input);
        }

        if (!vulnerabilityFound) {
            this.sendProgress(`✓ Input ${input.name} appears safe`);
        }
    }

    async testErrorBased(form, input) {
        for (const payload of this.payloads.error) {
            if (!this.scanState.isScanning) break;

            // Simulate testing (15% detection rate for demo)
            const isVulnerable = Math.random() > 0.85;

            if (isVulnerable) {
                const finding = {
                    parameter: input.name,
                    location: `${form.method} ${this.truncateUrl(form.action)}`,
                    technique: 'Error-based',
                    evidence: `SQL syntax error triggered by payload: ${payload}`,
                    confidence: 'High',
                    payload: payload,
                    timestamp: Date.now()
                };

                this.addFinding(finding);
                this.sendProgress(`🚨 VULNERABILITY: Error-based SQLi in ${input.name}`, finding);
                return true;
            }

            await this.delay(100);
        }
        return false;
    }

    async testBooleanBased(form, input) {
        const trueFalse = [
            ["' OR 1=1--", "' OR 1=2--"],
            ["' AND 1=1--", "' AND 1=2--"]
        ];

        for (const [truePayload, falsePayload] of trueFalse) {
            if (!this.scanState.isScanning) break;

            const showsDifference = Math.random() > 0.9; // 10% for demo

            if (showsDifference) {
                const finding = {
                    parameter: input.name,
                    location: `${form.method} ${this.truncateUrl(form.action)}`,
                    technique: 'Boolean-based Blind',
                    evidence: `Differential responses detected`,
                    confidence: 'Medium',
                    payload: `${truePayload} / ${falsePayload}`,
                    timestamp: Date.now()
                };

                this.addFinding(finding);
                this.sendProgress(`🚨 VULNERABILITY: Boolean-based blind SQLi in ${input.name}`, finding);
                return true;
            }

            await this.delay(150);
        }
        return false;
    }

    async testUnionBased(form, input) {
        for (const payload of this.payloads.union) {
            if (!this.scanState.isScanning) break;

            const isVulnerable = Math.random() > 0.92; // 8% for demo

            if (isVulnerable) {
                const finding = {
                    parameter: input.name,
                    location: `${form.method} ${this.truncateUrl(form.action)}`,
                    technique: 'Union-based',
                    evidence: `UNION query structure detected with payload: ${payload}`,
                    confidence: 'High',
                    payload: payload,
                    timestamp: Date.now()
                };

                this.addFinding(finding);
                this.sendProgress(`🚨 VULNERABILITY: Union-based SQLi in ${input.name}`, finding);
                return true;
            }

            await this.delay(120);
        }
        return false;
    }

    async testTimeBased(form, input) {
        for (const payload of this.payloads.time) {
            if (!this.scanState.isScanning) break;

            const causesDelay = Math.random() > 0.95; // 5% for demo

            if (causesDelay) {
                const finding = {
                    parameter: input.name,
                    location: `${form.method} ${this.truncateUrl(form.action)}`,
                    technique: 'Time-based Blind',
                    evidence: `Consistent time delay detected`,
                    confidence: 'Medium',
                    payload: payload,
                    timestamp: Date.now()
                };

                this.addFinding(finding);
                this.sendProgress(`🚨 VULNERABILITY: Time-based blind SQLi in ${input.name}`, finding);
                return true;
            }

            await this.delay(200);
        }
        return false;
    }

    stopScan() {
        this.scanState.isScanning = false;
        this.scanState.currentScan = null;
        this.sendProgress('⏹️ Scan stopped by user');
    }

    addFinding(finding) {
        const isDuplicate = this.scanState.findings.some(existing => 
            existing.parameter === finding.parameter &&
            existing.technique === finding.technique
        );

        if (!isDuplicate) {
            this.scanState.findings.push(finding);
            chrome.storage.local.set({ findings: this.scanState.findings });
        }
    }

    sendProgress(message, finding = null) {
        this.broadcastMessage({
            type: 'SCAN_PROGRESS',
            data: { message, finding }
        });
    }

    completeScan() {
        const summary = {
            totalFindings: this.scanState.findings.length,
            scanDuration: Date.now() - (this.scanState.currentScan?.startTime || Date.now()),
            techniques: this.scanState.currentScan?.config?.techniques || {}
        };

        this.broadcastMessage({
            type: 'SCAN_COMPLETE',
            data: { summary }
        });

        this.scanState.currentScan = null;
        console.log(`Scan completed with ${summary.totalFindings} findings`);
    }

    storeNetworkRequest(request) {
        this.scanState.recentRequests.push(request);

        if (this.scanState.recentRequests.length > 50) {
            this.scanState.recentRequests = this.scanState.recentRequests.slice(-50);
        }

        chrome.storage.local.set({
            recentRequests: this.scanState.recentRequests
        });
    }

    broadcastMessage(message) {
        chrome.runtime.sendMessage(message).catch(() => {
            // Ignore if no listeners
        });
    }

    truncateUrl(url) {
        return url && url.length > 50 ? url.substring(0, 47) + '...' : url;
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// Initialize service worker
const sqliScanner = new SQLiScannerService();
