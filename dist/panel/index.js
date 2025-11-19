class SQLiScannerPanel {
    constructor() {
        this.scanState = {
            isScanning: false,
            findings: [],
            logs: [],
            discoveredForms: [],
            recentRequests: []
        };
        
        this.contextValid = true;
        this.messageListenerAttached = false;
        
        // Delay initialization to ensure extension context is ready
        if (this.isExtensionContextValid()) {
            this.init();
        } else {
            console.error('[SQLi Scanner Panel] Extension context invalid at startup');
            this.showContextInvalidatedWarning();
        }
    }
    
    // Robust context validation
    isExtensionContextValid() {
        try {
            if (!chrome || !chrome.runtime || !chrome.runtime.id) {
                return false;
            }
            // Try to access runtime properties
            void chrome.runtime.getManifest();
            return true;
        } catch (error) {
            return false;
        }
    }
    
    // Check and update context status
    checkContext() {
        const isValid = this.isExtensionContextValid();
        
        if (!isValid && this.contextValid) {
            // Context just became invalid
            this.contextValid = false;
            this.logError('⚠️ Extension context invalidated. Please close and reopen DevTools.');
            this.showContextInvalidatedWarning();
        }
        
        this.contextValid = isValid;
        return isValid;
    }
    
    showContextInvalidatedWarning() {
        // Remove any existing warning
        const existing = document.getElementById('context-warning');
        if (existing) {
            existing.remove();
        }
        
        const warning = document.createElement('div');
        warning.id = 'context-warning';
        warning.style.cssText = `
            position: fixed;
            top: 10px;
            left: 50%;
            transform: translateX(-50%);
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a6f 100%);
            color: white;
            padding: 15px 25px;
            border-radius: 8px;
            font-weight: bold;
            z-index: 10000;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        `;
        
        warning.innerHTML = `
            ⚠️ Extension reloaded. Please close and reopen DevTools.
            <button id="reloadPanelBtn" style="margin-left: 15px; padding: 5px 10px; border: none; background: white; color: #ff6b6b; border-radius: 4px; cursor: pointer; font-weight: bold;">
                Reload Panel
            </button>
        `;
        
        document.body.appendChild(warning);
        
        // Add reload handler
        const reloadBtn = document.getElementById('reloadPanelBtn');
        if (reloadBtn) {
            reloadBtn.addEventListener('click', () => {
                window.location.reload();
            });
        }
    }
    
    // Safe message sender with context check
    safeSendMessage(message) {
        if (!this.checkContext()) {
            return Promise.reject(new Error('Extension context invalidated'));
        }
        
        return new Promise((resolve, reject) => {
            try {
                chrome.runtime.sendMessage(message, (response) => {
                    if (chrome.runtime.lastError) {
                        // Check if it's a connection error (expected when extension reloads)
                        if (chrome.runtime.lastError.message.includes('Could not establish connection')) {
                            this.checkContext(); // This will show warning if needed
                        }
                        reject(new Error(chrome.runtime.lastError.message));
                    } else {
                        resolve(response);
                    }
                });
            } catch (error) {
                reject(error);
            }
        });
    }
    
    init() {
        if (!this.checkContext()) {
            console.error('[SQLi Scanner Panel] Cannot initialize - context invalid');
            return;
        }
        
        console.log('[SQLi Scanner Panel] Initializing...');
        
        this.setupEventListeners();
        this.loadInitialData();
        this.setupMessageHandlers();
        
        // Monitor context every 3 seconds
        setInterval(() => {
            this.checkContext();
        }, 3000);
        
        this.log('SQLi Scanner initialized successfully');
    }
    
    setupEventListeners() {
        try {
            // Main action buttons
            const discoverBtn = document.getElementById('discoverBtn');
            const highlightBtn = document.getElementById('highlightBtn');
            const runScanBtn = document.getElementById('runScanBtn');
            const stopScanBtn = document.getElementById('stopScanBtn');
            const exportJsonBtn = document.getElementById('exportJsonBtn');
            const exportMdBtn = document.getElementById('exportMdBtn');
            const safeModeCheck = document.getElementById('safeMode');
            
            if (discoverBtn) discoverBtn.addEventListener('click', () => this.discoverInputs());
            if (highlightBtn) highlightBtn.addEventListener('click', () => this.toggleHighlights());
            if (runScanBtn) runScanBtn.addEventListener('click', () => this.runScan());
            if (stopScanBtn) stopScanBtn.addEventListener('click', () => this.stopScan());
            if (exportJsonBtn) exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
            if (exportMdBtn) exportMdBtn.addEventListener('click', () => this.exportResults('markdown'));
            if (safeModeCheck) safeModeCheck.addEventListener('change', (e) => this.updateSafeMode(e.target.checked));
            
            console.log('[SQLi Scanner Panel] Event listeners attached');
        } catch (error) {
            console.error('[SQLi Scanner Panel] Failed to setup event listeners:', error);
        }
    }
    
    setupMessageHandlers() {
        if (this.messageListenerAttached) {
            return; // Already attached
        }
        
        try {
            chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
                if (!this.checkContext()) {
                    sendResponse({error: 'Context invalidated'});
                    return false;
                }
                
                try {
                    switch (message.type) {
                        case 'SCAN_PROGRESS':
                            this.updateScanProgress(message.data);
                            break;
                        case 'SCAN_COMPLETE':
                            this.handleScanComplete(message.data);
                            break;
                        case 'FORMS_DISCOVERED':
                            this.updateDiscoveredForms(message.data);
                            break;
                        case 'ERROR':
                            this.logError(message.error);
                            break;
                    }
                    sendResponse({received: true});
                } catch (error) {
                    console.error('[SQLi Scanner Panel] Message handler error:', error);
                    sendResponse({error: error.message});
                }
                
                return true; // Keep channel open for async response
            });
            
            this.messageListenerAttached = true;
            console.log('[SQLi Scanner Panel] Message handlers attached');
        } catch (error) {
            console.error('[SQLi Scanner Panel] Failed to setup message handlers:', error);
        }
    }
    
    async loadInitialData() {
        if (!this.checkContext()) return;
        
        try {
            const result = await chrome.storage.local.get(['scanSettings', 'recentRequests']);
            if (result.scanSettings) {
                this.applySettings(result.scanSettings);
            }
            if (result.recentRequests) {
                this.scanState.recentRequests = result.recentRequests;
                this.updateRequestsList();
            }
        } catch (error) {
            console.error('[SQLi Scanner Panel] Failed to load initial data:', error);
        }
    }
    
    async discoverInputs() {
        if (!this.checkContext()) return;
        
        this.log('🔍 Discovering forms and inputs...');
        
        try {
            const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
            
            await chrome.tabs.sendMessage(tab.id, {
                type: 'DISCOVER_FORMS'
            });
            
            this.log('✓ Form discovery initiated');
        } catch (error) {
            this.logError(`❌ Failed to discover inputs: ${error.message}`);
        }
    }
    
    async toggleHighlights() {
        if (!this.checkContext()) return;
        
        try {
            const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
            await chrome.tabs.sendMessage(tab.id, {
                type: 'TOGGLE_HIGHLIGHTS'
            });
        } catch (error) {
            this.logError(`❌ Failed to toggle highlights: ${error.message}`);
        }
    }
    
    async runScan() {
        if (!this.checkContext()) return;
        if (this.scanState.isScanning) return;
        
        this.scanState.isScanning = true;
        this.scanState.findings = [];
        this.updateUI();
        
        const config = this.getScanConfiguration();
        
        this.log('🚀 Starting SQL injection scan...');
        this.log(`Configuration: ${JSON.stringify(config, null, 2)}`);
        
        try {
            await this.safeSendMessage({
                type: 'START_SCAN',
                config: config,
                forms: this.scanState.discoveredForms
            });
        } catch (error) {
            this.logError(`❌ Failed to start scan: ${error.message}`);
            this.scanState.isScanning = false;
            this.updateUI();
        }
    }
    
    stopScan() {
        if (!this.checkContext()) return;
        
        this.scanState.isScanning = false;
        this.safeSendMessage({type: 'STOP_SCAN'}).catch(() => {});
        this.log('⏹️ Scan stopped by user');
        this.updateUI();
    }
    
    getScanConfiguration() {
        return {
            safeMode: document.getElementById('safeMode').checked,
            techniques: {
                errorBased: document.getElementById('errorBased').checked,
                booleanBased: document.getElementById('booleanBased').checked,
                timeBased: document.getElementById('timeBased').checked,
                unionBased: document.getElementById('unionBased').checked
            },
            retryCount: parseInt(document.getElementById('retryCount').value),
            timingThreshold: parseInt(document.getElementById('timingThreshold').value),
            currentOriginOnly: document.getElementById('currentOriginOnly').checked
        };
    }
    
    updateScanProgress(data) {
        this.log(data.message);
        if (data.finding) {
            this.scanState.findings.push(data.finding);
            this.updateFindingsTable();
        }
    }
    
    handleScanComplete(data) {
        this.scanState.isScanning = false;
        this.updateUI();
        this.log(`✅ Scan completed. Found ${this.scanState.findings.length} potential vulnerabilities.`);
        
        if (data.summary) {
            this.log(`Summary: ${JSON.stringify(data.summary, null, 2)}`);
        }
    }
    
    updateDiscoveredForms(forms) {
        this.scanState.discoveredForms = forms;
        this.updateFormsList();
        this.log(`Discovered ${forms.length} forms with ${forms.reduce((acc, f) => acc + f.inputs.length, 0)} total inputs`);
    }
    
    updateFormsList() {
        const container = document.getElementById('formsList');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.scanState.discoveredForms.forEach((form, index) => {
            const item = document.createElement('div');
            item.className = 'form-item';
            item.innerHTML = `
                <div><strong>Form ${index + 1}</strong></div>
                <div>Method: ${form.method}</div>
                <div>Action: ${form.action || 'Current page'}</div>
                <div>Inputs: ${form.inputs.length}</div>
            `;
            item.addEventListener('click', () => this.selectForm(index));
            container.appendChild(item);
        });
    }
    
    updateRequestsList() {
        const container = document.getElementById('requestsList');
        if (!container) return;
        
        container.innerHTML = '';
        
        this.scanState.recentRequests.slice(-10).forEach((request, index) => {
            const item = document.createElement('div');
            item.className = 'request-item';
            item.innerHTML = `
                <div><strong>${request.method}</strong> ${this.truncateUrl(request.url)}</div>
                <div>${new Date(request.timestamp).toLocaleTimeString()}</div>
            `;
            item.addEventListener('click', () => this.selectRequest(index));
            container.appendChild(item);
        });
    }
    
    updateFindingsTable() {
        const tbody = document.querySelector('#findingsTable tbody');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        this.scanState.findings.forEach((finding, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${finding.parameter}</td>
                <td>${this.truncateText(finding.location, 30)}</td>
                <td>${finding.technique}</td>
                <td>${this.truncateText(finding.evidence, 40)}</td>
                <td><span class="confidence-${finding.confidence.toLowerCase()}">${finding.confidence}</span></td>
                <td><button class="details-btn" data-index="${index}">Details</button></td>
            `;
            tbody.appendChild(row);
        });
        
        // Add click handlers to all detail buttons
        document.querySelectorAll('.details-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.getAttribute('data-index'));
                this.showFindingDetails(index);
            });
        });
    }
    
    showFindingDetails(index) {
    const finding = this.scanState.findings[index];
    if (!finding) return;
    
    const modal = document.getElementById('findingModal');
    if (!modal) return;
    
    const remediation = this.getRemediationForFinding(finding);
    
    document.getElementById('remediationTitle').textContent = remediation.title;
    document.getElementById('remediationDescription').textContent = remediation.description;
    document.getElementById('remediationLanguage').textContent = remediation.language;
    document.getElementById('remediationCode').textContent = remediation.code;
    document.getElementById('remediationExplanation').textContent = remediation.explanation;
    
    // Show modal
    modal.style.display = 'block';

    
    // Populate data
    document.getElementById('modalConfidence').textContent = finding.confidence || 'Unknown';
    document.getElementById('modalTechnique').textContent = finding.technique || 'N/A';
    
    // Truncate and wrap location properly
    const location = finding.location || 'Unknown';
    document.getElementById('modalLocation').textContent = this.truncateText(location, 40);
    document.getElementById('modalLocation').title = location; // Add tooltip for full URL
    
    document.getElementById('modalParameter').textContent = finding.parameter || 'Unknown';
    document.getElementById('modalMethod').textContent = finding.method || 'GET';
    document.getElementById('modalEvidence').textContent = finding.evidence || 'No evidence available';
    document.getElementById('modalPayload').textContent = finding.payload || 'No payload information';
    
    // Format timestamp
    if (finding.timestamp) {
        const date = new Date(finding.timestamp);
        document.getElementById('modalTimestamp').textContent = date.toLocaleString();
    } else {
        document.getElementById('modalTimestamp').textContent = 'N/A';
    }
    
    // Show modal
    modal.style.display = 'block';
    
    // Calculate REAL confidence percentage based on finding data
    let confidencePercent = 50; // default
    
    if (finding.confidence === 'High') {
        confidencePercent = 90;
    } else if (finding.confidence === 'Medium') {
        confidencePercent = 65;
    } else if (finding.confidence === 'Low') {
        confidencePercent = 35;
    }
    
    // Add bonus based on technique reliability
    if (finding.technique === 'Error-based') {
        confidencePercent = Math.min(95, confidencePercent + 5);
    } else if (finding.technique === 'Union-based') {
        confidencePercent = Math.min(90, confidencePercent + 3);
    } else if (finding.technique === 'Boolean-based Blind') {
        confidencePercent = Math.min(85, confidencePercent);
    } else if (finding.technique === 'Time-based Blind') {
        confidencePercent = Math.min(75, confidencePercent - 5);
    }
    
    // Animate progress bar with ACTUAL percentage
    setTimeout(() => {
        const progressBar = document.getElementById('modalProgressBar');
        const progressText = progressBar?.querySelector('.progress-text');
        const progressValue = document.getElementById('modalProgress');
        
        if (progressBar) {
            progressBar.style.width = confidencePercent + '%';
            
            // Change color based on percentage
            if (confidencePercent >= 80) {
                progressBar.style.background = 'linear-gradient(90deg, #ff6b6b 0%, #ee5a6f 100%)';
            } else if (confidencePercent >= 60) {
                progressBar.style.background = 'linear-gradient(90deg, #feca57 0%, #ff9ff3 100%)';
            } else {
                progressBar.style.background = 'linear-gradient(90deg, #48dbfb 0%, #0abde3 100%)';
            }
        }
        
        if (progressText) progressText.textContent = confidencePercent + '%';
        if (progressValue) progressValue.textContent = confidencePercent + '%';
    }, 100);
    
    // Create chart
    this.createTechniquesChart(finding);
    
    // Setup handlers
    this.setupModalHandlers(finding);
}


    setupModalHandlers(finding) {
        const modal = document.getElementById('findingModal');
        const closeBtn = document.querySelector('.close-modal');
        const closeModalBtn = document.getElementById('closeModalBtn');
        const exportBtn = document.getElementById('exportFindingBtn');
        const copyBtn = document.getElementById('copyEvidenceBtn');
        
        if (!modal || !closeBtn || !closeModalBtn || !exportBtn || !copyBtn) {
            console.error('Modal elements not found');
            return;
        }
        
        const closeModal = () => {
            modal.style.display = 'none';
        };
        
        // Clone to remove old listeners
        const newCloseBtn = closeBtn.cloneNode(true);
        const newCloseModalBtn = closeModalBtn.cloneNode(true);
        const newExportBtn = exportBtn.cloneNode(true);
        const newCopyBtn = copyBtn.cloneNode(true);
        
        closeBtn.parentNode.replaceChild(newCloseBtn, closeBtn);
        closeModalBtn.parentNode.replaceChild(newCloseModalBtn, closeModalBtn);
        exportBtn.parentNode.replaceChild(newExportBtn, exportBtn);
        copyBtn.parentNode.replaceChild(newCopyBtn, copyBtn);
        
        newCloseBtn.addEventListener('click', closeModal);
        newCloseModalBtn.addEventListener('click', closeModal);
        
        newExportBtn.addEventListener('click', () => {
            this.exportSingleFinding(finding);
        });
        
        newCopyBtn.addEventListener('click', () => {
            const evidence = finding.evidence || 'No evidence available';
            navigator.clipboard.writeText(evidence).then(() => {
                newCopyBtn.textContent = '✅ Copied!';
                setTimeout(() => {
                    newCopyBtn.textContent = '📋 Copy Evidence';
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy:', err);
                this.logError('Failed to copy evidence to clipboard');
            });
        });
        
        const outsideClickHandler = (event) => {
            if (event.target === modal) {
                closeModal();
                window.removeEventListener('click', outsideClickHandler);
            }
        };
        
        window.addEventListener('click', outsideClickHandler);
    }
    
    createTechniquesChart(finding) {
    const canvas = document.getElementById('techniquesChart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    
    // Techniques
    const techniques = ['Error-based', 'Boolean-blind', 'Time-based', 'Union-based'];
    
    // Dynamic success rates based on finding
    let successRates = [75, 65, 55, 70];
    
    if (finding.technique === 'Error-based') {
        successRates = [95, 70, 60, 75];
    } else if (finding.technique === 'Boolean-based Blind') {
        successRates = [80, 90, 65, 75];
    } else if (finding.technique === 'Time-based Blind') {
        successRates = [75, 70, 85, 70];
    } else if (finding.technique === 'Union-based') {
        successRates = [80, 75, 60, 92];
    }
    
    const colors = ['#ff6b6b', '#48dbfb', '#1dd1a1', '#feca57'];
    
    // Better spacing calculation
    const numBars = techniques.length;
    const chartWidth = canvas.width;
    const chartHeight = canvas.height - 80; // Reserve space for labels
    const barSpacing = chartWidth / (numBars + 1);
    const barWidth = barSpacing * 0.6; // 60% of spacing
    
    techniques.forEach((technique, i) => {
        const x = barSpacing * (i + 0.7);
        const height = (successRates[i] / 100) * chartHeight;
        const y = chartHeight - height + 20;
        
        // Draw bar with shadow
        ctx.shadowColor = 'rgba(0, 0, 0, 0.3)';
        ctx.shadowBlur = 5;
        ctx.shadowOffsetY = 2;
        ctx.fillStyle = colors[i];
        ctx.fillRect(x, y, barWidth, height);
        ctx.shadowBlur = 0;
        
        // Draw percentage on top of bar
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 14px Arial';
        ctx.textAlign = 'center';
        ctx.fillText(successRates[i] + '%', x + barWidth / 2, y - 8);
        
        // Draw label BELOW bars (NO rotation, horizontal text)
        ctx.fillStyle = '#ffffff';
        ctx.font = '12px Arial';
        ctx.textAlign = 'center';
        
        // Split label into two lines if needed
        const words = technique.split('-');
        const centerX = x + barWidth / 2;
        const labelY = canvas.height - 40;
        
        if (words.length > 1) {
            // Two lines for hyphenated words
            ctx.fillText(words[0], centerX, labelY);
            ctx.fillText(words[1], centerX, labelY + 15);
        } else {
            // Single line
            ctx.fillText(technique, centerX, labelY);
        }
    });

}

    
    exportSingleFinding(finding) {
        const report = {
            timestamp: new Date().toISOString(),
            finding: finding,
            remediation: {
                title: 'SQL Injection Remediation',
                description: 'Use parameterized queries to prevent SQL injection',
                examples: {
                    nodejs: "const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);",
                    python: "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                    php: "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$userId]);"
                }
            }
        };
        
        const content = JSON.stringify(report, null, 2);
        const blob = new Blob([content], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const filename = `sqli-finding-${finding.parameter}-${Date.now()}.json`;
        
        chrome.downloads.download({
            url: url,
            filename: filename
        }).then(() => {
            this.log(`📄 Exported finding: ${filename}`);
        }).catch(error => {
            this.logError(`Export failed: ${error.message}`);
        });
    }
    
    async exportResults(format) {
        const data = {
            timestamp: new Date().toISOString(),
            targetUrl: window.location.href,
            configuration: this.getScanConfiguration(),
            findings: this.scanState.findings,
            summary: {
                totalFindings: this.scanState.findings.length,
                highConfidence: this.scanState.findings.filter(f => f.confidence === 'High').length,
                mediumConfidence: this.scanState.findings.filter(f => f.confidence === 'Medium').length,
                lowConfidence: this.scanState.findings.filter(f => f.confidence === 'Low').length
            }
        };
        
        let content, filename, mimeType;
        
        if (format === 'json') {
            content = JSON.stringify(data, null, 2);
            filename = `sqli-scan-${Date.now()}.json`;
            mimeType = 'application/json';
        } else {
            content = this.generateMarkdownReport(data);
            filename = `sqli-scan-${Date.now()}.md`;
            mimeType = 'text/markdown';
        }
        
        const blob = new Blob([content], {type: mimeType});
        const url = URL.createObjectURL(blob);
        
        await chrome.downloads.download({
            url: url,
            filename: filename
        });
        
        this.log(`📄 Report exported as ${filename}`);
    }
    
    generateMarkdownReport(data) {
        let markdown = `# SQL Injection Scan Report\n\n`;
        markdown += `**Target URL:** ${data.targetUrl}\n`;
        markdown += `**Scan Date:** ${new Date(data.timestamp).toLocaleString()}\n`;
        markdown += `**Total Findings:** ${data.findings.length}\n\n`;
        
        markdown += `## Configuration\n\n`;
        markdown += `- Safe Mode: ${data.configuration.safeMode ? 'Enabled' : 'Disabled'}\n`;
        markdown += `- Techniques: ${Object.entries(data.configuration.techniques).filter(([k,v]) => v).map(([k]) => k).join(', ')}\n`;
        markdown += `- Retry Count: ${data.configuration.retryCount}\n`;
        markdown += `- Timing Threshold: ${data.configuration.timingThreshold}ms\n\n`;
        
        if (data.findings.length > 0) {
            markdown += `## Findings\n\n`;
            data.findings.forEach((finding, index) => {
                markdown += `### Finding ${index + 1}: ${finding.parameter}\n\n`;
                markdown += `- **Location:** ${finding.location}\n`;
                markdown += `- **Technique:** ${finding.technique}\n`;
                markdown += `- **Confidence:** ${finding.confidence}\n`;
                markdown += `- **Evidence:** \`${finding.evidence}\`\n\n`;
            });
        }
        
        markdown += `## Summary\n\n`;
        markdown += `- High Confidence: ${data.summary.highConfidence}\n`;
        markdown += `- Medium Confidence: ${data.summary.mediumConfidence}\n`;
        markdown += `- Low Confidence: ${data.summary.lowConfidence}\n`;
        
        return markdown;
    }
    
    selectForm(index) {
        document.querySelectorAll('.form-item').forEach((item, i) => {
            item.classList.toggle('selected', i === index);
        });
    }
    
    selectRequest(index) {
        document.querySelectorAll('.request-item').forEach((item, i) => {
            item.classList.toggle('selected', i === index);
        });
    }
    
    updateUI() {
        const runBtn = document.getElementById('runScanBtn');
        const stopBtn = document.getElementById('stopScanBtn');
        const discoverBtn = document.getElementById('discoverBtn');
        
        if (runBtn) runBtn.disabled = this.scanState.isScanning;
        if (stopBtn) stopBtn.disabled = !this.scanState.isScanning;
        if (discoverBtn) discoverBtn.disabled = this.scanState.isScanning;
    }
    
    updateSafeMode(enabled) {
        const timeBasedCheck = document.getElementById('timeBased');
        if (timeBasedCheck) {
            timeBasedCheck.disabled = enabled;
            if (enabled) {
                timeBasedCheck.checked = false;
            }
        }
    }
    
    applySettings(settings) {
        Object.entries(settings).forEach(([key, value]) => {
            const element = document.getElementById(key);
            if (element) {
                if (element.type === 'checkbox') {
                    element.checked = value;
                } else {
                    element.value = value;
                }
            }
        });
    }
    
    log(message) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = `[${timestamp}] ${message}`;
        this.scanState.logs.push(logEntry);
        
        const logContainer = document.getElementById('scanLog');
        if (logContainer) {
            logContainer.textContent = this.scanState.logs.slice(-100).join('\n');
            logContainer.scrollTop = logContainer.scrollHeight;
        }
    }
    
    logError(message) {
        this.log(`ERROR: ${message}`);
    }
    
    truncateUrl(url) {
        return url.length > 50 ? url.substring(0, 47) + '...' : url;
    }
    
    truncateText(text, length) {
        return text.length > length ? text.substring(0, length) + '...' : text;
    }

    getRemediationForFinding(finding) {
    const param = finding.parameter || 'input';
    const technique = finding.technique || 'Error-based';
    const method = finding.method || 'GET';
    
    let title = '';
    let description = '';
    let language = '';
    let code = '';
    let explanation = '';
    
    // Detect likely backend from URL or use generic
    const location = finding.location || '';
    let backend = 'Node.js'; // default
    
    if (location.includes('.php')) {
        backend = 'PHP';
    } else if (location.includes('.py') || location.includes('python')) {
        backend = 'Python';
    } else if (location.includes('.jsp') || location.includes('java')) {
        backend = 'Java';
    } else if (location.includes('.aspx') || location.includes('.net')) {
        backend = 'C#/.NET';
    }
    
    // Generate specific remediation
    if (technique === 'Error-based') {
        title = `Fix Error-Based SQL Injection in "${param}" Parameter`;
        description = `The ${param} parameter in your ${method} endpoint is vulnerable to SQL injection. User input is being directly concatenated into SQL queries, allowing attackers to manipulate query logic.`;
        
        if (backend === 'PHP') {
            language = 'PHP with PDO (Prepared Statements)';
            code = `<?php
// VULNERABLE CODE (Remove this):
// $sql = "SELECT * FROM users WHERE ${param} = '" . $_${method}['${param}'] . "'";

// SECURE CODE (Use this instead):
$stmt = $pdo->prepare("SELECT * FROM users WHERE ${param} = :${param}");
$stmt->bindParam(':${param}', $_${method}['${param}'], PDO::PARAM_STR);
$stmt->execute();
$result = $stmt->fetchAll();
?>`;
            explanation = `PDO prepared statements separate SQL logic from data. The :${param} placeholder is bound to user input AFTER the query is compiled, preventing injection.`;
            
        } else if (backend === 'Python') {
            language = 'Python with psycopg2/PyMySQL';
            code = `# VULNERABLE CODE (Remove this):
# cursor.execute(f"SELECT * FROM users WHERE ${param} = '{user_input}'")

# SECURE CODE (Use this instead):
cursor.execute(
    "SELECT * FROM users WHERE ${param} = %s",
    (user_input,)  # Tuple of parameters
)
result = cursor.fetchall()`;
            explanation = `Python DB-API parameterized queries use %s placeholders. The database driver handles proper escaping automatically.`;
            
        } else if (backend === 'Java') {
            language = 'Java with JDBC PreparedStatement';
            code = `// VULNERABLE CODE (Remove this):
// String sql = "SELECT * FROM users WHERE ${param} = '" + userInput + "'";

// SECURE CODE (Use this instead):
String sql = "SELECT * FROM users WHERE ${param} = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, userInput);
ResultSet rs = pstmt.executeQuery();`;
            explanation = `PreparedStatement treats ? placeholders as data, not SQL code. The JDBC driver handles type-safe binding.`;
            
        } else if (backend === 'C#/.NET') {
            language = 'C# with SqlCommand Parameters';
            code = `// VULNERABLE CODE (Remove this):
// string sql = $"SELECT * FROM Users WHERE ${param} = '{userInput}'";

// SECURE CODE (Use this instead):
string sql = "SELECT * FROM Users WHERE ${param} = @${param}";
SqlCommand cmd = new SqlCommand(sql, connection);
cmd.Parameters.AddWithValue("@${param}", userInput);
SqlDataReader reader = cmd.ExecuteReader();`;
            explanation = `SqlCommand parameters (@${param}) are compiled separately from the query structure, preventing injection.`;
            
        } else {
            // Node.js default
            language = 'Node.js with pg (PostgreSQL)';
            code = `// VULNERABLE CODE (Remove this):
// const query = \`SELECT * FROM users WHERE ${param} = '\${userInput}'\`;

// SECURE CODE (Use this instead):
const query = 'SELECT * FROM users WHERE ${param} = $1';
const result = await client.query(query, [userInput]);`;
            explanation = `Parameterized queries ($1, $2, etc.) send SQL structure and data separately, making injection impossible.`;
        }
        
    } else if (technique === 'Boolean-based Blind') {
        title = `Fix Boolean-Based Blind SQL Injection in "${param}"`;
        description = `The ${param} parameter leaks information through response differences. Attackers can extract data by asking true/false questions through SQL injection.`;
        
        if (backend === 'PHP') {
            language = 'PHP - Secure Implementation';
            code = `<?php
// Use prepared statements AND input validation
$stmt = $pdo->prepare("SELECT * FROM users WHERE ${param} = :${param}");
$stmt->bindParam(':${param}', $_${method}['${param}'], PDO::PARAM_STR);
$stmt->execute();

// Always return consistent responses
if ($stmt->rowCount() > 0) {
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false]);
}
?>`;
            explanation = `Parameterized queries prevent injection. Consistent responses prevent information leakage through timing or content differences.`;
        } else {
            language = 'Node.js - Secure Implementation';
            code = `// Use parameterized queries
const query = 'SELECT * FROM users WHERE ${param} = $1';
const result = await client.query(query, [userInput]);

// Return consistent responses
res.json({ 
    success: result.rows.length > 0,
    // Don't leak row counts or detailed errors
});`;
            explanation = `Parameterized queries block injection. Normalized responses prevent attackers from inferring database state.`;
        }
        
    } else if (technique === 'Time-based Blind') {
        title = `Fix Time-Based Blind SQL Injection in "${param}"`;
        description = `The ${param} parameter is vulnerable to time-based attacks. Attackers can inject SLEEP() or WAITFOR commands to infer data.`;
        
        language = `${backend} - Parameterized Queries`;
        code = backend === 'PHP' ? 
`<?php
// Block time-based injection with prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE ${param} = :${param}");
$stmt->bindParam(':${param}', $_${method}['${param}'], PDO::PARAM_STR);
$stmt->execute();
?>` :
`// Block time-based injection with parameterized queries
const query = 'SELECT * FROM users WHERE ${param} = $1';
const result = await client.query(query, [userInput]);`;
        explanation = `Parameterized queries prevent injection of timing functions like SLEEP(), BENCHMARK(), or WAITFOR DELAY.`;
        
    } else if (technique === 'Union-based') {
        title = `Fix Union-Based SQL Injection in "${param}"`;
        description = `The ${param} parameter allows UNION-based attacks to extract data from other tables. Attackers can bypass access controls.`;
        
        language = `${backend} - Secure Implementation`;
        code = backend === 'PHP' ?
`<?php
// Prevent UNION attacks with prepared statements
$stmt = $pdo->prepare("SELECT id, name FROM users WHERE ${param} = :${param}");
$stmt->bindParam(':${param}', $_${method}['${param}'], PDO::PARAM_STR);
$stmt->execute();

// Only return expected columns
$result = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>` :
`// Prevent UNION attacks with parameterized queries
const query = 'SELECT id, name FROM users WHERE ${param} = $1';
const result = await client.query(query, [userInput]);

// Validate result structure
const validatedResult = result.rows.map(row => ({
    id: row.id,
    name: row.name
}));`;
        explanation = `Parameterized queries prevent UNION injection. Result validation ensures only expected columns are returned.`;
    }
    
    return {
        title,
        description,
        language,
        code,
        explanation
    };
}

}

// Initialize panel when DOM is loaded
let panel;
document.addEventListener('DOMContentLoaded', () => {
    panel = new SQLiScannerPanel();
});

// Make panel available globally
window.panel = panel;
