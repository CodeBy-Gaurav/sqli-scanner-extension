class SQLiScannerPanel {
    constructor() {
        this.scanState = {
            isScanning: false,
            findings: [],
            logs: [],
            discoveredForms: [],
            recentRequests: []
        };
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadInitialData();
        this.setupMessageHandlers();
    }
    
    setupEventListeners() {
        // Main action buttons
        document.getElementById('discoverBtn').addEventListener('click', () => this.discoverInputs());
        document.getElementById('highlightBtn').addEventListener('click', () => this.toggleHighlights());
        document.getElementById('runScanBtn').addEventListener('click', () => this.runScan());
        document.getElementById('stopScanBtn').addEventListener('click', () => this.stopScan());
        
        // Export buttons
        document.getElementById('exportJsonBtn').addEventListener('click', () => this.exportResults('json'));
        document.getElementById('exportMdBtn').addEventListener('click', () => this.exportResults('markdown'));
        
        // Modal close
        document.querySelector('.close').addEventListener('click', () => this.closeModal());
        
        // Settings changes
        document.getElementById('safeMode').addEventListener('change', (e) => {
            this.updateSafeMode(e.target.checked);
        });
    }
    
    setupMessageHandlers() {
        // Listen for messages from background and content scripts
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
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
        });
    }
    
    async loadInitialData() {
        // Load stored scan results and settings
        const result = await chrome.storage.local.get(['scanSettings', 'recentRequests']);
        if (result.scanSettings) {
            this.applySettings(result.scanSettings);
        }
        if (result.recentRequests) {
            this.scanState.recentRequests = result.recentRequests;
            this.updateRequestsList();
        }
    }
    
    async discoverInputs() {
        this.log('Discovering forms and inputs...');
        
        try {
            // Get current tab
            const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
            
            // Send message to content script to discover forms
            await chrome.tabs.sendMessage(tab.id, {
                type: 'DISCOVER_FORMS'
            });
            
            this.log('Form discovery initiated');
        } catch (error) {
            this.logError(`Failed to discover inputs: ${error.message}`);
        }
    }
    
    async toggleHighlights() {
        try {
            const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
            await chrome.tabs.sendMessage(tab.id, {
                type: 'TOGGLE_HIGHLIGHTS'
            });
        } catch (error) {
            this.logError(`Failed to toggle highlights: ${error.message}`);
        }
    }
    
    async runScan() {
        if (this.scanState.isScanning) return;
        
        this.scanState.isScanning = true;
        this.scanState.findings = [];
        this.updateUI();
        
        // Collect scan configuration
        const config = this.getScanConfiguration();
        
        this.log('Starting SQL injection scan...');
        this.log(`Configuration: ${JSON.stringify(config, null, 2)}`);
        
        try {
            // Send scan request to background script
            await chrome.runtime.sendMessage({
                type: 'START_SCAN',
                config: config,
                forms: this.scanState.discoveredForms
            });
        } catch (error) {
            this.logError(`Failed to start scan: ${error.message}`);
            this.scanState.isScanning = false;
            this.updateUI();
        }
    }
    
    stopScan() {
        this.scanState.isScanning = false;
        chrome.runtime.sendMessage({type: 'STOP_SCAN'});
        this.log('Scan stopped by user');
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
        this.log(`Scan completed. Found ${this.scanState.findings.length} potential vulnerabilities.`);
        
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
        tbody.innerHTML = '';
        
        this.scanState.findings.forEach((finding, index) => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${finding.parameter}</td>
                <td>${finding.location}</td>
                <td>${finding.technique}</td>
                <td>${this.truncateText(finding.evidence, 50)}</td>
                <td><span class="confidence-${finding.confidence.toLowerCase()}">${finding.confidence}</span></td>
                <td><button onclick="panel.showFindingDetails(${index})">Details</button></td>
            `;
            tbody.appendChild(row);
        });
    }
    
    showFindingDetails(index) {
        const finding = this.scanState.findings[index];
        const modalBody = document.getElementById('modalBody');
        
        modalBody.innerHTML = `
            <h3>Finding Details</h3>
            <div class="finding-details">
                <p><strong>Parameter:</strong> ${finding.parameter}</p>
                <p><strong>Location:</strong> ${finding.location}</p>
                <p><strong>Technique:</strong> ${finding.technique}</p>
                <p><strong>Confidence:</strong> <span class="confidence-${finding.confidence.toLowerCase()}">${finding.confidence}</span></p>
                <p><strong>Evidence:</strong></p>
                <pre>${finding.evidence}</pre>
                
                <h4>Remediation</h4>
                <div class="remediation-content">
                    ${this.getRemediationContent(finding)}
                </div>
                
                <h4>Request Sample</h4>
                <pre>${finding.requestSample || 'N/A'}</pre>
                
                <h4>Response Sample</h4>
                <pre>${finding.responseSample || 'N/A'}</pre>
            </div>
        `;
        
        document.getElementById('modal').classList.remove('hidden');
    }
    
    getRemediationContent(finding) {
        // Import remediation guidance based on technique
        const remediation = {
            'Error-based': `
                <p>Use parameterized queries or prepared statements:</p>
                <pre>// Node.js with pg
const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);

// Python with psycopg2
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// PHP with PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);</pre>
            `,
            'Boolean-based': `
                <p>Implement proper input validation and use parameterized queries:</p>
                <pre>// Java with JDBC
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);</pre>
            `,
            'Time-based': `
                <p>Use parameterized queries and implement proper error handling:</p>
                <pre>// C# with SqlCommand
using (SqlCommand cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn))
{
    cmd.Parameters.AddWithValue("@id", userId);
    // Execute query
}</pre>
            `,
            'Union-based': `
                <p>Limit data exposure and use parameterized queries:</p>
                <pre>// Use ORM like Hibernate
@Query("SELECT u FROM User u WHERE u.id = :id")
User findUserById(@Param("id") Long id);</pre>
            `
        };
        
        return remediation[finding.technique] || 'Use parameterized queries and proper input validation.';
    }
    
    closeModal() {
        document.getElementById('modal').classList.add('hidden');
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
        
        // Use Chrome downloads API
        const blob = new Blob([content], {type: mimeType});
        const url = URL.createObjectURL(blob);
        
        await chrome.downloads.download({
            url: url,
            filename: filename
        });
        
        this.log(`Report exported as ${filename}`);
    }
    
    generateMarkdownReport(data) {
        let markdown = `# SQL Injection Scan Report\n\n`;
        markdown += `**Target URL:** ${data.targetUrl}\n`;
        markdown += `**Scan Date:** ${new Date(data.timestamp).toLocaleString()}\n`;
        markdown += `**Total Findings:** ${data.findings.length}\n\n`;
        
        markdown += `## Configuration\n\n`;
        markdown += `- Safe Mode: ${data.configuration.safeMode ? 'Enabled' : 'Disabled'}\n`;
        markdown += `- Techniques: ${Object.entries(data.configuration.techniques).filter(([k,v]) => v).map(([k,v]) => k).join(', ')}\n`;
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
        // Handle form selection
        document.querySelectorAll('.form-item').forEach((item, i) => {
            item.classList.toggle('selected', i === index);
        });
    }
    
    selectRequest(index) {
        // Handle request selection for baseline cloning
        document.querySelectorAll('.request-item').forEach((item, i) => {
            item.classList.toggle('selected', i === index);
        });
    }
    
    updateUI() {
        document.getElementById('runScanBtn').disabled = this.scanState.isScanning;
        document.getElementById('stopScanBtn').disabled = !this.scanState.isScanning;
        document.getElementById('discoverBtn').disabled = this.scanState.isScanning;
    }
    
    updateSafeMode(enabled) {
        // Update UI based on safe mode
        if (enabled) {
            document.getElementById('timeBased').disabled = true;
            document.getElementById('timeBased').checked = false;
        } else {
            document.getElementById('timeBased').disabled = false;
        }
    }
    
    applySettings(settings) {
        // Apply saved settings to UI
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
        logContainer.innerHTML = this.scanState.logs.slice(-100).join('\n');
        logContainer.scrollTop = logContainer.scrollHeight;
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
}

// Initialize panel when DOM is loaded
let panel;
document.addEventListener('DOMContentLoaded', () => {
    panel = new SQLiScannerPanel();
});

// Make panel available globally for button callbacks
window.panel = panel;
