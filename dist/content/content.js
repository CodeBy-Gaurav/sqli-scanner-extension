class SQLiContentScript {
    constructor() {
        this.discoveredForms = [];
        this.highlightedElements = [];
        this.isHighlighting = false;
        
        this.init();
    }
    
    init() {
        this.setupMessageHandlers();
        console.log('SQLi Scanner content script loaded');
    }
    
    setupMessageHandlers() {
        chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
            switch (request.type) {
                case 'DISCOVER_FORMS':
                    this.discoverForms();
                    sendResponse({success: true});
                    break;
                case 'TOGGLE_HIGHLIGHTS':
                    this.toggleHighlights();
                    sendResponse({success: true});
                    break;
                case 'INJECT_PAYLOAD':
                    this.injectPayload(request.payload, request.target);
                    sendResponse({success: true});
                    break;
                default:
                    sendResponse({success: false, error: 'Unknown message type'});
            }
        });
    }
    
    discoverForms() {
        this.discoveredForms = [];
        
        // Discover HTML forms
        const forms = document.querySelectorAll('form');
        forms.forEach((form, formIndex) => {
            const formData = {
                index: formIndex,
                method: (form.method || 'GET').toUpperCase(),
                action: form.action || window.location.href,
                inputs: []
            };
            
            // Find all input elements in the form
            const inputs = form.querySelectorAll('input, textarea, select');
            inputs.forEach((input, inputIndex) => {
                if (input.type !== 'submit' && input.type !== 'button' && input.type !== 'reset') {
                    formData.inputs.push({
                        name: input.name || `input_${inputIndex}`,
                        type: input.type || 'text',
                        value: input.value || '',
                        id: input.id || null,
                        element: input
                    });
                }
            });
            
            if (formData.inputs.length > 0) {
                this.discoveredForms.push(formData);
            }
        });
        
        // Discover URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.size > 0) {
            const urlForm = {
                index: this.discoveredForms.length,
                method: 'GET',
                action: window.location.href,
                inputs: []
            };
            
            urlParams.forEach((value, key) => {
                urlForm.inputs.push({
                    name: key,
                    type: 'url-parameter',
                    value: value,
                    location: 'url'
                });
            });
            
            this.discoveredForms.push(urlForm);
        }
        
        // Send discovered forms to panel
        chrome.runtime.sendMessage({
            type: 'FORMS_DISCOVERED',
            data: this.discoveredForms.map(form => ({
                ...form,
                inputs: form.inputs.map(input => ({
                    ...input,
                    element: undefined // Remove DOM reference for messaging
                }))
            }))
        });
        
        console.log(`Discovered ${this.discoveredForms.length} forms with testable inputs`);
    }
    
    toggleHighlights() {
        if (this.isHighlighting) {
            this.removeHighlights();
        } else {
            this.addHighlights();
        }
        this.isHighlighting = !this.isHighlighting;
    }
    
    addHighlights() {
        this.discoveredForms.forEach(form => {
            form.inputs.forEach(input => {
                if (input.element && input.element.style !== undefined) {
                    input.element.classList.add('highlighted-input');
                    this.highlightedElements.push(input.element);
                }
            });
        });
        
        // Add custom CSS for highlights if not exists
        if (!document.getElementById('sqli-highlight-styles')) {
            const style = document.createElement('style');
            style.id = 'sqli-highlight-styles';
            style.textContent = `
                .highlighted-input {
                    border: 3px solid #ff5722 !important;
                    background-color: rgba(255, 87, 34, 0.1) !important;
                    position: relative;
                }
                .highlighted-input::after {
                    content: 'SQLi Test Target';
                    position: absolute;
                    top: -25px;
                    left: 0;
                    background: #ff5722;
                    color: white;
                    padding: 2px 6px;
                    font-size: 10px;
                    border-radius: 3px;
                    z-index: 10000;
                }
            `;
            document.head.appendChild(style);
        }
    }
    
    removeHighlights() {
        this.highlightedElements.forEach(element => {
            if (element) {
                element.classList.remove('highlighted-input');
            }
        });
        this.highlightedElements = [];
        
        // Remove highlight styles
        const style = document.getElementById('sqli-highlight-styles');
        if (style) {
            style.remove();
        }
    }
    
    injectPayload(payload, target) {
        // Find target input and inject payload
        const form = this.discoveredForms[target.formIndex];
        if (!form) return;
        
        const input = form.inputs[target.inputIndex];
        if (!input || !input.element) return;
        
        // Store original value
        if (!input.originalValue) {
            input.originalValue = input.element.value;
        }
        
        // Inject payload
        input.element.value = payload;
        
        // Trigger change event
        input.element.dispatchEvent(new Event('change', { bubbles: true }));
        input.element.dispatchEvent(new Event('input', { bubbles: true }));
        
        console.log(`Injected payload "${payload}" into ${input.name}`);
    }
    
    restoreOriginalValues() {
        this.discoveredForms.forEach(form => {
            form.inputs.forEach(input => {
                if (input.element && input.originalValue !== undefined) {
                    input.element.value = input.originalValue;
                    delete input.originalValue;
                }
            });
        });
    }
    
    getPageInfo() {
        return {
            url: window.location.href,
            title: document.title,
            formCount: this.discoveredForms.length,
            inputCount: this.discoveredForms.reduce((acc, form) => acc + form.inputs.length, 0)
        };
    }
}

// Initialize content script
const sqliContentScript = new SQLiContentScript();

// Auto-discover forms when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => sqliContentScript.discoverForms(), 1000);
    });
} else {
    setTimeout(() => sqliContentScript.discoverForms(), 1000);
}
