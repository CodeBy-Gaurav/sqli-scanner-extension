// devtools.js - Bulletproof version with context validation

(function() {
    'use strict';
    
    let panelWindow = null;
    let isContextValid = true;
    let networkListenerAttached = false;
    
    // Validate extension context
    function isExtensionContextValid() {
        try {
            // Test if chrome.runtime is accessible
            if (!chrome.runtime || !chrome.runtime.id) {
                return false;
            }
            // Try to access a runtime property
            void chrome.runtime.getManifest();
            return true;
        } catch (error) {
            return false;
        }
    }
    
    // Safe wrapper for chrome.runtime.sendMessage
    function safeSendMessage(message, callback) {
        if (!isExtensionContextValid()) {
            console.warn('[SQLi Scanner] Extension context invalidated - message not sent');
            if (callback) callback(null);
            return;
        }
        
        try {
            chrome.runtime.sendMessage(message, (response) => {
                if (chrome.runtime.lastError) {
                    // Ignore "Could not establish connection" errors silently
                    if (!chrome.runtime.lastError.message.includes('Could not establish connection')) {
                        console.warn('[SQLi Scanner] Message error:', chrome.runtime.lastError.message);
                    }
                }
                if (callback) callback(response);
            });
        } catch (error) {
            console.warn('[SQLi Scanner] Failed to send message:', error.message);
            if (callback) callback(null);
        }
    }
    
    // Initialize DevTools panel
    function initializePanel() {
        if (!isExtensionContextValid()) {
            console.error('[SQLi Scanner] Cannot initialize - extension context invalid');
            return;
        }
        
        try {
            chrome.devtools.panels.create(
                'SQLi Scanner',
                'assets/icons/icon16.png',
                'panel/index.html',
                function(panel) {
                    if (!panel) {
                        console.error('[SQLi Scanner] Failed to create panel');
                        return;
                    }
                    
                    console.log('[SQLi Scanner] Panel created successfully');
                    
                    // Panel shown event
                    panel.onShown.addListener(function(window) {
                        if (isExtensionContextValid()) {
                            panelWindow = window;
                            console.log('[SQLi Scanner] Panel shown');
                        }
                    });
                    
                    // Panel hidden event
                    panel.onHidden.addListener(function() {
                        if (isExtensionContextValid()) {
                            console.log('[SQLi Scanner] Panel hidden');
                        }
                    });
                }
            );
        } catch (error) {
            console.error('[SQLi Scanner] Error creating panel:', error);
        }
    }
    
    // Setup network listener (only once and only if context is valid)
    function setupNetworkListener() {
        if (!isExtensionContextValid()) {
            console.warn('[SQLi Scanner] Cannot setup network listener - context invalid');
            return;
        }
        
        if (networkListenerAttached) {
            return; // Already attached
        }
        
        if (!chrome.devtools || !chrome.devtools.network) {
            console.warn('[SQLi Scanner] DevTools network API not available');
            return;
        }
        
        try {
            chrome.devtools.network.onRequestFinished.addListener(function(request) {
                // Check context on EVERY request
                if (!isExtensionContextValid()) {
                    return; // Silently ignore if context is invalid
                }
                
                // Extract request data safely
                try {
                    const requestData = {
                        type: 'STORE_NETWORK_REQUEST',
                        request: {
                            method: request.request?.method || 'GET',
                            url: request.request?.url || '',
                            headers: request.request?.headers || [],
                            postData: request.request?.postData || null,
                            timestamp: Date.now()
                        }
                    };
                    
                    // Send message with safe wrapper
                    safeSendMessage(requestData);
                    
                } catch (error) {
                    // Silently ignore errors in request processing
                }
            });
            
            networkListenerAttached = true;
            console.log('[SQLi Scanner] Network listener attached');
            
        } catch (error) {
            console.error('[SQLi Scanner] Failed to attach network listener:', error);
        }
    }
    
    // Monitor context validity
    function monitorContext() {
        const checkInterval = setInterval(function() {
            const currentlyValid = isExtensionContextValid();
            
            if (!currentlyValid && isContextValid) {
                // Context just became invalid
                isContextValid = false;
                console.warn('[SQLi Scanner] ⚠️ Extension context invalidated. Please close and reopen DevTools.');
                clearInterval(checkInterval);
            }
        }, 5000);
    }
    
    // Initialize everything
    function initialize() {
        console.log('[SQLi Scanner] Initializing...');
        
        // Check if context is valid before doing anything
        if (!isExtensionContextValid()) {
            console.error('[SQLi Scanner] Extension context is invalid at initialization');
            return;
        }
        
        // Initialize panel
        initializePanel();
        
        // Setup network listener after a short delay
        setTimeout(function() {
            setupNetworkListener();
        }, 500);
        
        // Start monitoring
        monitorContext();
    }
    
    // Start initialization
    initialize();
    
})();
