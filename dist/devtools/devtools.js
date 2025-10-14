// Register the SQLi Scanner panel
chrome.devtools.panels.create(
    'SQLi Scanner',
    'assets/icons/icon16.png',
    'panel/index.html',
    (panel) => {
        console.log('SQLi Scanner panel created');
        
        // Panel lifecycle management
        panel.onShown.addListener(() => {
            console.log('SQLi Scanner panel shown');
        });
        
        panel.onHidden.addListener(() => {
            console.log('SQLi Scanner panel hidden');
        });
    }
);

// Listen for network requests to capture baseline requests
chrome.devtools.network.onRequestFinished.addListener((request) => {
    // Store recent requests for baseline cloning
    chrome.runtime.sendMessage({
        type: 'STORE_NETWORK_REQUEST',
        request: {
            method: request.request.method,
            url: request.request.url,
            headers: request.request.headers,
            postData: request.request.postData,
            timestamp: Date.now()
        }
    });
});
