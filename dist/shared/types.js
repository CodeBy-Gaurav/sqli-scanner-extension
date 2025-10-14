/**
 * Type definitions and interfaces for SQLi Scanner
 */

export const ScanState = {
    IDLE: 'idle',
    DISCOVERING: 'discovering',
    SCANNING: 'scanning', 
    PAUSED: 'paused',
    COMPLETED: 'completed',
    ERROR: 'error'
};

export const MessageTypes = {
    // Panel to Background
    START_SCAN: 'START_SCAN',
    STOP_SCAN: 'STOP_SCAN',
    PAUSE_SCAN: 'PAUSE_SCAN',
    RESUME_SCAN: 'RESUME_SCAN',

    // Content Script Messages
    DISCOVER_FORMS: 'DISCOVER_FORMS',
    TOGGLE_HIGHLIGHTS: 'TOGGLE_HIGHLIGHTS',
    INJECT_PAYLOAD: 'INJECT_PAYLOAD',

    // Background to Panel
    SCAN_PROGRESS: 'SCAN_PROGRESS',
    SCAN_COMPLETE: 'SCAN_COMPLETE',
    SCAN_ERROR: 'SCAN_ERROR',
    FORMS_DISCOVERED: 'FORMS_DISCOVERED',

    // Network
    STORE_NETWORK_REQUEST: 'STORE_NETWORK_REQUEST',
    GET_NETWORK_REQUESTS: 'GET_NETWORK_REQUESTS',

    // Storage
    SAVE_SETTINGS: 'SAVE_SETTINGS',
    LOAD_SETTINGS: 'LOAD_SETTINGS',
    EXPORT_RESULTS: 'EXPORT_RESULTS'
};

export const Techniques = {
    ERROR_BASED: 'error-based',
    BOOLEAN_BLIND: 'boolean-blind',
    TIME_BLIND: 'time-blind',
    UNION_BASED: 'union-based',
    WAF_BYPASS: 'waf-bypass'
};

export const ConfidenceLevel = {
    LOW: 'Low',
    MEDIUM: 'Medium',
    HIGH: 'High',
    CRITICAL: 'Critical'
};

export const DatabaseTypes = {
    MYSQL: 'MySQL',
    POSTGRESQL: 'PostgreSQL',
    MSSQL: 'SQL Server',
    ORACLE: 'Oracle',
    SQLITE: 'SQLite',
    MONGODB: 'MongoDB',
    UNKNOWN: 'Unknown'
};

export const HttpMethods = {
    GET: 'GET',
    POST: 'POST',
    PUT: 'PUT',
    DELETE: 'DELETE',
    PATCH: 'PATCH',
    HEAD: 'HEAD',
    OPTIONS: 'OPTIONS'
};

export const InputTypes = {
    TEXT: 'text',
    PASSWORD: 'password',
    EMAIL: 'email',
    NUMBER: 'number',
    HIDDEN: 'hidden',
    TEXTAREA: 'textarea',
    SELECT: 'select',
    URL_PARAM: 'url-parameter',
    HEADER: 'header',
    COOKIE: 'cookie',
    JSON: 'json'
};

export const PayloadCategories = {
    SAFE: 'safe',
    MODERATE: 'moderate',
    AGGRESSIVE: 'aggressive',
    DESTRUCTIVE: 'destructive'
};

export const ScanModes = {
    SAFE: 'safe',
    NORMAL: 'normal', 
    AGGRESSIVE: 'aggressive',
    CUSTOM: 'custom'
};

export const ExportFormats = {
    JSON: 'json',
    MARKDOWN: 'markdown',
    CSV: 'csv',
    HTML: 'html',
    XML: 'xml',
    PDF: 'pdf'
};

/**
 * Creates a new scan configuration object
 */
export function createScanConfig(options = {}) {
    return {
        mode: options.mode || ScanModes.SAFE,
        techniques: {
            [Techniques.ERROR_BASED]: options.errorBased ?? true,
            [Techniques.BOOLEAN_BLIND]: options.booleanBlind ?? true,
            [Techniques.TIME_BLIND]: options.timeBlind ?? false,
            [Techniques.UNION_BASED]: options.unionBased ?? true,
            [Techniques.WAF_BYPASS]: options.wafBypass ?? false
        },
        advanced: {
            retryCount: options.retryCount || 3,
            timingThreshold: options.timingThreshold || 2000,
            concurrentRequests: options.concurrentRequests || 1,
            requestDelay: options.requestDelay || 100,
            userAgent: options.userAgent || 'SQLi Scanner v1.0',
            followRedirects: options.followRedirects ?? true,
            maxRedirects: options.maxRedirects || 3
        },
        scope: {
            currentOriginOnly: options.currentOriginOnly ?? false,
            includeCookies: options.includeCookies ?? true,
            includeHeaders: options.includeHeaders ?? false,
            maxDepth: options.maxDepth || 1
        }
    };
}

/**
 * Creates a new finding object
 */
export function createFinding(data) {
    return {
        id: data.id || Date.now().toString(),
        parameter: data.parameter,
        location: data.location,
        method: data.method || 'GET',
        technique: data.technique,
        evidence: data.evidence,
        confidence: data.confidence,
        severity: data.severity || 'Medium',
        payload: data.payload,
        request: data.request || null,
        response: data.response || null,
        remediation: data.remediation || null,
        timestamp: data.timestamp || Date.now(),
        verified: data.verified || false,
        falsePositive: data.falsePositive || false
    };
}

/**
 * Creates a new form object
 */
export function createForm(element) {
    return {
        id: element.id || null,
        method: (element.method || 'GET').toUpperCase(),
        action: element.action || window.location.href,
        enctype: element.enctype || 'application/x-www-form-urlencoded',
        inputs: [],
        timestamp: Date.now()
    };
}

/**
 * Creates a new input object  
 */
export function createInput(element) {
    return {
        name: element.name || element.id || 'unnamed',
        type: element.type || 'text',
        value: element.value || '',
        placeholder: element.placeholder || '',
        required: element.required || false,
        maxLength: element.maxLength || null,
        pattern: element.pattern || null,
        id: element.id || null,
        className: element.className || ''
    };
}

/**
 * Validation functions
 */
export const Validators = {
    isValidUrl: (url) => {
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    },

    isValidMethod: (method) => {
        return Object.values(HttpMethods).includes(method.toUpperCase());
    },

    isValidConfidence: (confidence) => {
        return Object.values(ConfidenceLevel).includes(confidence);
    },

    isValidTechnique: (technique) => {
        return Object.values(Techniques).includes(technique);
    }
};