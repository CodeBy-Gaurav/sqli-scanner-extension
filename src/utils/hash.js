/**
 * Hashing utilities for response comparison and caching
 */

export class HashUtils {

    /**
     * Generate SHA-256 hash of a string
     */
    static async sha256(text) {
        if (!text) return '';

        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Generate MD5-like hash (using crypto.subtle)
     */
    static async md5Like(text) {
        if (!text) return '';

        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data); // Use SHA-1 as MD5 alternative
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
    }

    /**
     * Fast non-cryptographic hash for quick comparisons
     */
    static fastHash(text) {
        if (!text) return 0;

        let hash = 0;
        for (let i = 0; i < text.length; i++) {
            const char = text.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash;
    }

    /**
     * Generate hash for HTTP response
     */
    static async hashResponse(response) {
        const responseData = {
            status: response.status,
            headers: this.normalizeHeaders(response.headers),
            body: this.normalizeBody(response.body),
            contentLength: response.contentLength || response.body?.length || 0
        };

        const responseString = JSON.stringify(responseData);
        return await this.sha256(responseString);
    }

    /**
     * Generate hash for HTTP request
     */
    static async hashRequest(request) {
        const requestData = {
            method: request.method,
            url: this.normalizeUrl(request.url),
            headers: this.normalizeHeaders(request.headers),
            body: request.body || ''
        };

        const requestString = JSON.stringify(requestData);
        return await this.sha256(requestString);
    }

    /**
     * Normalize response body for consistent hashing
     */
    static normalizeBody(body) {
        if (!body) return '';

        return body
            // Remove dynamic content that changes on each request
            .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/g, 'TIMESTAMP') // ISO timestamps
            .replace(/\d{10,13}/g, 'UNIX_TIMESTAMP') // Unix timestamps
            .replace(/sessionid[=:][^\s;&]+/gi, 'sessionid=SESSION_ID') // Session IDs
            .replace(/csrf[_-]?token[=:][^\s;&]+/gi, 'csrf_token=CSRF_TOKEN') // CSRF tokens
            .replace(/token[=:][^\s;&]+/gi, 'token=TOKEN') // Generic tokens
            .replace(/nonce[=:][^\s;&]+/gi, 'nonce=NONCE') // Nonces
            .replace(/\b[A-Za-z0-9+/]{20,}={0,2}\b/g, 'BASE64_TOKEN') // Base64 tokens
            .replace(/<!--[\s\S]*?-->/g, '') // HTML comments
            .replace(/<script[\s\S]*?<\/script>/gi, '') // Script tags
            .replace(/\s+/g, ' ') // Normalize whitespace
            .trim()
            .toLowerCase();
    }

    /**
     * Normalize headers for consistent hashing
     */
    static normalizeHeaders(headers) {
        if (!headers) return {};

        const normalized = {};
        const headersObj = headers instanceof Headers ? 
            Object.fromEntries(headers.entries()) : headers;

        // Only include stable headers, exclude dynamic ones
        const stableHeaders = [
            'content-type',
            'content-encoding',
            'cache-control',
            'server',
            'x-powered-by',
            'x-frame-options',
            'x-content-type-options'
        ];

        for (const [key, value] of Object.entries(headersObj)) {
            const lowerKey = key.toLowerCase();
            if (stableHeaders.includes(lowerKey)) {
                normalized[lowerKey] = value;
            }
        }

        return normalized;
    }

    /**
     * Normalize URL for consistent hashing
     */
    static normalizeUrl(url) {
        if (!url) return '';

        try {
            const urlObj = new URL(url);

            // Sort query parameters for consistent hashing
            const params = new URLSearchParams(urlObj.search);
            const sortedParams = new URLSearchParams();

            Array.from(params.keys())
                .sort()
                .forEach(key => {
                    sortedParams.append(key, params.get(key));
                });

            urlObj.search = sortedParams.toString();

            return urlObj.toString().toLowerCase();
        } catch {
            return url.toLowerCase();
        }
    }

    /**
     * Compare two responses by hash
     */
    static async compareResponses(response1, response2) {
        const hash1 = await this.hashResponse(response1);
        const hash2 = await this.hashResponse(response2);

        return {
            identical: hash1 === hash2,
            hash1,
            hash2,
            similarity: this.calculateSimilarity(response1, response2)
        };
    }

    /**
     * Calculate similarity between two responses
     */
    static calculateSimilarity(response1, response2) {
        let score = 0;
        let factors = 0;

        // Status code similarity (20%)
        if (response1.status === response2.status) {
            score += 0.2;
        }
        factors++;

        // Content length similarity (20%)
        const len1 = parseInt(response1.contentLength) || response1.body?.length || 0;
        const len2 = parseInt(response2.contentLength) || response2.body?.length || 0;
        const lengthDiff = Math.abs(len1 - len2) / Math.max(len1, len2, 1);
        score += (1 - lengthDiff) * 0.2;
        factors++;

        // Body content similarity (40%)
        const bodySimilarity = this.stringSimilarity(
            this.normalizeBody(response1.body),
            this.normalizeBody(response2.body)
        );
        score += bodySimilarity * 0.4;
        factors++;

        // Headers similarity (20%)
        const headers1 = this.normalizeHeaders(response1.headers);
        const headers2 = this.normalizeHeaders(response2.headers);
        const headersSimilarity = this.objectSimilarity(headers1, headers2);
        score += headersSimilarity * 0.2;
        factors++;

        return Math.min(1, score / factors);
    }

    /**
     * Calculate string similarity using Levenshtein distance
     */
    static stringSimilarity(str1, str2) {
        if (!str1 && !str2) return 1;
        if (!str1 || !str2) return 0;

        const maxLength = Math.max(str1.length, str2.length);
        if (maxLength === 0) return 1;

        const distance = this.levenshteinDistance(str1, str2);
        return 1 - distance / maxLength;
    }

    /**
     * Calculate Levenshtein distance between two strings
     */
    static levenshteinDistance(str1, str2) {
        const matrix = [];

        for (let i = 0; i <= str2.length; i++) {
            matrix[i] = [i];
        }

        for (let j = 0; j <= str1.length; j++) {
            matrix[0][j] = j;
        }

        for (let i = 1; i <= str2.length; i++) {
            for (let j = 1; j <= str1.length; j++) {
                if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
                    matrix[i][j] = matrix[i - 1][j - 1];
                } else {
                    matrix[i][j] = Math.min(
                        matrix[i - 1][j - 1] + 1,
                        matrix[i][j - 1] + 1,
                        matrix[i - 1][j] + 1
                    );
                }
            }
        }

        return matrix[str2.length][str1.length];
    }

    /**
     * Calculate object similarity
     */
    static objectSimilarity(obj1, obj2) {
        const keys1 = Object.keys(obj1 || {});
        const keys2 = Object.keys(obj2 || {});
        const allKeys = new Set([...keys1, ...keys2]);

        if (allKeys.size === 0) return 1;

        let matches = 0;
        for (const key of allKeys) {
            if (obj1[key] === obj2[key]) {
                matches++;
            }
        }

        return matches / allKeys.size;
    }

    /**
     * Generate cache key for request/response pair
     */
    static async generateCacheKey(request, options = {}) {
        const keyData = {
            method: request.method,
            url: this.normalizeUrl(request.url),
            body: request.body || '',
            timestamp: options.includeTimestamp ? Date.now() : undefined,
            parameters: options.parameters || {}
        };

        const keyString = JSON.stringify(keyData);
        return await this.sha256(keyString);
    }

    /**
     * Hash payload for deduplication
     */
    static hashPayload(payload) {
        return this.fastHash(JSON.stringify({
            value: payload.value,
            type: payload.type || 'unknown',
            technique: payload.technique || 'unknown'
        }));
    }

    /**
     * Generate fingerprint for finding deduplication
     */
    static async generateFindingFingerprint(finding) {
        const fingerprintData = {
            parameter: finding.parameter,
            location: finding.location,
            technique: finding.technique,
            evidence: this.normalizeBody(finding.evidence)
        };

        const fingerprintString = JSON.stringify(fingerprintData);
        return await this.sha256(fingerprintString);
    }
}