/**
 * Response difference analysis utilities for boolean-based blind SQL injection detection
 */

export class DiffUtils {

    /**
     * Analyze differences between true/false response pairs
     */
    static analyzeBooleanDifferences(trueResponses, falseResponses) {
        const analysis = {
            isSignificant: false,
            confidence: 'Low',
            differences: [],
            sampleDifference: null,
            consistency: 0,
            metrics: {}
        };

        if (!trueResponses.length || !falseResponses.length) {
            return analysis;
        }

        // Analyze different response characteristics
        const statusCodeDiff = this.analyzeStatusCodes(trueResponses, falseResponses);
        const contentLengthDiff = this.analyzeContentLengths(trueResponses, falseResponses);
        const bodyHashDiff = this.analyzeBodyHashes(trueResponses, falseResponses);
        const timingDiff = this.analyzeResponseTimes(trueResponses, falseResponses);
        const headerDiff = this.analyzeHeaders(trueResponses, falseResponses);

        analysis.metrics = {
            statusCode: statusCodeDiff,
            contentLength: contentLengthDiff,
            bodyHash: bodyHashDiff,
            timing: timingDiff,
            headers: headerDiff
        };

        // Determine if differences are significant
        const significantDiffs = [];

        if (statusCodeDiff.isSignificant) {
            significantDiffs.push('Status Code');
            analysis.differences.push(`Status: ${statusCodeDiff.trueValue} vs ${statusCodeDiff.falseValue}`);
        }

        if (contentLengthDiff.isSignificant) {
            significantDiffs.push('Content Length');
            analysis.differences.push(`Length: ${contentLengthDiff.trueAvg} vs ${contentLengthDiff.falseAvg} bytes`);
        }

        if (bodyHashDiff.isSignificant) {
            significantDiffs.push('Response Body');
            analysis.differences.push(`Body content differs consistently`);
        }

        if (timingDiff.isSignificant) {
            significantDiffs.push('Response Time');
            analysis.differences.push(`Timing: ${timingDiff.trueAvg}ms vs ${timingDiff.falseAvg}ms`);
        }

        if (headerDiff.isSignificant) {
            significantDiffs.push('Headers');
            analysis.differences.push(`Headers differ: ${headerDiff.differences.join(', ')}`);
        }

        // Calculate overall significance and confidence
        analysis.isSignificant = significantDiffs.length >= 1;
        analysis.consistency = this.calculateConsistency(trueResponses, falseResponses);

        if (analysis.isSignificant && analysis.consistency > 0.8) {
            analysis.confidence = 'High';
        } else if (analysis.isSignificant && analysis.consistency > 0.6) {
            analysis.confidence = 'Medium';
        } else if (analysis.isSignificant) {
            analysis.confidence = 'Low';
        }

        // Create sample difference for display
        if (trueResponses.length > 0 && falseResponses.length > 0) {
            analysis.sampleDifference = {
                true: this.createResponseSummary(trueResponses[0]),
                false: this.createResponseSummary(falseResponses[0])
            };
        }

        return analysis;
    }

    /**
     * Analyze status code differences
     */
    static analyzeStatusCodes(trueResponses, falseResponses) {
        const trueStatuses = trueResponses.map(r => r.status);
        const falseStatuses = falseResponses.map(r => r.status);

        const trueMostCommon = this.getMostCommon(trueStatuses);
        const falseMostCommon = this.getMostCommon(falseStatuses);

        return {
            isSignificant: trueMostCommon !== falseMostCommon,
            trueValue: trueMostCommon,
            falseValue: falseMostCommon,
            consistency: this.calculateArrayConsistency(trueStatuses) * this.calculateArrayConsistency(falseStatuses)
        };
    }

    /**
     * Analyze content length differences
     */
    static analyzeContentLengths(trueResponses, falseResponses) {
        const trueLengths = trueResponses.map(r => parseInt(r.contentLength) || r.body?.length || 0);
        const falseLengths = falseResponses.map(r => parseInt(r.contentLength) || r.body?.length || 0);

        const trueAvg = this.average(trueLengths);
        const falseAvg = this.average(falseLengths);
        const difference = Math.abs(trueAvg - falseAvg);
        const percentageDiff = difference / Math.max(trueAvg, falseAvg, 1);

        return {
            isSignificant: difference > 10 && percentageDiff > 0.05, // 5% difference threshold
            trueAvg: Math.round(trueAvg),
            falseAvg: Math.round(falseAvg),
            difference: Math.round(difference),
            percentageDiff: Math.round(percentageDiff * 100)
        };
    }

    /**
     * Analyze response body hash differences
     */
    static analyzeBodyHashes(trueResponses, falseResponses) {
        const trueHashes = trueResponses.map(r => this.simpleHash(this.normalizeBody(r.body)));
        const falseHashes = falseResponses.map(r => this.simpleHash(this.normalizeBody(r.body)));

        const trueUnique = new Set(trueHashes).size;
        const falseUnique = new Set(falseHashes).size;
        const overlap = new Set([...trueHashes, ...falseHashes]).size;

        return {
            isSignificant: overlap !== trueUnique && overlap !== falseUnique,
            trueUnique,
            falseUnique,
            totalUnique: overlap,
            consistency: (trueHashes.length - trueUnique + falseHashes.length - falseUnique) / (trueHashes.length + falseHashes.length)
        };
    }

    /**
     * Analyze response time differences
     */
    static analyzeResponseTimes(trueResponses, falseResponses) {
        const trueTimes = trueResponses.map(r => r.responseTime || 0);
        const falseTimes = falseResponses.map(r => r.responseTime || 0);

        const trueAvg = this.average(trueTimes);
        const falseAvg = this.average(falseTimes);
        const difference = Math.abs(trueAvg - falseAvg);

        return {
            isSignificant: difference > 500, // 500ms threshold
            trueAvg: Math.round(trueAvg),
            falseAvg: Math.round(falseAvg),
            difference: Math.round(difference)
        };
    }

    /**
     * Analyze header differences
     */
    static analyzeHeaders(trueResponses, falseResponses) {
        const trueHeaderSets = trueResponses.map(r => this.extractHeaderKeys(r.headers));
        const falseHeaderSets = falseResponses.map(r => this.extractHeaderKeys(r.headers));

        const trueHeaders = this.getMostCommon(trueHeaderSets.flat());
        const falseHeaders = this.getMostCommon(falseHeaderSets.flat());

        const differences = [];
        const allHeaders = new Set([...trueHeaders, ...falseHeaders]);

        for (const header of allHeaders) {
            const inTrue = trueHeaders.includes(header);
            const inFalse = falseHeaders.includes(header);

            if (inTrue !== inFalse) {
                differences.push(`${header} (${inTrue ? 'true' : 'false'} only)`);
            }
        }

        return {
            isSignificant: differences.length > 0,
            differences,
            trueHeaders,
            falseHeaders
        };
    }

    /**
     * Calculate response consistency
     */
    static calculateConsistency(trueResponses, falseResponses) {
        if (trueResponses.length === 0 || falseResponses.length === 0) {
            return 0;
        }

        // Check consistency within true responses
        const trueConsistency = this.calculateResponseSetConsistency(trueResponses);

        // Check consistency within false responses  
        const falseConsistency = this.calculateResponseSetConsistency(falseResponses);

        // Overall consistency is the minimum of the two
        return Math.min(trueConsistency, falseConsistency);
    }

    /**
     * Calculate consistency within a set of responses
     */
    static calculateResponseSetConsistency(responses) {
        if (responses.length <= 1) return 1.0;

        const statuses = responses.map(r => r.status);
        const lengths = responses.map(r => parseInt(r.contentLength) || r.body?.length || 0);
        const hashes = responses.map(r => this.simpleHash(this.normalizeBody(r.body)));

        const statusConsistency = this.calculateArrayConsistency(statuses);
        const lengthConsistency = this.calculateArrayVarianceConsistency(lengths);
        const hashConsistency = this.calculateArrayConsistency(hashes);

        return (statusConsistency + lengthConsistency + hashConsistency) / 3;
    }

    /**
     * Calculate array consistency (how similar values are)
     */
    static calculateArrayConsistency(arr) {
        if (arr.length <= 1) return 1.0;

        const unique = new Set(arr).size;
        return (arr.length - unique + 1) / arr.length;
    }

    /**
     * Calculate variance-based consistency for numeric arrays
     */
    static calculateArrayVarianceConsistency(arr) {
        if (arr.length <= 1) return 1.0;

        const avg = this.average(arr);
        const variance = arr.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / arr.length;
        const cv = Math.sqrt(variance) / (avg || 1); // Coefficient of variation

        return Math.max(0, 1 - cv); // Lower variance = higher consistency
    }

    /**
     * Utility functions
     */
    static getMostCommon(arr) {
        const counts = {};
        let maxCount = 0;
        let mostCommon = null;

        for (const item of arr) {
            counts[item] = (counts[item] || 0) + 1;
            if (counts[item] > maxCount) {
                maxCount = counts[item];
                mostCommon = item;
            }
        }

        return mostCommon;
    }

    static average(arr) {
        return arr.length ? arr.reduce((sum, val) => sum + val, 0) / arr.length : 0;
    }

    static simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return hash;
    }

    static normalizeBody(body) {
        if (!body) return '';

        return body
            .replace(/\s+/g, ' ')  // Normalize whitespace
            .replace(/<!--[\s\S]*?-->/g, '') // Remove HTML comments
            .replace(/<script[\s\S]*?<\/script>/gi, '') // Remove scripts
            .replace(/<style[\s\S]*?<\/style>/gi, '') // Remove styles
            .toLowerCase()
            .trim();
    }

    static extractHeaderKeys(headers) {
        if (!headers) return [];

        if (headers instanceof Headers) {
            return Array.from(headers.keys());
        }

        if (typeof headers === 'object') {
            return Object.keys(headers);
        }

        return [];
    }

    static createResponseSummary(response) {
        return {
            status: response.status,
            contentLength: parseInt(response.contentLength) || response.body?.length || 0,
            bodyPreview: response.body ? response.body.substring(0, 100) + '...' : '',
            headers: this.extractHeaderKeys(response.headers).slice(0, 5)
        };
    }
}