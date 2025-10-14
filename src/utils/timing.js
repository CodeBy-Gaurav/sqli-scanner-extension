/**
 * Timing analysis utilities for time-based blind SQL injection detection
 */

export class TimingUtils {

    /**
     * Analyze timing patterns to detect time-based SQL injection
     */
    static analyzeTimings(timings, baselineTime, threshold) {
        const analysis = {
            isDelayConsistent: false,
            confidence: 'Low',
            averageDelay: 0,
            medianDelay: 0,
            variance: 0,
            outliers: [],
            consistencyScore: 0,
            thresholdExceeded: false
        };

        if (!timings.length) {
            return analysis;
        }

        // Calculate basic statistics
        analysis.averageDelay = this.average(timings);
        analysis.medianDelay = this.median(timings);
        analysis.variance = this.variance(timings);
        analysis.outliers = this.detectOutliers(timings);

        // Check if delay exceeds threshold
        analysis.thresholdExceeded = analysis.averageDelay > threshold;

        // Calculate baseline comparison
        const baselineDiff = analysis.averageDelay - (baselineTime || 0);
        const isSignificantDelay = baselineDiff > threshold;

        // Calculate consistency score
        analysis.consistencyScore = this.calculateConsistency(timings, threshold);

        // Determine if delay is consistent and significant
        analysis.isDelayConsistent = isSignificantDelay && 
                                    analysis.consistencyScore > 0.7 && 
                                    analysis.outliers.length < timings.length * 0.3;

        // Calculate confidence based on multiple factors
        analysis.confidence = this.calculateConfidence(analysis, timings.length);

        return analysis;
    }

    /**
     * Calculate statistical measures
     */
    static average(arr) {
        return arr.length ? arr.reduce((sum, val) => sum + val, 0) / arr.length : 0;
    }

    static median(arr) {
        if (!arr.length) return 0;

        const sorted = [...arr].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);

        return sorted.length % 2 === 0
            ? (sorted[mid - 1] + sorted[mid]) / 2
            : sorted[mid];
    }

    static variance(arr) {
        if (arr.length <= 1) return 0;

        const avg = this.average(arr);
        return arr.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / (arr.length - 1);
    }

    static standardDeviation(arr) {
        return Math.sqrt(this.variance(arr));
    }

    /**
     * Detect outliers using IQR method
     */
    static detectOutliers(arr) {
        if (arr.length < 4) return [];

        const sorted = [...arr].sort((a, b) => a - b);
        const q1 = this.percentile(sorted, 25);
        const q3 = this.percentile(sorted, 75);
        const iqr = q3 - q1;

        const lowerBound = q1 - 1.5 * iqr;
        const upperBound = q3 + 1.5 * iqr;

        return arr.filter(val => val < lowerBound || val > upperBound);
    }

    /**
     * Calculate percentile
     */
    static percentile(arr, p) {
        if (!arr.length) return 0;

        const sorted = [...arr].sort((a, b) => a - b);
        const index = (p / 100) * (sorted.length - 1);

        if (Number.isInteger(index)) {
            return sorted[index];
        }

        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        const weight = index - lower;

        return sorted[lower] * (1 - weight) + sorted[upper] * weight;
    }

    /**
     * Calculate timing consistency score
     */
    static calculateConsistency(timings, expectedDelay) {
        if (timings.length <= 1) return 0;

        // Calculate how many timings are within acceptable range of expected delay
        const tolerance = Math.max(expectedDelay * 0.2, 200); // 20% tolerance or 200ms
        const consistentTimings = timings.filter(time => 
            Math.abs(time - expectedDelay) <= tolerance
        );

        const consistencyRatio = consistentTimings.length / timings.length;

        // Also consider coefficient of variation
        const cv = this.standardDeviation(timings) / this.average(timings);
        const cvScore = Math.max(0, 1 - cv); // Lower CV = higher consistency

        // Combine both scores
        return (consistencyRatio + cvScore) / 2;
    }

    /**
     * Calculate confidence level based on analysis results
     */
    static calculateConfidence(analysis, sampleSize) {
        let score = 0;

        // Consistency score contributes 40%
        score += analysis.consistencyScore * 0.4;

        // Threshold exceeded contributes 30%
        if (analysis.thresholdExceeded) {
            score += 0.3;
        }

        // Low variance contributes 20%
        const normalizedVariance = Math.min(analysis.variance / 1000000, 1); // Normalize to 0-1
        score += (1 - normalizedVariance) * 0.2;

        // Sample size contributes 10%
        const sampleScore = Math.min(sampleSize / 10, 1); // Max benefit at 10 samples
        score += sampleScore * 0.1;

        // Convert to confidence level
        if (score >= 0.8) return 'High';
        if (score >= 0.6) return 'Medium';
        return 'Low';
    }

    /**
     * Detect time-based injection patterns
     */
    static detectInjectionPattern(timings, payloadDelays) {
        if (timings.length !== payloadDelays.length) {
            return { detected: false, reason: 'Mismatched timing/payload arrays' };
        }

        const correlations = [];

        for (let i = 0; i < timings.length; i++) {
            const actualDelay = timings[i];
            const expectedDelay = payloadDelays[i];

            if (expectedDelay > 0) {
                const correlation = this.calculateCorrelation(actualDelay, expectedDelay);
                correlations.push(correlation);
            }
        }

        if (correlations.length === 0) {
            return { detected: false, reason: 'No time-based payloads found' };
        }

        const avgCorrelation = this.average(correlations);
        const detected = avgCorrelation > 0.7;

        return {
            detected,
            correlation: avgCorrelation,
            confidence: detected ? (avgCorrelation > 0.9 ? 'High' : 'Medium') : 'Low',
            details: correlations
        };
    }

    /**
     * Calculate correlation between actual and expected delay
     */
    static calculateCorrelation(actual, expected) {
        if (expected === 0) return 0;

        const tolerance = Math.max(expected * 0.3, 500); // 30% tolerance or 500ms
        const diff = Math.abs(actual - expected);

        if (diff <= tolerance) {
            return 1 - (diff / tolerance); // Perfect match = 1, tolerance boundary = 0
        }

        return 0; // Outside tolerance
    }

    /**
     * Filter timing noise and anomalies
     */
    static filterNoise(timings, options = {}) {
        const {
            removeOutliers = true,
            minSamples = 3,
            maxVariance = 1000000 // 1 second variance
        } = options;

        let filtered = [...timings];

        // Remove outliers if requested
        if (removeOutliers && filtered.length >= 4) {
            const outliers = this.detectOutliers(filtered);
            filtered = filtered.filter(timing => !outliers.includes(timing));
        }

        // Check if we have enough samples
        if (filtered.length < minSamples) {
            return {
                filtered: timings, // Return original if not enough samples
                removed: 0,
                reason: 'Insufficient samples after filtering'
            };
        }

        // Check variance
        const variance = this.variance(filtered);
        if (variance > maxVariance) {
            return {
                filtered: timings,
                removed: 0,
                reason: 'High variance detected - possible network issues'
            };
        }

        return {
            filtered,
            removed: timings.length - filtered.length,
            variance,
            reason: 'Filtering successful'
        };
    }

    /**
     * Generate timing analysis report
     */
    static generateReport(analysis, timings) {
        return {
            summary: {
                detected: analysis.isDelayConsistent,
                confidence: analysis.confidence,
                sampleSize: timings.length
            },
            statistics: {
                average: Math.round(analysis.averageDelay),
                median: Math.round(analysis.medianDelay),
                variance: Math.round(analysis.variance),
                standardDeviation: Math.round(Math.sqrt(analysis.variance))
            },
            quality: {
                consistencyScore: Math.round(analysis.consistencyScore * 100) / 100,
                outlierCount: analysis.outliers.length,
                outlierPercentage: Math.round((analysis.outliers.length / timings.length) * 100)
            },
            thresholds: {
                exceeded: analysis.thresholdExceeded,
                averageDelay: Math.round(analysis.averageDelay),
                medianDelay: Math.round(analysis.medianDelay)
            }
        };
    }
}