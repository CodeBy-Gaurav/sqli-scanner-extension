// Database Error Pattern Detection
// No ES6 exports - using global scope for Chrome Extension

const DBErrorPatterns = {
    patterns: {
        mysql: {
            patterns: [
                /You have an error in your SQL syntax/i,
                /MySQL server version for the right syntax/i,
                /mysql_fetch_array\(\)/i,
                /supplied argument is not a valid MySQL/i
            ],
            dbType: 'MySQL',
            specificity: 'high'
        },
        mssql: {
            patterns: [
                /Microsoft.*ODBC.*SQL Server Driver/i,
                /Unclosed quotation mark/i,
                /Incorrect syntax near/i
            ],
            dbType: 'SQL Server',
            specificity: 'high'
        },
        postgresql: {
            patterns: [
                /PostgreSQL.*ERROR/i,
                /pg_query\(\)/i,
                /unterminated quoted string/i
            ],
            dbType: 'PostgreSQL',
            specificity: 'high'
        },
        oracle: {
            patterns: [
                /ORA-\d{5}/i,
                /Oracle.*Driver/i,
                /quoted string not properly terminated/i
            ],
            dbType: 'Oracle',
            specificity: 'high'
        }
    },

    findErrorPattern: function(responseText) {
        for (const [dbName, config] of Object.entries(this.patterns)) {
            for (const pattern of config.patterns) {
                const match = responseText.match(pattern);
                if (match) {
                    return {
                        pattern: match[0],
                        dbType: config.dbType,
                        specificity: config.specificity,
                        evidence: match[0]
                    };
                }
            }
        }
        return null;
    }
};
