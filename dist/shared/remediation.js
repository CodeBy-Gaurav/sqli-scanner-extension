/**
 * Comprehensive remediation guidance for SQL injection vulnerabilities
 */

export class RemediationGuide {

    static getRemediation(technique, dbType = 'Generic') {
        const baseRemediation = {
            title: `${technique} SQL Injection Remediation`,
            description: this.getDescription(technique),
            priority: this.getPriority(technique),
            examples: this.getExamples(technique, dbType),
            resources: this.getResources(technique),
            testing: this.getTestingGuidance(technique)
        };

        return baseRemediation;
    }

    static getDescription(technique) {
        const descriptions = {
            'Error-based': 'Prevent database errors from being displayed to users and use parameterized queries to block malicious SQL injection attempts.',
            'Boolean-based Blind': 'Eliminate response differences between true/false conditions by using parameterized queries and consistent error handling.',
            'Time-based Blind': 'Use parameterized queries to prevent time-based attacks and implement proper timeout handling.',
            'Union-based': 'Block UNION attacks by using parameterized queries and limiting data exposure through proper access controls.',
            'WAF Bypass': 'Implement defense-in-depth with parameterized queries as the primary defense, not just WAF rules.'
        };

        return descriptions[technique] || 'Use parameterized queries and proper input validation to prevent SQL injection.';
    }

    static getPriority(technique) {
        const priorities = {
            'Error-based': 'HIGH',
            'Boolean-based Blind': 'CRITICAL', 
            'Time-based Blind': 'HIGH',
            'Union-based': 'CRITICAL',
            'WAF Bypass': 'CRITICAL'
        };

        return priorities[technique] || 'HIGH';
    }

    static getExamples(technique, dbType) {
        return {
            nodejs: this.getNodeJSExamples(dbType),
            python: this.getPythonExamples(dbType),
            php: this.getPHPExamples(dbType),
            java: this.getJavaExamples(dbType),
            csharp: this.getCSharpExamples(dbType),
            generic: this.getGenericExamples()
        };
    }

    static getNodeJSExamples(dbType) {
        const examples = {
            'MySQL': `// Node.js with mysql2
const mysql = require('mysql2/promise');

// ❌ VULNERABLE
const query = \`SELECT * FROM users WHERE id = \${userId}\`;

// ✅ SECURE - Parameterized Query
const query = 'SELECT * FROM users WHERE id = ?';
const [rows] = await connection.execute(query, [userId]);

// ✅ SECURE - Using Prepared Statements
const stmt = await connection.prepare('SELECT * FROM users WHERE id = ?');
const [rows] = await stmt.execute([userId]);`,

            'PostgreSQL': `// Node.js with pg
const { Client } = require('pg');

// ❌ VULNERABLE
const query = \`SELECT * FROM users WHERE id = \${userId}\`;

// ✅ SECURE - Parameterized Query
const query = 'SELECT * FROM users WHERE id = $1';
const result = await client.query(query, [userId]);

// ✅ SECURE - Named Parameters
const query = 'SELECT * FROM users WHERE email = $1 AND status = $2';
const result = await client.query(query, [email, 'active']);`,

            'MongoDB': `// Node.js with MongoDB
const { MongoClient } = require('mongodb');

// ❌ VULNERABLE - String concatenation
const query = { name: eval(userInput) };

// ✅ SECURE - Parameterized queries
const query = { name: userName, status: 'active' };
const result = await collection.findOne(query);

// ✅ SECURE - Using strict comparison
const query = { 
    _id: new ObjectId(userId),
    $and: [{ status: { $eq: 'active' } }]
};`
        };

        return examples[dbType] || examples['MySQL'];
    }

    static getPythonExamples(dbType) {
        const examples = {
            'MySQL': `# Python with PyMySQL
import pymysql

# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ SECURE - Parameterized Query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# ✅ SECURE - Dictionary parameters
query = "SELECT * FROM users WHERE email = %(email)s AND status = %(status)s"
cursor.execute(query, {'email': email, 'status': 'active'})`,

            'PostgreSQL': `# Python with psycopg2
import psycopg2

# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ SECURE - Parameterized Query
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))

# ✅ SECURE - Using psycopg2.sql for dynamic queries
from psycopg2 import sql
query = sql.SQL("SELECT * FROM {} WHERE id = %s").format(
    sql.Identifier('users')
)
cursor.execute(query, (user_id,))`,

            'SQLite': `# Python with sqlite3
import sqlite3

# ❌ VULNERABLE
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ SECURE - Parameterized Query
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

# ✅ SECURE - Named parameters
query = "SELECT * FROM users WHERE email = :email AND status = :status"
cursor.execute(query, {'email': email, 'status': 'active'})`
        };

        return examples[dbType] || examples['MySQL'];
    }

    static getPHPExamples(dbType) {
        return `<?php
// PHP with PDO

// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE id = " . $userId;

// ✅ SECURE - Prepared Statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);

// ✅ SECURE - Named parameters  
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email AND status = :status");
$stmt->execute(['email' => $email, 'status' => 'active']);

// ✅ SECURE - mysqli with prepared statements
$stmt = $mysqli->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
?>`;
    }

    static getJavaExamples(dbType) {
        return `// Java with JDBC

// ❌ VULNERABLE
String query = "SELECT * FROM users WHERE id = " + userId;

// ✅ SECURE - PreparedStatement
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setInt(1, userId);
ResultSet rs = pstmt.executeQuery();

// ✅ SECURE - JPA/Hibernate
@Query("SELECT u FROM User u WHERE u.id = :id")
User findUserById(@Param("id") Long id);

// ✅ SECURE - MyBatis
@Select("SELECT * FROM users WHERE id = #{id}")
User findById(@Param("id") Long id);`;
    }

    static getCSharpExamples(dbType) {
        return `// C# with SqlCommand

// ❌ VULNERABLE
string query = $"SELECT * FROM users WHERE id = {userId}";

// ✅ SECURE - Parameterized Query
string query = "SELECT * FROM users WHERE id = @id";
using (SqlCommand cmd = new SqlCommand(query, connection))
{
    cmd.Parameters.AddWithValue("@id", userId);
    SqlDataReader reader = cmd.ExecuteReader();
}

// ✅ SECURE - Entity Framework
var user = context.Users.Where(u => u.Id == userId).FirstOrDefault();

// ✅ SECURE - Dapper
var user = connection.QueryFirst<User>("SELECT * FROM users WHERE id = @id", new { id = userId });`;
    }

    static getGenericExamples() {
        return `Generic SQL Injection Prevention:

1. Use Parameterized Queries/Prepared Statements
2. Input Validation and Sanitization
3. Principle of Least Privilege
4. Error Handling (don't expose DB errors)
5. Regular Security Testing`;
    }

    static getResources(technique) {
        return {
            owasp: [
                'https://owasp.org/www-community/attacks/SQL_Injection',
                'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
                'https://owasp.org/www-project-top-ten/'
            ],
            cwe: [
                'https://cwe.mitre.org/data/definitions/89.html',
                'https://cwe.mitre.org/data/definitions/564.html'
            ],
            testing: [
                'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection',
                'https://portswigger.net/web-security/sql-injection'
            ]
        };
    }

    static getTestingGuidance(technique) {
        return {
            verification: [
                'Test with various SQL injection payloads',
                'Verify parameterized queries are used',
                'Check error handling and logging',
                'Validate input sanitization',
                'Test with different character encodings'
            ],
            automation: [
                'Use SAST tools to scan source code',
                'Implement DAST in CI/CD pipeline', 
                'Regular dependency vulnerability scans',
                'Database security configuration reviews'
            ],
            manual: [
                'Code review of database interaction points',
                'Architecture review of data flow',
                'Penetration testing by security experts',
                'Security-focused unit tests'
            ]
        };
    }

    static getQuickFix(finding) {
        const quickFixes = {
            'Error-based': 'Replace string concatenation with parameterized queries',
            'Boolean-based Blind': 'Use parameterized queries and consistent error responses',
            'Time-based Blind': 'Implement parameterized queries and proper timeout handling',
            'Union-based': 'Use parameterized queries and limit data exposure',
            'WAF Bypass': 'Fix underlying vulnerability with parameterized queries'
        };

        return quickFixes[finding.technique] || 'Use parameterized queries';
    }

    static getPriorityLevel(confidence, technique) {
        const priorityMatrix = {
            'Critical': { 'Error-based': 'P0', 'Boolean-based Blind': 'P0', 'Union-based': 'P0' },
            'High': { 'Error-based': 'P1', 'Boolean-based Blind': 'P0', 'Time-based Blind': 'P1' },
            'Medium': { 'Error-based': 'P2', 'Boolean-based Blind': 'P1', 'Time-based Blind': 'P2' },
            'Low': { 'Error-based': 'P3', 'Boolean-based Blind': 'P2', 'Time-based Blind': 'P3' }
        };

        return priorityMatrix[confidence]?.[technique] || 'P2';
    }
}