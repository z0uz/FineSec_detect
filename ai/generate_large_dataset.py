#!/usr/bin/env python3
"""
Generate Large Training Dataset for DeepSeek
Creates 500+ vulnerability examples across all categories
"""

import json
import random

class LargeDatasetGenerator:
    """Generate comprehensive vulnerability training dataset"""
    
    def __init__(self):
        self.training_data = []
    
    def generate_sql_injection_examples(self, count=100):
        """Generate SQL injection examples"""
        print(f"Generating {count} SQL injection examples...")
        
        # SQL injection patterns
        patterns = [
            "SELECT * FROM users WHERE id = 'USER_INPUT'",
            "SELECT * FROM products WHERE name = 'PRODUCT_NAME'",
            "DELETE FROM users WHERE username = 'USERNAME'",
            "UPDATE users SET password = 'NEW_PASS' WHERE id = 1",
            "INSERT INTO logs VALUES ('USER_DATA', 'timestamp')",
            "SELECT * FROM orders WHERE user_id = 1 AND status = 'STATUS'",
            "SELECT COUNT(*) FROM users WHERE email = 'EMAIL'",
            "SELECT * FROM posts WHERE author = 'AUTHOR' ORDER BY date",
            "SELECT balance FROM accounts WHERE account_id = 'ACC_ID'",
            "SELECT * FROM sessions WHERE token = 'TOKEN'",
        ]
        
        contexts = [
            "Login form",
            "Search functionality",
            "User profile update",
            "Product filtering",
            "Admin panel",
            "API endpoint",
            "Database query",
            "Authentication check",
            "Data retrieval",
            "Report generation"
        ]
        
        for i in range(count):
            pattern = random.choice(patterns)
            context = random.choice(contexts)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Analyze this SQL query from {context}:\n\n{pattern}"},
                    {'role': 'assistant', 'content': f"""Vulnerability Type: SQL Injection
Severity: CRITICAL
Context: {context}

The query concatenates user input directly without parameterization, allowing SQL injection attacks.

Attack Vector:
- Attacker can inject: ' OR '1'='1
- Bypass authentication
- Extract sensitive data
- Modify/delete records
- Execute arbitrary SQL

Recommendation:
1. Use parameterized queries/prepared statements
2. Implement input validation and sanitization
3. Use ORM frameworks
4. Apply principle of least privilege
5. Enable SQL injection detection/prevention tools"""}
                ],
                'metadata': {'severity': 'CRITICAL', 'category': 'sqli'}
            }
            self.training_data.append(example)
    
    def generate_xss_examples(self, count=80):
        """Generate XSS examples"""
        print(f"Generating {count} XSS examples...")
        
        patterns = [
            "document.write('<div>' + userInput + '</div>')",
            "innerHTML = userData",
            "$('#output').html(userComment)",
            "echo '<h1>' . $_GET['name'] . '</h1>'",
            "<div>{{ user_input }}</div>",
            "response.write('<p>' + request.query.msg + '</p>')",
            "print(f'<span>{user_data}</span>')",
            "<script>var data = 'USER_INPUT';</script>",
            "eval(userCode)",
            "new Function(userScript)()",
        ]
        
        types = ["Reflected XSS", "Stored XSS", "DOM-based XSS"]
        
        for i in range(count):
            pattern = random.choice(patterns)
            xss_type = random.choice(types)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Check this code for XSS vulnerabilities:\n\n{pattern}"},
                    {'role': 'assistant', 'content': f"""Vulnerability Type: {xss_type}
Severity: HIGH

User input is rendered without proper sanitization or encoding, allowing XSS attacks.

Attack Vector:
- Inject: <script>alert(document.cookie)</script>
- Steal session cookies
- Redirect users to malicious sites
- Modify page content
- Perform actions on behalf of user

Recommendation:
1. Encode all output (HTML, JavaScript, URL encoding)
2. Use Content Security Policy (CSP)
3. Implement HttpOnly cookies
4. Use framework's built-in escaping
5. Validate and sanitize input
6. Use textContent instead of innerHTML"""}
                ],
                'metadata': {'severity': 'HIGH', 'category': 'xss'}
            }
            self.training_data.append(example)
    
    def generate_command_injection_examples(self, count=60):
        """Generate command injection examples"""
        print(f"Generating {count} command injection examples...")
        
        patterns = [
            "os.system('ping ' + user_ip)",
            "exec('ls ' + directory)",
            "subprocess.call('wget ' + url)",
            "system('cat ' . $filename)",
            "Runtime.getRuntime().exec('rm ' + file)",
            "shell_exec('tar -xzf ' . $archive)",
            "popen('grep SEARCH_TERM /var/log/app.log')",
            "os.popen('nslookup ' + hostname)",
            "`curl #{user_url}`",
            "eval('echo ' + user_input)",
        ]
        
        for i in range(count):
            pattern = random.choice(patterns)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Identify command injection in this code:\n\n{pattern}"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Command Injection / Remote Code Execution
Severity: CRITICAL

User input is passed directly to system command execution without validation.

Attack Vector:
- Inject: ; rm -rf / or && cat /etc/passwd
- Execute arbitrary commands
- Read sensitive files
- Modify system files
- Establish reverse shell
- Full system compromise

Recommendation:
1. Never pass user input to system commands
2. Use subprocess with argument lists (not shell=True)
3. Implement strict input validation
4. Use allowlists for permitted values
5. Run with minimal privileges
6. Use language-specific safe alternatives"""}
                ],
                'metadata': {'severity': 'CRITICAL', 'category': 'rce'}
            }
            self.training_data.append(example)
    
    def generate_idor_examples(self, count=50):
        """Generate IDOR examples"""
        print(f"Generating {count} IDOR examples...")
        
        endpoints = [
            "GET /api/user/{}/profile",
            "GET /api/order/{}",
            "DELETE /api/document/{}",
            "PUT /api/account/{}/settings",
            "GET /api/message/{}",
            "POST /api/file/{}/download",
            "GET /api/invoice/{}",
            "PUT /api/user/{}/password",
            "GET /api/report/{}",
            "DELETE /api/post/{}",
        ]
        
        for i in range(count):
            endpoint = random.choice(endpoints)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Detect IDOR vulnerability in this endpoint:\n\n{endpoint}\n\nNo authorization check implemented"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Insecure Direct Object Reference (IDOR)
Severity: HIGH

Endpoint allows direct access to resources using predictable identifiers without proper authorization checks.

Attack Vector:
- Enumerate IDs (1, 2, 3...)
- Access other users' data
- Modify unauthorized resources
- Delete other users' content
- Horizontal/vertical privilege escalation

Recommendation:
1. Implement proper authorization checks
2. Verify user ownership of resource
3. Use indirect references (UUIDs, tokens)
4. Check permissions before every access
5. Log access attempts
6. Implement rate limiting"""}
                ],
                'metadata': {'severity': 'HIGH', 'category': 'idor'}
            }
            self.training_data.append(example)
    
    def generate_ssrf_examples(self, count=40):
        """Generate SSRF examples"""
        print(f"Generating {count} SSRF examples...")
        
        patterns = [
            "requests.get(user_provided_url)",
            "urllib.request.urlopen(user_url)",
            "fetch(user_input_url)",
            "file_get_contents(url_param)",
            "curl(user_url)",
            "HttpClient.get(external_url)",
            "axios.get(user_provided_url)",
            "RestTemplate.getForObject(url_input)",
        ]
        
        for i in range(count):
            pattern = random.choice(patterns)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Find SSRF vulnerability:\n\n{pattern}"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Server-Side Request Forgery (SSRF)
Severity: CRITICAL

Application fetches user-provided URLs without validation, allowing SSRF attacks.

Attack Vector:
- Access internal services: http://localhost:8080
- Read cloud metadata: http://169.254.169.254/
- Scan internal network
- Access restricted resources
- Bypass firewall rules
- Pivot to internal systems

Recommendation:
1. Validate and whitelist allowed domains
2. Disable unnecessary protocols (file://, gopher://)
3. Use network segmentation
4. Block internal IP ranges
5. Implement URL parsing and validation
6. Use DNS rebinding protection"""}
                ],
                'metadata': {'severity': 'CRITICAL', 'category': 'ssrf'}
            }
            self.training_data.append(example)
    
    def generate_auth_bypass_examples(self, count=40):
        """Generate authentication bypass examples"""
        print(f"Generating {count} authentication bypass examples...")
        
        patterns = [
            "if username == 'admin' and password == 'password':",
            "if request.cookies.get('admin') == 'true':",
            "if $_SESSION['role'] == 'admin':",
            "if (user.isAdmin || req.query.admin):",
            "if password == md5(input):",
        ]
        
        for i in range(count):
            pattern = random.choice(patterns)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Analyze authentication mechanism:\n\n{pattern}"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Authentication Bypass
Severity: CRITICAL

Weak or bypassable authentication mechanism detected.

Issues:
- Hardcoded credentials
- Client-side authentication
- Weak password hashing
- Missing authentication checks
- Predictable session tokens

Recommendation:
1. Use strong authentication frameworks
2. Implement server-side validation
3. Use bcrypt/argon2 for password hashing
4. Implement MFA
5. Use secure session management
6. Apply rate limiting on auth endpoints"""}
                ],
                'metadata': {'severity': 'CRITICAL', 'category': 'auth_bypass'}
            }
            self.training_data.append(example)
    
    def generate_csrf_examples(self, count=40):
        """Generate CSRF examples"""
        print(f"Generating {count} CSRF examples...")
        
        endpoints = [
            "POST /api/user/update",
            "POST /api/password/change",
            "DELETE /api/account",
            "POST /api/email/change",
            "POST /api/transfer/money",
            "PUT /api/settings",
            "POST /api/admin/add",
        ]
        
        for i in range(count):
            endpoint = random.choice(endpoints)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Check for CSRF protection:\n\n{endpoint}\n\nNo CSRF token validation"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Cross-Site Request Forgery (CSRF)
Severity: HIGH

State-changing operation without CSRF protection allows attackers to perform actions on behalf of authenticated users.

Attack Vector:
- Craft malicious HTML form
- Trick user into visiting attacker's page
- Auto-submit form to vulnerable endpoint
- Perform unauthorized actions
- Change user settings/password
- Transfer funds

Recommendation:
1. Implement CSRF tokens
2. Use SameSite cookie attribute
3. Validate Origin/Referer headers
4. Require re-authentication for sensitive actions
5. Use POST for state-changing operations
6. Implement double-submit cookie pattern"""}
                ],
                'metadata': {'severity': 'HIGH', 'category': 'csrf'}
            }
            self.training_data.append(example)
    
    def generate_path_traversal_examples(self, count=30):
        """Generate path traversal examples"""
        print(f"Generating {count} path traversal examples...")
        
        patterns = [
            "open('/uploads/' + filename)",
            "File.read('documents/' + user_file)",
            "include($_GET['page'] . '.php')",
            "readFile('./files/' + file_param)",
            "fs.readFileSync(path.join(__dirname, user_path))",
        ]
        
        for i in range(count):
            pattern = random.choice(patterns)
            
            example = {
                'messages': [
                    {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                    {'role': 'user', 'content': f"Detect path traversal:\n\n{pattern}"},
                    {'role': 'assistant', 'content': """Vulnerability Type: Path Traversal / Directory Traversal
Severity: HIGH

File path constructed from user input without validation allows access to arbitrary files.

Attack Vector:
- Use: ../../etc/passwd
- Read sensitive files
- Access configuration files
- Read source code
- Bypass access controls

Recommendation:
1. Validate and sanitize file paths
2. Use allowlist of permitted files
3. Resolve canonical paths
4. Check if path is within allowed directory
5. Use file IDs instead of names
6. Implement proper access controls"""}
                ],
                'metadata': {'severity': 'HIGH', 'category': 'path_traversal'}
            }
            self.training_data.append(example)
    
    def generate_all(self):
        """Generate complete large dataset"""
        print("\n🚀 Generating Large Training Dataset...")
        print("="*60)
        
        self.generate_sql_injection_examples(100)
        self.generate_xss_examples(80)
        self.generate_command_injection_examples(60)
        self.generate_idor_examples(50)
        self.generate_ssrf_examples(40)
        self.generate_auth_bypass_examples(40)
        self.generate_csrf_examples(40)
        self.generate_path_traversal_examples(30)
        
        print("="*60)
        print(f"✅ Generated {len(self.training_data)} total examples")
        
        return self.training_data
    
    def save_to_jsonl(self, filename='training_data_large.jsonl'):
        """Save to JSONL format"""
        with open(filename, 'w', encoding='utf-8') as f:
            for example in self.training_data:
                f.write(json.dumps(example) + '\n')
        
        print(f"\n💾 Saved to {filename}")
        print(f"   Size: {len(self.training_data)} examples")
        
        # Statistics
        severity_counts = {}
        category_counts = {}
        
        for example in self.training_data:
            severity = example['metadata']['severity']
            category = example['metadata']['category']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        print(f"\n📊 Statistics:")
        print(f"   By Severity:")
        for sev, count in sorted(severity_counts.items()):
            print(f"      {sev}: {count}")
        
        print(f"   By Category:")
        for cat, count in sorted(category_counts.items()):
            print(f"      {cat}: {count}")


def main():
    generator = LargeDatasetGenerator()
    generator.generate_all()
    generator.save_to_jsonl('training_data_large.jsonl')
    
    print("\n✅ Large dataset ready for Colab training!")
    print(f"   File: training_data_large.jsonl")
    print(f"   Upload this to Colab for better model training")


if __name__ == '__main__':
    main()
