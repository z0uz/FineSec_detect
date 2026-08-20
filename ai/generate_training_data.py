#!/usr/bin/env python3
"""
Generate Training Data from Pentesting Results
Converts pentesting findings into training data for DeepSeek model
"""

import json
import csv
import os
from datetime import datetime

class PentestDataGenerator:
    """Generate training data from pentesting results"""
    
    def __init__(self):
        self.training_data = []
        self.vulnerability_templates = self._load_templates()
    
    def _load_templates(self):
        """Load vulnerability description templates"""
        return {
            'RCE': {
                'instruction': 'Analyze this code for Remote Code Execution vulnerabilities',
                'context': 'Remote Code Execution allows attackers to execute arbitrary commands on the server',
                'severity': 'CRITICAL'
            },
            'SQLI': {
                'instruction': 'Detect SQL Injection vulnerabilities in this code',
                'context': 'SQL Injection can lead to unauthorized database access and data theft',
                'severity': 'CRITICAL'
            },
            'SQLI_PII': {
                'instruction': 'Identify SQL Injection that could expose PII data',
                'context': 'SQL Injection with PII access can lead to mass data breaches',
                'severity': 'CRITICAL'
            },
            'SSRF': {
                'instruction': 'Find Server-Side Request Forgery vulnerabilities',
                'context': 'SSRF allows attackers to make requests to internal services',
                'severity': 'CRITICAL'
            },
            'STORED_XSS': {
                'instruction': 'Detect Stored Cross-Site Scripting vulnerabilities',
                'context': 'Stored XSS can steal user sessions and compromise accounts',
                'severity': 'HIGH'
            },
            'IDOR': {
                'instruction': 'Identify Insecure Direct Object Reference vulnerabilities',
                'context': 'IDOR allows unauthorized access to other users\' data',
                'severity': 'HIGH'
            },
            'CSRF': {
                'instruction': 'Check for Cross-Site Request Forgery vulnerabilities',
                'context': 'CSRF can force users to perform unwanted actions',
                'severity': 'HIGH'
            },
            'CREDENTIAL_LEAK': {
                'instruction': 'Find exposed credentials in configuration files',
                'context': 'Leaked credentials can lead to full system compromise',
                'severity': 'HIGH'
            },
            'REFLECTED_XSS': {
                'instruction': 'Detect Reflected Cross-Site Scripting',
                'context': 'Reflected XSS can be used in phishing attacks',
                'severity': 'MEDIUM'
            },
            'DIRECTORY_LISTING': {
                'instruction': 'Check for directory listing vulnerabilities',
                'context': 'Directory listings expose file structure and sensitive files',
                'severity': 'LOW'
            }
        }
    
    def generate_from_pentest_results(self, results_dict):
        """Generate training data from pentesting results"""
        
        for category, findings in results_dict.items():
            if isinstance(findings, list):
                for finding in findings:
                    self._process_finding(finding, category)
            elif isinstance(findings, dict):
                self._process_dict_findings(findings, category)
        
        return self.training_data
    
    def _process_finding(self, finding, category):
        """Process individual finding"""
        vuln_type = finding.get('type', 'UNKNOWN')
        template = self.vulnerability_templates.get(vuln_type, {
            'instruction': f'Analyze for {vuln_type} vulnerability',
            'context': f'{vuln_type} vulnerability detected',
            'severity': finding.get('severity', 'MEDIUM')
        })
        
        # Create training example
        example = {
            'instruction': template['instruction'],
            'input': self._format_input(finding),
            'output': self._format_output(finding, template),
            'severity': template['severity'],
            'category': category
        }
        
        self.training_data.append(example)
    
    def _process_dict_findings(self, findings, category):
        """Process dictionary-based findings"""
        for key, value in findings.items():
            if isinstance(value, list) and value:
                example = {
                    'instruction': f'Analyze {key} in the target system',
                    'input': f'Category: {category}, Finding: {key}',
                    'output': f'Found {len(value)} instances: {str(value)[:200]}',
                    'severity': 'INFO',
                    'category': category
                }
                self.training_data.append(example)
    
    def _format_input(self, finding):
        """Format finding as input"""
        input_parts = []
        
        if 'endpoint' in finding:
            input_parts.append(f"Endpoint: {finding['endpoint']}")
        if 'parameter' in finding:
            input_parts.append(f"Parameter: {finding['parameter']}")
        if 'payload' in finding:
            input_parts.append(f"Payload: {finding['payload']}")
        if 'method' in finding:
            input_parts.append(f"Method: {finding['method']}")
        
        return ' | '.join(input_parts) if input_parts else str(finding)
    
    def _format_output(self, finding, template):
        """Format finding as output"""
        output_parts = [
            f"Vulnerability Type: {finding.get('type', 'UNKNOWN')}",
            f"Severity: {finding.get('severity', 'UNKNOWN')}",
            f"Context: {template['context']}"
        ]
        
        if 'evidence' in finding:
            output_parts.append(f"Evidence: {finding['evidence']}")
        
        if 'recommendation' in finding:
            output_parts.append(f"Recommendation: {finding['recommendation']}")
        else:
            output_parts.append(self._get_recommendation(finding.get('type')))
        
        return '\n'.join(output_parts)
    
    def _get_recommendation(self, vuln_type):
        """Get remediation recommendation"""
        recommendations = {
            'RCE': 'Sanitize all user input, use parameterized commands, implement input validation',
            'SQLI': 'Use parameterized queries, implement input validation, use ORM frameworks',
            'SQLI_PII': 'Use parameterized queries, encrypt sensitive data, implement access controls',
            'SSRF': 'Validate and whitelist URLs, use network segmentation, disable unnecessary protocols',
            'STORED_XSS': 'Sanitize and encode output, use Content Security Policy, implement HttpOnly cookies',
            'IDOR': 'Implement proper authorization checks, use indirect references, validate user permissions',
            'CSRF': 'Implement CSRF tokens, use SameSite cookies, validate Origin headers',
            'CREDENTIAL_LEAK': 'Use environment variables, implement secrets management, rotate credentials',
            'REFLECTED_XSS': 'Encode output, validate input, use Content Security Policy',
            'DIRECTORY_LISTING': 'Disable directory listing, implement proper access controls'
        }
        return f"Recommendation: {recommendations.get(vuln_type, 'Implement security best practices')}"
    
    def add_synthetic_examples(self):
        """Add synthetic training examples for common vulnerabilities"""
        
        synthetic_examples = [
            {
                'instruction': 'Analyze this SQL query for injection vulnerabilities',
                'input': "SELECT * FROM users WHERE id = '" + "user_input" + "'",
                'output': 'Vulnerability Type: SQL Injection\nSeverity: CRITICAL\nThe query concatenates user input directly without parameterization.\nRecommendation: Use parameterized queries or prepared statements.',
                'severity': 'CRITICAL',
                'category': 'synthetic'
            },
            {
                'instruction': 'Check this code for XSS vulnerabilities',
                'input': 'document.write("<div>" + userInput + "</div>")',
                'output': 'Vulnerability Type: Cross-Site Scripting\nSeverity: HIGH\nUser input is rendered without sanitization.\nRecommendation: Use textContent or sanitize HTML output.',
                'severity': 'HIGH',
                'category': 'synthetic'
            },
            {
                'instruction': 'Identify command injection in this code',
                'input': 'os.system("ping " + user_ip)',
                'output': 'Vulnerability Type: Command Injection\nSeverity: CRITICAL\nUser input is passed directly to system command.\nRecommendation: Use subprocess with argument list, validate input.',
                'severity': 'CRITICAL',
                'category': 'synthetic'
            },
            {
                'instruction': 'Detect IDOR vulnerability in this endpoint',
                'input': 'GET /api/user/{user_id}/profile - No authorization check',
                'output': 'Vulnerability Type: IDOR\nSeverity: HIGH\nEndpoint allows access to any user profile without authorization.\nRecommendation: Implement user ownership validation.',
                'severity': 'HIGH',
                'category': 'synthetic'
            },
            {
                'instruction': 'Find SSRF vulnerability in this code',
                'input': 'requests.get(user_provided_url)',
                'output': 'Vulnerability Type: SSRF\nSeverity: CRITICAL\nApplication fetches user-provided URLs without validation.\nRecommendation: Whitelist allowed domains, disable internal IP access.',
                'severity': 'CRITICAL',
                'category': 'synthetic'
            }
        ]
        
        self.training_data.extend(synthetic_examples)
    
    def save_to_csv(self, filename='pentest_training_data.csv'):
        """Save training data to CSV"""
        if not self.training_data:
            print("No training data to save")
            return
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['instruction', 'input', 'output', 'severity', 'category'])
            writer.writeheader()
            writer.writerows(self.training_data)
        
        print(f"✅ Saved {len(self.training_data)} training examples to {filename}")
    
    def save_to_jsonl(self, filename='pentest_training_data.jsonl'):
        """Save training data to JSONL format (better for LLM training)"""
        if not self.training_data:
            print("No training data to save")
            return
        
        with open(filename, 'w', encoding='utf-8') as f:
            for example in self.training_data:
                # Format for instruction tuning
                formatted = {
                    'messages': [
                        {'role': 'system', 'content': 'You are a security expert analyzing code for vulnerabilities.'},
                        {'role': 'user', 'content': f"{example['instruction']}\n\n{example['input']}"},
                        {'role': 'assistant', 'content': example['output']}
                    ],
                    'metadata': {
                        'severity': example['severity'],
                        'category': example['category']
                    }
                }
                f.write(json.dumps(formatted) + '\n')
        
        print(f"✅ Saved {len(self.training_data)} training examples to {filename}")
    
    def get_statistics(self):
        """Get statistics about training data"""
        if not self.training_data:
            return "No training data available"
        
        severity_counts = {}
        category_counts = {}
        
        for example in self.training_data:
            severity = example.get('severity', 'UNKNOWN')
            category = example.get('category', 'UNKNOWN')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        stats = f"""
Training Data Statistics:
========================
Total Examples: {len(self.training_data)}

By Severity:
{chr(10).join(f'  {k}: {v}' for k, v in sorted(severity_counts.items()))}

By Category:
{chr(10).join(f'  {k}: {v}' for k, v in sorted(category_counts.items()))}
"""
        return stats


def main():
    """Main function to generate training data"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate training data from pentesting results')
    parser.add_argument('--report', help='Path to pentest report JSON file')
    parser.add_argument('--output-csv', default='pentest_training_data.csv', help='Output CSV file')
    parser.add_argument('--output-jsonl', default='pentest_training_data.jsonl', help='Output JSONL file')
    parser.add_argument('--add-synthetic', action='store_true', help='Add synthetic examples')
    
    args = parser.parse_args()
    
    generator = PentestDataGenerator()
    
    # Load pentest results if provided
    if args.report and os.path.exists(args.report):
        with open(args.report, 'r') as f:
            results = json.load(f)
        generator.generate_from_pentest_results(results)
        print(f"✅ Loaded results from {args.report}")
    
    # Add synthetic examples
    if args.add_synthetic:
        generator.add_synthetic_examples()
        print("✅ Added synthetic examples")
    
    # Save data
    if generator.training_data:
        generator.save_to_csv(args.output_csv)
        generator.save_to_jsonl(args.output_jsonl)
        print(generator.get_statistics())
    else:
        print("❌ No training data generated. Run pentests first or use --add-synthetic")


if __name__ == '__main__':
    main()
