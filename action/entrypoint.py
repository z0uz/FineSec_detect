#!/usr/bin/env python3
import os
import sys
import json
import re
import requests

SECURITY_RULES = [
    {
        "pattern": r"(SELECT\s+.*\s+FROM\s+.*WHERE\s+.*['\"][+\s]*\$?\{?\w+\}?[+\s]*['\"]|f[\"']SELECT\s+.*WHERE\s+.*\{)",
        "cwe": "CWE-89",
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "explanation": "Untrusted request parameter is directly concatenated into SQL query string without parameterization.",
        "remediation": "Use parameterized SQL queries with placeholder parameters.",
        "fix": "query = 'SELECT * FROM users WHERE username = ? AND password = ?'\ncursor.execute(query, (username, password))"
    },
    {
        "pattern": r"(os\.system|subprocess\.call|eval|exec)\s*\([^)]*[\+\%f]",
        "cwe": "CWE-78",
        "type": "OS Command Injection",
        "severity": "CRITICAL",
        "explanation": "User input is directly concatenated into shell command string executed via system shell.",
        "remediation": "Use subprocess.run with argument array and shell=False to prevent shell command injection.",
        "fix": "import subprocess\nsubprocess.run(['ping', '-c', '1', host], check=True)"
    },
    {
        "pattern": r"open\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+|\bfilepath\.Join\b.*r\.URL",
        "cwe": "CWE-22",
        "type": "Path Traversal",
        "severity": "HIGH",
        "explanation": "Unsanitized user input path allows directory traversal sequences (../).",
        "remediation": "Sanitize path inputs with os.path.basename or verify clean absolute path bounds.",
        "fix": "safe_name = os.path.basename(filename)\nwith open('/var/www/uploads/' + safe_name, 'r') as f:\n    return f.read()"
    },
    {
        "pattern": r"res\.send\(.*req\.query|res\.write\(.*req\.params|innerHTML\s*=",
        "cwe": "CWE-79",
        "type": "Reflected Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "explanation": "Untrusted user request input is rendered directly into HTML response body without sanitization.",
        "remediation": "Escape HTML special characters or use textContent/DOMPurify before rendering.",
        "fix": "const data = escapeHtml(req.query.search || '');\nres.send(`<div>Search result: ${data}</div>`);"
    },
    {
        "pattern": r"strcpy\s*\(|strcat\s*\(|gets\s*\(",
        "cwe": "CWE-120",
        "type": "Buffer Overflow",
        "severity": "CRITICAL",
        "explanation": "Unbounded string copy routine used on fixed-size buffer leading to memory corruption.",
        "remediation": "Use bounded string routines such as strncpy or strlcpy with size bounds.",
        "fix": "strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = '\\0';"
    }
]

SUPPORTED_EXTENSIONS = ('.py', '.c', '.cpp', '.h', '.js', '.ts', '.go', '.java', '.php', '.sol', '.sh')

def audit_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception:
        return None

    lines = content.splitlines()
    findings = []

    for rule in SECURITY_RULES:
        matches = [i + 1 for i, l in enumerate(lines) if re.search(rule["pattern"], l, re.IGNORECASE)]
        if matches:
            findings.append({
                "filepath": filepath,
                "lines": matches,
                "cwe": rule["cwe"],
                "type": rule["type"],
                "severity": rule["severity"],
                "explanation": rule["explanation"],
                "remediation": rule["remediation"],
                "fix": rule["fix"]
            })
    return findings

def scan_directory(target_dir):
    all_findings = []
    for root, _, files in os.walk(target_dir):
        # Skip git and cache dirs
        if '.git' in root or '__pycache__' in root or 'node_modules' in root:
            continue
        for file in files:
            if file.endswith(SUPPORTED_EXTENSIONS):
                full_path = os.path.join(root, file)
                res = audit_file(full_path)
                if res:
                    all_findings.extend(res)
    return all_findings

def post_pr_comment(token, repo, pr_number, body):
    if not token or not repo or not pr_number:
        return
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    requests.post(url, headers=headers, json={"body": body})

def main():
    target_path = os.environ.get("INPUT_PATH", ".")
    github_token = os.environ.get("INPUT_GITHUB-TOKEN") or os.environ.get("GITHUB_TOKEN")
    fail_on_vuln = os.environ.get("INPUT_FAIL-ON-VULNERABILITY", "false").lower() == "true"
    
    print("🛡️ FineSec Security Auditor GitHub Action Running...")
    print(f"📁 Auditing path: {target_path}")

    findings = scan_directory(target_path)
    total_findings = len(findings)

    print(f"📊 Audit Complete. Total High-Risk Flaws Detected: {total_findings}")

    # Format Markdown Report
    if total_findings == 0:
        comment_body = "### 🛡️ FineSec Security Auditor: SAFE ✅\nNo high-risk security vulnerabilities detected."
    else:
        comment_body = f"### 🛡️ FineSec Security Audit Report: VULNERABLE 🔴\n**{total_findings} High-Risk Vulnerabilities Detected**\n\n"
        for idx, f in enumerate(findings, 1):
            comment_body += f"#### {idx}. {f['type']} ({f['severity']} - {f['cwe']})\n"
            comment_body += f"- **File**: `{f['filepath']}` (Lines: `{f['lines']}`)\n"
            comment_body += f"- **Explanation**: {f['explanation']}\n"
            comment_body += f"- **Remediation**: {f['remediation']}\n"
            comment_body += f"- **Recommended Secure Fix**:\n```python\n{f['fix']}\n```\n\n"

    print(comment_body)

    # If running inside a Pull Request, post PR comment
    github_repository = os.environ.get("GITHUB_REPOSITORY")
    github_event_path = os.environ.get("GITHUB_EVENT_PATH")
    
    if github_event_path and os.path.exists(github_event_path):
        try:
            with open(github_event_path, 'r') as ef:
                event_data = json.load(ef)
                pr_number = event_data.get("pull_request", {}).get("number")
                if pr_number and github_token and github_repository:
                    print(f"💬 Posting PR comment to #{pr_number}...")
                    post_pr_comment(github_token, github_repository, pr_number, comment_body)
        except Exception as e:
            print(f"Could not post PR comment: {e}")

    # Set Outputs for GitHub Actions
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a") as f:
            f.write(f"vulnerabilities-found={total_findings}\n")
            f.write(f"report-json={json.dumps(findings)}\n")

    if fail_on_vuln and total_findings > 0:
        print("❌ Failing workflow step due to detected vulnerabilities (fail-on-vulnerability=true).")
        sys.exit(1)

if __name__ == "__main__":
    main()
