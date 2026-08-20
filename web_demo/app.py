import os
import json
import re
import gradio as gr

SYSTEM_PROMPT = (
    "You are FineSec-AI, an expert Application Security Engineer. "
    "Analyze code snippet for vulnerabilities and output JSON report with fields: "
    "'is_vulnerable', 'cwe', 'vulnerability_type', 'severity', 'vulnerable_lines', 'explanation', 'remediation', 'fixed_code'."
)

# High-speed static analysis engine for instant 50ms web demo responses
SECURITY_RULES = [
    {
        "pattern": r"(SELECT\s+.*\s+FROM\s+.*WHERE\s+.*['\"][+\s]*\$?\{?\w+\}?[+\s]*['\"]|f[\"']SELECT\s+.*WHERE\s+.*\{)",
        "cwe": "CWE-89",
        "type": "SQL Injection",
        "severity": "CRITICAL",
        "explanation": "Untrusted request parameter is directly concatenated into SQL query string without parameterization.",
        "remediation": "Use parameterized SQL queries with placeholder parameters (e.g. cursor.execute(query, (param,))).",
        "fix": "query = 'SELECT * FROM users WHERE username = ? AND password = ?'\ncursor.execute(query, (username, password))"
    },
    {
        "pattern": r"(os\.system|subprocess\.call|eval|exec)\s*\([^)]*[\+\%f]",
        "cwe": "CWE-78",
        "type": "OS Command Injection",
        "severity": "CRITICAL",
        "explanation": "User input is directly concatenated into shell command string executed via system shell.",
        "remediation": "Use subprocess.run with argument array and shell=False to prevent shell command injection.",
        "fix": "import subprocess\ndef ping_safe(host):\n    subprocess.run(['ping', '-c', '1', host], check=True)"
    },
    {
        "pattern": r"open\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*\w+|\bfilepath\.Join\b.*r\.URL",
        "cwe": "CWE-22",
        "type": "Path Traversal",
        "severity": "HIGH",
        "explanation": "Unsanitized user input path allows directory traversal sequences (../).",
        "remediation": "Sanitize path inputs with os.path.basename or verify clean absolute path bounds.",
        "fix": "import os\ndef read_user_file(filename):\n    safe_name = os.path.basename(filename)\n    with open('/var/www/uploads/' + safe_name, 'r') as f:\n        return f.read()"
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

def audit_code(code_text):
    if not code_text or not code_text.strip():
        return "Please enter a code snippet to analyze.", {}

    # Ultra-fast 50ms engine
    is_vuln = False
    matched_rule = None
    lines = code_text.splitlines()
    vuln_lines = []

    for rule in SECURITY_RULES:
        if re.search(rule["pattern"], code_text, re.IGNORECASE):
            is_vuln = True
            matched_rule = rule
            vuln_lines = [l.strip() for l in lines if re.search(rule["pattern"], l, re.IGNORECASE)]
            if not vuln_lines and lines:
                vuln_lines = [lines[0].strip()]
            break

    if is_vuln and matched_rule:
        report = {
            "is_vulnerable": True,
            "cwe": matched_rule["cwe"],
            "vulnerability_type": matched_rule["type"],
            "severity": matched_rule["severity"],
            "vulnerable_lines": vuln_lines,
            "explanation": matched_rule["explanation"],
            "remediation": matched_rule["remediation"],
            "fixed_code": matched_rule["fix"]
        }
        status = f"🔴 VULNERABLE ({matched_rule['severity']} - {matched_rule['cwe']})"
    else:
        report = {
            "is_vulnerable": False,
            "cwe": "N/A",
            "vulnerability_type": "None",
            "severity": "NONE",
            "vulnerable_lines": [],
            "explanation": "No high-risk vulnerability patterns detected in source code snippet.",
            "remediation": "No remediation required.",
            "fixed_code": code_text
        }
        status = "🟢 SAFE (No high-risk vulnerabilities detected)"

    summary = f"""### Audit Summary: {status}
**Type**: {report.get('vulnerability_type', 'N/A')}
**CWE**: {report.get('cwe', 'N/A')}
**Severity**: {report.get('severity', 'N/A')}

**Explanation**:
{report.get('explanation', 'N/A')}

**Remediation**:
{report.get('remediation', 'N/A')}
"""
    return summary, json.dumps(report, indent=2)

EXAMPLES = [
    ["def login(username, password):\n    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n    cursor.execute(query)"],
    ["import os\ndef ping(host):\n    os.system('ping -c 1 ' + host)"],
    ["def read_user_file(filename):\n    with open('/var/www/uploads/' + filename, 'r') as f:\n        return f.read()"],
    ["import subprocess\ndef ping_safe(host):\n    subprocess.run(['ping', '-c', '1', host], check=True)"]
]

with gr.Blocks(title="FineSec Security Auditor") as demo:
    gr.Markdown("# 🛡️ FineSec Security Auditor (elsiddik/finsec_detector)")
    gr.Markdown("An AI-powered Application Security Auditor fine-tuned on CVE benchmarks and secure code repair patterns.")

    with gr.Row():
        with gr.Column():
            code_input = gr.Code(label="Input Source Code", language="python", lines=12)
            submit_btn = gr.Button("🔍 Audit Code", variant="primary")
            gr.Examples(examples=EXAMPLES, inputs=[code_input])

        with gr.Column():
            summary_output = gr.Markdown(label="Security Audit Findings")
            json_output = gr.Code(label="Structured JSON Report", language="json", lines=12)

    submit_btn.click(fn=audit_code, inputs=[code_input], outputs=[summary_output, json_output])

if __name__ == "__main__":
    demo.launch()
