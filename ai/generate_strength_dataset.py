#!/usr/bin/env python3
"""
Advanced Training Dataset Generator for FineSec Security LLM
Generates multi-line vulnerable, patched/safe, and real-world CVE code examples
with structured JSON outputs to build a state-of-the-art vulnerability detection LLM.
Supports processing up to all 115,230+ local CVE records.
"""

import os
import json
import random
import argparse
import pandas as pd

SYSTEM_PROMPT = (
    "You are an expert security engineer and vulnerability researcher. "
    "Analyze the provided code or security report for security vulnerabilities. "
    "Respond strictly with a valid JSON object matching this schema:\n"
    "{\n"
    '  "is_vulnerable": boolean,\n'
    '  "cwe": string,\n'
    '  "vulnerability_type": string,\n'
    '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE",\n'
    '  "vulnerable_lines": array of strings,\n'
    '  "explanation": string,\n'
    '  "remediation": string\n'
    "}"
)

# Multi-line Vulnerable & Safe Code Samples
CURATED_EXAMPLES = [
    {
        "code": """def get_user_profile(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    query = f"SELECT id, username, email, is_admin FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    user = cursor.fetchone()
    return JsonResponse({'user': user})""",
        "response": {
            "is_vulnerable": True,
            "cwe": "CWE-89",
            "vulnerability_type": "SQL Injection",
            "severity": "CRITICAL",
            "vulnerable_lines": ["query = f\"SELECT id, username, email, is_admin FROM users WHERE id = '{user_id}'\""],
            "explanation": "User input `user_id` from HTTP GET parameter is directly interpolated into a raw SQL query string without parameterization or sanitization.",
            "remediation": "Use parameterized SQL queries: `cursor.execute('SELECT id, username, email, is_admin FROM users WHERE id = %s', [user_id])` or Django ORM `User.objects.filter(id=user_id)`."
        }
    },
    {
        "code": """def get_user_profile(request):
    user_id = request.GET.get('id')
    if not user_id or not user_id.isdigit():
        return JsonResponse({'error': 'Invalid ID'}, status=400)
    
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = %s", [int(user_id)])
        user = cursor.fetchone()
    return JsonResponse({'user': user})""",
        "response": {
            "is_vulnerable": False,
            "cwe": "N/A",
            "vulnerability_type": "None",
            "severity": "NONE",
            "vulnerable_lines": [],
            "explanation": "The code safely validates that `user_id` is numeric and uses parameterized database queries (%s placeholder with parameter list).",
            "remediation": "No remediation needed. Code follows secure coding best practices."
        }
    },
    {
        "code": """import os
from flask import Flask, request

app = Flask(__name__)

@app.route('/api/ping')
def ping_host():
    target = request.args.get('target')
    cmd = f"ping -c 1 {target}"
    output = os.popen(cmd).read()
    return {"output": output}""",
        "response": {
            "is_vulnerable": True,
            "cwe": "CWE-78",
            "vulnerability_type": "OS Command Injection",
            "severity": "CRITICAL",
            "vulnerable_lines": [
                "cmd = f\"ping -c 1 {target}\"",
                "output = os.popen(cmd).read()"
            ],
            "explanation": "The target parameter is passed directly to system shell execution via `os.popen`. Attackers can append command separators like `;`, `&&`, or `|` to execute arbitrary OS commands.",
            "remediation": "Use `subprocess.run` with argument lists and `shell=False`, or validate the input against a strict IP address regex (e.g. `ipaddress.ip_address(target)`)."
        }
    },
    {
        "code": """import subprocess
import ipaddress
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/ping')
def ping_host():
    target = request.args.get('target')
    try:
        ip = str(ipaddress.ip_address(target))
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400
    
    res = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True, timeout=5)
    return jsonify({'output': res.stdout})""",
        "response": {
            "is_vulnerable": False,
            "cwe": "N/A",
            "vulnerability_type": "None",
            "severity": "NONE",
            "vulnerable_lines": [],
            "explanation": "Input is strictly validated as an IP address using standard library parsing, and system invocation uses `subprocess.run` with list arguments (avoiding shell evaluation).",
            "remediation": "No remediation required."
        }
    },
    {
        "code": """app.get('/search', (req, res) => {
    const query = req.query.q || '';
    res.send(`
        <html>
            <body>
                <h1>Search Results for: ${query}</h1>
                <div id="results">No results found.</div>
            </body>
        </html>
    `);
});""",
        "response": {
            "is_vulnerable": True,
            "cwe": "CWE-79",
            "vulnerability_type": "Reflected Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "vulnerable_lines": ["<h1>Search Results for: ${query}</h1>"],
            "explanation": "Untrusted user query parameter `query` is interpolated directly into raw HTML without output escaping, allowing execution of arbitrary client-side JavaScript.",
            "remediation": "Use a templating engine with automatic HTML escaping (e.g. EJS, Pug) or sanitize user input using a library like `DOMPurify` / `he.encode()`."
        }
    },
    {
        "code": """const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/search', (req, res) => {
    const query = escapeHtml(req.query.q || '');
    res.send(`
        <html>
            <body>
                <h1>Search Results for: ${query}</h1>
                <div id="results">No results found.</div>
            </body>
        </html>
    `);
});""",
        "response": {
            "is_vulnerable": False,
            "cwe": "N/A",
            "vulnerability_type": "None",
            "severity": "NONE",
            "vulnerable_lines": [],
            "explanation": "User input `req.query.q` is sanitized with `escapeHtml` before rendering into the HTML document context.",
            "remediation": "No remediation required."
        }
    }
]

def load_cve_parquet(parquet_path, max_samples=None):
    """Load real-world CVE records from parquet dataset"""
    if not os.path.exists(parquet_path):
        print(f"⚠️ Parquet file not found at {parquet_path}, skipping CVE parquet generation.")
        return []
    
    print(f"📦 Loading CVE parquet dataset from {parquet_path}...")
    df = pd.read_parquet(parquet_path)
    total_in_file = len(df)
    
    if max_samples and max_samples < total_in_file:
        df = df.head(max_samples)
        print(f"📊 Processing {len(df)} of {total_in_file} total available CVEs...")
    else:
        print(f"🔥 Processing ALL {total_in_file} available CVEs...")
    
    samples = []
    for idx, row in df.iterrows():
        try:
            cve_id = row.get('id', 'CVE-Unknown')
            desc = row.get('descriptions', '')
            primary_cwe = row.get('primary_cwe')
            
            if pd.isna(primary_cwe) or not desc:
                continue
            
            cwe_str = f"CWE-{int(primary_cwe)}"
            
            code_text = f"CVE Record: {cve_id}\nDescription: {desc}"
            resp_data = {
                "is_vulnerable": True,
                "cwe": cwe_str,
                "vulnerability_type": f"Security Vulnerability ({cwe_str})",
                "severity": "HIGH",
                "vulnerable_lines": [desc[:100] + "..."],
                "explanation": f"{cve_id}: {desc}",
                "remediation": "Apply vendor patches, implement strict input validation, and enforce proper security controls corresponding to " + cwe_str + "."
            }
            
            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this security report:\n\n{code_text}"},
                    {"role": "assistant", "content": json.dumps(resp_data, indent=2)}
                ]
            })
        except Exception:
            continue
            
    print(f"✅ Extracted {len(samples)} valid CVE samples.")
    return samples

def build_dataset(output_path="data/training_data_strong.jsonl", cve_limit=None):
    """Build and save dataset with optional CVE limits"""
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    dataset = []
    
    # 1. Add Curated Multi-line Code Examples
    print(f"⚡ Adding {len(CURATED_EXAMPLES)} curated code samples...")
    for item in CURATED_EXAMPLES:
        example = {
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this code snippet for security vulnerabilities:\n\n```\n{item['code']}\n```"},
                {"role": "assistant", "content": json.dumps(item['response'], indent=2)}
            ]
        }
        dataset.append(example)
    
    # Multiply curated code snippets for higher weighting
    expanded_curated = []
    for _ in range(50):
        for item in CURATED_EXAMPLES:
            expanded_curated.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze this code snippet for security vulnerabilities:\n\n```\n{item['code']}\n```"},
                    {"role": "assistant", "content": json.dumps(item['response'], indent=2)}
                ]
            })
    dataset.extend(expanded_curated)
    
    # 2. Add Parquet CVE Samples
    parquet_path = "data/train-00000-of-00001.parquet"
    if not os.path.exists(parquet_path):
        parquet_path = "/home/zouz/Documents/coding/FineSec_detect/train-00000-of-00001.parquet"
    
    cve_samples = load_cve_parquet(parquet_path, max_samples=cve_limit)
    dataset.extend(cve_samples)
    
    # Shuffle dataset
    random.seed(42)
    random.shuffle(dataset)
    
    # Save to JSONL
    with open(output_path, "w", encoding="utf-8") as f:
        for entry in dataset:
            f.write(json.dumps(entry) + "\n")
            
    print("=" * 60)
    print(f"🎉 Dataset creation complete! Total samples: {len(dataset)}")
    print(f"📁 Saved to: {output_path}")
    print("=" * 60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate FineSec Security LLM Training Dataset")
    parser.add_argument("--output", default="data/training_data_strong.jsonl", help="Output jsonl file path")
    parser.add_argument("--cve-limit", type=int, default=10000, help="Max CVEs to extract (default: 10000, set to 0 or leave empty for all 115k)")
    parser.add_argument("--all-cves", action="store_true", help="Process ALL 115,230 CVEs from local parquet file")
    
    args = parser.parse_args()
    limit = None if args.all_cves or args.cve_limit == 0 else args.cve_limit
    build_dataset(output_path=args.output, cve_limit=limit)
