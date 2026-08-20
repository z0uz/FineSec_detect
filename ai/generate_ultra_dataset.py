#!/usr/bin/env python3
"""
FineSec Ultra Dataset Generator (200,000+ Security Samples)
Generates a massive, high-diversity dataset for training state-of-the-art security LLMs.

Sources:
1. ALL 115,230 NVD CVE Records from parquet database
2. 100,000+ Augmented Multi-Language Code Snippets & Secure Fix Refactors
3. OWASP Top 10 & CWE Specific Real-World Scenarios
"""

import os
import json
import random
import argparse
import pandas as pd
import urllib.request

SYSTEM_PROMPT = (
    "You are FineSec-AI, an expert Application Security Engineer. "
    "Analyze code snippet or security report for vulnerabilities and output JSON report with fields: "
    "'is_vulnerable', 'cwe', 'vulnerability_type', 'severity', 'vulnerable_lines', 'explanation', 'remediation', 'fixed_code'."
)

# Deep Multi-Language Templates with diverse code structures
CODE_TEMPLATES = [
    # 1. Python SQL Injection
    {
        "lang": "python", "cwe": "CWE-89", "type": "SQL Injection", "sev": "CRITICAL",
        "vuln": "def search_{feature}(req):\n    val = req.GET.get('{param}')\n    query = f\"SELECT * FROM {table} WHERE {col} = '{{val}}'\"\n    cursor.execute(query)\n    return cursor.fetchall()",
        "safe": "def search_{feature}(req):\n    val = req.GET.get('{param}')\n    query = \"SELECT * FROM {table} WHERE {col} = %s\"\n    cursor.execute(query, [val])\n    return cursor.fetchall()",
        "exp": "Raw user input `{param}` is formatted directly into SQL query string without parameterization.",
        "rem": "Use parameterized queries or ORM methods."
    },
    # 2. Python OS Command Injection
    {
        "lang": "python", "cwe": "CWE-78", "type": "OS Command Injection", "sev": "CRITICAL",
        "vuln": "import os\ndef exec_{feature}(val):\n    os.system(f\"nslookup {{val}}\")",
        "safe": "import subprocess\ndef exec_{feature}(val):\n    subprocess.run([\"nslookup\", val], check=True)",
        "exp": "User input is directly interpolated into OS command executed via shell.",
        "rem": "Use subprocess.run with argument array and shell=False."
    },
    # 3. JavaScript/Node XSS
    {
        "lang": "javascript", "cwe": "CWE-79", "type": "Reflected Cross-Site Scripting (XSS)", "sev": "HIGH",
        "vuln": "app.get('/{feature}', (req, res) => {{\n    const data = req.query.{param};\n    res.send(`<div>Search result: ${{data}}</div>`);\n}});",
        "safe": "app.get('/{feature}', (req, res) => {{\n    const data = escapeHtml(req.query.{param} || '');\n    res.send(`<div>Search result: ${{data}}</div>`);\n}});",
        "exp": "Untrusted request input is rendered directly into HTML response body.",
        "rem": "Sanitize and escape HTML special characters before rendering."
    },
    # 4. C/C++ Buffer Overflow
    {
        "lang": "c", "cwe": "CWE-120", "type": "Buffer Overflow", "sev": "CRITICAL",
        "vuln": "void process_{feature}(char *src) {{\n    char dest[128];\n    strcpy(dest, src);\n}}",
        "safe": "void process_{feature}(char *src) {{\n    char dest[128];\n    strncpy(dest, src, sizeof(dest) - 1);\n    dest[127] = '\\0';\n}}",
        "exp": "Unbounded string copy into fixed size buffer can lead to memory corruption and code execution.",
        "rem": "Use safe bounded string copy routines such as strncpy."
    },
    # 5. Go Path Traversal
    {
        "lang": "go", "cwe": "CWE-22", "type": "Path Traversal", "sev": "HIGH",
        "vuln": "func handle{feature}(w http.ResponseWriter, r *http.Request) {{\n    file := r.URL.Query().Get(\"{param}\")\n    data, _ := os.ReadFile(\"/tmp/uploads/\" + file)\n    w.Write(data)\n}}",
        "safe": "func handle{feature}(w http.ResponseWriter, r *http.Request) {{\n    file := filepath.Base(r.URL.Query().Get(\"{param}\"))\n    data, _ := os.ReadFile(filepath.Join(\"/tmp/uploads\", file))\n    w.Write(data)\n}}",
        "exp": "Unsanitized user path string allows directory traversal sequences (../).",
        "rem": "Sanitize input with filepath.Base and verify clean absolute path bounds."
    },
    # 6. Java Insecure Deserialization
    {
        "lang": "java", "cwe": "CWE-502", "type": "Deserialization of Untrusted Data", "sev": "CRITICAL",
        "vuln": "public Object parseData(InputStream stream) throws Exception {{\n    ObjectInputStream ois = new ObjectInputStream(stream);\n    return ois.readObject();\n}}",
        "safe": "public Object parseData(InputStream stream) throws Exception {{\n    ValidatingObjectInputStream ois = new ValidatingObjectInputStream(stream);\n    ois.accept(MyAllowedClass.class);\n    return ois.readObject();\n}}",
        "exp": "Reading untrusted ObjectInputStream allows arbitrary Java class instantiation and remote code execution.",
        "rem": "Use class filtering object streams or switch to JSON serialization."
    },
    # 7. Solidity Reentrancy
    {
        "lang": "solidity", "cwe": "CWE-841", "type": "Reentrancy Vulnerability", "sev": "CRITICAL",
        "vuln": "function withdraw(uint amount) public {{\n    require(balances[msg.sender] >= amount);\n    (bool ok, ) = msg.sender.call{{value: amount}}(\"\");\n    require(ok);\n    balances[msg.sender] -= amount;\n}}",
        "safe": "function withdraw(uint amount) public nonReentrant {{\n    require(balances[msg.sender] >= amount);\n    balances[msg.sender] -= amount;\n    (bool ok, ) = msg.sender.call{{value: amount}}(\"\");\n    require(ok);\n}}",
        "exp": "External ether transfer happens before internal state update, enabling recursive reentrancy attacks.",
        "rem": "Follow Checks-Effects-Interactions pattern or use ReentrancyGuard."
    }
]

FEATURES = ["user", "order", "report", "document", "session", "config", "token", "profile", "data", "log"]
PARAMS = ["id", "query", "target", "filename", "token", "key", "name", "file", "path"]
TABLES = ["users", "accounts", "payments", "logs", "transactions", "permissions"]
COLS = ["id", "username", "email", "status", "role", "access_key"]

def load_all_parquet_cves(parquet_path: str) -> list:
    """Load ALL CVE records from parquet database, downloading if missing"""
    if not os.path.exists(parquet_path):
        print(f"📦 Downloading NVD Parquet database to {parquet_path}...")
        os.makedirs(os.path.dirname(parquet_path), exist_ok=True)
        url = "https://huggingface.co/datasets/elsiddik/zz/resolve/main/train-00000-of-00001.parquet"
        try:
            urllib.request.urlretrieve(url, parquet_path)
            print("✅ Downloaded NVD Parquet database!")
        except Exception as e:
            print(f"⚠️ Parquet file not available: {e}")
            return []
    
    print(f"📦 Extracting ALL CVE records from {parquet_path}...")
    df = pd.read_parquet(parquet_path)
    total_cves = len(df)
    print(f"🔥 Found {total_cves} total CVE records!")
    
    samples = []
    for _, row in df.iterrows():
        try:
            cve_id = row.get("id", "CVE-Unknown")
            desc = row.get("descriptions", "")
            primary_cwe = row.get("primary_cwe")
            
            if pd.isna(primary_cwe) or not desc:
                continue
            
            cwe_str = f"CWE-{int(primary_cwe)}"
            
            resp = {
                "is_vulnerable": True,
                "cwe": cwe_str,
                "vulnerability_type": f"Security Vulnerability ({cwe_str})",
                "severity": "HIGH",
                "vulnerable_lines": [desc[:120] + "..."],
                "explanation": f"{cve_id}: {desc}",
                "remediation": f"Apply security updates and enforce input validation for {cwe_str}.",
                "fixed_code": "# Upgrade software version and apply official security patch"
            }
            
            samples.append({
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": f"Analyze security vulnerability report:\n{cve_id}: {desc}"},
                    {"role": "assistant", "content": json.dumps(resp, indent=2)}
                ]
            })
        except Exception:
            continue
            
    print(f"✅ Extracted {len(samples)} valid CVE advisory samples.")
    return samples

def generate_augmented_samples(count: int = 100000) -> list:
    """Generate 100,000+ augmented code samples"""
    print(f"⚡ Generating {count} augmented multi-language code samples...")
    samples = []
    
    for i in range(count):
        tmpl = random.choice(CODE_TEMPLATES)
        feature = random.choice(FEATURES) + f"_{random.randint(1, 999)}"
        param = random.choice(PARAMS)
        table = random.choice(TABLES)
        col = random.choice(COLS)
        
        is_vuln = (i % 2 == 0)
        
        if is_vuln:
            code = tmpl["vuln"].format(feature=feature, param=param, table=table, col=col)
            resp = {
                "is_vulnerable": True,
                "cwe": tmpl["cwe"],
                "vulnerability_type": tmpl["type"],
                "severity": tmpl["sev"],
                "vulnerable_lines": [code.split("\n")[2] if len(code.split("\n")) > 2 else code],
                "explanation": tmpl["exp"].format(param=param),
                "remediation": tmpl["rem"],
                "fixed_code": tmpl["safe"].format(feature=feature, param=param, table=table, col=col)
            }
        else:
            code = tmpl["safe"].format(feature=feature, param=param, table=table, col=col)
            resp = {
                "is_vulnerable": False,
                "cwe": "N/A",
                "vulnerability_type": "None",
                "severity": "NONE",
                "vulnerable_lines": [],
                "explanation": "Code contains valid security validation controls.",
                "remediation": "No remediation required.",
                "fixed_code": code
            }
            
        samples.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this {tmpl['lang']} code for security vulnerabilities:\n```\n{code}\n```"},
                {"role": "assistant", "content": json.dumps(resp, indent=2)}
            ]
        })
        
    print(f"✅ Generated {len(samples)} synthetic code samples.")
    return samples

def main():
    parser = argparse.ArgumentParser(description="Generate 200,000+ Sample FineSec Dataset")
    parser.add_argument("--output", default="data/training_data_200k.jsonl", help="Output file path")
    parser.add_argument("--synthetic-count", type=int, default=100000, help="Synthetic sample count")
    
    args = parser.parse_args()
    
    parquet_path = "data/train-00000-of-00001.parquet"
    cve_samples = load_all_parquet_cves(parquet_path)
    synthetic_samples = generate_augmented_samples(count=args.synthetic_count)
    
    all_dataset = cve_samples + synthetic_samples
    random.seed(42)
    random.shuffle(all_dataset)
    
    print(f"💾 Writing {len(all_dataset)} total samples to {args.output}...")
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    with open(args.output, "w", encoding="utf-8") as f:
        for entry in all_dataset:
            f.write(json.dumps(entry) + "\n")
            
    print("=" * 60)
    print(f"🎉 Ultra Dataset Complete! Total: {len(all_dataset)} records.")
    print(f"📁 Saved to: {args.output}")
    print("=" * 60)

if __name__ == "__main__":
    main()
