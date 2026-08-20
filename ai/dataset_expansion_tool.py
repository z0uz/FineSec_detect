#!/usr/bin/env python3
"""
FineSec Custom Dataset Synthesizer & Expander
Generates targeted security training pairs across Python, C/C++, JS, Go, Java, PHP, and Solidity.
"""

import json
import random
import argparse

SYSTEM_PROMPT = (
    "You are FineSec-AI, an expert Application Security Engineer. "
    "Analyze code snippet or security report for vulnerabilities and output JSON report with fields: "
    "'is_vulnerable', 'cwe', 'vulnerability_type', 'severity', 'vulnerable_lines', 'explanation', 'remediation', 'fixed_code'."
)

EXPANDED_TEMPLATES = [
    # SSRF (CWE-918)
    {
        "lang": "python", "cwe": "CWE-918", "type": "Server-Side Request Forgery (SSRF)", "sev": "HIGH",
        "vuln": "import requests\ndef fetch_{feature}(req):\n    url = req.GET.get('{param}')\n    return requests.get(url).text",
        "safe": "import requests, urllib.parse\nALLOWED_HOSTS = ['api.internal.com']\ndef fetch_{feature}(req):\n    url = req.GET.get('{param}')\n    host = urllib.parse.urlparse(url).netloc\n    if host not in ALLOWED_HOSTS:\n        raise ValueError('Host not allowed')\n    return requests.get(url).text",
        "exp": "Untrusted request parameter `{param}` is passed directly to HTTP fetch without hostname validation.",
        "rem": "Enforce strict domain whitelist validation before initiating outgoing HTTP requests."
    },
    # Unquoted Search Path (CWE-428)
    {
        "lang": "c", "cwe": "CWE-428", "type": "Unquoted Search Path", "sev": "HIGH",
        "vuln": "void start_{feature}() {{\n    WinExec(\"C:\\\\Program Files\\\\MyApp\\\\{feature}.exe\", SW_SHOW);\n}}",
        "safe": "void start_{feature}() {{\n    CreateProcess(\"C:\\\\Program Files\\\\MyApp\\\\{feature}.exe\", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);\n}}",
        "exp": "Unquoted binary executable path containing spaces allows privilege escalation via malicious binary placement.",
        "rem": "Enclose path in quotation marks or pass application name directly as first argument to CreateProcess."
    },
    # Insecure Randomness (CWE-330)
    {
        "lang": "python", "cwe": "CWE-330", "type": "Insecure Randomness", "sev": "MEDIUM",
        "vuln": "import random\ndef gen_{feature}_token():\n    return str(random.randint(100000, 999999))",
        "safe": "import secrets\ndef gen_{feature}_token():\n    return secrets.token_hex(16)",
        "exp": "Standard pseudo-random generator `random` is predictable and non-cryptographic.",
        "rem": "Use cryptographically secure random number generators such as secrets or os.urandom."
    }
]

FEATURES = ["auth", "webhook", "proxy", "image", "report", "exporter", "backup", "session"]
PARAMS = ["url", "target", "host", "endpoint", "callback", "redirect"]

def generate_samples(count: int) -> list:
    samples = []
    for i in range(count):
        tmpl = random.choice(EXPANDED_TEMPLATES)
        feature = random.choice(FEATURES) + f"_{random.randint(10, 999)}"
        param = random.choice(PARAMS)
        
        is_vuln = (i % 2 == 0)
        
        if is_vuln:
            code = tmpl["vuln"].format(feature=feature, param=param)
            resp = {
                "is_vulnerable": True,
                "cwe": tmpl["cwe"],
                "vulnerability_type": tmpl["type"],
                "severity": tmpl["sev"],
                "vulnerable_lines": [code.split("\n")[2] if len(code.split("\n")) > 2 else code],
                "explanation": tmpl["exp"].format(param=param),
                "remediation": tmpl["rem"],
                "fixed_code": tmpl["safe"].format(feature=feature, param=param)
            }
        else:
            code = tmpl["safe"].format(feature=feature, param=param)
            resp = {
                "is_vulnerable": False,
                "cwe": "N/A",
                "vulnerability_type": "None",
                "severity": "NONE",
                "vulnerable_lines": [],
                "explanation": "Code includes secure input validation and cryptographic controls.",
                "remediation": "No remediation required.",
                "fixed_code": code
            }

        samples.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Analyze this {tmpl['lang']} code snippet for vulnerabilities:\n```\n{code}\n```"},
                {"role": "assistant", "content": json.dumps(resp, indent=2)}
            ]
        })
    return samples

def main():
    parser = argparse.ArgumentParser(description="Expand FineSec Custom Security Dataset")
    parser.add_argument("--count", type=int, default=1000, help="Number of samples to generate")
    parser.add_argument("--output", default="data/custom_expansion.jsonl", help="Output file path")
    args = parser.parse_args()

    samples = generate_samples(args.count)
    with open(args.output, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")
    print(f"Generated {len(samples)} samples in {args.output}")

if __name__ == "__main__":
    main()
