#!/usr/bin/env python3
"""
FineSec Vulnerability Model Benchmark & Rating Script
Evaluates 'elsiddik/finsec_detector' against a benchmark dataset of vulnerable & secure code snippets.
Supports both GPU (Unsloth 4-bit) and CPU (Transformers) execution.

Metrics Computed:
- Precision (Avoidance of False Positives)
- Recall / Detection Rate (Avoidance of Missed Vulnerabilities)
- F1-Score (Balanced Quality)
- False Positive Rate (FPR)
- CWE Classification Accuracy
- Valid JSON Output Rate
"""

import os
import json
import re
import argparse
import torch

# Standard benchmark suite for rating security detection models
BENCHMARK_SUITE = [
    # 1. SQL Injection (Vulnerable)
    {
        "id": "SQLi-01",
        "language": "python",
        "is_vulnerable": True,
        "cwe": "CWE-89",
        "code": """def get_user(username):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchone()"""
    },
    # 2. SQL Injection (Safe - Parameterized)
    {
        "id": "SQLi-02-Safe",
        "language": "python",
        "is_vulnerable": False,
        "cwe": "N/A",
        "code": """def get_user(username):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()"""
    },
    # 3. Remote Code Execution / Command Injection (Vulnerable)
    {
        "id": "RCE-01",
        "language": "python",
        "is_vulnerable": True,
        "cwe": "CWE-78",
        "code": """import os

def ping_host(host):
    os.system("ping -c 1 " + host)"""
    },
    # 4. Command Injection (Safe - Subprocess array)
    {
        "id": "RCE-02-Safe",
        "language": "python",
        "is_vulnerable": False,
        "cwe": "N/A",
        "code": """import subprocess

def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], check=True)"""
    },
    # 5. Cross-Site Scripting XSS (Vulnerable)
    {
        "id": "XSS-01",
        "language": "javascript",
        "is_vulnerable": True,
        "cwe": "CWE-79",
        "code": """app.get('/welcome', (req, res) => {
    let name = req.query.name;
    res.send("<h1>Welcome " + name + "</h1>");
});"""
    },
    # 6. Path Traversal (Vulnerable)
    {
        "id": "PathTraversal-01",
        "language": "python",
        "is_vulnerable": True,
        "cwe": "CWE-22",
        "code": """def read_file(filename):
    with open('/var/www/uploads/' + filename, 'r') as f:
        return f.read()"""
    },
    # 7. Insecure Deserialization (Vulnerable)
    {
        "id": "Deserialization-01",
        "language": "python",
        "is_vulnerable": True,
        "cwe": "CWE-502",
        "code": """import pickle

def load_user_data(raw_bytes):
    return pickle.loads(raw_bytes)"""
    },
    # 8. Buffer Overflow (Vulnerable)
    {
        "id": "BufferOverflow-01",
        "language": "c",
        "is_vulnerable": True,
        "cwe": "CWE-120",
        "code": """void copy_input(char *user_str) {
    char buffer[64];
    strcpy(buffer, user_str);
}"""
    },
    # 9. Hardcoded Secret (Vulnerable)
    {
        "id": "HardcodedSecret-01",
        "language": "python",
        "is_vulnerable": True,
        "cwe": "CWE-798",
        "code": """AWS_SECRET_KEY = "DUMMY_AWS_KEY_EXAMPLE_12345"
def connect_aws():
    return boto3.client('s3', aws_secret_access_key=AWS_SECRET_KEY)"""
    },
    # 10. Safe Input Validation (Safe)
    {
        "id": "Safe-01",
        "language": "python",
        "is_vulnerable": False,
        "cwe": "N/A",
        "code": """import os, re

def get_clean_path(user_input):
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', user_input)
    return os.path.join('/tmp/safe', safe_name)"""
    }
]

SYSTEM_PROMPT = """You are FineSec-AI, an expert Application Security Engineer. Analyze code snippet for vulnerabilities and output JSON report with fields: 'vulnerabilities' (list of objects with severity, cwe, description, vulnerable_line, fix_code)."""

def extract_json(response: str) -> dict:
    """Extract JSON object from response string."""
    try:
        return json.loads(response)
    except Exception:
        pass
    
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
            
    match = re.search(r'(\{.*\})', response, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            pass
            
    return {}

def evaluate_model(model_name_or_path: str):
    """Load model and run benchmark evaluation."""
    print("=" * 70)
    print(f"🛡️ FineSec Model Evaluation Suite")
    print(f"📦 Model: {model_name_or_path}")
    
    use_cuda = torch.cuda.is_available()
    device_str = "CUDA (GPU)" if use_cuda else "CPU"
    print(f"⚡ Device: {device_str}")
    print("=" * 70)

    if use_cuda:
        try:
            from unsloth import FastLanguageModel
            print("🚀 Loading with Unsloth 4-bit on GPU...")
            model, tokenizer = FastLanguageModel.from_pretrained(
                model_name = model_name_or_path,
                max_seq_length = 1024,
                load_in_4bit = True,
            )
            FastLanguageModel.for_inference(model)
        except Exception as e:
            print(f"⚠️ Unsloth load failed, falling back to HuggingFace Transformers: {e}")
            from transformers import AutoModelForCausalLM, AutoTokenizer
            tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
            model = AutoModelForCausalLM.from_pretrained(
                model_name_or_path,
                torch_dtype=torch.float16,
                device_map="auto"
            )
    else:
        print("💻 Loading with Transformers on CPU (this may take a moment)...")
        from transformers import AutoModelForCausalLM, AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(model_name_or_path)
        model = AutoModelForCausalLM.from_pretrained(
            model_name_or_path,
            torch_dtype=torch.float32,
            device_map="cpu"
        )

    print("✅ Model loaded successfully!\n")

    tp, fp, tn, fn = 0, 0, 0, 0
    correct_cwe = 0
    valid_json_count = 0
    total = len(BENCHMARK_SUITE)

    for idx, sample in enumerate(BENCHMARK_SUITE, 1):
        prompt = f"### System Prompt:\n{SYSTEM_PROMPT}\n\n### Input Code ({sample['language']}):\n```{sample['language']}\n{sample['code']}\n```\n\n### Security Analysis (JSON):"
        
        device_target = "cuda" if use_cuda else "cpu"
        inputs = tokenizer(prompt, return_tensors="pt").to(device_target)
        
        with torch.no_grad():
            outputs = model.generate(**inputs, max_new_tokens=512)
            
        input_length = inputs.input_ids.shape[1]
        response_text = tokenizer.decode(outputs[0][input_length:], skip_special_tokens=True)

        parsed = extract_json(response_text)
        is_valid_json = len(parsed) > 0
        if is_valid_json:
            valid_json_count += 1

        has_vuln = False
        if isinstance(parsed, dict):
            if parsed.get("is_vulnerable") is True:
                has_vuln = True
            elif "vulnerabilities" in parsed and isinstance(parsed["vulnerabilities"], list) and len(parsed["vulnerabilities"]) > 0:
                has_vuln = True
            elif parsed.get("cwe") and str(parsed.get("cwe")).upper() != "N/A":
                has_vuln = True

        actual_vuln = sample["is_vulnerable"]

        if actual_vuln and has_vuln:
            tp += 1
            status = "✅ True Positive"
        elif not actual_vuln and not has_vuln:
            tn += 1
            status = "✅ True Negative"
        elif not actual_vuln and has_vuln:
            fp += 1
            status = "❌ False Positive"
        else:
            fn += 1
            status = "❌ False Negative (Missed Vuln!)"

        cwe_match = False
        if actual_vuln and sample["cwe"] in response_text:
            correct_cwe += 1
            cwe_match = True

        print(f"[{idx}/{total}] {sample['id']:<18} -> {status:<30} | CWE Match: {str(cwe_match):<5} | Valid JSON: {is_valid_json}")

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total
    cwe_acc = (correct_cwe / (tp + fn)) * 100 if (tp + fn) > 0 else 0.0
    json_rate = (valid_json_count / total) * 100

    print("\n" + "=" * 70)
    print("📊 BENCHMARK RATING SUMMARY REPORT")
    print("=" * 70)
    print(f"🎯 Total Test Samples       : {total}")
    print(f"✅ Overall Accuracy         : {accuracy * 100:.1f}%")
    print(f"🎯 Precision (No FP)        : {precision * 100:.1f}%")
    print(f"🔎 Recall / Detection Rate  : {recall * 100:.1f}%")
    print(f"⚖️ F1 Score                 : {f1_score * 100:.1f}%")
    print(f"🏷️ CWE Match Accuracy       : {cwe_acc:.1f}%")
    print(f"📄 Valid JSON Format Rate   : {json_rate:.1f}%")
    print("-" * 70)
    print(f"Confusion Matrix -> TP: {tp} | FP: {fp} | TN: {tn} | FN: {fn}")
    print("=" * 70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate FineSec Security Model")
    parser.add_argument("--model", type=str, default="elsiddik/finsec_detector", help="Hugging Face model ID or local path")
    args = parser.parse_args()
    
    evaluate_model(args.model)
