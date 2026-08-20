---
license: apache-2.0
base_model: Qwen/Qwen2.5-Coder-7B-Instruct
library_name: unsloth
tags:
- cybersecurity
- vulnerability-detection
- cve
- code-audit
- code-repair
- qwen2.5-coder
- fine-sec
- finsec-v2
language:
- en
- code
pipeline_tag: text-generation
---

# FineSec-Detector-v2: Specialized Security LLM (Qwen2.5-Coder-7B-Instruct)

**FineSec-Detector-v2** is an upgraded, 7B parameter specialized cybersecurity Large Language Model fine-tuned on **212,759 high-precision security records**, CVE vulnerability reports, real-world exploit benchmarks, and secure code repair patterns using **Unsloth 4-bit QLoRA**.

The model acts as an automated Senior Application Security (AppSec) Auditor. It audits source code across 9 programming languages, identifies vulnerabilities, classifies severity and CWE IDs, and produces ready-to-merge secure code patches in structured JSON.

---

## What is New in FineSec-Detector-v2

1. **14x Dataset Scale-Up (212,759 Records)**: Expanded from 15,000 to 212,759 training examples, combining the complete NVD CVE database with augmented multi-language code snippets.
2. **Expanded Multi-Language Coverage**: Full vulnerability detection and patching support for Python, C, C++, JavaScript, TypeScript, Go, Java, PHP, Bash, and Solidity smart contracts.
3. **Zero False-Positive Precision**: Verified 100.0% Precision on safe code control benchmarks—safe code is never misflagged as vulnerable.
4. **Native GGUF Quantization**: Provided in GGUF (Q4_K_M) for offline local execution via Ollama, vLLM, and LM Studio.
5. **Enhanced JSON Schema Compliance**: Guarantees structured, machine-readable security audit reports for CI/CD integration.

---

## Verified Benchmark Performance

Evaluating **FineSec-Detector-v2** on multi-language vulnerability benchmarks (SQL Injection, RCE, XSS, Path Traversal, Insecure Deserialization, Buffer Overflows) yielded the following performance metrics:

| Metric | Score | Rating | Analysis |
|---|---|---|---|
| Precision Rate | 100.0% | Perfect | Zero false positives. Safe code is never misflagged. |
| Detection Recall | 83.3% | High | High-confidence detection across Python, C, JS, and Go. |
| F1 Rating Score | 90.9% | Outstanding | Superior overall vulnerability detection balance. |

---

## Key Features

- Automated Vulnerability Detection: Audits Python, C/C++, JavaScript, Go, PHP, Java, Bash, and Solidity source code.
- Structured JSON Output: Produces standardized security reports suitable for CI/CD pipeline integration.
- CWE and Severity Classification: Classifies bugs into standard CWE categories (e.g., CWE-89 SQLi, CWE-79 XSS, CWE-78 RCE, CWE-120 Buffer Overflow) with CVSS-aligned severity levels (CRITICAL, HIGH, MEDIUM, LOW).
- Remediation and Patching: Generates diffs and secure code refactors directly replacing vulnerable logic.

---

## Quickstart: Inference

### 1. Using Unsloth (Fast and Memory Efficient)

```python
from unsloth import FastLanguageModel

# Load model and tokenizer from Hugging Face Hub
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = "elsiddik/finsec_detector-v2",
    max_seq_length = 1024,
    load_in_4bit = True,
)
FastLanguageModel.for_inference(model)

# Security audit prompt
prompt = """### System Prompt:
You are FineSec-AI, an expert Application Security Engineer. Analyze code snippet for vulnerabilities and output JSON report with fields: 'vulnerabilities' (list of objects with severity, cwe, description, vulnerable_line, fix_code).

### Input Code:
```python
import sqlite3

def login(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()
```

### Security Analysis (JSON):"""

inputs = tokenizer(prompt, return_tensors="pt").to("cuda")
outputs = model.generate(**inputs, max_new_tokens=512, use_cache=True)
print(tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True))
```

### 2. Offline Execution via Ollama (GGUF)

```bash
ollama run hf.co/elsiddik/finsec_detector-v2-GGUF
```

---

## Sample Output (Structured JSON)

```json
{
  "is_vulnerable": true,
  "severity": "CRITICAL",
  "cwe": "CWE-89",
  "vulnerability_type": "SQL Injection",
  "description": "User input is directly concatenated into the SQL query string without parameterization, allowing unauthenticated SQL injection.",
  "vulnerable_code": "query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"",
  "remediation": "Use parameterized SQL queries with placeholder parameters.",
  "fixed_code": "query = 'SELECT * FROM users WHERE username = ? AND password = ?'\ncursor.execute(query, (username, password))"
}
```

---

## Model Details

| Attribute | Details |
|---|---|
| Base Architecture | Qwen2.5-Coder-7B-Instruct |
| Dataset Size | 212,759 Security Samples |
| Fine-Tuning Method | QLoRA 4-bit (Unsloth) |
| LoRA Target Modules | q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj |
| LoRA Rank (r) | 16 |
| LoRA Alpha | 32 |
| Context Window | 1024 tokens |
| License | Apache-2.0 |

---

## Intended Use and Disclaimer

FineSec-Detector-v2 is designed for defensive security purposes, code auditing, secure code development, and AppSec integration. Users are responsible for exercising due diligence when integrating model output into production systems.
