#!/usr/bin/env python3
import os
from huggingface_hub import HfApi

v1_readme = """---
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
language:
- en
- code
pipeline_tag: text-generation
---

# FineSec-Detector: Specialized Security LLM (Qwen2.5-Coder-7B-Instruct)

**FineSec-Detector** is a 7B parameter specialized cybersecurity Large Language Model fine-tuned on high-precision CVE vulnerability reports, real-world exploit benchmarks, and secure code repair patterns using **Unsloth 4-bit QLoRA**.

The model acts as an automated Senior Application Security (AppSec) Auditor. It audits source code across 9 programming languages, identifies vulnerabilities, classifies severity and CWE IDs, and produces ready-to-merge secure code patches in structured JSON.

---

## Verified Benchmark Performance

Evaluating **FineSec-Detector** on multi-language vulnerability benchmarks (SQL Injection, RCE, XSS, Path Traversal, Insecure Deserialization, Buffer Overflows) yielded the following performance metrics:

| Metric | Score | Rating | Analysis |
|---|---|---|---|
| Precision Rate | 100.0% | Perfect | Zero false positives. Safe code is never misflagged. |
| Detection Recall | 83.3% | High | High-confidence detection across Python, C, JS, and Go. |
| F1 Rating Score | 90.9% | Outstanding | Superior overall vulnerability detection balance. |

---

## Key Features

- Automated Vulnerability Detection: Audits Python, C/C++, JavaScript, Go, PHP, Java, and Bash source code.
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
    model_name = "elsiddik/finsec_detector",
    max_seq_length = 1024,
    load_in_4bit = True,
)
FastLanguageModel.for_inference(model)
```

---

## Model Details

| Attribute | Details |
|---|---|
| Base Architecture | Qwen2.5-Coder-7B-Instruct |
| Fine-Tuning Method | QLoRA 4-bit (Unsloth) |
| Context Window | 1024 tokens |
| License | Apache-2.0 |
"""

api = HfApi()
token = os.environ.get('HF_TOKEN')

if token:
    print('Restoring original v1 Model Card on elsiddik/finsec_detector...')
    api.upload_file(
        path_or_fileobj=v1_readme.encode('utf-8'),
        path_in_repo='README.md',
        repo_id='elsiddik/finsec_detector',
        token=token
    )
    print('✅ Successfully restored original v1 repository elsiddik/finsec_detector!')
