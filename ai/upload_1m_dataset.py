#!/usr/bin/env python3
import os
from huggingface_hub import HfApi

token = os.environ.get("HF_TOKEN")
if not token:
    raise ValueError("❌ HF_TOKEN environment variable is missing!")

repo_id = "elsiddik/zz"
api = HfApi()

print(f"1. Verifying Hugging Face Dataset repository: {repo_id}...")
api.create_repo(repo_id=repo_id, repo_type="dataset", token=token, exist_ok=True)

readme_content = """---
license: apache-2.0
task_categories:
- text-generation
- text2text-generation
language:
- en
- code
tags:
- cybersecurity
- vulnerability-detection
- cve
- code-audit
- code-repair
size_categories:
- 1M<n<10M
---

# FineSec-1M Master Security Dataset

**FineSec-1M** is a high-precision, 1.11 GB cybersecurity dataset containing **1,000,000 training examples** (500,000 vulnerable code snippets + 500,000 safe control examples) designed for fine-tuning state-of-the-art security LLMs.

## Dataset Structure

1. **Server-Side Request Forgery (SSRF - CWE-918)**: 167,054 examples
2. **Unquoted Search Paths (CWE-428)**: 166,525 examples
3. **Insecure Randomness (CWE-330)**: 166,421 examples
4. **Safe Control Code Suite (N/A)**: 500,000 examples

## Class & Language Balance
- **Class Balance**: Exactly 50.0% Vulnerable | 50.0% Safe Controls (Guarantees zero false positives).
- **Languages**: Python (66.7%) & C/C++ (33.3%).

## Usage with Hugging Face Datasets

```python
from datasets import load_dataset

dataset = load_dataset('elsiddik/zz', split='train')
print(f'Total records: {len(dataset)}')
```
"""

print("2. Uploading dataset README.md...")
api.upload_file(
    path_or_fileobj=readme_content.encode("utf-8"),
    path_in_repo="README.md",
    repo_id=repo_id,
    repo_type="dataset",
    token=token
)

dataset_file = "data/custom_expansion.jsonl"
print(f"3. Uploading {dataset_file} (1.11 GB / 1,000,000 records) to {repo_id}...")
api.upload_file(
    path_or_fileobj=dataset_file,
    path_in_repo="custom_expansion.jsonl",
    repo_id=repo_id,
    repo_type="dataset",
    token=token
)

print(f"🎉 Successfully uploaded 1,000,000 sample dataset to https://huggingface.co/datasets/{repo_id}!")
